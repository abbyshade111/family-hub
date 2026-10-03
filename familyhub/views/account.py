from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from .. import audit, forms, oidc, security
from ..db import get_db
from ..security import login_required
from .oauth import begin

bp = Blueprint("account", __name__, url_prefix="/account")

WRONG_PASSWORD = "Your current password isn't right."
LOCKED_OUT = "Too many wrong passwords. Wait 15 minutes and try again."
CONFIRM_FIRST = "To do that, first confirm it's you with one of the \"Confirm with\" buttons below."
LAST_WAY_IN = "You can't disconnect your only way to sign in. Set a password or connect another account first."

# How recently someone without a password must have signed in to make sensitive changes.
RECENT_SIGN_IN_SECONDS = 10 * 60


def _check_password(db, password):
    """Check the signed-in user's password, counting wrong ones like sign-in does. Returns an error or None."""
    email = g.user["email"]
    if security.too_many_failures(db, email):
        security.spend_password_time(password)
        audit.event("password_check", "locked", path=request.path)
        return LOCKED_OUT, 429
    stored = db.execute("SELECT password_hash FROM users WHERE id = ?", (g.user["id"],)).fetchone()[0]
    if not security.verify_password(password, stored):
        security.record_failure(db, email)
        db.commit()
        audit.event("password_check", "failed", path=request.path)
        return WRONG_PASSWORD, 400
    security.clear_failures(db, email)
    security.upgrade_password_if_needed(db, g.user["id"], password, stored)
    return None


def _recently_signed_in():
    return security.now() - g.user["created_at"] <= RECENT_SIGN_IN_SECONDS


def confirm_identity(db, password):
    """Is it really them? Their password if they have one; otherwise a sign-in in the last few minutes."""
    if g.user["has_password"]:
        return _check_password(db, password)
    if _recently_signed_in():
        return None
    audit.event("request_refused", "refused", reason="confirm_first", path=request.path, status=403)
    return CONFIRM_FIRST, 403


def _identities(db):
    return db.execute(
        "SELECT provider, email FROM oauth_identities WHERE user_id = ? ORDER BY provider", (g.user["id"],)
    ).fetchall()


def _other_sessions(db):
    """Sessions of this user, besides this one, that haven't timed out."""
    t = security.now()
    cfg = current_app.config
    return db.execute(
        """SELECT COUNT(*) FROM sessions
            WHERE user_id = ? AND token_hash != ? AND last_seen > ? AND created_at > ?""",
        (g.user["id"], g.session_hash, t - cfg["SESSION_IDLE_SECONDS"], t - cfg["SESSION_LIFETIME_SECONDS"]),
    ).fetchone()[0]


def _page(status=200, errors=None):
    db = get_db()
    connected = {row["provider"]: row for row in _identities(db)}
    return render_template(
        "account.html", errors=errors, providers=oidc.configured_providers(), connected=connected,
        recently_signed_in=_recently_signed_in(), other_sessions=_other_sessions(db),
    ), status


@bp.post("/name")
@login_required
def change_name():
    f = forms.FormReader(request.form)
    name = f.text("display_name", "Your name", 60)
    if f.errors:
        return _page(400, f.errors)
    db = get_db()
    db.execute("UPDATE users SET display_name = ? WHERE id = ?", (name, g.user["id"]))
    db.commit()
    return redirect(url_for("account.index", done="name-saved"))


@bp.post("/sign-out-others")
@login_required
def sign_out_others():
    # Only takes access away, so no password is asked for; the CSRF check still applies.
    db = get_db()
    ended = db.execute(
        "DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (g.user["id"], g.session_hash)
    ).rowcount
    db.commit()
    audit.event("sign_out_others", count=ended)
    return redirect(url_for("account.index", done="signed-out-others"))


@bp.get("")
@login_required
def index():
    return _page()


@bp.post("/password")
@login_required
def change_password():
    db = get_db()
    failed = confirm_identity(db, request.form.get("current", ""))
    if failed:
        return _page(failed[1], [failed[0]])
    new = request.form.get("new", "")
    problem = security.password_problem(new, g.user["email"], g.user["display_name"])
    if problem:
        return _page(400, [problem])
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (security.hash_password(new), g.user["id"]))
    security.end_all_sessions(db, g.user["id"])
    db.commit()
    audit.event("password_changed" if g.user["has_password"] else "password_set")
    response = redirect(url_for("account.index", done="password"))
    security.start_session(response, g.user["id"])
    return response


@bp.post("/connect/<provider_key>")
@login_required
def connect(provider_key):
    if provider_key not in oidc.configured_providers():
        abort(404)
    db = get_db()
    failed = confirm_identity(db, request.form.get("password", ""))
    if failed:
        return _page(failed[1], [failed[0]])
    db.commit()
    return begin(provider_key, "link", g.user["id"])


@bp.post("/confirm/<provider_key>")
@login_required
def confirm(provider_key):
    db = get_db()
    linked = db.execute(
        "SELECT 1 FROM oauth_identities WHERE user_id = ? AND provider = ?", (g.user["id"], provider_key)
    ).fetchone()
    if linked is None or provider_key not in oidc.configured_providers():
        abort(404)
    return begin(provider_key, "reauth", g.user["id"])


@bp.post("/disconnect/<provider_key>")
@login_required
def disconnect(provider_key):
    db = get_db()
    identities = [row["provider"] for row in _identities(db)]
    if provider_key not in identities:
        abort(404)
    failed = confirm_identity(db, request.form.get("password", ""))
    if failed:
        return _page(failed[1], [failed[0]])
    if not g.user["has_password"] and len(identities) < 2:
        return _page(400, [LAST_WAY_IN])
    db.execute("DELETE FROM oauth_identities WHERE user_id = ? AND provider = ?", (g.user["id"], provider_key))
    db.commit()
    audit.event("provider_disconnected", method=provider_key)
    return redirect(url_for("account.index", done="disconnected"))


@bp.post("/delete")
@login_required
def delete():
    db = get_db()
    failed = confirm_identity(db, request.form.get("password", ""))
    if failed:
        return _page(failed[1], [failed[0]])
    user_id, family_id = g.user["id"], g.user["family_id"]
    with db:
        others = db.execute(
            "SELECT id FROM users WHERE family_id = ? AND id != ? ORDER BY created_at, id",
            (family_id, user_id),
        ).fetchall()
        if others and g.user["role"] == "admin":
            has_other_admin = db.execute(
                "SELECT 1 FROM users WHERE family_id = ? AND id != ? AND role = 'admin'", (family_id, user_id)
            ).fetchone()
            if not has_other_admin:
                db.execute("UPDATE users SET role = 'admin' WHERE id = ?", (others[0]["id"],))
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        if not others:
            db.execute("DELETE FROM families WHERE id = ?", (family_id,))
    audit.event("account_deleted", reason=None if others else "family_deleted_too")
    response = redirect(url_for("auth.login_form", done="account-deleted"))
    security.clear_browser(response)
    return response

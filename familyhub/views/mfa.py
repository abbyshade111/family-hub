"""Authenticator app codes: the sign-in step, and setting one up or turning it off.

The owner's rule: optional for members, required for admins (security.admin_required sends an
admin without one here before they can use family settings, and admins can't turn it off).
"""

from flask import Blueprint, g, redirect, render_template, request, url_for

from .. import audit, security, signin, totp
from ..db import get_db
from ..security import login_required
from .account import confirm_identity

bp = Blueprint("mfa", __name__)

WRONG_CODE = "That code isn't right. Check your authenticator app and try again."
LOCKED_OUT = "Too many wrong codes. Wait 15 minutes and try again."


# --- the sign-in step -----------------------------------------------------------

@bp.get("/login/2fa")
def challenge():
    if signin.pending() is None:
        return redirect(url_for("auth.login_form"))
    return render_template("login_2fa.html")


@bp.post("/login/2fa")
def answer():
    waiting = signin.pending()
    if waiting is None:
        return redirect(url_for("auth.login_form"))
    db = get_db()
    who = {"user_id": waiting["user_id"], "family_id": waiting["family_id"]}
    if security.too_many_failures(db, waiting["email"]):
        audit.event("mfa_check", "locked", **who)
        return render_template("login_2fa.html", errors=[LOCKED_OUT]), 429

    code = request.form.get("code", "")[:60]
    step = totp.matching_step(waiting["totp_secret"], code, waiting["totp_last_step"])
    used_recovery = False
    if step is None and "-" in code:
        recovery_hash = security.lookup_hash(totp.normalize_recovery_code(code))
        used_recovery = db.execute(
            "DELETE FROM mfa_recovery_codes WHERE user_id = ? AND code_hash = ?",
            (waiting["user_id"], recovery_hash),
        ).rowcount == 1
    if step is None and not used_recovery:
        security.record_failure(db, waiting["email"])
        db.commit()
        audit.event("mfa_check", "failed", **who)
        return render_template("login_2fa.html", errors=[WRONG_CODE]), 401

    if step is not None:
        db.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, waiting["user_id"]))
    security.clear_failures(db, waiting["email"])
    response = redirect(url_for("home.index"))
    signin.forget_pending(response, waiting["token_hash"])
    db.commit()
    security.start_session(response, waiting["user_id"])
    audit.event("mfa_check", **who, method="recovery_code" if used_recovery else "authenticator")
    audit.event("sign_in", method=waiting["method"], **who)
    return response


# --- the Account page -----------------------------------------------------------

def _account_error(failed):
    from .account import _page   # the Account page, with an error on it
    return _page(failed[1], [failed[0]])


def _store_recovery_codes(db, user_id):
    codes = totp.new_recovery_codes()
    db.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (user_id,))
    db.executemany(
        "INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (?, ?)",
        [(user_id, security.lookup_hash(totp.normalize_recovery_code(c))) for c in codes],
    )
    return codes


@bp.post("/account/2fa/start")
@login_required
def start_setup():
    db = get_db()
    failed = confirm_identity(db, request.form.get("password", ""))
    if failed:
        return _account_error(failed)
    secret = totp.new_secret()
    db.execute("UPDATE users SET totp_pending_secret = ? WHERE id = ?", (secret, g.user["id"]))
    db.commit()
    # Shown in this response only (never in an address): the key and the link that opens an authenticator app.
    return render_template("mfa_setup.html", secret=secret, uri=totp.provisioning_uri(secret, g.user["email"]))


@bp.post("/account/2fa/confirm")
@login_required
def confirm_setup():
    db = get_db()
    pending_secret = db.execute(
        "SELECT totp_pending_secret FROM users WHERE id = ?", (g.user["id"],)
    ).fetchone()[0]
    if not pending_secret:
        return redirect(url_for("account.index"))
    step = totp.matching_step(pending_secret, request.form.get("code", "")[:40])
    if step is None:
        return render_template(
            "mfa_setup.html", secret=pending_secret, uri=totp.provisioning_uri(pending_secret, g.user["email"]),
            errors=[WRONG_CODE],
        ), 400
    db.execute(
        "UPDATE users SET totp_secret = ?, totp_pending_secret = NULL, totp_last_step = ? WHERE id = ?",
        (pending_secret, step, g.user["id"]),
    )
    codes = _store_recovery_codes(db, g.user["id"])
    # Other sessions signed in without the code: end them.
    db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (g.user["id"], g.session_hash))
    db.commit()
    audit.event("mfa_enabled")
    return render_template("mfa_codes.html", codes=codes, just_enabled=True)


@bp.post("/account/2fa/recovery-codes")
@login_required
def new_recovery_codes():
    if not g.user["totp_enabled"]:
        return redirect(url_for("account.index"))
    db = get_db()
    failed = confirm_identity(db, request.form.get("password", ""))
    if failed:
        return _account_error(failed)
    codes = _store_recovery_codes(db, g.user["id"])
    db.commit()
    audit.event("recovery_codes_replaced")
    return render_template("mfa_codes.html", codes=codes, just_enabled=False)


@bp.post("/account/2fa/disable")
@login_required
def disable():
    if not g.user["totp_enabled"]:
        return redirect(url_for("account.index"))
    if g.user["role"] == "admin":
        return _account_error(("Family admins need an authenticator app, so it can't be turned off.", 400))
    db = get_db()
    failed = confirm_identity(db, request.form.get("password", ""))
    if failed:
        return _account_error(failed)
    db.execute(
        "UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL, totp_last_step = NULL WHERE id = ?",
        (g.user["id"],),
    )
    db.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (g.user["id"],))
    db.commit()
    audit.event("mfa_disabled")
    return redirect(url_for("account.index", done="2fa-off"))

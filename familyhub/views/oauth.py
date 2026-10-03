"""Routes for signing in, signing up, connecting and re-confirming through a provider.

Every flow is tied to the browser that started it: a random value goes in a short-lived
cookie, its hash is stored with the flow's `state`, and the answer is only accepted from
a browser holding that cookie. Each state is used once.
"""

import hmac
import os
import secrets
import sqlite3

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from .. import accounts, audit, forms, limits, oidc, security, signin
from ..db import get_db
from .auth import read_family_choice

bp = Blueprint("oauth", __name__)

STATE_TTL_SECONDS = 10 * 60
PENDING_TTL_SECONDS = 15 * 60

TRY_AGAIN = "That sign-in didn't work or has expired. Please try again."


def _hash(value):
    return security.lookup_hash(value)


def _browser_cookie_name():
    return "__Host-fh_oauth" if current_app.config["COOKIE_SECURE"] else "fh_oauth"


def _set_browser_cookie(response, value):
    secure = current_app.config["COOKIE_SECURE"]
    # Apple answers with a cross-site form POST, which only carries SameSite=None cookies.
    response.set_cookie(
        _browser_cookie_name(), value, max_age=PENDING_TTL_SECONDS, httponly=True, secure=secure,
        samesite="None" if secure else "Lax", path="/",
    )


def _browser_hash():
    value = request.cookies.get(_browser_cookie_name(), "")
    return _hash(value) if 20 <= len(value) <= 100 else None


def _redirect_uri(provider):
    base = os.environ.get("FAMILY_HUB_BASE_URL", "").rstrip("/") or request.url_root.rstrip("/")
    return base + url_for("oauth.callback", provider_key=provider.key)


def _provider_or_404(provider_key):
    provider = oidc.configured_providers().get(provider_key)
    if provider is None:
        abort(404)
    return provider


def _failed(message=TRY_AGAIN, status=400):
    return render_template("oauth_error.html", message=message), status


def begin(provider_key, purpose, user_id=None):
    """Send the browser to the provider. Used here and by the Account page."""
    provider = _provider_or_404(provider_key)
    try:
        meta = oidc.discover(provider)
    except oidc.OIDCError as error:
        current_app.logger.warning("Sign-in with %s unavailable: %s", provider.key, error)
        return _failed(f"Signing in with {provider.label} isn't available right now. Please try again later.", 502)
    state, nonce, verifier, browser = (secrets.token_urlsafe(32) for _ in range(4))
    db = get_db()
    db.execute("DELETE FROM oauth_states WHERE created_at <= ?", (security.now() - STATE_TTL_SECONDS,))
    db.execute(
        """INSERT INTO oauth_states (state_hash, browser_hash, provider, purpose, user_id, nonce, code_verifier, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (_hash(state), _hash(browser), provider.key, purpose, user_id, nonce, verifier, security.now()),
    )
    db.commit()
    response = redirect(oidc.authorization_url(provider, meta, _redirect_uri(provider), state, nonce, verifier))
    _set_browser_cookie(response, browser)
    return response


@bp.get("/login/<provider_key>")
def login(provider_key):
    return begin(provider_key, "login")


ANSWER_FIELDS = ("state", "code", "error", "iss")


@bp.post("/auth/<provider_key>/callback")
def callback_post(provider_key):
    """Apple answers with a cross-site form POST, which browsers send without the (SameSite=Lax) session
    cookie. Bounce it to the GET handler as a top-level navigation, which does carry it. This is the one
    endpoint exempt from the CSRF check (see security.check_request); it changes nothing itself."""
    _provider_or_404(provider_key)
    fields = {k: request.form[k] for k in ANSWER_FIELDS if k in request.form and len(request.form[k]) <= 2000}
    return redirect(url_for("oauth.callback", provider_key=provider_key, **fields), code=303)


@bp.get("/auth/<provider_key>/callback")
def callback(provider_key):
    """Where the provider sends the browser back. The single-use state, tied to this browser, protects it."""
    provider = _provider_or_404(provider_key)
    answer = request.args
    state = answer.get("state", "")
    browser_hash = _browser_hash()
    if not state or len(state) > 200 or browser_hash is None:
        audit.event("sign_in", "failed", method=provider.key, reason="no_state")
        return _failed()
    db = get_db()
    flow = db.execute("SELECT * FROM oauth_states WHERE state_hash = ?", (_hash(state),)).fetchone()
    if flow is None or db.execute(
        "DELETE FROM oauth_states WHERE state_hash = ?", (_hash(state),)
    ).rowcount != 1:
        audit.event("sign_in", "failed", method=provider.key, reason="unknown_state")
        return _failed()
    db.commit()
    if (
        flow["provider"] != provider.key
        or not hmac.compare_digest(flow["browser_hash"], browser_hash)
        or security.now() - flow["created_at"] > STATE_TTL_SECONDS
    ):
        audit.event("sign_in", "failed", method=provider.key, reason="state_mismatch")
        return _failed()
    # RFC 9207: when the provider names itself in the answer, it must be the one this flow started with
    if "iss" in answer and answer.get("iss") != provider.issuer:
        audit.event("sign_in", "failed", method=provider.key, reason="wrong_issuer")
        return _failed()
    if answer.get("error"):
        audit.event("sign_in", "cancelled", method=provider.key)
        return _failed(f"Signing in with {provider.label} was cancelled.")
    code = answer.get("code", "")
    if not code or len(code) > 2000:
        audit.event("sign_in", "failed", method=provider.key, reason="no_code")
        return _failed()
    try:
        meta = oidc.discover(provider)
        claims = oidc.exchange_code(provider, meta, code, _redirect_uri(provider), flow["code_verifier"])
        subject = oidc.check_claims(provider, claims, flow["nonce"])
    except oidc.OIDCError as error:
        current_app.logger.warning("Sign-in with %s failed: %s", provider.key, error)
        audit.event("sign_in", "failed", method=provider.key, reason="token_rejected")
        return _failed()

    linked = db.execute(
        "SELECT user_id FROM oauth_identities WHERE provider = ? AND subject = ?", (provider.key, subject)
    ).fetchone()
    if flow["purpose"] == "login":
        return _finish_login(provider, subject, claims, linked, browser_hash)
    if flow["purpose"] == "link":
        return _finish_link(provider, subject, claims, linked, flow["user_id"])
    return _finish_reauth(provider, linked, flow["user_id"])


def _finish_login(provider, subject, claims, linked, browser_hash):
    db = get_db()
    if linked:
        if g.get("session_hash"):
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (g.session_hash,))
            db.commit()
        return signin.complete(linked["user_id"], provider.key)
    audit.event("sign_in", "new_person", method=provider.key)
    # Someone new: keep who they are for a few minutes while they choose a family.
    db.execute("DELETE FROM oauth_pending WHERE created_at <= ?", (security.now() - PENDING_TTL_SECONDS,))
    db.execute(
        """INSERT OR REPLACE INTO oauth_pending (browser_hash, provider, subject, email, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (browser_hash, provider.key, subject, oidc.verified_email(claims), security.now()),
    )
    db.commit()
    return redirect(url_for("oauth.finish_signup"))


def _finish_link(provider, subject, claims, linked, user_id):
    if g.user is None or g.user["id"] != user_id:
        audit.event("provider_connected", "failed", method=provider.key, reason="different_user")
        return _failed()
    if linked:
        if linked["user_id"] == user_id:
            return redirect(url_for("account.index", done="connected"))
        audit.event("provider_connected", "failed", method=provider.key, reason="linked_elsewhere")
        return _failed(f"That {provider.label} account is already connected to another Family Hub account.")
    db = get_db()
    try:
        with db:
            db.execute(
                "INSERT INTO oauth_identities (provider, subject, user_id, email) VALUES (?, ?, ?, ?)",
                (provider.key, subject, user_id, oidc.verified_email(claims)),
            )
    except sqlite3.IntegrityError:  # UNIQUE (user_id, provider): one account per provider
        return _failed(f"Your account already has a {provider.label} account connected.")
    audit.event("provider_connected", method=provider.key)
    return redirect(url_for("account.index", done="connected"))


def _finish_reauth(provider, linked, user_id):
    if g.user is None or g.user["id"] != user_id or not linked or linked["user_id"] != user_id:
        audit.event("reauthenticated", "failed", method=provider.key)
        return _failed(f"That isn't the {provider.label} account connected to your Family Hub account.")
    audit.event("reauthenticated", method=provider.key)
    # A fresh session: it counts as a recent sign-in for the Account page's sensitive changes.
    response = redirect(url_for("account.index", done="confirmed"))
    security.end_session(response)
    security.start_session(response, user_id)
    return response


def _pending():
    browser_hash = _browser_hash()
    if browser_hash is None:
        return None
    return get_db().execute(
        "SELECT * FROM oauth_pending WHERE browser_hash = ? AND created_at > ?",
        (browser_hash, security.now() - PENDING_TTL_SECONDS),
    ).fetchone()


@bp.get("/signup/finish")
def finish_signup():
    pending = _pending()
    if pending is None:
        return _failed()
    return render_template("signup_finish.html", pending=pending, values={},
                           provider=oidc.configured_providers().get(pending["provider"]))


@bp.post("/signup/finish")
def finish_signup_post():
    pending = _pending()
    if pending is None:
        return _failed()
    provider = oidc.configured_providers().get(pending["provider"])
    if provider is None:
        return _failed()
    f = forms.FormReader(request.form)
    display_name = f.text("display_name", "Your name", 60)
    family_name, invite_code = read_family_choice(f)
    values = {"display_name": display_name, "family_name": family_name}
    if not pending["email"]:
        f.errors.append(f"{provider.label} didn't share a verified email address, so an account can't be made.")
    if f.errors:
        return render_template("signup_finish.html", pending=pending, values=values, errors=f.errors,
                               provider=provider), 400
    db = get_db()
    try:
        user_id = accounts.create_account(
            db, pending["email"], display_name, accounts.NO_PASSWORD, family_name, invite_code,
            identity=(pending["provider"], pending["subject"], pending["email"]), method=pending["provider"],
        )
    except (accounts.SignupError, limits.LimitReached) as error:
        status = 429 if isinstance(error, limits.LimitReached) else 400
        return render_template("signup_finish.html", pending=pending, values=values, errors=[str(error)],
                               provider=provider), status
    db.execute("DELETE FROM oauth_pending WHERE browser_hash = ?", (pending["browser_hash"],))
    db.commit()
    response = redirect(url_for("home.index", done="welcome"))
    security.start_session(response, user_id)
    return response

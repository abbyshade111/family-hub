"""Finishing a sign-in, by any method. If the person has an authenticator app set up, no session
starts yet: they are remembered for a few minutes (a single-use token in a cookie) and sent to
enter a code. Every way in goes through here, so none of them skips the code."""

import secrets

from flask import current_app, redirect, request, url_for

from . import audit, security
from .db import get_db

PENDING_TTL_SECONDS = 5 * 60


def pending_cookie_name():
    return security.cookie_name("fh_mfa")


def complete(user_id, method):
    """Sign `user_id` in and send them home, or send them to the code step. Returns the response."""
    db = get_db()
    user = db.execute("SELECT family_id, totp_secret FROM users WHERE id = ?", (user_id,)).fetchone()
    if user["totp_secret"]:
        token = secrets.token_urlsafe(32)
        db.execute("DELETE FROM mfa_pending WHERE created_at <= ?", (security.now() - PENDING_TTL_SECONDS,))
        db.execute(
            "INSERT INTO mfa_pending (token_hash, user_id, method, created_at) VALUES (?, ?, ?, ?)",
            (security.lookup_hash(token), user_id, method, security.now()),
        )
        db.commit()
        response = redirect(url_for("mfa.challenge"))
        security.set_cookie(response, pending_cookie_name(), token)
        audit.event("sign_in", "needs_code", method=method, user_id=user_id, family_id=user["family_id"])
        return response
    response = redirect(url_for("home.index"))
    security.start_session(response, user_id)
    audit.event("sign_in", method=method, user_id=user_id, family_id=user["family_id"])
    return response


def pending():
    """The sign-in waiting for a code in this browser, or None."""
    token = request.cookies.get(pending_cookie_name(), "")
    if not 20 <= len(token) <= 100:
        return None
    return get_db().execute(
        """SELECT p.token_hash, p.method, p.user_id, u.email, u.family_id, u.totp_secret, u.totp_last_step
             FROM mfa_pending p JOIN users u ON u.id = p.user_id
            WHERE p.token_hash = ? AND p.created_at > ?""",
        (security.lookup_hash(token), security.now() - PENDING_TTL_SECONDS),
    ).fetchone()


def forget_pending(response, token_hash):
    get_db().execute("DELETE FROM mfa_pending WHERE token_hash = ?", (token_hash,))
    response.delete_cookie(pending_cookie_name(), path="/", secure=current_app.config["COOKIE_SECURE"],
                           httponly=True, samesite="Lax")

"""Passwords, sessions, CSRF protection, and response headers.

Sessions are opaque random tokens kept server-side (only a SHA-256 of each
token is stored), so signing out or changing a password really ends them.
"""

import hashlib
import hmac
import os
import secrets
import time
from functools import wraps
from urllib.parse import urlsplit

from flask import abort, current_app, g, redirect, request, url_for
from markupsafe import Markup

from . import audit, breached, oidc
from .db import get_db

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024

PASSWORD_MIN = 12
PASSWORD_MAX = 128
CONTEXT_WORDS = ("familyhub", "family hub")

MAX_FAILED_SIGN_INS = 5            # per account
MAX_FAILED_SIGN_INS_PER_IP = 20    # per IP address, across all accounts
FAILED_WINDOW_SECONDS = 15 * 60

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def now():
    return time.time()


def load_secret_key(data_dir):
    """The key that signs CSRF tokens: from the environment, or made once and kept in the data folder."""
    from_env = os.environ.get("FAMILY_HUB_SECRET_KEY")
    if from_env:
        if len(from_env) < 32:
            raise RuntimeError("FAMILY_HUB_SECRET_KEY must be at least 32 characters long")
        return from_env.encode()
    path = os.path.join(data_dir, "secret_key")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, "rb") as f:
            return f.read().strip()
    key = secrets.token_hex(32).encode()
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


# --- lookup hashes ----------------------------------------------------------
#
# Session tokens, invite codes and sign-in state values are stored only as this hash, so the
# database never holds the real values. Change the algorithm here and only here; values stored
# under the old one then stop matching (everyone signs in again, open invite codes stop working).

LOOKUP_HASH = "sha256"


def lookup_hash(value):
    return hashlib.new(LOOKUP_HASH, value.encode()).hexdigest()


# --- passwords -------------------------------------------------------------
#
# Each stored hash names its algorithm and settings ("scrypt$N$r$p$salt$hash"), so the settings
# below can change without breaking existing passwords: they are upgraded the next time the
# person's password is checked successfully (see password_needs_upgrade).

PASSWORD_ALGORITHM = "scrypt"


def hash_password(password):
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM, dklen=32,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${derived.hex()}"


def verify_password(password, stored):
    if len(password) > PASSWORD_MAX:
        return False
    try:
        algo, n, r, p, salt, expected = stored.split("$")
        if algo != "scrypt":
            return False
        expected = bytes.fromhex(expected)
        derived = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
            maxmem=SCRYPT_MAXMEM, dklen=len(expected),
        )
    except ValueError:
        return False
    return hmac.compare_digest(derived, expected)


def password_needs_upgrade(stored):
    """True if a stored hash was made with another algorithm or other settings than today's."""
    try:
        algo, n, r, p, _salt, _expected = stored.split("$")
        return (algo, int(n), int(r), int(p)) != (PASSWORD_ALGORITHM, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    except ValueError:
        return False   # not a password hash (an account without a password)


def upgrade_password_if_needed(db, user_id, password, stored):
    """Call after `password` has been checked against `stored`: re-hash it with today's settings."""
    if password_needs_upgrade(stored):
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user_id))


_dummy_hash = None


def spend_password_time(password):
    """Take as long as a real password check, so a missing account can't be told apart by timing."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_urlsafe(16))
    verify_password(password, _dummy_hash)
    return False


def password_problem(password, email="", display_name=""):
    """Return why a new password is refused, or None if it is acceptable."""
    if len(password) < PASSWORD_MIN:
        return f"Use at least {PASSWORD_MIN} characters for your password."
    if len(password) > PASSWORD_MAX:
        return f"Use at most {PASSWORD_MAX} characters for your password."
    lowered = password.lower()
    words = list(CONTEXT_WORDS)
    local_part = email.split("@")[0].lower()
    if len(local_part) >= 4:
        words.append(local_part)
    if len(display_name) >= 4:
        words.append(display_name.lower())
    if any(word in lowered for word in words):
        return "Don't build your password from the app's name, your email address, or your name."
    if len(set(password)) < 4:
        return "That password is too easy to guess."
    if breached.is_breached(password):
        return ("That password has appeared in a data breach, so attackers try it early. "
                "Please choose a different one.")
    return None


# --- failed sign-in throttling ----------------------------------------------

def client_ip():
    # The direct peer, or the client named by FAMILY_HUB_TRUSTED_PROXIES trusted proxies (see create_app).
    return request.remote_addr or "unknown"


def too_many_failures(db, email):
    """True when this account, or the address the request comes from, has had too many wrong passwords."""
    cutoff = now() - FAILED_WINDOW_SECONDS
    by_account = db.execute(
        "SELECT COUNT(*) FROM failed_logins WHERE email = ? AND at > ?", (email, cutoff)
    ).fetchone()[0]
    by_ip = db.execute(
        "SELECT COUNT(*) FROM failed_logins_by_ip WHERE ip = ? AND at > ?", (client_ip(), cutoff)
    ).fetchone()[0]
    return by_account >= MAX_FAILED_SIGN_INS or by_ip >= MAX_FAILED_SIGN_INS_PER_IP


def record_failure(db, email):
    cutoff = now() - FAILED_WINDOW_SECONDS
    db.execute("DELETE FROM failed_logins WHERE at <= ?", (cutoff,))
    db.execute("DELETE FROM failed_logins_by_ip WHERE at <= ?", (cutoff,))
    db.execute("INSERT INTO failed_logins (email, at) VALUES (?, ?)", (email, now()))
    db.execute("INSERT INTO failed_logins_by_ip (ip, at) VALUES (?, ?)", (client_ip(), now()))


def clear_failures(db, email):
    # Only the account's count: signing in to your own account must not reset the address's count.
    db.execute("DELETE FROM failed_logins WHERE email = ?", (email,))


# --- sessions ---------------------------------------------------------------

def _hash_token(token):
    return lookup_hash(token)


def cookie_name(name):
    # The __Host- prefix makes browsers refuse the cookie unless it is Secure, path=/ and host-only.
    return f"__Host-{name}" if current_app.config["COOKIE_SECURE"] else name


def session_cookie_name():
    return cookie_name("fh_session")


def pre_session_cookie_name():
    return cookie_name("fh_pre")


def set_cookie(response, name, value):
    response.set_cookie(
        name, value, httponly=True, secure=current_app.config["COOKIE_SECURE"],
        samesite="Lax", path="/",
    )


def start_session(response, user_id):
    token = secrets.token_urlsafe(32)
    t = now()
    db = get_db()
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, last_seen) VALUES (?, ?, ?, ?)",
        (_hash_token(token), user_id, t, t),
    )
    db.commit()
    set_cookie(response, session_cookie_name(), token)


def end_session(response):
    if g.get("session_hash"):
        db = get_db()
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (g.session_hash,))
        db.commit()
    clear_browser(response)


def clear_browser(response):
    response.delete_cookie(
        session_cookie_name(), path="/", secure=current_app.config["COOKIE_SECURE"],
        httponly=True, samesite="Lax",
    )
    response.headers["Clear-Site-Data"] = '"cache", "storage"'


def end_all_sessions(db, user_id):
    db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def load_user():
    g.user = None
    g.session_hash = None
    g.session_ended = False   # a session cookie came in, but its session is over (timed out, signed out, unknown)
    token = request.cookies.get(session_cookie_name())
    if not token:
        return
    g.session_ended = True
    if len(token) > 100:
        return
    token_hash = _hash_token(token)
    db = get_db()
    row = db.execute(
        """SELECT s.created_at, s.last_seen, u.id, u.family_id, u.role, u.display_name,
                  u.email, f.name AS family_name, u.password_hash != '' AS has_password,
                  u.totp_secret IS NOT NULL AS totp_enabled
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             JOIN families f ON f.id = u.family_id
            WHERE s.token_hash = ?""",
        (token_hash,),
    ).fetchone()
    if row is None:
        return
    t = now()
    cfg = current_app.config
    if t - row["last_seen"] > cfg["SESSION_IDLE_SECONDS"] or t - row["created_at"] > cfg["SESSION_LIFETIME_SECONDS"]:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        db.commit()
        return
    g.session_ended = False
    if t - row["last_seen"] > 30:
        db.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (t, token_hash))
        db.commit()
    g.user = dict(row)
    g.session_hash = token_hash


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return _to_sign_in()
        return view(*args, **kwargs)
    return wrapped


def _to_sign_in():
    """Send someone to sign in, saying so when it's because their session ended."""
    if g.get("session_ended"):
        response = redirect(url_for("auth.login_form", done="session-ended"))
        response.delete_cookie(session_cookie_name(), path="/", secure=current_app.config["COOKIE_SECURE"],
                               httponly=True, samesite="Lax")
        return response
    return redirect(url_for("auth.login_form"))


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return _to_sign_in()
        if g.user["role"] != "admin":
            audit.event("request_refused", "refused", reason="not_admin", path=request.path, status=403)
            abort(403)
        if not g.user["totp_enabled"]:
            # The owner's rule: admins need an authenticator app before they can use family settings.
            audit.event("request_refused", "refused", reason="admin_needs_code", path=request.path, status=302)
            return redirect(url_for("account.index", done="admin-needs-2fa"))
        return view(*args, **kwargs)
    return wrapped


# --- CSRF -------------------------------------------------------------------

def _csrf_for(binding):
    key = current_app.config["FH_SECRET_KEY"]
    return hmac.new(key, binding.encode(), hashlib.sha256).hexdigest()


def csrf_token():
    """The token for forms on this page: tied to the session, or to a pre-session cookie before sign-in."""
    if g.get("session_hash"):
        return _csrf_for("s:" + g.session_hash)
    nonce = request.cookies.get(pre_session_cookie_name())
    if not nonce or len(nonce) > 100:
        nonce = g.get("new_pre_nonce") or secrets.token_urlsafe(24)
        g.new_pre_nonce = nonce
    return _csrf_for("a:" + nonce)


def csrf_field():
    return Markup('<input type="hidden" name="csrf_token" value="%s">') % csrf_token()


# Apple's answer arrives as a cross-site form POST; that endpoint only redirects (see views/oauth.py).
# The CSP report endpoint only writes a log line, and browsers send to it without a form token.
CSRF_EXEMPT_ENDPOINTS = {"oauth.callback_post", "reports.csp_report"}
# Forms for getting in: an old session cookie left in the browser doesn't stop them working.
SIGN_IN_ENDPOINTS = {"auth.login", "auth.signup", "mfa.answer", "oauth.finish_signup_post"}


def check_request():
    if request.method in SAFE_METHODS or request.endpoint in CSRF_EXEMPT_ENDPOINTS:
        return
    if request.headers.get("Sec-Fetch-Site") == "cross-site":
        audit.event("request_refused", "refused", reason="cross_site", path=request.path, status=403)
        abort(403)
    origin = request.headers.get("Origin")
    if origin and origin != "null" and urlsplit(origin).netloc != request.host:
        audit.event("request_refused", "refused", reason="foreign_origin", path=request.path, status=403)
        abort(403)
    if g.get("session_ended") and request.endpoint not in SIGN_IN_ENDPOINTS:
        # A form sent from a page whose session has since ended (say, after being away 30 minutes).
        # Nothing is done; the person is sent to sign in, told why, rather than shown an error.
        audit.event("request_refused", "refused", reason="session_ended", path=request.path, status=302)
        return _to_sign_in()
    if g.get("session_hash"):
        expected = _csrf_for("s:" + g.session_hash)
    else:
        nonce = request.cookies.get(pre_session_cookie_name())
        if not nonce or len(nonce) > 100:
            audit.event("request_refused", "refused", reason="csrf", path=request.path, status=400)
            abort(400)
        expected = _csrf_for("a:" + nonce)
    sent = request.form.get("csrf_token", "")
    if not hmac.compare_digest(sent.encode(), expected.encode()):
        audit.event("request_refused", "refused", reason="csrf", path=request.path, status=400)
        abort(400)


# --- response headers -------------------------------------------------------

def content_security_policy():
    # Forms on the Account page lead on to the sign-in providers, so they are allowed as form targets.
    form_action = " ".join(["'self'", *oidc.provider_origins()])
    return (
        f"default-src 'none'; style-src 'self'; img-src 'self'; form-action {form_action}; "
        "frame-ancestors 'none'; base-uri 'none'; report-uri /csp-report; report-to csp"
    )


def add_headers(response):
    if g.get("new_pre_nonce"):
        set_cookie(response, pre_session_cookie_name(), g.new_pre_nonce)
    h = response.headers
    h["Content-Security-Policy"] = content_security_policy()
    h["Reporting-Endpoints"] = 'csp="/csp-report"'
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "same-origin"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    h["Cache-Control"] = "no-store"
    return response


def init_app(app):
    app.before_request(load_user)
    app.before_request(check_request)
    app.after_request(add_headers)
    app.jinja_env.globals["csrf_field"] = csrf_field

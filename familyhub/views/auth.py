from flask import Blueprint, g, redirect, render_template, request, url_for

from .. import accounts, audit, forms, limits, security, signin
from ..db import get_db

bp = Blueprint("auth", __name__)

SIGN_IN_FAILED = "That email and password don't match an account."
LOCKED_OUT = "Too many wrong passwords. Wait 15 minutes and try again."


@bp.get("/health")
def health():
    return "ok", 200, {"Content-Type": "text/plain; charset=utf-8"}


@bp.get("/login")
def login_form():
    if g.user:
        return redirect(url_for("home.index"))
    return render_template("login.html")


@bp.post("/login")
def login():
    email = forms.normalize_email(request.form.get("email", ""))
    password = request.form.get("password", "")
    db = get_db()
    user = db.execute("SELECT id, family_id, password_hash FROM users WHERE email = ?", (email,)).fetchone()
    known = {"user_id": user["id"], "family_id": user["family_id"]} if user else {}
    if security.too_many_failures(db, email):
        security.spend_password_time(password)
        audit.event("sign_in", "locked", method="password", **known)
        return render_template("login.html", errors=[LOCKED_OUT], email=email), 429
    if user and user["password_hash"] != accounts.NO_PASSWORD:
        ok = security.verify_password(password, user["password_hash"])
    else:
        # no such account, or one that only signs in through a provider: take the same time either way
        ok = security.spend_password_time(password)
    if not ok:
        security.record_failure(db, email)
        db.commit()
        audit.event("sign_in", "failed", method="password", **known)
        return render_template("login.html", errors=[SIGN_IN_FAILED], email=email), 401
    security.clear_failures(db, email)
    security.upgrade_password_if_needed(db, user["id"], password, user["password_hash"])
    db.commit()
    return signin.complete(user["id"], "password")


@bp.get("/signup")
def signup_form():
    if g.user:
        return redirect(url_for("home.index"))
    return render_template("signup.html", values={})


@bp.post("/signup")
def signup():
    f = forms.FormReader(request.form)
    email = forms.normalize_email(request.form.get("email", ""))
    if not forms.valid_email(email):
        f.errors.append("Enter a valid email address.")
    display_name = f.text("display_name", "Your name", 60)
    password = request.form.get("password", "")
    problem = security.password_problem(password, email, display_name)
    if problem:
        f.errors.append(problem)
    family_name, invite_code = read_family_choice(f)

    values = {"email": email, "display_name": display_name, "family_name": family_name}
    if f.errors:
        return render_template("signup.html", errors=f.errors, values=values), 400

    try:
        user_id = accounts.create_account(
            get_db(), email, display_name, security.hash_password(password), family_name, invite_code,
            method="password",
        )
    except limits.LimitReached as reached:
        return render_template("signup.html", errors=[str(reached)], values=values), 429
    except accounts.SignupError as error:
        return render_template("signup.html", errors=[str(error)], values=values), 400

    response = redirect(url_for("home.index", done="welcome"))
    security.start_session(response, user_id)
    return response


def read_family_choice(f):
    """Start a new family (its name) or join one (an invite code). Returns (family_name, invite_code)."""
    invite_code = f.form.get("invite_code", "").strip()
    if not invite_code:
        return f.text("family_name", "Family name", 80), ""
    if len(invite_code) > 64:
        f.errors.append(accounts.INVITE_INVALID)
    return "", invite_code


@bp.post("/logout")
def logout():
    response = redirect(url_for("auth.login_form"))
    if g.user:
        audit.event("sign_out")
    security.end_session(response)
    return response

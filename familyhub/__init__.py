import os

from flask import Flask, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.routing import IntegerConverter

from . import audit, db, forms, oidc, security

NOTICES = {
    "welcome": "Welcome to Family Hub.",
    "added": "Added.",
    "saved": "Saved.",
    "deleted": "Deleted.",
    "renamed": "Family name updated.",
    "password": "Password changed. You've been signed out everywhere else.",
    "account-deleted": "Your account has been deleted.",
    "connected": "Connected. You can now sign in with it.",
    "disconnected": "Disconnected.",
    "signed-out-others": "Signed out everywhere else.",
    "name-saved": "Name saved.",
    "promoted": "They're now an admin too.",
    "shared": "Shared with your family.",
    "unshared": "Now only you can see it.",
    "archived": "Archived. You'll find it under Archived.",
    "restored": "Restored.",
    "confirmed": "Thanks, confirmed. You have 10 minutes to make changes that need it.",
    "admin-needs-2fa": "Family admins need an authenticator app. Set one up below to use family settings.",
    "2fa-off": "Authenticator app turned off.",
    "session-ended": "You've been signed out, perhaps after being away for a while. Please sign in again.",
}

ERROR_MESSAGES = {
    400: "That request couldn't be understood. Reload the page and try again.",
    403: "You don't have access to that.",
    404: "That page doesn't exist, or it isn't yours to see.",
    405: "That isn't allowed here.",
    413: "That was too much to send at once.",
    429: "Too many attempts. Wait a while and try again.",
    500: "Something went wrong on our side.",
}


class IdConverter(IntegerConverter):
    """Positive ids that fit in SQLite's 64-bit integers."""

    def __init__(self, map, *args, **kwargs):
        kwargs.setdefault("min", 1)
        kwargs.setdefault("max", 2**63 - 1)
        super().__init__(map, *args, **kwargs)


def create_app(config=None):
    app = Flask(__name__)
    config = dict(config or {})
    data_dir = config.pop("DATA_DIR", None) or os.environ.get("FAMILY_HUB_DATA", "/tmp/family-hub")
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    app.config.update(
        DATA_DIR=data_dir,
        DATABASE=os.path.join(data_dir, "family.db"),
        FH_SECRET_KEY=security.load_secret_key(data_dir),
        MAX_CONTENT_LENGTH=64 * 1024,
        COOKIE_SECURE=os.environ.get("FAMILY_HUB_INSECURE_COOKIES") != "1",
        SESSION_IDLE_SECONDS=30 * 60,
        SESSION_LIFETIME_SECONDS=12 * 60 * 60,
    )
    app.config.update(config)
    app.url_map.converters["id"] = IdConverter

    # Behind a reverse proxy, every request comes from the proxy's address. Set
    # FAMILY_HUB_TRUSTED_PROXIES to the number of proxies in front of the app so the
    # visitor's address is read from X-Forwarded-For instead. Left at 0, that header
    # is ignored, because a visitor could otherwise choose their own address.
    trusted_proxies = int(os.environ.get("FAMILY_HUB_TRUSTED_PROXIES", "0"))
    if trusted_proxies:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=trusted_proxies)

    audit.setup()
    db.init_app(app)
    security.init_app(app)

    app.jinja_env.filters["when"] = forms.format_datetime
    app.jinja_env.filters["day"] = forms.format_date

    @app.context_processor
    def notice():
        return {"notice": NOTICES.get(request.args.get("done", "")), "sign_in_providers": oidc.configured_providers()}

    from .views import account, auth, calendar, family, groceries, home, mfa, oauth, reminders, reports, todos
    for module in (auth, oauth, mfa, home, calendar, todos, groceries, reminders, family, account, reports):
        app.register_blueprint(module.bp)

    def error_page(error):
        code = getattr(error, "code", 500) or 500
        return render_template("error.html", code=code, message=ERROR_MESSAGES.get(code, ERROR_MESSAGES[500])), code

    for code in ERROR_MESSAGES:
        app.register_error_handler(code, error_page)

    return app

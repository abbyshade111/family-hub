import re
import shutil
import tempfile
import unittest
from unittest import mock

from familyhub import create_app, totp

BASE = "https://localhost"
CSRF_RE = re.compile(r'name="csrf_token" value="([0-9a-f]+)"')


class Browser:
    """A test client that keeps cookies, talks https, and fills in the CSRF token like a real form would."""

    def __init__(self, app):
        self.client = app.test_client()

    def get(self, path, **kwargs):
        return self.client.get(path, base_url=BASE, **kwargs)

    def token(self, page="/login"):
        match = CSRF_RE.search(self.get(page).get_data(as_text=True))
        assert match, f"no CSRF token on {page}"
        return match.group(1)

    def post(self, path, data=None, page=None, csrf=True, **kwargs):
        data = dict(data or {})
        if csrf and "csrf_token" not in data:
            data["csrf_token"] = self.token(page or self._page_for(path))
        return self.client.post(path, base_url=BASE, data=data, **kwargs)

    @staticmethod
    def _page_for(path):
        if path in ("/login", "/signup"):
            return path
        return "/account"

    def signup(self, email, password="a long test passphrase", name="Test Person", family="Test Family", invite=None):
        data = {"email": email, "password": password, "display_name": name}
        if invite:
            data["invite_code"] = invite
        else:
            data["family_name"] = family
        return self.post("/signup", data)

    def login(self, email, password="a long test passphrase", **kwargs):
        return self.post("/login", {"email": email, "password": password}, **kwargs)


class AppTestCase(unittest.TestCase):
    def setUp(self):
        # Tests never reach the real breached-password service: by default it behaves as unreachable.
        patcher = mock.patch("familyhub.breached._fetch_range", side_effect=OSError("no network in tests"))
        self.fetch_range = patcher.start()
        self.addCleanup(patcher.stop)
        self.data_dir = tempfile.mkdtemp(prefix="familyhub-test-")
        self.app = create_app({"DATA_DIR": self.data_dir, "TESTING": True})

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def browser(self):
        return Browser(self.app)

    def signed_up(self, email, **kwargs):
        b = self.browser()
        r = b.signup(email, **kwargs)
        self.assertEqual(r.status_code, 302, r.get_data(as_text=True))
        return b

    def enable_totp(self, browser, password="a long test passphrase"):
        """Set up an authenticator app through the Account page, as a person would. Returns the secret."""
        if getattr(browser, "totp_secret", None):
            return browser.totp_secret
        r = browser.post("/account/2fa/start", {"password": password}, page="/account")
        match = re.search(r'<p class="code">([A-Z2-7]+)</p>', r.get_data(as_text=True))
        assert match, r.get_data(as_text=True)[:500]
        secret = match.group(1)
        r = browser.post("/account/2fa/confirm", {"code": totp.code_at(secret, totp.current_step())}, page="/account")
        assert r.status_code == 200, r.get_data(as_text=True)[:500]
        browser.totp_secret = secret
        return secret

    def invite_code(self, admin):
        self.enable_totp(admin)   # family settings need the admin's authenticator app
        r = admin.post("/family/invites", page="/family")
        match = re.search(r'<p class="code">([^<]+)</p>', r.get_data(as_text=True))
        self.assertIsNotNone(match)
        return match.group(1)

    @staticmethod
    def created_id(response):
        match = re.search(r"/(\d+)", response.headers["Location"])
        return int(match.group(1))

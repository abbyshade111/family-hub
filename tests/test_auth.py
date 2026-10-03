import time
from unittest import mock

from tests.helpers import AppTestCase


class SignUpAndSignIn(AppTestCase):
    def test_signup_signs_in_and_makes_family_admin(self):
        b = self.signed_up("pat@example.com", family="The Rivers")
        page = b.get("/").get_data(as_text=True)
        self.assertIn("The Rivers", page)
        # an admin needs an authenticator app before using family settings
        r = b.get("/family")
        self.assertEqual(r.status_code, 302)
        self.assertIn("admin-needs-2fa", r.headers["Location"])
        self.enable_totp(b)
        self.assertEqual(b.get("/family").status_code, 200)

    def test_private_pages_need_sign_in(self):
        b = self.browser()
        for path in ("/", "/calendar", "/todos", "/groceries", "/reminders", "/account", "/family"):
            with self.subTest(path=path):
                r = b.get(path)
                self.assertEqual(r.status_code, 302)
                self.assertTrue(r.headers["Location"].endswith("/login"))

    def test_wrong_password_and_unknown_email_get_the_same_answer(self):
        self.signed_up("pat@example.com")
        wrong = self.browser().login("pat@example.com", "not the right password")
        unknown = self.browser().login("nobody@example.com", "not the right password")
        self.assertEqual(wrong.status_code, unknown.status_code)
        self.assertEqual(wrong.status_code, 401)
        self.assertIn("don&#39;t match an account", wrong.get_data(as_text=True))
        self.assertIn("don&#39;t match an account", unknown.get_data(as_text=True))

    def test_sign_in_is_refused_after_five_wrong_passwords(self):
        self.signed_up("pat@example.com")
        b = self.browser()
        for _ in range(5):
            self.assertEqual(b.login("pat@example.com", "wrong password here").status_code, 401)
        self.assertEqual(b.login("pat@example.com").status_code, 429)
        later = time.time() + 16 * 60
        with mock.patch("familyhub.security.now", return_value=later):
            self.assertEqual(b.login("pat@example.com").status_code, 302)

    # covers V6.3.1
    def test_V6_3_1_one_address_is_refused_after_twenty_wrong_passwords_across_accounts(self):
        for i in range(5):
            self.signed_up(f"person{i}@example.com")
        attacker = self.browser_at("203.0.113.5")
        for n in range(20):
            # five wrong passwords each for person0..person3: each stays within its own account limit
            r = attacker.login(f"person{n % 4}@example.com", "wrong password here")
            self.assertEqual(r.status_code, 401, n)
        # the right password for an account nobody has touched is refused from this address...
        self.assertEqual(attacker.login("person4@example.com").status_code, 429)
        # ...but still works from anywhere else
        self.assertEqual(self.browser_at("198.51.100.7").login("person4@example.com").status_code, 302)

    def test_signing_in_to_your_own_account_does_not_reset_the_address_count(self):
        self.signed_up("me@example.com")
        b = self.browser()
        b.client.environ_base["REMOTE_ADDR"] = "203.0.113.5"
        for n in range(19):
            b.login(f"nobody{n}@example.com", "wrong password here")
        self.assertEqual(b.login("me@example.com").status_code, 302)
        self.browser_at("203.0.113.5").login("nobody@example.com", "wrong password here")
        self.assertEqual(self.browser_at("203.0.113.5").login("me@example.com").status_code, 429)

    def test_forwarded_for_is_ignored_unless_proxies_are_trusted(self):
        self.signed_up("me@example.com")
        for n in range(20):
            self.browser().login(f"nobody{n}@example.com", "wrong password here",
                                 headers={"X-Forwarded-For": f"192.0.2.{n}"})
        self.assertEqual(self.browser().login("me@example.com").status_code, 429)

    def test_trusted_proxy_passes_on_the_visitor_address(self):
        with mock.patch.dict("os.environ", {"FAMILY_HUB_TRUSTED_PROXIES": "1"}):
            from familyhub import create_app
            app = create_app({"DATA_DIR": self.data_dir})
        from tests.helpers import Browser
        Browser(app).signup("me@example.com")
        for n in range(20):
            Browser(app).login(f"nobody{n}@example.com", "wrong password here",
                               headers={"X-Forwarded-For": "203.0.113.5"})
        blocked = Browser(app).login("me@example.com", headers={"X-Forwarded-For": "203.0.113.5"})
        self.assertEqual(blocked.status_code, 429)
        other = Browser(app).login("me@example.com", headers={"X-Forwarded-For": "198.51.100.7"})
        self.assertEqual(other.status_code, 302)

    def browser_at(self, ip):
        b = self.browser()
        b.client.environ_base["REMOTE_ADDR"] = ip
        return b

    def test_duplicate_email_is_refused(self):
        self.signed_up("pat@example.com")
        r = self.browser().signup("PAT@example.com")
        self.assertEqual(r.status_code, 400)


class Passwords(AppTestCase):
    def test_weak_passwords_are_refused(self):
        weak = [
            "", "short", "elevenchars", "a" * 129, "aaaaaaaaaaaaaaaa", "abababababababab",
            "familyhub2026!!", "FamilyHubFamilyHub", "patterson-secret-1", "Test Person is me",
        ]
        for i, password in enumerate(weak):
            with self.subTest(password=password):
                r = self.browser().signup(f"patterson@home{i}.example.com", password=password, name="Test Person")
                self.assertEqual(r.status_code, 400)

    def test_long_and_unicode_passwords_are_accepted(self):
        for i, password in enumerate(["x7!" * 42 + "ab", "żółta łódź płynie dziś", "pass phrase with spaces "]):
            with self.subTest(password=password):
                b = self.browser()
                self.assertEqual(b.signup(f"u{i}@example.com", password=password).status_code, 302)
                self.assertEqual(self.browser().login(f"u{i}@example.com", password).status_code, 302)

    def test_passwords_are_stored_hashed(self):
        self.signed_up("pat@example.com")
        import sqlite3
        db = sqlite3.connect(self.app.config["DATABASE"])
        stored = db.execute("SELECT password_hash FROM users").fetchone()[0]
        db.close()
        self.assertTrue(stored.startswith("scrypt$"))
        self.assertNotIn("a long test passphrase", stored)

    def test_changing_password_signs_out_other_sessions(self):
        laptop = self.signed_up("pat@example.com")
        phone = self.browser()
        self.assertEqual(phone.login("pat@example.com").status_code, 302)
        r = laptop.post("/account/password", {"current": "a long test passphrase", "new": "another long passphrase"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(laptop.get("/").status_code, 200)
        self.assertEqual(phone.get("/").status_code, 302)
        self.assertEqual(self.browser().login("pat@example.com", "another long passphrase").status_code, 302)

    def test_changing_password_needs_the_current_one(self):
        b = self.signed_up("pat@example.com")
        r = b.post("/account/password", {"current": "wrong current password", "new": "another long passphrase"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.browser().login("pat@example.com").status_code, 302)


class Sessions(AppTestCase):
    def test_signing_out_ends_the_session_on_the_server(self):
        b = self.signed_up("pat@example.com")
        cookie = b.client.get_cookie("__Host-fh_session", domain="localhost")
        self.assertIsNotNone(cookie)
        r = b.post("/logout", page="/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("Clear-Site-Data", r.headers)
        replay = self.browser()
        replay.client.set_cookie("__Host-fh_session", cookie.value, domain="localhost")
        self.assertEqual(replay.get("/").status_code, 302)

    def test_session_cookie_flags(self):
        b = self.browser()
        r = b.signup("pat@example.com")
        cookie = [h for h in r.headers.getlist("Set-Cookie") if h.startswith("__Host-fh_session=")][0]
        for flag in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
            self.assertIn(flag, cookie)
        self.assertNotIn("Domain=", cookie)

    # covers V3.3.1
    def test_V3_3_1_every_cookie_is_secure_with_the_host_prefix(self):
        """The pre-sign-in, session and authenticator-step cookies (the provider one is in test_oidc.py)."""
        seen = {}

        def collect(response):
            for header in response.headers.getlist("Set-Cookie"):
                name = header.split("=", 1)[0]
                if "Max-Age=0" not in header and "expires=Thu, 01 Jan 1970" not in header:
                    seen[name] = header

        b = self.browser()
        collect(b.get("/login"))                                            # pre-sign-in cookie
        collect(b.signup("pat@example.com"))                               # session cookie
        self.enable_totp(b)
        other = self.browser()
        collect(other.get("/login"))
        collect(other.login("pat@example.com"))                            # authenticator-step cookie
        self.assertEqual(set(seen), {"__Host-fh_pre", "__Host-fh_session", "__Host-fh_mfa"})
        for name, header in seen.items():
            with self.subTest(cookie=name):
                self.assertIn("Secure", header)
                self.assertIn("Path=/", header)
                self.assertNotIn("Domain=", header)                        # what __Host- requires
                self.assertIn("HttpOnly", header)

    def test_idle_session_expires(self):
        b = self.signed_up("pat@example.com")
        with mock.patch("familyhub.security.now", return_value=time.time() + 31 * 60):
            self.assertEqual(b.get("/").status_code, 302)

    def test_busy_session_still_ends_after_its_lifetime(self):
        b = self.signed_up("pat@example.com")
        start = time.time()
        for minutes in range(20, 12 * 60, 20):
            with mock.patch("familyhub.security.now", return_value=start + minutes * 60):
                self.assertEqual(b.get("/").status_code, 200, minutes)
        with mock.patch("familyhub.security.now", return_value=start + 12 * 60 * 60 + 60):
            self.assertEqual(b.get("/").status_code, 302)

    def test_sign_out_everywhere_else(self):
        laptop = self.signed_up("pat@example.com")
        phone, tablet = self.browser(), self.browser()
        phone.login("pat@example.com")
        tablet.login("pat@example.com")
        sam = self.signed_up("sam@example.com")
        self.assertIn("2 other devices", laptop.get("/account").get_data(as_text=True))
        self.assertEqual(laptop.post("/account/sign-out-others", page="/account").status_code, 302)
        self.assertEqual(laptop.get("/").status_code, 200)
        self.assertEqual(phone.get("/").status_code, 302)
        self.assertEqual(tablet.get("/").status_code, 302)
        self.assertEqual(sam.get("/").status_code, 200)      # other people's sessions are untouched
        self.assertIn("Only here.", laptop.get("/account").get_data(as_text=True))

    def test_sign_out_everywhere_else_needs_the_form_token(self):
        laptop = self.signed_up("pat@example.com")
        phone = self.browser()
        phone.login("pat@example.com")
        self.assertEqual(laptop.post("/account/sign-out-others", csrf=False).status_code, 400)
        self.assertEqual(phone.get("/").status_code, 200)

    def test_forged_session_cookies_are_ignored(self):
        for value in ("", "x", "a" * 43, "a" * 5000, "' OR 1=1 --"):
            with self.subTest(value=value[:20]):
                b = self.browser()
                b.client.set_cookie("__Host-fh_session", value, domain="localhost")
                self.assertEqual(b.get("/").status_code, 302)


class CrossSiteRequests(AppTestCase):
    def test_post_without_token_is_refused(self):
        b = self.signed_up("pat@example.com")
        self.assertEqual(b.post("/todos", {"title": "x"}, csrf=False).status_code, 400)

    def test_token_from_another_session_is_refused(self):
        a = self.signed_up("pat@example.com")
        other = self.signed_up("sam@example.com")
        stolen = other.token("/todos")
        self.assertEqual(a.post("/todos", {"title": "x", "csrf_token": stolen}).status_code, 400)

    def test_cross_site_origin_is_refused(self):
        b = self.signed_up("pat@example.com")
        r = b.post("/todos", {"title": "x"}, headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 403)
        r = b.post("/todos", {"title": "x"}, headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(r.status_code, 403)

    def test_login_form_needs_token(self):
        self.signed_up("pat@example.com")
        b = self.browser()
        r = b.post("/login", {"email": "pat@example.com", "password": "a long test passphrase"}, csrf=False)
        self.assertEqual(r.status_code, 400)


class DeletingAnAccount(AppTestCase):
    def test_last_member_takes_the_family_with_them(self):
        b = self.signed_up("pat@example.com")
        b.post("/todos", {"title": "Mow lawn"}, page="/todos")
        r = b.post("/account/delete", {"password": "a long test passphrase"})
        self.assertEqual(r.status_code, 302)
        import sqlite3
        db = sqlite3.connect(self.app.config["DATABASE"])
        counts = [db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("users", "families", "todos", "sessions")]
        db.close()
        self.assertEqual(counts, [0, 0, 0, 0])
        self.assertEqual(self.browser().login("pat@example.com").status_code, 401)

    def test_admin_leaving_hands_over_to_another_member(self):
        admin = self.signed_up("pat@example.com")
        member = self.signed_up("sam@example.com", invite=self.invite_code(admin))
        self.assertEqual(member.get("/family").status_code, 403)
        admin.post("/account/delete", {"password": "a long test passphrase"})
        self.assertEqual(member.get("/family").status_code, 302)   # admin now, but needs an authenticator app
        self.enable_totp(member)
        self.assertEqual(member.get("/family").status_code, 200)

    def test_wrong_password_keeps_the_account(self):
        b = self.signed_up("pat@example.com")
        self.assertEqual(b.post("/account/delete", {"password": "nope nope nope"}).status_code, 400)
        self.assertEqual(b.get("/").status_code, 200)

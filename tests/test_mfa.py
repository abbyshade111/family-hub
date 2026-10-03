"""Authenticator app codes: optional for members, required for admins."""

import re
import sqlite3
import time
from unittest import mock

from familyhub import security, totp
from tests.helpers import AppTestCase
from tests.test_oidc import ProviderTestCase

PASSWORD = "a long test passphrase"


def at_step(step):
    return mock.patch("familyhub.totp.current_step", return_value=step)


class CodeTestCase(AppTestCase):
    def setUp(self):
        super().setUp()
        self.pat = self.signed_up("pat@example.com")
        self.secret = self.enable_totp(self.pat)
        self.step = totp.current_step() + 1       # the setup used the current step

    def password_step(self, browser=None, email="pat@example.com"):
        browser = browser or self.browser()
        r = browser.login(email)
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/login/2fa"))
        return browser

    def send_code(self, browser, code, step=None):
        with at_step(self.step if step is None else step):
            return browser.post("/login/2fa", {"code": code}, page="/login")


class SigningIn(CodeTestCase):
    # covers V6.3.3
    def test_V6_3_3_password_alone_does_not_sign_in(self):
        b = self.password_step()
        self.assertEqual(b.get("/").status_code, 302)          # no session yet
        r = self.send_code(b, totp.code_at(self.secret, self.step))
        self.assertEqual(r.status_code, 302)
        self.assertEqual(b.get("/").status_code, 200)

    def test_wrong_codes_are_refused_and_counted(self):
        b = self.password_step()
        for code in ("000000", "12345", "abcdef", "", "1" * 60):
            with self.subTest(code=code[:10]):
                self.assertEqual(self.send_code(b, code).status_code, 401)
        self.assertEqual(self.send_code(b, totp.code_at(self.secret, self.step)).status_code, 429)
        self.assertEqual(b.get("/").status_code, 302)

    # covers V6.5.1
    def test_V6_5_1_a_code_works_once(self):
        code = totp.code_at(self.secret, self.step)
        first = self.password_step()
        self.assertEqual(self.send_code(first, code).status_code, 302)
        second = self.password_step()
        self.assertEqual(self.send_code(second, code).status_code, 401)

    # covers V6.5.5
    def test_V6_5_5_a_code_lives_30_seconds(self):
        b = self.password_step()
        stale = totp.code_at(self.secret, self.step - 1)
        early = totp.code_at(self.secret, self.step + 1)
        self.assertEqual(self.send_code(b, stale).status_code, 401)
        self.assertEqual(self.send_code(b, early).status_code, 401)
        self.assertEqual(self.send_code(b, totp.code_at(self.secret, self.step)).status_code, 302)

    def test_the_code_step_belongs_to_the_browser_that_gave_the_password(self):
        self.password_step()
        stranger = self.browser()
        self.assertEqual(self.send_code(stranger, totp.code_at(self.secret, self.step)).status_code, 302)
        self.assertTrue(stranger.get("/").headers["Location"].endswith("/login"))   # still not signed in

    def test_waiting_for_a_code_expires(self):
        b = self.password_step()
        with mock.patch("familyhub.security.now", return_value=time.time() + 6 * 60):
            r = self.send_code(b, totp.code_at(self.secret, self.step))
        self.assertTrue(r.headers["Location"].endswith("/login"))
        self.assertEqual(b.get("/").status_code, 302)

    def test_member_without_an_app_signs_in_with_a_password(self):
        self.signed_up("sam@example.com")
        self.assertTrue(self.browser().login("sam@example.com").headers["Location"].endswith("/"))


class RecoveryCodes(CodeTestCase):
    def codes(self, browser):
        r = browser.post("/account/2fa/recovery-codes", {"password": PASSWORD})
        return re.findall(r'<li class="code">([^<]+)</li>', r.get_data(as_text=True))

    # covers V6.5.1
    def test_V6_5_1_a_recovery_code_works_once(self):
        code = self.codes(self.pat)[0]
        b = self.password_step()
        self.assertEqual(self.send_code(b, code.upper()).status_code, 302)
        again = self.password_step()
        self.assertEqual(self.send_code(again, code).status_code, 401)

    # covers V6.5.2
    def test_V6_5_2_recovery_codes_are_long_and_stored_hashed(self):
        codes = self.codes(self.pat)
        self.assertEqual(len(codes), 10)
        self.assertTrue(all(re.fullmatch(r"([a-z2-9]{5}-){4}[a-z2-9]{5}", c) for c in codes))
        db = sqlite3.connect(self.app.config["DATABASE"])
        stored = {row[0] for row in db.execute("SELECT code_hash FROM mfa_recovery_codes")}
        db.close()
        self.assertEqual(stored, {security.lookup_hash(c) for c in codes})

    def test_new_codes_replace_the_old_ones(self):
        old = self.codes(self.pat)
        self.codes(self.pat)
        b = self.password_step()
        self.assertEqual(self.send_code(b, old[0]).status_code, 401)


class SettingUp(AppTestCase):
    def test_setup_needs_the_password_and_a_working_code(self):
        b = self.signed_up("pat@example.com")
        self.assertEqual(b.post("/account/2fa/start", {"password": "not my password"}).status_code, 400)
        r = b.post("/account/2fa/start", {"password": PASSWORD})
        secret = re.search(r'<p class="code">([A-Z2-7]+)</p>', r.get_data(as_text=True)).group(1)
        self.assertIn("otpauth://totp/", r.get_data(as_text=True))
        self.assertEqual(b.post("/account/2fa/confirm", {"code": "000000"}).status_code, 400)
        self.assertTrue(self.browser().login("pat@example.com").headers["Location"].endswith("/"))   # not on yet
        b.post("/account/2fa/confirm", {"code": totp.code_at(secret, totp.current_step())})
        self.assertTrue(self.browser().login("pat@example.com").headers["Location"].endswith("/login/2fa"))

    def test_turning_it_on_signs_out_other_sessions(self):
        laptop = self.signed_up("pat@example.com")
        phone = self.browser()
        phone.login("pat@example.com")
        self.enable_totp(laptop)
        self.assertEqual(laptop.get("/").status_code, 200)
        self.assertEqual(phone.get("/").status_code, 302)

    def test_member_can_turn_it_off_admin_cannot(self):
        admin = self.signed_up("pat@example.com")
        kid = self.signed_up("kid@example.com", invite=self.invite_code(admin))
        self.enable_totp(kid)
        self.assertEqual(admin.post("/account/2fa/disable", {"password": PASSWORD}).status_code, 400)
        self.assertEqual(kid.post("/account/2fa/disable", {"password": "wrong password here"}).status_code, 400)
        self.assertEqual(kid.post("/account/2fa/disable", {"password": PASSWORD}).status_code, 302)
        self.assertTrue(self.browser().login("kid@example.com").headers["Location"].endswith("/"))
        self.assertTrue(self.browser().login("pat@example.com").headers["Location"].endswith("/login/2fa"))


class AdminsNeedIt(AppTestCase):
    # covers V6.3.3
    def test_V6_3_3_admin_pages_wait_for_an_authenticator_app(self):
        admin = self.signed_up("pat@example.com")
        for path, method in (("/family", "get"), ("/family/invites", "post"), ("/family/rename", "post")):
            with self.subTest(path=path):
                r = admin.get(path) if method == "get" else admin.post(path, {"name": "x"}, page="/account")
                self.assertEqual(r.status_code, 302)
                self.assertIn("admin-needs-2fa", r.headers["Location"])
        self.enable_totp(admin)
        self.assertEqual(admin.get("/family").status_code, 200)

    def test_member_features_still_work_for_an_admin_without_one(self):
        admin = self.signed_up("pat@example.com")
        self.assertEqual(admin.post("/todos", {"title": "x"}, page="/todos").status_code, 302)


class ProviderSignInNeedsTheCodeToo(ProviderTestCase):
    # covers V6.3.3
    def test_V6_3_3_google_or_apple_sign_in_also_asks_for_the_code(self):
        b = self.sign_up_with_provider(subject="pat-sub")
        b.post("/account/password", {"new": "another long passphrase"})   # set a password to confirm with
        secret = self.enable_totp(b, password="another long passphrase")
        other = self.browser()
        r = self.answer(other, self.start(other), subject="pat-sub")
        self.assertTrue(r.headers["Location"].endswith("/login/2fa"))
        self.assertEqual(other.get("/").status_code, 302)
        step = totp.current_step() + 1
        with at_step(step):
            r = other.post("/login/2fa", {"code": totp.code_at(secret, step)}, page="/login/2fa")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(other.get("/").status_code, 200)

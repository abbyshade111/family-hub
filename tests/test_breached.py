"""New passwords that are known to have leaked are refused."""

import hashlib
from unittest import mock

from familyhub import breached
from tests.helpers import AppTestCase

LISTED = ["Q1w2e3r4t5y6", "1qaz2wsx3edc", "111222tianya"]   # 12+ characters, in common-passwords.txt
FRESH = "a long test passphrase"


def range_reply_for(password, count=42):
    """What the range API answers for a password it has seen, plus padding lines."""
    digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    return "\r\n".join([
        "0" * 35 + ":0",
        digest[5:] + f":{count}",
        "F" * 35 + ":3",
    ])


class LocalList(AppTestCase):
    # covers V6.2.4
    def test_V6_2_4_common_passwords_are_refused_at_signup(self):
        for i, password in enumerate(LISTED + [LISTED[0].lower(), LISTED[1].upper()]):
            with self.subTest(password=password):
                r = self.browser().signup(f"u{i}@example.com", password=password)
                self.assertEqual(r.status_code, 400)
                self.assertIn("data breach", r.get_data(as_text=True))

    # covers V6.2.4
    def test_V6_2_4_common_passwords_are_refused_at_password_change(self):
        b = self.signed_up("pat@example.com")
        r = b.post("/account/password", {"current": FRESH, "new": LISTED[0]})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.browser().login("pat@example.com").status_code, 302)

    def test_list_is_loaded(self):
        self.assertGreater(len(breached._common_passwords()), 90_000)

    def test_unlisted_password_is_accepted_when_the_service_is_down(self):
        self.assertEqual(self.browser().signup("pat@example.com", password=FRESH).status_code, 302)
        self.assertTrue(self.fetch_range.called)


class OnlineCheck(AppTestCase):
    # covers V6.2.12
    def test_V6_2_12_breached_password_is_refused_at_signup(self):
        password = "an unlisted but leaked phrase"
        self.fetch_range.side_effect = None
        self.fetch_range.return_value = range_reply_for(password)
        r = self.browser().signup("pat@example.com", password=password)
        self.assertEqual(r.status_code, 400)
        self.assertIn("data breach", r.get_data(as_text=True))

    # covers V6.2.12
    def test_V6_2_12_breached_password_is_refused_at_password_change(self):
        b = self.signed_up("pat@example.com")
        password = "an unlisted but leaked phrase"
        self.fetch_range.side_effect = None
        self.fetch_range.return_value = range_reply_for(password)
        r = b.post("/account/password", {"current": FRESH, "new": password})
        self.assertEqual(r.status_code, 400)

    def test_only_the_hash_prefix_is_sent(self):
        password = "an unlisted but leaked phrase"
        self.fetch_range.side_effect = None
        self.fetch_range.return_value = ""
        self.browser().signup("pat@example.com", password=password)
        (prefix,), _ = self.fetch_range.call_args
        self.assertEqual(prefix, hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()[:5])
        self.assertEqual(len(prefix), 5)

    def test_padding_lines_and_odd_replies_do_not_refuse_a_good_password(self):
        self.fetch_range.side_effect = None
        for reply in ("", "garbage", "0" * 35 + ":0", ":::", "\x00" * 50, range_reply_for(FRESH, count=0)):
            with self.subTest(reply=reply[:20]):
                self.fetch_range.return_value = reply
                self.assertFalse(breached.in_breach_corpus(FRESH))

    def test_unreachable_service_falls_back_to_the_local_list(self):
        for error in (OSError("down"), TimeoutError(), ValueError("bad url")):
            with self.subTest(error=type(error).__name__):
                self.fetch_range.side_effect = error
                self.assertIsNone(breached.in_breach_corpus(FRESH))
                self.assertTrue(breached.is_breached(LISTED[0]))

    def test_online_check_can_be_turned_off(self):
        with mock.patch.dict("os.environ", {"FAMILY_HUB_BREACH_CHECK": "0"}):
            self.assertIsNone(breached.in_breach_corpus(FRESH))
        self.assertFalse(self.fetch_range.called)

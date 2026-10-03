"""Algorithms can be changed in one place: lookup hashes go through one function, and old password
hashes are upgraded to today's settings the next time the password is checked."""

import os
import re
import sqlite3
from unittest import mock

from familyhub import security
from tests.helpers import AppTestCase

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASSWORD = "a long test passphrase"


def stored_hash(app, email):
    db = sqlite3.connect(app.config["DATABASE"])
    value = db.execute("SELECT password_hash FROM users WHERE email = ?", (email,)).fetchone()[0]
    db.close()
    return value


class PasswordUpgrade(AppTestCase):
    def make_old_hash(self, email):
        """Pretend this account's password was hashed with weaker settings years ago."""
        with mock.patch.object(security, "SCRYPT_N", 2**14):
            old = security.hash_password(PASSWORD)
        db = sqlite3.connect(self.app.config["DATABASE"])
        db.execute("UPDATE users SET password_hash = ? WHERE email = ?", (old, email))
        db.commit()
        db.close()
        self.assertTrue(old.startswith("scrypt$16384$"))

    # covers V11.2.2
    def test_V11_2_2_old_hash_is_upgraded_at_sign_in(self):
        self.signed_up("pat@example.com")
        self.make_old_hash("pat@example.com")
        self.assertEqual(self.browser().login("pat@example.com").status_code, 302)
        self.assertTrue(stored_hash(self.app, "pat@example.com").startswith(f"scrypt${security.SCRYPT_N}$"))
        self.assertEqual(self.browser().login("pat@example.com").status_code, 302)   # still the same password

    def test_wrong_password_upgrades_nothing(self):
        self.signed_up("pat@example.com")
        self.make_old_hash("pat@example.com")
        self.browser().login("pat@example.com", "not the right password")
        self.assertTrue(stored_hash(self.app, "pat@example.com").startswith("scrypt$16384$"))

    def test_old_hash_is_upgraded_when_confirming_a_sensitive_change(self):
        admin = self.signed_up("pat@example.com")
        self.signed_up("kid@example.com", invite=self.invite_code(admin))
        self.make_old_hash("pat@example.com")
        db = sqlite3.connect(self.app.config["DATABASE"])
        kid_id = db.execute("SELECT id FROM users WHERE email = 'kid@example.com'").fetchone()[0]
        db.close()
        r = admin.post(f"/family/members/{kid_id}/promote", {"password": "not the right password"}, page="/family")
        self.assertEqual(r.status_code, 400)
        self.assertTrue(stored_hash(self.app, "pat@example.com").startswith("scrypt$16384$"))
        r = admin.post(f"/family/members/{kid_id}/promote", {"password": PASSWORD}, page="/family")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(stored_hash(self.app, "pat@example.com").startswith(f"scrypt${security.SCRYPT_N}$"))

    def test_current_and_passwordless_hashes_need_no_upgrade(self):
        self.assertFalse(security.password_needs_upgrade(security.hash_password(PASSWORD)))
        self.assertFalse(security.password_needs_upgrade(""))
        self.assertFalse(security.password_needs_upgrade("garbage"))
        self.assertTrue(security.password_needs_upgrade("bcrypt$1$1$1$00$00"))


class LookupHashes(AppTestCase):
    # covers V11.2.2
    def test_V11_2_2_one_function_makes_every_lookup_hash(self):
        admin = self.signed_up("pat@example.com")
        code = self.invite_code(admin)
        db = sqlite3.connect(self.app.config["DATABASE"])
        stored = db.execute("SELECT code_hash FROM invites").fetchone()[0]
        db.close()
        self.assertEqual(stored, security.lookup_hash(code))

    # covers V11.2.2
    def test_V11_2_2_no_other_code_picks_its_own_hash(self):
        """Only security.py names the lookup algorithm. Two others are fixed by outside standards, not chosen:
        oidc.py's SHA-256 (PKCE's S256) and breached.py's SHA-1 (Have I Been Pwned's range API)."""
        allowed = {os.path.join("familyhub", name) for name in ("security.py", "oidc.py", "breached.py")}
        for folder, _, files in os.walk(os.path.join(ROOT, "familyhub")):
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(folder, name)
                relative = os.path.relpath(path, ROOT)
                with open(path, encoding="utf-8") as f:
                    source = f.read()
                with self.subTest(file=relative):
                    if relative not in allowed:
                        self.assertFalse("hashlib.sha" in source or "hashlib.new" in source,
                                         f"{relative} picks its own hash algorithm")

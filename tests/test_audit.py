"""The security event log (familyhub/audit.py): which events it records, and what it never contains."""

import json
import re
import sqlite3

from familyhub import audit
from tests.helpers import AppTestCase

PASSWORD = "a long test passphrase"


class AuditTestCase(AppTestCase):
    def capture(self):
        return self.assertLogs("familyhub.audit", level="INFO")

    @staticmethod
    def events(logs):
        return [json.loads(line.split(":", 2)[2]) for line in logs.output]

    def find(self, logs, name, outcome=None):
        found = [e for e in self.events(logs) if e["event"] == name and (outcome is None or e["outcome"] == outcome)]
        self.assertTrue(found, f"no {name}/{outcome} event in {self.events(logs)}")
        return found[-1]


class WhatIsRecorded(AuditTestCase):
    def test_password_sign_ins(self):
        self.signed_up("pat@example.com")
        with self.capture() as logs:
            self.browser().login("pat@example.com", "wrong password here")
            self.browser().login("nobody@example.com", "wrong password here")
            self.browser().login("pat@example.com")
        failed = [e for e in self.events(logs) if e["event"] == "sign_in" and e["outcome"] == "failed"]
        self.assertEqual(len(failed), 2)
        self.assertIsNotNone(failed[0]["user_id"])      # a real account: its id, not its email
        self.assertIsNone(failed[1]["user_id"])         # no such account
        ok = self.find(logs, "sign_in", "ok")
        self.assertEqual(ok["method"], "password")
        self.assertEqual(ok["ip"], "127.0.0.1")

    def test_lockout(self):
        self.signed_up("pat@example.com")
        b = self.browser()
        for _ in range(5):
            b.login("pat@example.com", "wrong password here")
        with self.capture() as logs:
            b.login("pat@example.com")
        self.find(logs, "sign_in", "locked")

    def test_sign_up_invite_and_sign_out(self):
        with self.capture() as logs:
            admin = self.signed_up("pat@example.com")
            code = self.invite_code(admin)
            kid = self.signed_up("kid@example.com", invite=code)
            kid.post("/logout", page="/")
        self.assertEqual(len([e for e in self.events(logs) if e["event"] == "account_created"]), 2)
        self.find(logs, "invite_created")
        self.find(logs, "invite_used")
        self.find(logs, "sign_out")

    def test_account_changes(self):
        admin = self.signed_up("pat@example.com")
        kid = self.signed_up("kid@example.com", invite=self.invite_code(admin))
        db = sqlite3.connect(self.app.config["DATABASE"])
        kid_id = db.execute("SELECT id FROM users WHERE email = 'kid@example.com'").fetchone()[0]
        db.close()
        with self.capture() as logs:
            admin.post(f"/family/members/{kid_id}/promote", {"password": PASSWORD}, page="/family")
            admin.post("/family/invites/revoke", page="/family")
            kid.post("/account/password", {"current": "not it at all", "new": "another long passphrase"})
            kid.post("/account/password", {"current": PASSWORD, "new": "another long passphrase"})
            kid.post("/account/sign-out-others", page="/account")
            kid.post("/account/delete", {"password": "another long passphrase"})
        self.assertEqual(self.find(logs, "admin_granted")["target_user_id"], kid_id)
        self.find(logs, "invites_revoked")
        self.find(logs, "password_check", "failed")
        self.find(logs, "password_changed")
        self.find(logs, "sign_out_others")
        self.find(logs, "account_deleted")

    def test_refused_requests(self):
        admin = self.signed_up("pat@example.com")
        kid = self.signed_up("kid@example.com", invite=self.invite_code(admin))
        with self.capture() as logs:
            kid.get("/family")
            kid.post("/todos", {"title": "x"}, csrf=False)
            kid.post("/todos", {"title": "x"}, headers={"Sec-Fetch-Site": "cross-site"})
        reasons = {e["reason"] for e in self.events(logs) if e["event"] == "request_refused"}
        self.assertEqual(reasons, {"not_admin", "csrf", "cross_site"})

    def test_times_are_utc(self):
        with self.capture() as logs:
            self.signed_up("pat@example.com")
        for e in self.events(logs):
            self.assertRegex(e["time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")


class WhatIsNeverRecorded(AuditTestCase):
    def test_no_emails_passwords_or_tokens(self):
        secrets_seen = ["pat@example.com", "kid@example.com", PASSWORD, "wrong password here"]
        with self.capture() as logs:
            admin = self.signed_up("pat@example.com")
            code = self.invite_code(admin)
            secrets_seen.append(code)
            kid = self.signed_up("kid@example.com", invite=code)
            self.browser().login("pat@example.com", "wrong password here")
            kid.post("/account/password", {"current": PASSWORD, "new": "another long passphrase"})
            secrets_seen.append("another long passphrase")
            kid.post("/logout", page="/")
        text = "\n".join(logs.output)
        for value in secrets_seen:
            self.assertNotIn(value, text)
        self.assertIsNone(re.search(r"[0-9a-f]{40,}", text))   # no hashes or tokens

    def test_unknown_details_are_refused(self):
        with self.assertRaises(ValueError):
            audit.event("sign_in", email="pat@example.com")
        with self.assertRaises(ValueError):
            audit.event("sign_in", token="abc")

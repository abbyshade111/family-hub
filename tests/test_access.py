"""Each family sees only its own things, and each person only their own reminders."""

import sqlite3

from tests.helpers import AppTestCase


class FamilyBoundaries(AppTestCase):
    def setUp(self):
        super().setUp()
        self.pat = self.signed_up("pat@example.com", family="Pat's family")
        self.sam = self.signed_up("sam@example.com", family="Sam's family")
        r = self.pat.post("/todos", {"title": "Pat's secret task"}, page="/todos")
        self.todo_id = self.created_id(r)
        self.pat.post("/calendar", {"title": "Pat's appointment", "starts_at": "2099-01-01T10:00"}, page="/calendar")
        self.pat.post("/groceries", {"name": "Pat's milk"}, page="/groceries")
        self.pat.post("/reminders", {"text": "Pat's pills", "remind_at": "2099-01-01T09:00"}, page="/reminders")
        db = sqlite3.connect(self.app.config["DATABASE"])
        self.event_id = db.execute("SELECT id FROM events").fetchone()[0]
        self.item_id = db.execute("SELECT id FROM grocery_items").fetchone()[0]
        self.reminder_id = db.execute("SELECT id FROM reminders").fetchone()[0]
        db.close()

    def snapshot(self):
        db = sqlite3.connect(self.app.config["DATABASE"])
        rows = {t: db.execute(f"SELECT * FROM {t} ORDER BY id").fetchall()
                for t in ("todos", "events", "grocery_items", "reminders", "families")}
        db.close()
        return rows

    def test_other_family_cannot_see_lists(self):
        for path, secret in (("/todos", "Pat&#39;s secret task"), ("/calendar", "Pat&#39;s appointment"),
                             ("/groceries", "Pat&#39;s milk"), ("/reminders", "Pat&#39;s pills"), ("/", "Pat&#39;s")):
            with self.subTest(path=path):
                page = self.sam.get(path).get_data(as_text=True)
                self.assertNotIn(secret, page)
                self.assertIn(secret, self.pat.get(path).get_data(as_text=True))

    def test_other_family_cannot_read_items(self):
        for path in (f"/todos/{self.todo_id}", f"/calendar/{self.event_id}"):
            with self.subTest(path=path):
                self.assertEqual(self.sam.get(path).status_code, 404)
                self.assertEqual(self.pat.get(path).status_code, 200)

    def test_other_family_cannot_change_or_delete_items(self):
        before = self.snapshot()
        attempts = [
            (f"/todos/{self.todo_id}", {"title": "hijacked"}),
            (f"/todos/{self.todo_id}/toggle", {}),
            (f"/todos/{self.todo_id}/delete", {}),
            (f"/calendar/{self.event_id}", {"title": "hijacked", "starts_at": "2099-01-01T10:00"}),
            (f"/calendar/{self.event_id}/delete", {}),
            (f"/groceries/{self.item_id}/toggle", {}),
            (f"/groceries/{self.item_id}/delete", {}),
            (f"/reminders/{self.reminder_id}/done", {}),
            (f"/reminders/{self.reminder_id}/delete", {}),
        ]
        for path, data in attempts:
            with self.subTest(path=path):
                self.assertEqual(self.sam.post(path, data).status_code, 404)
        self.sam.post("/groceries/clear-checked", {})
        self.assertEqual(self.snapshot(), before)

    def test_cannot_assign_a_todo_to_someone_in_another_family(self):
        db = sqlite3.connect(self.app.config["DATABASE"])
        sam_id = db.execute("SELECT id FROM users WHERE email = 'sam@example.com'").fetchone()[0]
        db.close()
        for value in (str(sam_id), "-1", "0", "abc", "1.5", "9" * 30, " ", "1 OR 1=1"):
            with self.subTest(value=value):
                r = self.pat.post("/todos", {"title": "x", "assigned_to": value}, page="/todos")
                if value.strip():
                    self.assertEqual(r.status_code, 400)

    def test_odd_ids_are_not_found(self):
        for path in ("/todos/0", "/todos/-1", "/todos/abc", "/todos/1.0", "/todos/" + "9" * 40,
                     "/calendar/9223372036854775808", "/todos/%00"):
            with self.subTest(path=path):
                self.assertEqual(self.sam.get(path).status_code, 404)

    def test_family_settings_are_admin_only(self):
        member = self.signed_up("kid@example.com", invite=self.invite_code(self.pat))
        self.assertIn("Pat&#39;s secret task", member.get("/todos").get_data(as_text=True))
        self.assertEqual(member.get("/family").status_code, 403)
        for path in ("/family/rename", "/family/invites", "/family/invites/revoke"):
            with self.subTest(path=path):
                self.assertEqual(member.post(path, {"name": "renamed"}).status_code, 403)
        self.assertIn("Pat&#39;s family", member.get("/").get_data(as_text=True))

    def test_reminders_are_private_inside_a_family(self):
        member = self.signed_up("kid@example.com", invite=self.invite_code(self.pat))
        self.assertNotIn("Pat&#39;s pills", member.get("/reminders").get_data(as_text=True))
        self.assertEqual(member.post(f"/reminders/{self.reminder_id}/delete", {}).status_code, 404)

    def test_admin_rename_only_touches_own_family(self):
        self.enable_totp(self.pat)
        self.pat.post("/family/rename", {"name": "The Pats"}, page="/family")
        self.assertIn("Sam&#39;s family", self.sam.get("/").get_data(as_text=True))


class Invites(AppTestCase):
    def test_invite_works_once(self):
        admin = self.signed_up("pat@example.com", family="Pat's family")
        code = self.invite_code(admin)
        self.signed_up("kid@example.com", invite=code)
        self.assertEqual(self.browser().signup("other@example.com", invite=code).status_code, 400)

    def test_invite_expires(self):
        import time
        from unittest import mock
        admin = self.signed_up("pat@example.com")
        code = self.invite_code(admin)
        with mock.patch("familyhub.security.now", return_value=time.time() + 8 * 24 * 3600):
            self.assertEqual(self.browser().signup("kid@example.com", invite=code).status_code, 400)

    def test_made_up_codes_are_refused(self):
        self.signed_up("pat@example.com")
        for i, code in enumerate(("x", "a" * 16, "' OR 1=1 --", "a" * 65, "\u0000")):
            with self.subTest(code=code[:10]):
                self.assertEqual(self.browser().signup(f"u{i}@example.com", invite=code).status_code, 400)

    def test_revoked_invites_stop_working(self):
        admin = self.signed_up("pat@example.com")
        code = self.invite_code(admin)
        admin.post("/family/invites/revoke", page="/family")
        self.assertEqual(self.browser().signup("kid@example.com", invite=code).status_code, 400)

    def test_codes_are_stored_hashed(self):
        admin = self.signed_up("pat@example.com")
        code = self.invite_code(admin)
        db = sqlite3.connect(self.app.config["DATABASE"])
        stored = db.execute("SELECT code_hash FROM invites").fetchone()[0]
        db.close()
        self.assertNotEqual(stored, code)

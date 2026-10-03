"""Editing your own name, making another member an admin, and sharing reminders."""

import sqlite3

from familyhub import create_app
from tests.helpers import AppTestCase

PASSWORD = "a long test passphrase"


class FamilyTestCase(AppTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.signed_up("pat@example.com", name="Pat", family="Pat's family")
        self.kid = self.signed_up("kid@example.com", name="Kid", invite=self.invite_code(self.admin))
        self.outsider = self.signed_up("sam@example.com", name="Sam", family="Sam's family")

    def user_id(self, email):
        db = sqlite3.connect(self.app.config["DATABASE"])
        row = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        db.close()
        return row[0]

    def last_reminder_id(self):
        db = sqlite3.connect(self.app.config["DATABASE"])
        row = db.execute("SELECT MAX(id) FROM reminders").fetchone()
        db.close()
        return row[0]


class EditingYourName(FamilyTestCase):
    def test_name_can_be_changed_and_the_family_sees_it(self):
        r = self.kid.post("/account/name", {"display_name": "Robin"})
        self.assertEqual(r.status_code, 302)
        self.assertIn("Robin", self.admin.get("/family").get_data(as_text=True))

    def test_bad_names_are_refused(self):
        for name in ("", "   ", "x" * 61, "bell\x07", "nul\x00"):
            with self.subTest(name=name[:10]):
                self.assertEqual(self.kid.post("/account/name", {"display_name": name}).status_code, 400)

    def test_name_is_shown_as_text(self):
        self.kid.post("/account/name", {"display_name": "<b>Kid</b>"})
        self.assertNotIn("<b>Kid</b>", self.admin.get("/family").get_data(as_text=True))

    def test_changing_a_name_needs_the_form_token(self):
        self.assertEqual(self.kid.post("/account/name", {"display_name": "Robin"}, csrf=False).status_code, 400)


class MakingAnAdmin(FamilyTestCase):
    # covers V8.3.1
    def test_V8_3_1_only_an_admin_can_promote(self):
        kid_id = self.user_id("kid@example.com")
        r = self.kid.post(f"/family/members/{kid_id}/promote", {"password": PASSWORD}, page="/account")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.kid.get("/family").status_code, 403)

    def test_admin_promotes_with_their_password(self):
        kid_id = self.user_id("kid@example.com")
        r = self.admin.post(f"/family/members/{kid_id}/promote", {"password": "not my password"}, page="/family")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.kid.get("/family").status_code, 403)
        r = self.admin.post(f"/family/members/{kid_id}/promote", {"password": PASSWORD}, page="/family")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.kid.get("/family").status_code, 302)    # admin now; needs an authenticator app
        self.enable_totp(self.kid)
        self.assertEqual(self.kid.get("/family").status_code, 200)
        self.assertEqual(self.admin.get("/family").status_code, 200)   # both are admins now

    # covers V8.3.1
    def test_V8_3_1_cannot_promote_someone_in_another_family(self):
        sam_id = self.user_id("sam@example.com")
        r = self.admin.post(f"/family/members/{sam_id}/promote", {"password": PASSWORD}, page="/family")
        self.assertEqual(r.status_code, 404)
        self.enable_totp(self.outsider)
        self.assertEqual(self.outsider.get("/family").status_code, 200)   # Sam runs their own family...
        db = sqlite3.connect(self.app.config["DATABASE"])
        family = db.execute("SELECT family_id FROM users WHERE email = 'sam@example.com'").fetchone()[0]
        db.close()
        self.assertNotEqual(family, self.user_id("pat@example.com"))     # ...and wasn't moved into Pat's

    def test_odd_member_ids(self):
        for member in ("0", "-1", "abc", "9" * 30):
            with self.subTest(member=member):
                r = self.admin.post(f"/family/members/{member}/promote", {"password": PASSWORD}, page="/family")
                self.assertEqual(r.status_code, 404)

    def test_promotion_is_rate_limited_like_other_password_checks(self):
        kid_id = self.user_id("kid@example.com")
        for _ in range(5):
            self.admin.post(f"/family/members/{kid_id}/promote", {"password": "wrong password"}, page="/family")
        r = self.admin.post(f"/family/members/{kid_id}/promote", {"password": PASSWORD}, page="/family")
        self.assertEqual(r.status_code, 429)


class SharedReminders(FamilyTestCase):
    def add(self, browser, text, shared, when="2099-01-01T09:00"):
        data = {"text": text, "remind_at": when}
        if shared:
            data["shared"] = "1"
        self.assertEqual(browser.post("/reminders", data, page="/reminders").status_code, 302)
        return self.last_reminder_id()

    def test_shared_reminder_is_seen_by_the_family_only(self):
        self.add(self.admin, "Bins out tonight", shared=True)
        self.add(self.admin, "Pat's private thing", shared=False)
        kid_page = self.kid.get("/reminders").get_data(as_text=True)
        self.assertIn("Bins out tonight", kid_page)
        self.assertIn("shared by Pat", kid_page)
        self.assertNotIn("private thing", kid_page)
        self.assertNotIn("Bins out tonight", self.outsider.get("/reminders").get_data(as_text=True))

    def test_due_shared_reminder_shows_on_family_home_pages(self):
        self.add(self.admin, "Dentist at four", shared=True, when="2000-01-01T09:00")
        self.assertIn("Dentist at four", self.kid.get("/").get_data(as_text=True))
        self.assertNotIn("Dentist at four", self.outsider.get("/").get_data(as_text=True))

    def test_anyone_in_the_family_marks_it_done_for_everyone(self):
        reminder = self.add(self.admin, "Bins out tonight", shared=True, when="2000-01-01T09:00")
        self.assertEqual(self.kid.post(f"/reminders/{reminder}/done", page="/reminders").status_code, 302)
        self.assertNotIn("Bins out tonight", self.admin.get("/").get_data(as_text=True))

    # covers V8.3.1
    def test_V8_3_1_only_the_maker_can_unshare_or_delete(self):
        reminder = self.add(self.admin, "Bins out tonight", shared=True)
        self.assertEqual(self.kid.post(f"/reminders/{reminder}/share", page="/reminders").status_code, 404)
        self.assertEqual(self.kid.post(f"/reminders/{reminder}/delete", page="/reminders").status_code, 404)
        self.assertIn("Bins out tonight", self.kid.get("/reminders").get_data(as_text=True))

    # covers V8.3.1
    def test_V8_3_1_other_families_cannot_touch_a_shared_reminder(self):
        reminder = self.add(self.admin, "Bins out tonight", shared=True)
        for action in ("done", "share", "delete"):
            with self.subTest(action=action):
                r = self.outsider.post(f"/reminders/{reminder}/{action}", page="/reminders")
                self.assertEqual(r.status_code, 404)

    def test_unsharing_makes_it_private_again(self):
        reminder = self.add(self.admin, "Bins out tonight", shared=True)
        self.admin.post(f"/reminders/{reminder}/share", page="/reminders")
        self.assertNotIn("Bins out tonight", self.kid.get("/reminders").get_data(as_text=True))
        self.assertEqual(self.kid.post(f"/reminders/{reminder}/done", page="/reminders").status_code, 404)

    def test_shared_reminder_goes_when_its_maker_leaves(self):
        self.add(self.kid, "Kid's shared note", shared=True)
        self.kid.post("/account/delete", {"password": PASSWORD})
        self.assertNotIn("shared note", self.admin.get("/reminders").get_data(as_text=True))


class Upgrade(AppTestCase):
    def test_older_database_gains_the_shared_column(self):
        # a reminders table from before sharing existed
        db = sqlite3.connect(self.app.config["DATABASE"])
        db.executescript("""
            PRAGMA foreign_keys = OFF;
            DROP TABLE reminders;
            CREATE TABLE reminders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, text TEXT NOT NULL,
                                    remind_at TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0,
                                    created_at TEXT NOT NULL DEFAULT (datetime('now')));
            INSERT INTO reminders (user_id, text, remind_at) VALUES (1, 'old one', '2099-01-01T09:00');
        """)
        db.commit()
        db.close()
        create_app({"DATA_DIR": self.data_dir})
        db = sqlite3.connect(self.app.config["DATABASE"])
        row = db.execute("SELECT text, shared FROM reminders").fetchone()
        db.close()
        self.assertEqual(row, ("old one", 0))

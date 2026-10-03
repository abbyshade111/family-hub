"""The business limits in familyhub/limits.py are enforced (security-notes.md, V2.1.3).

Each test lowers one limit so it can be reached quickly; the code path is the same one the real number uses.
"""

import time
from unittest import mock

from familyhub import limits
from tests.helpers import AppTestCase


class FamilyAndPersonLimits(AppTestCase):
    def setUp(self):
        super().setUp()
        self.b = self.signed_up("pat@example.com")

    # covers V2.3.2
    def test_V2_3_2_open_todos_per_family(self):
        with mock.patch.object(limits, "OPEN_TODOS_PER_FAMILY", 3):
            for n in range(3):
                self.assertEqual(self.b.post("/todos", {"title": f"t{n}"}, page="/todos").status_code, 302)
            r = self.b.post("/todos", {"title": "one too many"}, page="/todos")
            self.assertEqual(r.status_code, 400)
            self.assertIn("the most allowed", r.get_data(as_text=True))
            # the limit is per family: another family is unaffected
            other = self.signed_up("sam@example.com")
            self.assertEqual(other.post("/todos", {"title": "theirs"}, page="/todos").status_code, 302)

    # covers V2.3.2
    def test_V2_3_2_reopening_a_done_todo_counts(self):
        with mock.patch.object(limits, "OPEN_TODOS_PER_FAMILY", 2):
            first = self.created_id(self.b.post("/todos", {"title": "a"}, page="/todos"))
            self.b.post(f"/todos/{first}/toggle", page="/todos")          # done: 0 open
            self.b.post("/todos", {"title": "b"}, page="/todos")
            self.b.post("/todos", {"title": "c"}, page="/todos")          # 2 open
            self.assertEqual(self.b.post(f"/todos/{first}/toggle", page="/todos").status_code, 400)
            self.assertEqual(self.b.post("/todos", {"title": "d"}, page="/todos").status_code, 400)

    def test_done_todos_do_not_count_and_old_ones_are_summarised(self):
        with mock.patch.object(limits, "OPEN_TODOS_PER_FAMILY", 2), \
             mock.patch.object(limits, "DONE_TODOS_SHOWN", 1):
            for n in range(3):
                todo = self.created_id(self.b.post("/todos", {"title": f"t{n}"}, page="/todos"))
                self.b.post(f"/todos/{todo}/toggle", page="/todos")
            page = self.b.get("/todos").get_data(as_text=True)
            self.assertIn("2 older done to-dos", page)

    # covers V2.3.2
    def test_V2_3_2_grocery_items_per_family(self):
        with mock.patch.object(limits, "GROCERY_ITEMS_PER_FAMILY", 3):
            for n in range(3):
                self.assertEqual(self.b.post("/groceries", {"name": f"g{n}"}, page="/groceries").status_code, 302)
            self.assertEqual(self.b.post("/groceries", {"name": "more"}, page="/groceries").status_code, 400)

    # covers V2.3.2
    def test_V2_3_2_upcoming_events_per_family(self):
        with mock.patch.object(limits, "UPCOMING_EVENTS_PER_FAMILY", 2):
            for n in range(2):
                r = self.b.post("/calendar", {"title": f"e{n}", "starts_at": "2099-01-01T10:00"}, page="/calendar")
                self.assertEqual(r.status_code, 302)
            r = self.b.post("/calendar", {"title": "full", "starts_at": "2099-01-02T10:00"}, page="/calendar")
            self.assertEqual(r.status_code, 400)
            # past events don't count, so they can still be added
            r = self.b.post("/calendar", {"title": "past", "starts_at": "2000-01-01T10:00"}, page="/calendar")
            self.assertEqual(r.status_code, 302)

    # covers V2.3.2
    def test_V2_3_2_moving_a_past_event_into_the_future_counts(self):
        import sqlite3
        with mock.patch.object(limits, "UPCOMING_EVENTS_PER_FAMILY", 1):
            self.b.post("/calendar", {"title": "past", "starts_at": "2000-01-01T10:00"}, page="/calendar")
            self.b.post("/calendar", {"title": "soon", "starts_at": "2099-01-01T10:00"}, page="/calendar")
            db = sqlite3.connect(self.app.config["DATABASE"])
            past_id = db.execute("SELECT id FROM events WHERE title = 'past'").fetchone()[0]
            db.close()
            r = self.b.post(f"/calendar/{past_id}", {"title": "past", "starts_at": "2099-02-01T10:00"},
                            page="/calendar")
            self.assertEqual(r.status_code, 400)

    # covers V2.3.2
    def test_V2_3_2_reminders_per_person(self):
        with mock.patch.object(limits, "REMINDERS_PER_PERSON", 2):
            for n in range(2):
                r = self.b.post("/reminders", {"text": f"r{n}", "remind_at": "2099-01-01T09:00"}, page="/reminders")
                self.assertEqual(r.status_code, 302)
            r = self.b.post("/reminders", {"text": "more", "remind_at": "2099-01-01T09:00"}, page="/reminders")
            self.assertEqual(r.status_code, 400)
            # per person: someone else in the same family still can
            member = self.signed_up("kid@example.com", invite=self.invite_code(self.b))
            r = member.post("/reminders", {"text": "mine", "remind_at": "2099-01-01T09:00"}, page="/reminders")
            self.assertEqual(r.status_code, 302)


class RateLimits(AppTestCase):
    # covers V2.3.2
    def test_V2_3_2_invite_codes_per_admin_per_day(self):
        admin = self.signed_up("pat@example.com")
        with mock.patch.object(limits, "INVITES_PER_ADMIN_PER_DAY", 2):
            self.invite_code(admin)
            code = self.invite_code(admin)
            # using or cancelling codes doesn't give the allowance back
            self.signed_up("kid@example.com", invite=code)
            admin.post("/family/invites/revoke", page="/family")
            self.assertEqual(admin.post("/family/invites", page="/family").status_code, 429)
            # a day later the allowance is back (age the records rather than the clock, which would end the session)
            import sqlite3
            db = sqlite3.connect(self.app.config["DATABASE"])
            db.execute("UPDATE invites_made SET at = at - ?", (24 * 3600 + 60,))
            db.commit()
            db.close()
            self.assertEqual(admin.post("/family/invites", page="/family").status_code, 200)

    # covers V2.3.2
    def test_V2_3_2_signups_across_the_app_per_hour(self):
        with mock.patch.object(limits, "SIGNUPS_PER_HOUR", 2):
            self.signed_up("a@example.com")
            self.signed_up("b@example.com")
            r = self.browser().signup("c@example.com")
            self.assertEqual(r.status_code, 429)
            self.assertIn("try again in an hour", r.get_data(as_text=True))
            self.assertEqual(self.browser().login("c@example.com").status_code, 401)
            with mock.patch("familyhub.security.now", return_value=time.time() + 3600 + 60):
                self.assertEqual(self.browser().signup("c@example.com").status_code, 302)

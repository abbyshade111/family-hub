"""Archiving, what the access log keeps, and local backups."""

import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import shutil
from unittest import mock

from tests.helpers import AppTestCase

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASSWORD = "a long test passphrase"


class Archiving(AppTestCase):
    def setUp(self):
        super().setUp()
        self.pat = self.signed_up("pat@example.com", name="Pat", family="Pat's family")
        self.kid = self.signed_up("kid@example.com", name="Kid", invite=self.invite_code(self.pat))
        self.sam = self.signed_up("sam@example.com", family="Sam's family")

    def newest(self, table):
        db = sqlite3.connect(self.app.config["DATABASE"])
        row = db.execute(f"SELECT MAX(id) FROM {table}").fetchone()   # table name is a fixed test value
        db.close()
        return row[0]

    def test_archived_todo_leaves_the_list_and_can_be_restored(self):
        todo = self.created_id(self.pat.post("/todos", {"title": "Old chore", "assigned_to": ""}, page="/todos"))
        self.assertEqual(self.kid.post(f"/todos/{todo}/archive", page="/todos").status_code, 302)
        self.assertNotIn("Old chore", self.pat.get("/todos").get_data(as_text=True))
        self.assertIn("Old chore", self.pat.get("/todos/archived").get_data(as_text=True))
        self.assertEqual(self.pat.get(f"/todos/{todo}").status_code, 200)       # kept, still reachable
        self.pat.post(f"/todos/{todo}/archive", page="/todos")                  # restore
        self.assertIn("Old chore", self.pat.get("/todos").get_data(as_text=True))

    def test_archived_todo_leaves_the_home_page(self):
        db = sqlite3.connect(self.app.config["DATABASE"])
        pat_id = db.execute("SELECT id FROM users WHERE email = 'pat@example.com'").fetchone()[0]
        db.close()
        todo = self.created_id(self.pat.post("/todos", {"title": "Mine", "assigned_to": str(pat_id)}, page="/todos"))
        self.assertIn("Mine", self.pat.get("/").get_data(as_text=True))
        self.pat.post(f"/todos/{todo}/archive", page="/todos")
        self.assertNotIn("Mine", self.pat.get("/").get_data(as_text=True))

    def test_archived_event_leaves_the_calendar(self):
        self.pat.post("/calendar", {"title": "Old party", "starts_at": "2099-01-01T10:00"}, page="/calendar")
        event = self.newest("events")
        self.kid.post(f"/calendar/{event}/archive", page="/calendar")
        self.assertNotIn("Old party", self.pat.get("/calendar").get_data(as_text=True))
        self.assertNotIn("Old party", self.pat.get("/").get_data(as_text=True))
        self.assertIn("Old party", self.pat.get("/calendar/archived").get_data(as_text=True))

    # covers V8.3.1
    def test_V8_3_1_other_families_cannot_archive_or_see_archives(self):
        todo = self.created_id(self.pat.post("/todos", {"title": "Pat's chore"}, page="/todos"))
        self.pat.post("/calendar", {"title": "Pat's party", "starts_at": "2099-01-01T10:00"}, page="/calendar")
        event = self.newest("events")
        self.assertEqual(self.sam.post(f"/todos/{todo}/archive", page="/todos").status_code, 404)
        self.assertEqual(self.sam.post(f"/calendar/{event}/archive", page="/calendar").status_code, 404)
        self.pat.post(f"/todos/{todo}/archive", page="/todos")
        self.pat.post(f"/calendar/{event}/archive", page="/calendar")
        self.assertNotIn("Pat&#39;s chore", self.sam.get("/todos/archived").get_data(as_text=True))
        self.assertNotIn("Pat&#39;s party", self.sam.get("/calendar/archived").get_data(as_text=True))

    # covers V8.3.1
    def test_V8_3_1_only_the_maker_archives_a_reminder(self):
        self.pat.post("/reminders", {"text": "Shared one", "remind_at": "2000-01-01T09:00", "shared": "1"},
                      page="/reminders")
        reminder = self.newest("reminders")
        self.assertEqual(self.kid.post(f"/reminders/{reminder}/archive", page="/reminders").status_code, 404)
        self.assertEqual(self.sam.post(f"/reminders/{reminder}/archive", page="/reminders").status_code, 404)
        self.assertEqual(self.pat.post(f"/reminders/{reminder}/archive", page="/reminders").status_code, 302)
        # archived: gone from everyone's home page and list, still in the archive
        self.assertNotIn("Shared one", self.kid.get("/").get_data(as_text=True))
        self.assertNotIn("Shared one", self.kid.get("/reminders").get_data(as_text=True))
        self.assertIn("Shared one", self.pat.get("/reminders/archived").get_data(as_text=True))

    # covers V2.3.2
    def test_V2_3_2_archived_items_still_count_toward_limits(self):
        from familyhub import limits
        with mock.patch.object(limits, "OPEN_TODOS_PER_FAMILY", 2):
            first = self.created_id(self.pat.post("/todos", {"title": "a"}, page="/todos"))
            self.pat.post("/todos", {"title": "b"}, page="/todos")
            self.pat.post(f"/todos/{first}/archive", page="/todos")
            self.assertEqual(self.pat.post("/todos", {"title": "c"}, page="/todos").status_code, 400)

    def test_archive_needs_the_form_token(self):
        todo = self.created_id(self.pat.post("/todos", {"title": "x"}, page="/todos"))
        self.assertEqual(self.pat.post(f"/todos/{todo}/archive", csrf=False).status_code, 400)


class AccessLog(AppTestCase):
    def test_query_strings_never_reach_the_log(self):
        sys.path.insert(0, ROOT)
        import run
        for raw, expected in (
            ("/auth/google/callback?state=abc&code=secret-code", "/auth/google/callback"),
            ("/todos/5?done=added", "/todos/5"),
            ("/login", "/login"),
            ("/x?" + "a" * 5000, "/x"),
        ):
            with self.subTest(raw=raw[:30]):
                self.assertEqual(run.loggable_path(raw), expected)


class RequestLogTime(AppTestCase):
    # covers V16.2.2
    def test_V16_2_2_request_log_uses_the_security_logs_utc_format(self):
        sys.path.insert(0, ROOT)
        import run
        stamp = run.QuietHandler.log_date_time_string(None)
        self.assertRegex(stamp, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")


class Backups(AppTestCase):
    def setUp(self):
        super().setUp()
        self.backup_dir = tempfile.mkdtemp(prefix="familyhub-backups-")
        self.addCleanup(shutil.rmtree, self.backup_dir, True)

    def run_tool(self, **env):
        full_env = dict(os.environ, FAMILY_HUB_DATA=self.data_dir, PYTHONDONTWRITEBYTECODE="1", **env)
        return subprocess.run([sys.executable, os.path.join(ROOT, "tools", "backup.py")],
                              capture_output=True, text=True, env=full_env)

    def test_off_unless_turned_on(self):
        result = self.run_tool()
        self.assertEqual(result.returncode, 0)
        self.assertIn("Backups are off", result.stdout)

    def test_backup_is_a_working_owner_only_copy(self):
        pat = self.signed_up("pat@example.com")
        pat.post("/todos", {"title": "Back me up"}, page="/todos")
        result = self.run_tool(FAMILY_HUB_BACKUP_DIR=self.backup_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        (name,) = os.listdir(self.backup_dir)
        path = os.path.join(self.backup_dir, name)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        db = sqlite3.connect(path)
        self.assertEqual(db.execute("SELECT title FROM todos").fetchone()[0], "Back me up")
        db.close()

    def test_only_the_newest_are_kept(self):
        for n in range(4):
            open(os.path.join(self.backup_dir, f"family-2000010{n}-000000.db"), "w").close()
        open(os.path.join(self.backup_dir, "unrelated.txt"), "w").close()
        result = self.run_tool(FAMILY_HUB_BACKUP_DIR=self.backup_dir, FAMILY_HUB_BACKUP_KEEP="2")
        self.assertEqual(result.returncode, 0, result.stderr)
        left = sorted(os.listdir(self.backup_dir))
        self.assertEqual(len([f for f in left if f.endswith(".db")]), 2)
        self.assertIn("unrelated.txt", left)           # nothing else in the folder is touched
        self.assertIn("family-20000103-000000.db", left)

    def test_bad_settings_are_reported(self):
        for keep in ("0", "-1", "many"):
            with self.subTest(keep=keep):
                result = self.run_tool(FAMILY_HUB_BACKUP_DIR=self.backup_dir, FAMILY_HUB_BACKUP_KEEP=keep)
                self.assertNotEqual(result.returncode, 0)

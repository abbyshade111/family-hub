"""The command-line tools in tools/."""

import os
import subprocess
import sys

from tests.helpers import AppTestCase

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tools", "sign_out_everyone.py")


class SignOutEveryone(AppTestCase):
    def run_tool(self, *args, answer=None):
        env = dict(os.environ, FAMILY_HUB_DATA=self.data_dir, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([sys.executable, TOOL, *args], input=answer, capture_output=True, text=True, env=env)

    def test_everyone_is_signed_out_and_nothing_else_changes(self):
        pat = self.signed_up("pat@example.com")
        sam = self.signed_up("sam@example.com")
        pat.post("/todos", {"title": "Keep me"}, page="/todos")
        result = self.run_tool("--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Ended 2 session(s)", result.stdout)
        self.assertEqual(pat.get("/").status_code, 302)
        self.assertEqual(sam.get("/").status_code, 302)
        again = self.browser()
        self.assertEqual(again.login("pat@example.com").status_code, 302)
        self.assertIn("Keep me", again.get("/todos").get_data(as_text=True))

    def test_it_asks_first(self):
        pat = self.signed_up("pat@example.com")
        result = self.run_tool(answer="no\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(pat.get("/").status_code, 200)
        result = self.run_tool(answer="yes\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(pat.get("/").status_code, 302)

    def test_wrong_data_folder_is_reported(self):
        env = dict(os.environ, FAMILY_HUB_DATA=os.path.join(self.data_dir, "nope"))
        result = subprocess.run([sys.executable, TOOL, "--yes"], capture_output=True, text=True, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No Family Hub database", result.stderr)

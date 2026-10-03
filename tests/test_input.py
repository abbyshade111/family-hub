"""What people type is checked, kept as text, and shown as text."""

from tests.helpers import AppTestCase

BAD_TEXT = ["", "   ", "x" * 5000, "bell\x07", "nul\x00byte", "esc\x1b[31m"]
BAD_DATETIMES = ["", "tomorrow", "2026-13-01T10:00", "2026-02-30T10:00", "2026-01-01 10:00",
                 "2026-01-01T25:00", "9" * 50, "2026-01-01T10:00' OR 1=1"]


class Validation(AppTestCase):
    def setUp(self):
        super().setUp()
        self.b = self.signed_up("pat@example.com")

    def test_bad_todo_titles(self):
        for title in BAD_TEXT:
            with self.subTest(title=title[:20]):
                self.assertEqual(self.b.post("/todos", {"title": title}, page="/todos").status_code, 400)

    def test_bad_due_dates(self):
        for due in ("soon", "2026-02-30", "2026/01/01", "0000-00-00", "1" * 40):
            with self.subTest(due=due):
                self.assertEqual(self.b.post("/todos", {"title": "ok", "due_date": due}, page="/todos").status_code, 400)

    def test_bad_event_times(self):
        for when in BAD_DATETIMES:
            with self.subTest(when=when[:20]):
                r = self.b.post("/calendar", {"title": "ok", "starts_at": when}, page="/calendar")
                self.assertEqual(r.status_code, 400)

    def test_event_cannot_end_before_it_starts(self):
        r = self.b.post("/calendar", {"title": "ok", "starts_at": "2099-01-02T10:00", "ends_at": "2099-01-01T10:00"},
                        page="/calendar")
        self.assertEqual(r.status_code, 400)

    def test_bad_grocery_items_and_reminders(self):
        for name in BAD_TEXT:
            with self.subTest(name=name[:20]):
                self.assertEqual(self.b.post("/groceries", {"name": name}, page="/groceries").status_code, 400)
        for when in BAD_DATETIMES:
            with self.subTest(when=when[:20]):
                r = self.b.post("/reminders", {"text": "ok", "remind_at": when}, page="/reminders")
                self.assertEqual(r.status_code, 400)

    def test_good_input_with_unusual_characters_is_kept(self):
        for title in ("Ölçü & ü 日本 🍎", "quote ' \" < > &", "x" * 200):
            with self.subTest(title=title[:20]):
                self.assertEqual(self.b.post("/todos", {"title": title}, page="/todos").status_code, 302)

    def test_oversized_request_is_refused(self):
        r = self.b.post("/todos", {"title": "x", "notes": "y" * 100_000}, page="/todos")
        self.assertEqual(r.status_code, 413)


class Escaping(AppTestCase):
    PAYLOADS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "{{ 7*7 }}", "javascript:alert(1)"]

    def test_typed_text_is_shown_as_text(self):
        b = self.signed_up("pat@example.com", name="<b>Pat</b>", family="<i>Fam</i>")
        for payload in self.PAYLOADS:
            b.post("/todos", {"title": payload}, page="/todos")
            b.post("/groceries", {"name": payload}, page="/groceries")
            b.post("/calendar", {"title": payload, "starts_at": "2099-01-01T10:00"}, page="/calendar")
        for path in ("/", "/todos", "/groceries", "/calendar", "/account", "/family"):
            with self.subTest(path=path):
                page = b.get(path).get_data(as_text=True)
                self.assertNotIn("<script>alert", page)
                self.assertNotIn("<img src=x", page)
                self.assertNotIn("<b>Pat</b>", page)
                self.assertNotIn("<i>Fam</i>", page)
                self.assertNotIn(">49<", page)


class Headers(AppTestCase):
    def test_security_headers_on_every_page(self):
        b = self.signed_up("pat@example.com")
        for path in ("/", "/login", "/todos", "/nope", "/static/style.css"):
            with self.subTest(path=path):
                h = b.get(path).headers
                self.assertIn("default-src 'none'", h["Content-Security-Policy"])
                self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
                self.assertEqual(h["X-Content-Type-Options"], "nosniff")
                self.assertEqual(h["X-Frame-Options"], "DENY")
                self.assertIn("max-age=", h["Strict-Transport-Security"])
                self.assertEqual(h["Cache-Control"], "no-store")

    def test_error_pages_do_not_leak_details(self):
        b = self.signed_up("pat@example.com")
        for r in (b.get("/nope"), b.post("/todos/1", {}), b.get("/logout")):
            body = r.get_data(as_text=True)
            self.assertNotIn("Traceback", body)
            self.assertNotIn("werkzeug", body.lower())

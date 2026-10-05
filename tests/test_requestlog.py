"""The production request log (familyhub/requestlog.py), and the production entry point (serve.py)."""

import io
import os
import re
import sys
from unittest import mock

from familyhub import create_app
from familyhub.requestlog import RequestLog
from tests.helpers import AppTestCase

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINE = re.compile(r'^(\S+) - - \[\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z\] "(\S+) (\S+)" (\d{3})$')


class RequestLogLines(AppTestCase):
    def logged(self, app, path, **kwargs):
        stream = io.StringIO()
        with mock.patch.object(sys, "stderr", stream):
            app.test_client().get(path, base_url="https://localhost", **kwargs)
        return stream.getvalue().splitlines()

    def test_one_line_per_request_without_the_query_string(self):
        app = create_app({"DATA_DIR": self.data_dir, "REQUEST_LOG": True})
        lines = self.logged(app, "/auth/google/callback?state=abc&code=secret-code")
        self.assertEqual(len(lines), 1)
        ip, method, path, status = LINE.match(lines[0]).groups()
        self.assertEqual((method, path, status), ("GET", "/auth/google/callback", "404"))
        self.assertNotIn("secret-code", lines[0])

    def test_records_the_visitor_behind_a_trusted_proxy(self):
        with mock.patch.dict("os.environ", {"FAMILY_HUB_TRUSTED_PROXIES": "1"}):
            app = create_app({"DATA_DIR": self.data_dir, "REQUEST_LOG": True})
        lines = self.logged(app, "/health", headers={"X-Forwarded-For": "100.101.102.103"})
        self.assertTrue(lines[0].startswith("100.101.102.103 "))

    def test_forwarded_address_is_ignored_without_a_trusted_proxy(self):
        app = create_app({"DATA_DIR": self.data_dir, "REQUEST_LOG": True})
        lines = self.logged(app, "/health", headers={"X-Forwarded-For": "100.101.102.103"})
        self.assertFalse(lines[0].startswith("100.101.102.103 "))

    def test_off_unless_asked_for(self):
        self.assertEqual(self.logged(self.app, "/health"), [])

    def test_a_crash_is_still_logged(self):
        def broken(environ, start_response):
            raise RuntimeError("boom")
        stream = io.StringIO()
        with self.assertRaises(RuntimeError):
            RequestLog(broken, stream)({"REQUEST_METHOD": "GET", "PATH_INFO": "/x", "REMOTE_ADDR": "10.0.0.1"}, None)
        self.assertRegex(stream.getvalue(), r'"GET /x" 500')

    def test_odd_paths_cannot_forge_log_lines(self):
        stream = io.StringIO()
        app = RequestLog(lambda e, s: (s("200 OK", []), [b""])[1], stream)
        app({"REQUEST_METHOD": "GET", "PATH_INFO": '/a\n127.0.0.1 - - "GET /admin" 200', "REMOTE_ADDR": "10.0.0.1"},
            lambda *a: None)
        self.assertEqual(len(stream.getvalue().splitlines()), 1)


class ProductionEntryPoint(AppTestCase):
    def test_serve_py_settings(self):
        sys.path.insert(0, ROOT)
        import serve
        self.assertEqual(serve.DEFAULT_THREADS, 4)
        self.assertLessEqual(serve.MAX_REQUEST_BODY_BYTES, 256 * 1024)
        with open(os.path.join(ROOT, "Procfile"), encoding="utf-8") as f:
            self.assertIn("python serve.py", f.read())

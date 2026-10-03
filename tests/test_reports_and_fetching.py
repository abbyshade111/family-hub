"""Reports of blocked content (CSP), and what the app will fetch from a sign-in provider."""

import io
import json
import urllib.error
import urllib.request
from unittest import mock

from familyhub import oidc
from familyhub.views import reports
from tests.helpers import AppTestCase


class CspReports(AppTestCase):
    def setUp(self):
        super().setUp()
        reports._recent.clear()
        self.addCleanup(reports._recent.clear)

    def send(self, payload, content_type="application/csp-report", ip="203.0.113.5"):
        b = self.browser()
        return b.client.post("/csp-report", base_url="https://localhost", data=json.dumps(payload),
                             content_type=content_type, environ_base={"REMOTE_ADDR": ip})

    # covers V3.4.7
    def test_V3_4_7_policy_asks_browsers_to_report(self):
        h = self.browser().get("/login").headers
        self.assertIn("report-uri /csp-report", h["Content-Security-Policy"])
        self.assertIn("report-to csp", h["Content-Security-Policy"])
        self.assertEqual(h["Reporting-Endpoints"], 'csp="/csp-report"')

    # covers V3.4.7
    def test_V3_4_7_a_report_is_logged_without_full_addresses(self):
        report = {"csp-report": {
            "document-uri": "https://family.example/todos/5?done=added&secret=abc",
            "violated-directive": "script-src-elem",
            "blocked-uri": "https://evil.example/steal.js?who=pat@example.com",
        }}
        with self.assertLogs("familyhub.audit", level="INFO") as logs:
            self.assertEqual(self.send(report).status_code, 204)
        line = json.loads(logs.output[-1].split(":", 2)[2])
        self.assertEqual((line["event"], line["reason"], line["path"], line["blocked"]),
                         ("csp_violation", "script-src-elem", "/todos/5", "https://evil.example"))
        self.assertNotIn("pat@example.com", logs.output[-1])
        self.assertNotIn("secret", logs.output[-1])

    def test_reporting_api_format_is_understood(self):
        report = [{"type": "csp-violation", "body": {
            "documentURL": "https://family.example/calendar", "effectiveDirective": "img-src",
            "blockedURL": "https://tracker.example/pixel.gif"}}]
        with self.assertLogs("familyhub.audit", level="INFO") as logs:
            self.send(report, content_type="application/reports+json")
        self.assertIn('"blocked":"https://tracker.example"', logs.output[-1])

    def test_junk_is_ignored(self):
        for payload in ("not json", 42, None, {"csp-report": "x"}, [1, 2, 3], {"x" * 10: "y" * 10}):
            with self.subTest(payload=str(payload)[:20]):
                self.assertEqual(self.send(payload).status_code, 204)

    def test_one_address_cannot_flood_the_log(self):
        report = {"csp-report": {"document-uri": "https://x/", "violated-directive": "img-src"}}
        with self.assertLogs("familyhub.audit", level="INFO") as logs:
            for _ in range(25):
                self.send(report)
            self.send(report, ip="198.51.100.7")       # someone else still gets through
        self.assertEqual(len(logs.output), reports.MAX_REPORTS_PER_MINUTE + 1)

    def test_only_this_endpoint_skips_the_form_token(self):
        b = self.signed_up("pat@example.com")
        r = b.client.post("/todos", base_url="https://localhost", data={"title": "x"})
        self.assertEqual(r.status_code, 400)


class WhatSignInWillFetch(AppTestCase):
    def test_only_web_addresses_are_fetched(self):
        for url in ("file:///etc/passwd", "ftp://example.test/x", "gopher://example.test/", "data:,hi"):
            with self.subTest(url=url):
                with self.assertRaises(oidc.OIDCError):
                    oidc._get_json(url)

    def test_an_issuer_that_isnt_a_web_address_is_ignored(self):
        env = {"OIDC_ISSUER": "file:///etc", "OIDC_CLIENT_ID": "x"}
        with mock.patch.dict("os.environ", env):
            self.assertNotIn("oidc", oidc.configured_providers())

    def test_redirects_are_refused(self):
        def redirecting(request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 302, "Found", {"Location": "ftp://x/"}, io.BytesIO())
        with mock.patch.object(oidc._opener, "open", side_effect=redirecting):
            with self.assertRaises(oidc.OIDCError):
                oidc._get_json("https://id.example.test/.well-known/openid-configuration")

    def test_redirect_handler_refuses(self):
        handler = oidc._NoRedirects()
        request = urllib.request.Request("https://id.example.test/token")
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(request, io.BytesIO(), 302, "Found", {}, "ftp://elsewhere/")

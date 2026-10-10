"""The app can be added to an iPhone or Android home screen (a web app manifest and icons)."""

import json

from tests.helpers import AppTestCase


class HomeScreen(AppTestCase):
    def test_pages_link_the_manifest_and_icon(self):
        page = self.browser().get("/login").get_data(as_text=True)
        self.assertIn('rel="manifest" href="/static/manifest.json"', page)
        self.assertIn('rel="apple-touch-icon" href="/static/icons/apple-touch-icon.png"', page)
        self.assertIn('name="theme-color" content="#2f6f5e"', page)

    def test_manifest_is_served_and_names_real_icons(self):
        b = self.browser()
        manifest = json.loads(b.get("/static/manifest.json").get_data(as_text=True))
        self.assertEqual(manifest["start_url"], "/")
        self.assertEqual(manifest["display"], "standalone")
        for icon in manifest["icons"]:
            with self.subTest(icon=icon["src"]):
                r = b.get("/" + icon["src"])
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.mimetype, "image/png")

    def test_csp_lets_the_manifest_load_from_this_site(self):
        csp = self.browser().get("/login").headers["Content-Security-Policy"]
        self.assertIn("manifest-src 'self'", csp)

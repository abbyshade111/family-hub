"""Signing in through Google, Apple, or another OpenID Connect provider.

A made-up provider stands in for the real ones: discovery and the token endpoint are
replaced, so nothing here reaches the network. All identities are made up.
"""

import base64
import hashlib
import json
import sqlite3
import time
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from familyhub import oidc
from tests.helpers import AppTestCase

ISSUER = "https://id.example.test"
OTHER_ISSUER = "https://accounts.google.com"
CLIENT_ID = "family-hub-test"
PASSWORD = "a long test passphrase"

ENV = {
    "OIDC_ISSUER": ISSUER, "OIDC_CLIENT_ID": CLIENT_ID, "OIDC_CLIENT_SECRET": "made-up-test-value",
    "OIDC_NAME": "Example ID",
}


def metadata(issuer):
    return {
        "issuer": issuer,
        "authorization_endpoint": issuer + "/authorize",
        "token_endpoint": issuer + "/token",
    }


def b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def id_token(**claims):
    return f"{b64({'alg': 'RS256'})}.{b64(claims)}.c2lnbmF0dXJl"


class ProviderTestCase(AppTestCase):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict("os.environ", ENV)
        env.start()
        self.addCleanup(env.stop)
        oidc._discovery_cache.clear()
        self.addCleanup(oidc._discovery_cache.clear)
        self.discovery = {ISSUER: metadata(ISSUER), OTHER_ISSUER: metadata(OTHER_ISSUER)}
        get = mock.patch("familyhub.oidc._get_json", side_effect=self._fake_get)
        get.start()
        self.addCleanup(get.stop)
        post = mock.patch("familyhub.oidc._post_form", side_effect=self._fake_token)
        self.token_endpoint = post.start()
        self.addCleanup(post.stop)
        self.claims = {}

    def _fake_get(self, url):
        issuer = url.removesuffix("/.well-known/openid-configuration")
        return self.discovery[issuer]

    def _fake_token(self, url, fields):
        return {"id_token": id_token(**self.claims)}

    def start(self, browser, path="/login/oidc", data=None):
        """Begin a sign-in; returns the parameters the provider would receive."""
        r = browser.post(path, data or {}, page="/account") if data is not None else browser.get(path)
        self.assertEqual(r.status_code, 302, r.get_data(as_text=True)[:300])
        query = parse_qs(urlsplit(r.headers["Location"]).query)
        return {k: v[0] for k, v in query.items()}

    def answer(self, browser, sent, subject="user-1", email="pat@example.com", provider="oidc", **overrides):
        """The provider sends the browser back, having signed in `subject`."""
        now = int(time.time())
        self.claims = {
            "iss": ISSUER, "aud": CLIENT_ID, "sub": subject, "email": email, "email_verified": True,
            "iat": now, "exp": now + 600, "nonce": sent["nonce"],
        }
        self.claims.update(overrides)
        return browser.get(f"/auth/{provider}/callback?state={sent['state']}&code=made-up-code")

    def sign_up_with_provider(self, subject="user-1", email="pat@example.com", family="Pat's family", invite=None):
        b = self.browser()
        r = self.answer(b, self.start(b), subject=subject, email=email)
        self.assertTrue(r.headers["Location"].endswith("/signup/finish"))
        data = {"display_name": "Pat"}
        data.update({"invite_code": invite} if invite else {"family_name": family})
        r = b.post("/signup/finish", data, page="/signup/finish")
        self.assertEqual(r.status_code, 302, r.get_data(as_text=True)[:500])
        return b


class SigningIn(ProviderTestCase):
    def test_buttons_show_only_for_configured_providers(self):
        page = self.browser().get("/login").get_data(as_text=True)
        self.assertIn("Sign in with Example ID", page)
        self.assertNotIn("Google", page)
        self.assertEqual(self.browser().get("/login/google").status_code, 404)

    # covers V3.3.1
    def test_V3_3_1_provider_sign_in_cookie_is_secure_with_the_host_prefix(self):
        r = self.browser().get("/login/oidc")
        (header,) = [h for h in r.headers.getlist("Set-Cookie") if h.startswith("__Host-fh_oauth=")]
        for part in ("Secure", "HttpOnly", "Path=/", "SameSite=None"):
            self.assertIn(part, header)
        self.assertNotIn("Domain=", header)

    # covers V10.5.2
    def test_V10_5_2_people_are_known_by_subject_not_email(self):
        self.sign_up_with_provider(subject="user-1", email="pat@example.com")
        b = self.browser()
        r = self.answer(b, self.start(b), subject="user-1", email="changed@example.com")
        self.assertTrue(r.headers["Location"].endswith("/"))
        self.assertIn("Pat&#39;s family", b.get("/").get_data(as_text=True))
        # a different person who claims the same email is not let into Pat's account
        other = self.browser()
        r = self.answer(other, self.start(other), subject="someone-else", email="pat@example.com")
        self.assertTrue(r.headers["Location"].endswith("/signup/finish"))
        r = other.post("/signup/finish", {"display_name": "Imposter", "family_name": "x"}, page="/signup/finish")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(other.get("/").status_code, 302)

    def test_new_person_can_join_with_an_invite(self):
        admin = self.signed_up("admin@example.com", family="Pat's family")
        self.sign_up_with_provider(subject="kid-1", email="kid@example.com", invite=self.invite_code(admin))
        db = sqlite3.connect(self.app.config["DATABASE"])
        role, password = db.execute("SELECT role, password_hash FROM users WHERE email = 'kid@example.com'").fetchone()
        db.close()
        self.assertEqual((role, password), ("member", ""))

    def test_unverified_email_cannot_make_an_account(self):
        b = self.browser()
        self.answer(b, self.start(b), email_verified=False)
        r = b.post("/signup/finish", {"display_name": "Pat", "family_name": "x"}, page="/signup/finish")
        self.assertEqual(r.status_code, 400)
        self.assertIn("verified email", r.get_data(as_text=True))

    def test_passwordless_account_cannot_sign_in_with_a_password(self):
        self.sign_up_with_provider()
        self.assertEqual(self.browser().login("pat@example.com", "").status_code, 401)
        self.assertEqual(self.browser().login("pat@example.com", "anything at all here").status_code, 401)

    # covers V10.2.1
    def test_V10_2_1_pkce_verifier_matches_the_challenge(self):
        b = self.browser()
        sent = self.start(b)
        self.assertEqual(sent["code_challenge_method"], "S256")
        self.answer(b, sent)
        (_, fields), _ = self.token_endpoint.call_args
        expected = base64.urlsafe_b64encode(hashlib.sha256(fields["code_verifier"].encode()).digest()).rstrip(b"=")
        self.assertEqual(expected.decode(), sent["code_challenge"])

    def test_cancelled_sign_in(self):
        b = self.browser()
        sent = self.start(b)
        r = b.get(f"/auth/oidc/callback?state={sent['state']}&error=access_denied")
        self.assertIn("cancelled", r.get_data(as_text=True))
        self.assertEqual(b.get("/").status_code, 302)


class TiedToTheBrowserAndTheSignIn(ProviderTestCase):
    def setUp(self):
        super().setUp()
        self.sign_up_with_provider()

    # covers V10.1.2
    def test_V10_1_2_answer_is_refused_in_another_browser(self):
        mine = self.browser()
        sent = self.start(mine)
        thief = self.browser()
        self.start(thief)                      # has a browser cookie of its own, just not this flow's
        self.assertEqual(self.answer(thief, sent).status_code, 400)
        self.assertEqual(thief.get("/").status_code, 302)
        self.assertEqual(self.answer(self.browser(), sent).status_code, 400)

    # covers V10.1.2
    def test_V10_1_2_state_works_once(self):
        b = self.browser()
        sent = self.start(b)
        self.assertEqual(self.answer(b, sent).status_code, 302)
        self.assertEqual(self.answer(b, sent).status_code, 400)

    # covers V10.1.2
    def test_V10_1_2_old_state_expires(self):
        b = self.browser()
        sent = self.start(b)
        with mock.patch("familyhub.security.now", return_value=time.time() + 11 * 60):
            self.assertEqual(self.answer(b, sent).status_code, 400)

    def test_made_up_states_are_refused(self):
        b = self.browser()
        sent = self.start(b)
        for state in ("", "x", "a" * 43, "a" * 5000, "' OR 1=1 --"):
            with self.subTest(state=state[:10]):
                self.assertEqual(self.answer(b, dict(sent, state=state)).status_code, 400)

    # covers V10.5.1
    def test_V10_5_1_token_from_another_sign_in_is_refused(self):
        b = self.browser()
        sent = self.start(b)
        self.assertEqual(self.answer(b, sent, nonce="nonce-from-elsewhere").status_code, 400)
        self.assertEqual(b.get("/").status_code, 302)

    def test_bad_tokens_are_refused(self):
        now = int(time.time())
        cases = {
            "other issuer": {"iss": "https://evil.example"},
            "other app": {"aud": "someone-else"},
            "other app in a list": {"aud": ["someone-else", CLIENT_ID], "azp": "someone-else"},
            "expired": {"exp": now - 3600},
            "from the future": {"iat": now + 3600},
            "no subject": {"sub": ""},
            "huge subject": {"sub": "x" * 300},
            "no nonce": {"nonce": None},
        }
        for name, change in cases.items():
            with self.subTest(name):
                b = self.browser()
                self.assertEqual(self.answer(b, self.start(b), **change).status_code, 400)
                self.assertEqual(b.get("/").status_code, 302)

    def test_malformed_tokens_are_refused(self):
        for token in ("", "a.b", "a.!!!.c", "a." + b64([1, 2]) + ".c", "a." + "x" * 30000 + ".c"):
            with self.subTest(token=token[:10]):
                self.token_endpoint.side_effect = lambda url, fields, token=token: {"id_token": token}
                b = self.browser()
                self.assertEqual(self.answer(b, self.start(b)).status_code, 400)


class MixUps(ProviderTestCase):
    # covers V10.5.3
    def test_V10_5_3_metadata_naming_another_issuer_is_refused(self):
        self.discovery[ISSUER] = dict(metadata(ISSUER), issuer="https://evil.example")
        r = self.browser().get("/login/oidc")
        self.assertEqual(r.status_code, 502)

    def test_endpoints_must_use_the_issuers_scheme(self):
        self.discovery[ISSUER] = dict(metadata(ISSUER), token_endpoint="http://id.example.test/token")
        self.assertEqual(self.browser().get("/login/oidc").status_code, 502)

    # covers V10.2.2
    def test_V10_2_2_answer_naming_another_issuer_is_refused(self):
        self.sign_up_with_provider()
        b = self.browser()
        sent = self.start(b)
        r = b.get(f"/auth/oidc/callback?state={sent['state']}&code=c&iss=https://evil.example")
        self.assertEqual(r.status_code, 400)

    # covers V10.2.2
    def test_V10_2_2_answer_at_another_providers_address_is_refused(self):
        with mock.patch.dict("os.environ", {"GOOGLE_CLIENT_ID": "g", "GOOGLE_CLIENT_SECRET": "made-up"}):
            self.sign_up_with_provider()
            b = self.browser()
            sent = self.start(b, "/login/oidc")
            self.assertEqual(self.answer(b, sent, provider="google").status_code, 400)


class ApplesFormPost(ProviderTestCase):
    def test_form_post_answer_is_bounced_to_get(self):
        b = self.browser()
        sent = self.start(b)
        r = b.client.post(
            "/auth/oidc/callback", base_url="https://localhost",
            data={"state": sent["state"], "code": "c", "user": '{"name": "x"}'},
            headers={"Origin": "https://appleid.apple.com", "Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(r.status_code, 303)
        location = urlsplit(r.headers["Location"])
        self.assertEqual(location.path, "/auth/oidc/callback")
        self.assertEqual(set(parse_qs(location.query)), {"state", "code"})

    def test_only_that_endpoint_skips_the_csrf_check(self):
        b = self.signed_up("pat@example.com")
        r = b.client.post("/todos", base_url="https://localhost", data={"title": "x"},
                          headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(r.status_code, 403)


class ConnectingAndConfirming(ProviderTestCase):
    def test_connecting_needs_the_password(self):
        b = self.signed_up("pat@example.com")
        r = b.post("/account/connect/oidc", {"password": "not my password at all"})
        self.assertEqual(r.status_code, 400)
        sent = self.start(b, "/account/connect/oidc", {"password": PASSWORD})
        self.assertEqual(self.answer(b, sent, subject="pat-sub").headers["Location"], "/account?done=connected")
        # now Pat can sign in either way
        other = self.browser()
        self.answer(other, self.start(other), subject="pat-sub")
        self.assertEqual(other.get("/").status_code, 200)

    def test_an_identity_belongs_to_one_account(self):
        self.sign_up_with_provider(subject="taken")
        b = self.signed_up("sam@example.com")
        sent = self.start(b, "/account/connect/oidc", {"password": PASSWORD})
        r = self.answer(b, sent, subject="taken")
        self.assertEqual(r.status_code, 400)
        self.assertIn("already connected to another", r.get_data(as_text=True))

    def test_link_answer_only_counts_for_the_person_who_started_it(self):
        pat = self.signed_up("pat@example.com")
        sent = self.start(pat, "/account/connect/oidc", {"password": PASSWORD})
        pat.post("/logout", page="/account")
        pat.login("pat@example.com")   # same browser, new session: fine, still Pat
        self.assertEqual(self.answer(pat, sent, subject="pat-sub").status_code, 302)

    def test_last_way_in_cannot_be_disconnected(self):
        b = self.sign_up_with_provider()
        r = b.post("/account/disconnect/oidc", {})
        self.assertEqual(r.status_code, 400)
        self.assertIn("only way to sign in", r.get_data(as_text=True))
        # after setting a password, it can
        self.assertEqual(b.post("/account/password", {"new": "another long passphrase"}).status_code, 302)
        # a password now exists, so the password is what's asked for
        self.assertEqual(b.post("/account/disconnect/oidc", {}).status_code, 400)
        self.assertEqual(b.post("/account/disconnect/oidc", {"password": "another long passphrase"}).status_code, 302)

    def test_passwordless_changes_need_a_recent_sign_in(self):
        b = self.sign_up_with_provider()
        later = time.time() + 11 * 60
        with mock.patch("familyhub.security.now", return_value=later):
            b.get("/")   # keep the session from going idle in the test's eyes
            self.assertEqual(b.post("/account/delete", {}).status_code, 403)
            self.assertEqual(b.post("/account/password", {"new": "another long passphrase"}).status_code, 403)
            sent = self.start(b, "/account/confirm/oidc", {})
            self.assertEqual(self.answer(b, sent).headers["Location"], "/account?done=confirmed")
            self.assertEqual(b.post("/account/delete", {}).status_code, 302)
        self.assertEqual(self.browser().get("/").status_code, 302)

    def test_confirming_with_someone_elses_identity_is_refused(self):
        b = self.sign_up_with_provider(subject="pat-sub")
        sent = self.start(b, "/account/confirm/oidc", {})
        r = self.answer(b, sent, subject="someone-else")
        self.assertEqual(r.status_code, 400)

    def test_form_action_allows_the_provider(self):
        csp = self.browser().get("/login").headers["Content-Security-Policy"]
        self.assertIn(f"form-action 'self' {ISSUER}", csp)

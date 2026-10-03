"""Signing in through Google, Apple, or another OpenID Connect provider.

Uses the authorization code flow. The ID token is fetched straight from the
provider's token endpoint over a verified HTTPS connection, which OpenID Connect
Core 1.0 section 3.1.3.7 allows in place of checking its signature; its issuer,
audience, expiry and nonce are still checked here.

Configured from the environment (secrets are only ever read by name):
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
  APPLE_CLIENT_ID (the Services ID), APPLE_CLIENT_SECRET (made by tools/apple_client_secret.py)
  OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_NAME (any other provider; `sv run` uses this)
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 1_000_000
DISCOVERY_CACHE_SECONDS = 3600
CLOCK_SKEW_SECONDS = 120


class OIDCError(Exception):
    """Sign-in through a provider failed. The message is safe to log; it never holds tokens."""


@dataclass(frozen=True)
class Provider:
    key: str
    label: str
    issuer: str
    client_id: str
    client_secret: str
    token_issuers: tuple            # values accepted in the ID token's `iss`
    scope: str = "openid email"
    pkce: bool = True
    https_only: bool = True
    extra_params: dict = field(default_factory=dict)


def configured_providers():
    """The providers whose settings are present, keyed by the name used in URLs."""
    env = os.environ
    providers = {}
    if env.get("GOOGLE_CLIENT_ID") and env.get("GOOGLE_CLIENT_SECRET"):
        providers["google"] = Provider(
            key="google", label="Google", issuer="https://accounts.google.com",
            client_id=env["GOOGLE_CLIENT_ID"], client_secret=env["GOOGLE_CLIENT_SECRET"],
            # Google's ID tokens use either form
            token_issuers=("https://accounts.google.com", "accounts.google.com"),
        )
    if env.get("APPLE_CLIENT_ID") and env.get("APPLE_CLIENT_SECRET"):
        providers["apple"] = Provider(
            key="apple", label="Apple", issuer="https://appleid.apple.com",
            client_id=env["APPLE_CLIENT_ID"], client_secret=env["APPLE_CLIENT_SECRET"],
            token_issuers=("https://appleid.apple.com",),
            # Apple sends the answer back as a form POST when an email is asked for
            pkce=False, extra_params={"response_mode": "form_post"},
        )
    if env.get("OIDC_ISSUER") and env.get("OIDC_CLIENT_ID") and urlsplit(env["OIDC_ISSUER"]).scheme in WEB_SCHEMES:
        issuer = env["OIDC_ISSUER"]
        providers["oidc"] = Provider(
            key="oidc", label=env.get("OIDC_NAME", "single sign-on")[:40], issuer=issuer,
            client_id=env["OIDC_CLIENT_ID"], client_secret=env.get("OIDC_CLIENT_SECRET", ""),
            token_issuers=(issuer,),
            # whoever sets OIDC_ISSUER chooses its scheme; endpoints must then use the same one
            https_only=False,
        )
    return providers


def provider_origins():
    """Origins the browser is sent to for signing in, for the Content-Security-Policy's form-action."""
    origins = set()
    for provider in configured_providers().values():
        parts = urlsplit(provider.issuer)
        origins.add(f"{parts.scheme}://{parts.netloc}")
        cached = _discovery_cache.get(provider.issuer)
        if cached:
            parts = urlsplit(cached[1]["authorization_endpoint"])
            origins.add(f"{parts.scheme}://{parts.netloc}")
    return sorted(origins)


# --- talking to the provider --------------------------------------------------

WEB_SCHEMES = ("https", "http")


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Sign-in calls go to exactly the address the provider published; a redirect elsewhere is refused."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


_opener = urllib.request.build_opener(_NoRedirects)


def _read_json(request):
    # Only web addresses: urllib would also open file:// and ftp:// ones.
    if urlsplit(request.full_url).scheme not in WEB_SCHEMES:
        raise OIDCError("provider address isn't a web address")
    try:
        with _opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise OIDCError(f"provider answered HTTP {error.code}") from None
    except (OSError, ValueError) as error:
        raise OIDCError(f"provider unreachable ({type(error).__name__})") from None
    if len(body) > MAX_RESPONSE_BYTES:
        raise OIDCError("provider's answer was too large")
    try:
        data = json.loads(body)
    except ValueError:
        raise OIDCError("provider's answer wasn't JSON") from None
    if not isinstance(data, dict):
        raise OIDCError("provider's answer wasn't a JSON object")
    return data


def _get_json(url):
    return _read_json(urllib.request.Request(url, headers={"Accept": "application/json"}))


def _post_form(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    return _read_json(urllib.request.Request(
        url, data=data, method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
    ))


_discovery_cache = {}


def _allowed_url(provider, url):
    if not isinstance(url, str):
        return False
    parts = urlsplit(url)
    if provider.https_only:
        return parts.scheme == "https" and bool(parts.netloc)
    return parts.scheme == urlsplit(provider.issuer).scheme and bool(parts.netloc)


def discover(provider):
    """The provider's published endpoints, checked to come from exactly the configured issuer."""
    cached = _discovery_cache.get(provider.issuer)
    if cached and time.time() - cached[0] < DISCOVERY_CACHE_SECONDS:
        return cached[1]
    meta = _get_json(provider.issuer.rstrip("/") + "/.well-known/openid-configuration")
    if meta.get("issuer") != provider.issuer:
        raise OIDCError("provider metadata names a different issuer")
    for key in ("authorization_endpoint", "token_endpoint"):
        if not _allowed_url(provider, meta.get(key)):
            raise OIDCError(f"provider metadata has an unusable {key}")
    _discovery_cache[provider.issuer] = (time.time(), meta)
    return meta


def pkce_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def authorization_url(provider, meta, redirect_uri, state, nonce, code_verifier):
    params = {
        "response_type": "code",
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri,
        "scope": provider.scope,
        "state": state,
        "nonce": nonce,
        **provider.extra_params,
    }
    if provider.pkce:
        params["code_challenge"] = pkce_challenge(code_verifier)
        params["code_challenge_method"] = "S256"
    endpoint = meta["authorization_endpoint"]
    separator = "&" if "?" in endpoint else "?"
    return endpoint + separator + urllib.parse.urlencode(params)


def exchange_code(provider, meta, code, redirect_uri, code_verifier):
    """Swap the authorization code for an ID token at the token endpoint. Returns the token's claims, unchecked."""
    fields = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": provider.client_id,
    }
    if provider.client_secret:
        fields["client_secret"] = provider.client_secret
    if provider.pkce:
        fields["code_verifier"] = code_verifier
    answer = _post_form(meta["token_endpoint"], fields)
    id_token = answer.get("id_token")
    if not isinstance(id_token, str):
        raise OIDCError("token endpoint returned no ID token")
    return decode_id_token(id_token)


def decode_id_token(id_token):
    """The claims in an ID token. The signature is not checked: see the module docstring for why that is safe here."""
    parts = id_token.split(".")
    if len(parts) != 3 or len(id_token) > 20_000:
        raise OIDCError("ID token is malformed")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (ValueError, binascii.Error, UnicodeError):
        raise OIDCError("ID token is malformed") from None
    if not isinstance(claims, dict):
        raise OIDCError("ID token is malformed")
    return claims


def check_claims(provider, claims, expected_nonce, now=None):
    """Check the ID token is for this app, from this provider, current, and from this sign-in. Returns the subject."""
    now = time.time() if now is None else now
    if claims.get("iss") not in provider.token_issuers:
        raise OIDCError("ID token is from a different issuer")
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if provider.client_id not in audiences:
        raise OIDCError("ID token is for a different app")
    if len(audiences) > 1 and claims.get("azp") != provider.client_id:
        raise OIDCError("ID token was issued to a different app")
    exp, iat = claims.get("exp"), claims.get("iat")
    if not isinstance(exp, (int, float)) or exp < now - CLOCK_SKEW_SECONDS:
        raise OIDCError("ID token has expired")
    if not isinstance(iat, (int, float)) or iat > now + CLOCK_SKEW_SECONDS:
        raise OIDCError("ID token was issued in the future")
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not hmac.compare_digest(nonce.encode(), expected_nonce.encode()):
        raise OIDCError("ID token is from a different sign-in")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject or len(subject) > 255:
        raise OIDCError("ID token has no usable subject")
    return subject


def verified_email(claims):
    """The email the provider vouches for, lower-cased, or None."""
    email = claims.get("email")
    verified = claims.get("email_verified")
    # Apple sends "true" as a string
    if isinstance(email, str) and verified in (True, "true") and 3 <= len(email) <= 254:
        return email.strip().lower()
    return None

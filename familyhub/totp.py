"""Authenticator app codes (TOTP, RFC 6238): 6 digits, a new one every 30 seconds.

HMAC-SHA1 is what RFC 6238 and every authenticator app use; it is not chosen here, and HMAC-SHA1
remains sound for this purpose. Only the current 30-second code is accepted (ASVS V6.5.5: a TOTP
lives at most 30 seconds), and each one can be used only once (V6.5.1).
"""

import base64
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

DIGITS = 6
STEP_SECONDS = 30
DRIFT_STEPS = 0   # codes from neighbouring steps would outlive 30 seconds
ISSUER = "Family Hub"


def new_secret():
    """A random 160-bit secret, in the base32 form authenticator apps take."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret):
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def code_at(secret, step):
    digest = hmac.new(_key(secret), struct.pack(">Q", step), "sha1").digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**DIGITS).zfill(DIGITS)


def current_step(now=None):
    return int((time.time() if now is None else now) // STEP_SECONDS)


def matching_step(secret, code, last_used_step=None, now=None):
    """The time step `code` belongs to, or None. Steps at or before `last_used_step` are refused."""
    code = code.strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    step = current_step(now)
    for candidate in range(step - DRIFT_STEPS, step + DRIFT_STEPS + 1):
        if last_used_step is not None and candidate <= last_used_step:
            continue
        if hmac.compare_digest(code_at(secret, candidate), code):
            return candidate
    return None


def provisioning_uri(secret, account_name):
    """The otpauth:// link an authenticator app understands (it opens the app on a phone)."""
    label = quote(f"{ISSUER}:{account_name}")
    query = urlencode({"secret": secret, "issuer": ISSUER, "digits": DIGITS, "period": STEP_SECONDS})
    return f"otpauth://totp/{label}?{query}"


RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # 31 symbols, none easily confused
RECOVERY_GROUPS, RECOVERY_GROUP_LENGTH = 5, 5


def new_recovery_codes(count=10):
    """Single-use codes for when the phone is lost, like 'abcde-fghjk-mnpqr-stuvw-xyz23'.

    25 symbols from 31 is about 123 bits, over the 112 that ASVS V6.5.2 asks for before a lookup
    secret may be stored with a plain hash (security.lookup_hash) instead of a password hash.
    """
    return [
        "-".join(
            "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(RECOVERY_GROUP_LENGTH))
            for _ in range(RECOVERY_GROUPS)
        )
        for _ in range(count)
    ]


def normalize_recovery_code(code):
    return code.strip().lower().replace(" ", "")

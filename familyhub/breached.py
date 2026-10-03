"""Refuse new passwords that are known to have leaked.

Two checks, both used for every new password (sign-up and password change):

1. A list kept in the app (data/common-passwords.txt): the NCSC's 100,000 most
   used passwords from Have I Been Pwned. Always available, works offline.
2. Have I Been Pwned's Pwned Passwords range API, when it can be reached. Only the
   first 5 characters of the password's SHA-1 hash are sent; the rest of the
   comparison happens here. If the service can't be reached, the check is
   skipped and only the local list applies. Set FAMILY_HUB_BREACH_CHECK=0 to
   turn the online check off.
"""

import hashlib
import logging
import os
import urllib.request
from functools import lru_cache

log = logging.getLogger(__name__)

LIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "common-passwords.txt")
PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/"
TIMEOUT_SECONDS = 3
MAX_RESPONSE_BYTES = 2_000_000


@lru_cache(maxsize=1)
def _common_passwords():
    with open(LIST_PATH, encoding="utf-8", errors="replace") as f:
        return frozenset(line.strip().lower() for line in f if line.strip())


def in_common_list(password):
    return password.lower() in _common_passwords()


def _fetch_range(prefix):
    request = urllib.request.Request(
        PWNED_RANGE_URL + prefix,
        headers={"Add-Padding": "true", "User-Agent": "FamilyHub-password-check"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return response.read(MAX_RESPONSE_BYTES).decode("ascii", "replace")


def in_breach_corpus(password):
    """True if Have I Been Pwned has seen this password, False if not, None if it couldn't be asked."""
    if os.environ.get("FAMILY_HUB_BREACH_CHECK", "1") == "0":
        return None
    # The range API is keyed by SHA-1. This is a lookup key, not how passwords are stored.
    digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    try:
        body = _fetch_range(prefix)
    except (OSError, ValueError) as error:
        log.warning("Breached-password service unreachable (%s); only the local list was checked",
                    type(error).__name__)
        return None
    for line in body.splitlines():
        hash_suffix, _, count = line.partition(":")
        count = count.strip()
        if hash_suffix.strip() == suffix and count.isdigit() and int(count) > 0:
            return True
    return False


def is_breached(password):
    return in_common_list(password) or bool(in_breach_corpus(password))

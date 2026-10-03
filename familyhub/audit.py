"""The security event log: one JSON line per event, on the console (standard error).

What goes in is the owner's decision (security-notes.md, V16.1.1): UTC time, the event, the
outcome, the user and family ids, the visitor's IP, and a few named details. Never passwords,
codes, tokens or email addresses; a user id is enough to look someone up.
"""

import json
import logging
import sys
from datetime import datetime, timezone

from flask import g, has_request_context, request

log = logging.getLogger("familyhub.audit")

# The only extra details an event may carry. Anything else passed in is refused, so a careless
# call can't put an email address or a token in the log.
ALLOWED_DETAILS = {"method", "reason", "target_user_id", "path", "status", "count", "blocked"}


def utc_timestamp():
    """The one timestamp format for every log line the app writes: UTC, saying so."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def setup():
    if not log.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False


def event(name, outcome="ok", user_id=None, family_id=None, **details):
    unknown = set(details) - ALLOWED_DETAILS
    if unknown:
        raise ValueError(f"not allowed in the security log: {sorted(unknown)}")
    record = {
        "time": utc_timestamp(),
        "event": name,
        "outcome": outcome,
        "user_id": user_id,
        "family_id": family_id,
        "ip": None,
    }
    if has_request_context():
        record["ip"] = request.remote_addr
        user = g.get("user")
        if user is not None:
            record["user_id"] = record["user_id"] if user_id is not None else user["id"]
            record["family_id"] = record["family_id"] if family_id is not None else user["family_id"]
    record.update({k: v for k, v in details.items() if v is not None})
    log.info(json.dumps(record, separators=(",", ":"), sort_keys=True))

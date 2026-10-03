"""Where browsers report what the Content-Security-Policy blocked (ASVS V3.4.7).

Each report becomes one security log line: which rule was broken, on which page (its path only),
and where the blocked content came from (its scheme and host only, never a full address, which
could carry personal data). At most a few reports a minute are taken from any one address, so the
log can't be flooded through this.
"""

import json
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlsplit

from flask import Blueprint, request

from .. import audit

bp = Blueprint("reports", __name__)

MAX_REPORTS_PER_MINUTE = 10
_recent = defaultdict(deque)
_lock = threading.Lock()


def _allowed(ip):
    now = time.monotonic()
    with _lock:
        stamps = _recent[ip]
        while stamps and now - stamps[0] > 60:
            stamps.popleft()
        if len(stamps) >= MAX_REPORTS_PER_MINUTE:
            return False
        stamps.append(now)
        if len(_recent) > 10_000:   # don't let the table itself grow without end
            _recent.clear()
        return True


def _origin(value):
    """Only the scheme and host of an address, or a keyword like 'inline'."""
    if not isinstance(value, str):
        return None
    parts = urlsplit(value)
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"[:100]
    return value[:30] if value.isalpha() else None


def _short(value, limit=60):
    return value[:limit] if isinstance(value, str) else None


@bp.post("/csp-report")
def csp_report():
    # Browsers send these without the form token; this endpoint only writes a log line.
    if not _allowed(request.remote_addr or "unknown"):
        return "", 204
    try:
        body = json.loads(request.get_data(cache=False, as_text=True) or "null")
    except ValueError:
        return "", 204
    reports = []
    if isinstance(body, dict) and isinstance(body.get("csp-report"), dict):    # report-uri format
        r = body["csp-report"]
        reports.append((r.get("violated-directive") or r.get("effective-directive"), r.get("document-uri"),
                        r.get("blocked-uri")))
    elif isinstance(body, list):                                                # Reporting API format
        for item in body[:5]:
            r = item.get("body") if isinstance(item, dict) else None
            if isinstance(r, dict):
                reports.append((r.get("effectiveDirective"), r.get("documentURL"), r.get("blockedURL")))
    for directive, document, blocked in reports:
        page = urlsplit(document).path[:200] if isinstance(document, str) else None
        audit.event("csp_violation", "blocked", reason=_short(directive), path=page, blocked=_origin(blocked))
    return "", 204

"""One log line per web request, the same under any server: the owner's rule (security-notes.md,
V14.1.2) keeps the visitor's IP, the method, the path and the status, never the query string.

    127.0.0.1 - - [2026-10-03T18:42:16.657481Z] "GET /todos" 200

The development server (run.py) writes this line itself; serve.py turns this on for waitress.
"""

import sys
from urllib.parse import quote

from .audit import utc_timestamp


class RequestLog:
    def __init__(self, app, stream=None):
        self.app = app
        self.stream = stream

    def __call__(self, environ, start_response):
        seen = {}

        def recording_start_response(status, headers, exc_info=None):
            seen["status"] = status.split(" ", 1)[0]
            return start_response(status, headers, exc_info)

        try:
            return self.app(environ, recording_start_response)
        finally:
            # PATH_INFO never holds the query string; SCRIPT_NAME is empty unless mounted below a prefix.
            path = quote(environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", ""), safe="/-._~")[:300]
            line = '{ip} - - [{time}] "{method} {path}" {status}\n'.format(
                ip=environ.get("REMOTE_ADDR", "-"), time=utc_timestamp(),
                method=environ.get("REQUEST_METHOD", "-")[:10], path=path, status=seen.get("status", "500"),
            )
            stream = self.stream or sys.stderr
            stream.write(line)
            stream.flush()

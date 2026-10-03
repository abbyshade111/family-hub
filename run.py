"""Start Family Hub: python run.py --host 127.0.0.1 --port 8000

Uses only the packages in ./vendor; nothing is downloaded. Data is kept in
FAMILY_HUB_DATA (default /tmp/family-hub).
"""

import argparse
import os
import sys

sys.dont_write_bytecode = True  # the app's folder may be read-only
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))

from urllib.parse import urlsplit  # noqa: E402

from werkzeug.serving import WSGIRequestHandler, run_simple  # noqa: E402

from familyhub import create_app  # noqa: E402
from familyhub.audit import utc_timestamp  # noqa: E402


def loggable_path(raw_path):
    """The request's path without its query string, which can hold sign-in codes and state."""
    return urlsplit(raw_path).path[:300]


class QuietHandler(WSGIRequestHandler):
    # Don't announce the server and Python versions in every response.
    server_version = "FamilyHub"
    sys_version = ""

    def log_request(self, code="-", size="-"):
        # The owner's choice (security-notes.md, V14.1.2): keep the visitor's IP, method, path and status;
        # never the query string.
        self.log("info", '"%s %s" %s', self.command, loggable_path(self.path), code)

    def log_date_time_string(self):
        # UTC and labelled as such, the same format as the security log (V16.2.2)
        return utc_timestamp()


def main():
    parser = argparse.ArgumentParser(description="Run Family Hub")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    args = parser.parse_args()
    run_simple(args.host, args.port, create_app(), threaded=True, request_handler=QuietHandler)


if __name__ == "__main__":
    main()

"""Run Family Hub in production with waitress: python serve.py [--host 127.0.0.1] [--port 8000]

Behind `tailscale serve` (see docs/DEPLOY-TAILSCALE.md) keep the default host, 127.0.0.1, so
only Tailscale can reach the app, and set FAMILY_HUB_TRUSTED_PROXIES=1.

Uses only the packages in ./vendor; nothing is downloaded. run.py is the development server.
"""

import argparse
import logging
import os
import sys

sys.dont_write_bytecode = True  # the app's folder may be read-only
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))

from waitress import serve  # noqa: E402

from familyhub import create_app  # noqa: E402

# A fixed number of worker threads also caps how many requests (and so password hashes, about
# 32 MB each) run at once.
DEFAULT_THREADS = 4
# Refuse oversized requests before reading them; the app itself allows 64 KB of form data.
MAX_REQUEST_BODY_BYTES = 128 * 1024


def main():
    parser = argparse.ArgumentParser(description="Run Family Hub with waitress")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stderr, level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    serve(
        create_app({"REQUEST_LOG": True}),
        host=args.host,
        port=args.port,
        threads=args.threads,
        ident="FamilyHub",                     # the Server header: no product name or version
        max_request_body_size=MAX_REQUEST_BODY_BYTES,
        # Proxy headers are handled by the app (FAMILY_HUB_TRUSTED_PROXIES), not by waitress.
        trusted_proxy=None,
        clear_untrusted_proxy_headers=False,
    )


if __name__ == "__main__":
    main()

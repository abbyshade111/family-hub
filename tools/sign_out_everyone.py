"""Sign everyone out of Family Hub: the step to take after a key or password may have leaked.

    python tools/sign_out_everyone.py          # asks before doing anything
    python tools/sign_out_everyone.py --yes    # for scripts

Ends every session, and any sign-in through Google, Apple or another provider that was
half-way through. Nobody's account, password or data is touched: everyone simply signs in
again. Run it where the app runs, with the same FAMILY_HUB_DATA (default /tmp/family-hub).
"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

DEFAULT_DATA_DIR = "/tmp/family-hub"


def sign_out_everyone(database):
    db = sqlite3.connect(database, timeout=10)
    try:
        with db:
            sessions = db.execute("DELETE FROM sessions").rowcount
            started = db.execute("DELETE FROM oauth_states").rowcount
            pending = db.execute("DELETE FROM oauth_pending").rowcount
    finally:
        db.close()
    return sessions, started + pending


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--yes", action="store_true", help="don't ask first")
    args = parser.parse_args()

    database = os.path.join(os.environ.get("FAMILY_HUB_DATA", DEFAULT_DATA_DIR), "family.db")
    if not os.path.exists(database):
        sys.exit(f"No Family Hub database at {database}. Set FAMILY_HUB_DATA to the app's data folder.")
    if not args.yes:
        answer = input(f"Sign everyone out of the Family Hub at {database}? Type yes to continue: ")
        if answer.strip().lower() != "yes":
            sys.exit("Nothing changed.")
    sessions, flows = sign_out_everyone(database)
    # the same kind of line the app writes to its security log (familyhub/audit.py)
    print(json.dumps({
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "event": "sign_out_everyone",
        "outcome": "ok", "user_id": None, "family_id": None, "ip": None, "count": sessions,
    }, separators=(",", ":"), sort_keys=True), file=sys.stderr)
    print(f"Ended {sessions} session(s) and {flows} unfinished provider sign-in(s). Everyone must sign in again.")


if __name__ == "__main__":
    main()

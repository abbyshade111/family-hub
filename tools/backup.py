"""Back up Family Hub's database to a local folder. Off unless FAMILY_HUB_BACKUP_DIR is set.

    FAMILY_HUB_BACKUP_DIR=/var/backups/family-hub python tools/backup.py

Run it from the host's scheduler, for example daily with cron:

    15 3 * * *  cd /path/to/app && FAMILY_HUB_DATA=... FAMILY_HUB_BACKUP_DIR=... python tools/backup.py

Each run makes a consistent copy (SQLite's backup API, safe while the app is running) named
family-YYYYMMDD-HHMMSS.db, readable only by the user running it, and keeps the newest
FAMILY_HUB_BACKUP_KEEP copies (default 7). Backups hold everything the app holds, including
password hashes: keep the folder on an encrypted disk, readable by nobody else.

To restore: stop the app, copy a backup over FAMILY_HUB_DATA/family.db, start the app.
"""

import os
import sqlite3
import sys
import time

DEFAULT_DATA_DIR = "/tmp/family-hub"
DEFAULT_KEEP = 7
PREFIX, SUFFIX = "family-", ".db"


def backup(database, backup_dir, keep):
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    name = f"{PREFIX}{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}{SUFFIX}"
    target = os.path.join(backup_dir, name)
    partial = target + ".partial"
    # create the file owner-only before anything is written to it
    os.close(os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    source = sqlite3.connect(database, timeout=30)
    copy = sqlite3.connect(partial)
    try:
        source.backup(copy)
    finally:
        copy.close()
        source.close()
    os.replace(partial, target)

    existing = sorted(
        f for f in os.listdir(backup_dir) if f.startswith(PREFIX) and f.endswith(SUFFIX)
    )
    removed = existing[:-keep] if keep < len(existing) else []
    for old in removed:
        os.remove(os.path.join(backup_dir, old))
    return target, removed


def main():
    backup_dir = os.environ.get("FAMILY_HUB_BACKUP_DIR")
    if not backup_dir:
        print("Backups are off: set FAMILY_HUB_BACKUP_DIR to a folder to turn them on.")
        return
    try:
        keep = int(os.environ.get("FAMILY_HUB_BACKUP_KEEP", DEFAULT_KEEP))
    except ValueError:
        sys.exit("FAMILY_HUB_BACKUP_KEEP must be a whole number.")
    if keep < 1:
        sys.exit("FAMILY_HUB_BACKUP_KEEP must be at least 1.")
    database = os.path.join(os.environ.get("FAMILY_HUB_DATA", DEFAULT_DATA_DIR), "family.db")
    if not os.path.exists(database):
        sys.exit(f"No Family Hub database at {database}. Set FAMILY_HUB_DATA to the app's data folder.")
    target, removed = backup(database, backup_dir, keep)
    print(f"Backed up to {target}" + (f"; removed {len(removed)} older backup(s)." if removed else "."))


if __name__ == "__main__":
    main()

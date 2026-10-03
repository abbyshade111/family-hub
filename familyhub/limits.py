"""Business limits: the owner's decision of 2026-10-03 (security-notes.md, V2.1.3).

Each check runs inside a write transaction taken before counting, so two
requests at once can't both squeeze past the limit.
"""

from . import security

OPEN_TODOS_PER_FAMILY = 1000
GROCERY_ITEMS_PER_FAMILY = 1000
UPCOMING_EVENTS_PER_FAMILY = 2000
REMINDERS_PER_PERSON = 500
INVITES_PER_ADMIN_PER_DAY = 20
SIGNUPS_PER_HOUR = 100

# Done to-dos aren't limited; the list shows the most recent ones.
DONE_TODOS_SHOWN = 200

DAY = 24 * 3600
HOUR = 3600


class LimitReached(Exception):
    pass


def lock(db):
    """Start a write transaction now, so the count and the insert that follows can't interleave with another request."""
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")


def _count(db, sql, args):
    return db.execute(sql, args).fetchone()[0]


def check_open_todos(db, family_id):
    n = _count(db, "SELECT COUNT(*) FROM todos WHERE family_id = ? AND done = 0", (family_id,))
    if n >= OPEN_TODOS_PER_FAMILY:
        raise LimitReached(
            f"Your family has {OPEN_TODOS_PER_FAMILY} open to-dos, the most allowed. "
            "Mark some done or delete some first."
        )


def check_grocery_items(db, family_id):
    n = _count(db, "SELECT COUNT(*) FROM grocery_items WHERE family_id = ?", (family_id,))
    if n >= GROCERY_ITEMS_PER_FAMILY:
        raise LimitReached(
            f"The grocery list has {GROCERY_ITEMS_PER_FAMILY} items, the most allowed. "
            "Clear or remove some first."
        )


def check_upcoming_events(db, family_id, now_local):
    n = _count(
        db,
        "SELECT COUNT(*) FROM events WHERE family_id = ? AND COALESCE(ends_at, starts_at) >= ?",
        (family_id, now_local),
    )
    if n >= UPCOMING_EVENTS_PER_FAMILY:
        raise LimitReached(
            f"Your family's calendar has {UPCOMING_EVENTS_PER_FAMILY} upcoming events, the most allowed. "
            "Delete some first."
        )


def check_reminders(db, user_id):
    n = _count(db, "SELECT COUNT(*) FROM reminders WHERE user_id = ?", (user_id,))
    if n >= REMINDERS_PER_PERSON:
        raise LimitReached(
            f"You have {REMINDERS_PER_PERSON} reminders, the most allowed. Delete some first."
        )


def check_and_record_invite(db, family_id, user_id):
    t = security.now()
    db.execute("DELETE FROM invites_made WHERE at <= ?", (t - DAY,))
    n = _count(db, "SELECT COUNT(*) FROM invites_made WHERE created_by = ? AND at > ?", (user_id, t - DAY))
    if n >= INVITES_PER_ADMIN_PER_DAY:
        raise LimitReached(
            f"You've made {INVITES_PER_ADMIN_PER_DAY} invite codes in the last day, the most allowed. "
            "Try again tomorrow."
        )
    db.execute("INSERT INTO invites_made (family_id, created_by, at) VALUES (?, ?, ?)", (family_id, user_id, t))


def check_and_record_signup(db):
    t = security.now()
    db.execute("DELETE FROM signups WHERE at <= ?", (t - HOUR,))
    n = _count(db, "SELECT COUNT(*) FROM signups WHERE at > ?", (t - HOUR,))
    if n >= SIGNUPS_PER_HOUR:
        raise LimitReached("Too many accounts are being made right now. Please try again in an hour.")
    db.execute("INSERT INTO signups (at) VALUES (?)", (t,))

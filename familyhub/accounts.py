"""Making accounts: shared by password sign-up and sign-up through Google, Apple or another provider."""

import sqlite3

from . import audit, limits, security

INVITE_INVALID = "That invite code isn't valid or has expired."
ACCOUNT_EXISTS = "An account can't be made with those details. If you already have one, sign in instead."

# Stored as the password hash of an account that signs in only through a provider.
NO_PASSWORD = ""


class SignupError(Exception):
    pass


def create_account(db, email, display_name, password_hash, family_name=None, invite_code=None, identity=None,
                   method="password"):
    """Make a user, and a family unless they join one with an invite code. Returns the new user's id.

    `identity` is an optional (provider, subject, email) to link in the same transaction.
    Raises SignupError or limits.LimitReached; nothing is saved when either is raised.
    """
    try:
        with db:
            limits.lock(db)
            limits.check_and_record_signup(db)
            if invite_code:
                code_hash = security.lookup_hash(invite_code)
                invite = db.execute(
                    "SELECT family_id FROM invites WHERE code_hash = ? AND expires_at > ?",
                    (code_hash, security.now()),
                ).fetchone()
                # single use: whoever deletes it first gets it
                if invite is None or db.execute(
                    "DELETE FROM invites WHERE code_hash = ?", (code_hash,)
                ).rowcount != 1:
                    raise SignupError(INVITE_INVALID)
                family_id, role = invite["family_id"], "member"
            else:
                family_id = db.execute("INSERT INTO families (name) VALUES (?)", (family_name,)).lastrowid
                role = "admin"
            user_id = db.execute(
                "INSERT INTO users (family_id, email, display_name, password_hash, role) VALUES (?, ?, ?, ?, ?)",
                (family_id, email, display_name, password_hash, role),
            ).lastrowid
            if identity:
                provider, subject, identity_email = identity
                db.execute(
                    "INSERT INTO oauth_identities (provider, subject, user_id, email) VALUES (?, ?, ?, ?)",
                    (provider, subject, user_id, identity_email),
                )
    except sqlite3.IntegrityError:
        raise SignupError(ACCOUNT_EXISTS) from None
    if invite_code:
        audit.event("invite_used", user_id=user_id, family_id=family_id)
    audit.event("account_created", user_id=user_id, family_id=family_id, method=method)
    return user_id

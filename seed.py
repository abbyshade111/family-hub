"""Make the test accounts `sv run` signs in with. Not for real use.

Reads SV_USER_A / SV_PASSWORD_A, SV_USER_B / SV_PASSWORD_B and, if set,
SV_ADMIN / SV_ADMIN_PASSWORD, and SV_USER_TOTP / SV_PASSWORD_TOTP / SV_TOTP_SECRET.
A and B are ordinary members of two different families, so neither should be
able to see the other's data. The admin runs A's family; the TOTP user is a
member of it who signs in with an authenticator app code too.

The admin has no authenticator app (`sv` signs it in with a password alone), so
the app's rule that admins need one keeps it out of family settings: `sv run`'s
admin checks will see the admin turned away too.
"""

import os
import secrets
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))

from familyhub import create_app, security  # noqa: E402
from familyhub.db import connect  # noqa: E402


def make_family(db, name):
    return db.execute("INSERT INTO families (name) VALUES (?)", (name,)).lastrowid


def put_user(db, family_id, email, password, name, role, totp_secret=None):
    email = email.strip().lower()
    db.execute("DELETE FROM users WHERE email = ?", (email,))
    db.execute(
        "INSERT INTO users (family_id, email, display_name, password_hash, role, totp_secret)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (family_id, email, name, security.hash_password(password), role, totp_secret),
    )


def main():
    env = os.environ
    app = create_app()
    db = connect(app.config["DATABASE"])
    with db:
        family_a = make_family(db, "Seed Family A")
        if env.get("SV_ADMIN"):
            put_user(db, family_a, env["SV_ADMIN"], env["SV_ADMIN_PASSWORD"], "Seed Admin", "admin")
        else:
            put_user(db, family_a, f"owner-a-{secrets.token_hex(4)}@example.invalid",
                     secrets.token_urlsafe(24), "Seed Owner A", "admin")
        put_user(db, family_a, env["SV_USER_A"], env["SV_PASSWORD_A"], "Seed Member A", "member")
        if env.get("SV_USER_TOTP"):
            # a member who signs in with an authenticator app code as well as a password
            put_user(db, family_a, env["SV_USER_TOTP"], env["SV_PASSWORD_TOTP"], "Seed Member TOTP", "member",
                     totp_secret=env["SV_TOTP_SECRET"].strip().upper().rstrip("="))

        family_b = make_family(db, "Seed Family B")
        put_user(db, family_b, f"owner-b-{secrets.token_hex(4)}@example.invalid",
                 secrets.token_urlsafe(24), "Seed Owner B", "admin")
        put_user(db, family_b, env["SV_USER_B"], env["SV_PASSWORD_B"], "Seed Member B", "member")
    db.close()
    print("Seeded two families with test accounts.")


if __name__ == "__main__":
    main()

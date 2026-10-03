import os
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS families (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    totp_secret TEXT,                 -- set: an authenticator app code is asked for at every sign-in
    totp_pending_secret TEXT,         -- during setup, until the first code is confirmed
    totp_last_step INTEGER,           -- the last code's time step, so a code can't be used twice
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS users_family ON users(family_id);

-- Someone who gave the right password (or provider sign-in) and still owes an authenticator code.
CREATE TABLE IF NOT EXISTS mfa_pending (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    created_at REAL NOT NULL
);

-- Single-use codes for when the phone is lost; stored only as lookup hashes.
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at REAL NOT NULL,
    last_seen REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS failed_logins (
    email TEXT NOT NULL COLLATE NOCASE,
    at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS failed_logins_email ON failed_logins(email, at);

CREATE TABLE IF NOT EXISTS failed_logins_by_ip (
    ip TEXT NOT NULL,
    at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS failed_logins_ip ON failed_logins_by_ip(ip, at);

CREATE TABLE IF NOT EXISTS invites (
    code_hash TEXT PRIMARY KEY,
    family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS invites_made (
    family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
    created_by INTEGER REFERENCES users(id) ON DELETE CASCADE,
    at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS invites_made_user ON invites_made(created_by, at);

CREATE TABLE IF NOT EXISTS signups (
    at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS signups_at ON signups(at);

-- A Google, Apple or other OpenID Connect account linked to a user. `subject` is the
-- provider's permanent id for the person (the `sub` claim), never their email.
CREATE TABLE IF NOT EXISTS oauth_identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (provider, subject),
    UNIQUE (user_id, provider)
);

-- One row per sign-in started with a provider; used once, then deleted.
CREATE TABLE IF NOT EXISTS oauth_states (
    state_hash TEXT PRIMARY KEY,
    browser_hash TEXT NOT NULL,
    provider TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('login', 'link', 'reauth')),
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    nonce TEXT NOT NULL,
    code_verifier TEXT,
    created_at REAL NOT NULL
);

-- A provider identity with no account yet, waiting for the person to finish signing up.
CREATE TABLE IF NOT EXISTS oauth_pending (
    browser_hash TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    starts_at TEXT NOT NULL,
    ends_at TEXT,
    notes TEXT NOT NULL DEFAULT '',
    archived INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS events_family ON events(family_id, starts_at);

CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY,
    family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
    due_date TEXT,
    done INTEGER NOT NULL DEFAULT 0,
    archived INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS todos_family ON todos(family_id);

CREATE TABLE IF NOT EXISTS grocery_items (
    id INTEGER PRIMARY KEY,
    family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    quantity TEXT NOT NULL DEFAULT '',
    checked INTEGER NOT NULL DEFAULT 0,
    added_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS grocery_family ON grocery_items(family_id);

CREATE TABLE IF NOT EXISTS reminders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    remind_at TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0,
    shared INTEGER NOT NULL DEFAULT 0,      -- 1: the whole family sees it and can mark it done
    archived INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS reminders_user ON reminders(user_id, remind_at);
"""


def connect(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db(path):
    conn = connect(path)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript(SCHEMA)
    _upgrade(conn)
    conn.commit()
    conn.close()
    os.chmod(path, 0o600)


def _upgrade(conn):
    """Bring databases made by earlier versions up to the current schema."""
    flag = "INTEGER NOT NULL DEFAULT 0"
    added = {
        "reminders": {"shared": flag, "archived": flag},
        "todos": {"archived": flag},
        "events": {"archived": flag},
        "users": {"totp_secret": "TEXT", "totp_pending_secret": "TEXT", "totp_last_step": "INTEGER"},
    }
    for table, columns in added.items():
        existing = {row[1] for row in conn.execute("SELECT name, name FROM pragma_table_info(?)", (table,))}
        for column, definition in columns.items():
            if column not in existing:
                # table, column and type come from the fixed dict above, never from input
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_app(app):
    init_db(app.config["DATABASE"])
    app.teardown_appcontext(close_db)

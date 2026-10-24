"""One place that opens SQLite. Swap this file for PostgreSQL later; the rest stays the same."""
import os
import sqlite3
from contextlib import closing

import config

_ready = set()  # database files that already have their tables (checked once per run, not on every query)

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT, src TEXT, dst TEXT,
    msg TEXT, level TEXT, status TEXT, note TEXT, count INTEGER);
CREATE TABLE IF NOT EXISTS blocklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, reason TEXT, created TEXT, actor TEXT,
    status TEXT, mode TEXT, result TEXT, removed TEXT);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password_hash TEXT, role TEXT, status TEXT,
    must_change INTEGER DEFAULT 0, sv INTEGER DEFAULT 0, created TEXT, approved_by TEXT, approved_at TEXT);
CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY, uid INTEGER, created REAL);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, target TEXT, detail TEXT);
"""


def run(sql, args=(), fetch=None):
    """fetch: 'all' (list of dicts), 'one' (dict or None), 'id' (new row id), 'count' (rows changed)."""
    os.makedirs(os.path.dirname(config.DB_FILE), exist_ok=True)
    first = config.DB_FILE not in _ready or not os.path.exists(config.DB_FILE)
    with closing(sqlite3.connect(config.DB_FILE)) as con:
        con.row_factory = sqlite3.Row
        if first:
            con.executescript(SCHEMA)
            if "username" in [r[1] for r in con.execute("PRAGMA table_info(users)")]:  # made by an older version
                con.execute("ALTER TABLE users RENAME COLUMN username TO email")
            if os.name != "nt":   # the file holds password hashes: owner-only (Windows has no such mode bits)
                try:
                    os.chmod(config.DB_FILE, 0o600)
                except OSError:
                    pass
            _ready.add(config.DB_FILE)
        cur = con.execute(sql, args)
        con.commit()
        if fetch == "all":
            return [dict(r) for r in cur.fetchall()]
        if fetch == "one":
            r = cur.fetchone()
            return dict(r) if r else None
        if fetch == "id":
            return cur.lastrowid
        if fetch == "count":
            return cur.rowcount

"""Users, roles and approval. Passwords are stored only as hashes (never as text).

Roles:   viewer  = look only
         analyst = viewer + create/update incidents + export CSV
         admin   = everything: block/unblock IPs, audit log, approve and manage users
Status:  pending (signed up, waiting for the admin) -> active -> disabled
"""
import re
import secrets
import sqlite3
import time
from datetime import datetime

from werkzeug.security import check_password_hash, generate_password_hash

import config
from services import audit, db

ROLES = ("viewer", "analyst", "admin")
MAX_PENDING = 50
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
_DUMMY = generate_password_hash("not-a-real-password")  # a wrong email must take as long as a wrong password

# A deliberately small safety net, not a breach list: very common passwords that are long enough to pass the length rule.
COMMON_PASSWORDS = frozenset((
    "password12", "password123", "password1234", "passw0rd123", "1234567890", "12345678910", "123456789012",
    "0123456789", "qwertyuiop", "qwerty1234", "qwerty12345", "1q2w3e4r5t", "iloveyou123", "letmein1234",
    "welcome123", "welcome1234", "administrator", "admin12345", "admin123456", "changeme123", "changemenow",
    "minisoc123", "minisoc1234",
))


class WrongCurrentPassword(ValueError):
    """The 'current password' typed in change-password was wrong (counted by auth to slow down guessing)."""


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def _by_id(uid):
    return db.run("SELECT * FROM users WHERE id=?", (uid,), "one")


def _by_email(name):
    return db.run("SELECT * FROM users WHERE email=?", (name,), "one")


def _public(r):
    keys = ("id", "email", "role", "status", "must_change", "created", "approved_by", "approved_at")
    return {k: r[k] for k in keys}


def _must_exist(uid):
    row = _by_id(uid)
    if not row:
        raise LookupError("User not found")
    return row


def _guard_last_admin(row):
    """Never allow the system to end up with no active admin."""
    if row["role"] == "admin" and row["status"] == "active":
        n = db.run("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND status='active' AND id!=?",
                   (row["id"],), "one")["n"]
        if n == 0:
            raise ValueError("You cannot remove the last active admin")


def clean_email(value):
    """The sign-in name. It is NOT verified by sending a mail: the admin approval is the gate."""
    value = str(value).strip().lower()
    if len(value) > 120 or not EMAIL_RE.match(value):
        raise ValueError("Enter a valid email address")
    return value


def check_password(pw, email=""):
    """THE password policy. Every place that stores a password calls this first (signup, change, admin reset,
    first-start admin, manage.py recovery), so the rules cannot differ between paths. Messages never repeat the password."""
    pw = str(pw)
    if len(pw) < 10:
        raise ValueError("Password must be at least 10 characters")
    if len(pw) > 128:
        raise ValueError("Password is too long (max 128 characters)")
    if email and pw.lower() in (email.lower(), email.split("@")[0].lower()):
        raise ValueError("Password must not be your email or the first part of it")
    if len(set(pw)) < 5:
        raise ValueError("Password is too repetitive: use at least 5 different characters")
    if pw.lower() in COMMON_PASSWORDS:
        raise ValueError("That password is too common. Choose a less predictable one")
    return pw


def generate_password():
    """A random password (12 URL-safe characters) that satisfies check_password."""
    while True:
        try:
            return check_password(secrets.token_urlsafe(9))
        except ValueError:
            continue


def ensure_admin_email(email):
    """Older versions named the admin 'admin'. Move that account to the configured email address."""
    if _by_email(email):
        return
    for old in ("admin", config.DEFAULT_ADMIN_EMAIL):
        row = _by_email(old)
        if row and row["role"] == "admin":
            db.run("UPDATE users SET email=?, sv=sv+1 WHERE id=?", (email, row["id"]))
            return


def count():
    return db.run("SELECT COUNT(*) AS n FROM users", (), "one")["n"]


def create_admin(name, password):
    """First start only. The password must pass the same policy as every other password.
    Others must use signup + approval."""
    check_password(password, name)
    db.run("INSERT INTO users (email,password_hash,role,status,must_change,sv,created,approved_by,approved_at) "
           "VALUES (?,?,?,?,0,0,?,'system',?)",
           (name, generate_password_hash(password), "admin", "active", _now(), _now()))


def signup(email, password):
    """Anyone can ask for an account. It stays 'pending' with no access until an admin approves it."""
    name = clean_email(email)
    check_password(password, name)
    if db.run("SELECT COUNT(*) AS n FROM users WHERE status='pending'", (), "one")["n"] >= MAX_PENDING:
        raise ValueError("Too many sign-ups are waiting for approval. Ask the admin.")
    try:
        uid = db.run("INSERT INTO users (email,password_hash,role,status,must_change,sv,created,approved_by,approved_at) "
                     "VALUES (?,?,?,?,0,0,?,'','')",
                     (name, generate_password_hash(password), "viewer", "pending", _now()), "id")
    except sqlite3.IntegrityError:
        # Same answer as a new account (the caller sends one message for both), so signup cannot be used to find
        # out which emails are registered. The attempt is only recorded in the audit log.
        audit.log(name, "user.signup_duplicate", name)
        return None
    audit.log(name, "user.signup", name)
    return uid


def authenticate(email, password):
    """Returns (user row, 'ok') or (None, 'bad' | 'pending' | 'disabled'). 'pending' is only revealed after a right password."""
    row = _by_email(str(email).strip().lower())
    good = check_password_hash(row["password_hash"] if row else _DUMMY, str(password))
    if not row or not good:
        return None, "bad"
    if row["status"] != "active":
        return None, row["status"]
    return row, "ok"


def new_session(uid):
    """Server-side login record. The cookie only carries this random id; logout deletes the record, so a copied
    cookie is dead the moment the user signs out (a signed cookie alone can not be revoked)."""
    now = time.time()
    db.run("DELETE FROM sessions WHERE created < ?", (now - config.SESSION_HOURS * 3600,))
    sid = secrets.token_urlsafe(24)
    db.run("INSERT INTO sessions (sid, uid, created) VALUES (?,?,?)", (sid, uid, now))
    return sid


def end_session(sid):
    if sid:
        db.run("DELETE FROM sessions WHERE sid=?", (str(sid),))


def _session_alive(uid, sid):
    if not sid:
        return False
    row = db.run("SELECT uid, created FROM sessions WHERE sid=?", (str(sid),), "one")
    return bool(row and row["uid"] == uid and time.time() - row["created"] < config.SESSION_HOURS * 3600)


def session_user(uid, sv, sid=None):
    """Checked on EVERY request, so a disabled user, a changed role or a logout takes effect at once."""
    row = _by_id(uid)
    if row and row["status"] == "active" and row["sv"] == sv and _session_alive(uid, sid):
        return {**_public(row), "sv": row["sv"]}
    return None


def list_all():
    rows = db.run("SELECT * FROM users ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, id", (), "all")
    return [_public(r) for r in rows]


def approve(uid, role, actor):
    row = _must_exist(uid)
    if role not in ROLES:
        raise ValueError("Role must be one of: " + ", ".join(ROLES))
    if row["status"] != "pending":
        raise ValueError("Only pending accounts can be approved")
    db.run("UPDATE users SET status='active', role=?, approved_by=?, approved_at=? WHERE id=?", (role, actor, _now(), uid))
    audit.log(actor, "user.approve", row["email"], "role=" + role)


def set_role(uid, role, actor):
    row = _must_exist(uid)
    if role not in ROLES:
        raise ValueError("Role must be one of: " + ", ".join(ROLES))
    if role != "admin":
        _guard_last_admin(row)
    db.run("UPDATE users SET role=? WHERE id=?", (role, uid))
    audit.log(actor, "user.role", row["email"], "role=" + role)


def set_status(uid, status, actor):
    row = _must_exist(uid)
    if status not in ("active", "disabled"):
        raise ValueError("Status must be active or disabled")
    if row["status"] == "pending":
        raise ValueError("Approve or reject pending accounts instead")
    if status == "disabled":
        _guard_last_admin(row)
    db.run("UPDATE users SET status=?, sv=sv+1 WHERE id=?", (status, uid))  # sv+1 signs the user out everywhere
    audit.log(actor, "user." + ("enable" if status == "active" else "disable"), row["email"])


def reset_password(uid, temp, actor):
    """Admin sets a temporary password; the user must choose a new one at next sign-in."""
    row = _must_exist(uid)
    check_password(temp, row["email"])
    db.run("UPDATE users SET password_hash=?, must_change=1, sv=sv+1 WHERE id=?", (generate_password_hash(temp), uid))
    audit.log(actor, "user.reset_password", row["email"])


def change_password(uid, old, new):
    """Returns the new session version (the caller keeps this browser signed in)."""
    row = _must_exist(uid)
    if not check_password_hash(row["password_hash"], str(old)):
        raise WrongCurrentPassword("Current password is wrong")
    check_password(new, row["email"])
    if new == old:
        raise ValueError("The new password must be different")
    db.run("UPDATE users SET password_hash=?, must_change=0, sv=sv+1 WHERE id=?", (generate_password_hash(new), uid))
    audit.log(row["email"], "user.change_password", row["email"])
    return row["sv"] + 1


def delete(uid, actor):
    row = _must_exist(uid)
    _guard_last_admin(row)
    db.run("DELETE FROM users WHERE id=?", (uid,))
    db.run("DELETE FROM sessions WHERE uid=?", (uid,))
    audit.log(actor, "user.delete", row["email"])


def force_set_password(email, new):
    """Recovery from the command line (backend/manage.py). The password rules are enforced HERE, not only in the
    caller, so no other caller can skip them. It still reactivates a disabled account, so a locked-out admin can get back in."""
    name = clean_email(email)
    row = _by_email(name)
    if not row:
        raise LookupError("User not found")
    check_password(new, name)
    db.run("UPDATE users SET password_hash=?, must_change=0, status='active', sv=sv+1 WHERE id=?",
           (generate_password_hash(new), row["id"]))
    audit.log("manage.py", "user.force_password", row["email"])

"""Login sessions, roles and brute-force limits."""
import time
from functools import wraps

from flask import g, jsonify, session

import config
from services import users

RANK = {"viewer": 1, "analyst": 2, "admin": 3}
_fails = {}       # address -> (first_fail_time, count)
_acct_fails = {}  # sign-in name (as typed, lower case; real or not) -> (first_fail_time, count)
_pw_fails = {}    # user id -> (first_fail_time, count) for wrong "current password" in change-password
_signups = {}     # address -> [times]
_LOCKED = "Too many wrong attempts. Wait a few minutes."


def _locked(table, key, limit, now):
    """True while this key has used up its wrong attempts. The window restarts after LOGIN_WINDOW seconds."""
    first, count = table.get(key, (now, 0))
    if now - first > config.LOGIN_WINDOW:
        table.pop(key, None)
        return False
    return count >= limit


def _note_fail(table, key, now):
    first, count = table.get(key, (now, 0))
    if now - first > config.LOGIN_WINDOW:
        first, count = now, 0
    table[key] = (first, count + 1)
    if len(table) > 10000:   # keys can come from an attacker: never let this grow without end
        for k in [k for k, (t, _) in table.items() if now - t > config.LOGIN_WINDOW]:
            table.pop(k, None)
        if len(table) > 10000:
            table.clear()


def pw_locked(uid):
    return _locked(_pw_fails, uid, config.PW_CHANGE_MAX_FAILS, time.time())


def note_pw_fail(uid):
    _note_fail(_pw_fails, uid, time.time())


def clear_pw_fail(uid):
    _pw_fails.pop(uid, None)


def current_user():
    """The signed-in user, read fresh from the database on every request (or None)."""
    uid = session.get("uid")
    if not uid:
        return None
    user = users.session_user(uid, session.get("sv"), session.get("sid"))
    if not user:
        session.clear()
    return user


def actor():
    user = getattr(g, "user", None)
    return user["email"] if user else "system"


def require(role):
    """Decorator: the route needs at least this role."""
    def deco(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            if RANK[g.user["role"]] < RANK[role]:
                return jsonify(error=f"Your role ({g.user['role']}) cannot do this. It needs {role}."), 403
            return fn(*args, **kwargs)
        return inner
    return deco


def try_login(email, password, address):
    """Returns (ok, message, http_status, user)."""
    now = time.time()
    name = str(email).strip().lower()[:120]
    # Two limits: per address (one machine guessing) and per account (many machines guessing one account).
    # The account limit counts the typed name even when no such account exists, so it reveals nothing.
    if _locked(_fails, address, config.LOGIN_MAX_FAILS, now) or _locked(_acct_fails, name, config.ACCOUNT_MAX_FAILS, now):
        return False, _LOCKED, 429, None
    user, why = users.authenticate(email, password)
    if why == "bad":
        _note_fail(_fails, address, now)
        _note_fail(_acct_fails, name, now)
        return False, "Wrong email or password.", 401, None
    if why == "pending":
        return False, "Your account is waiting for admin approval.", 403, None
    if why == "disabled":
        return False, "This account is disabled. Ask the admin.", 403, None
    _fails.pop(address, None)
    _acct_fails.pop(name, None)
    session.clear()
    session["uid"], session["sv"] = user["id"], user["sv"]
    session["sid"] = users.new_session(user["id"])
    session.permanent = True
    return True, "ok", 200, user


def allow_signup(address):
    """Only accounts that were really created count, so a typo in the form never locks anyone out."""
    now = time.time()
    _signups[address] = [t for t in _signups.get(address, []) if now - t < 3600]
    return len(_signups[address]) < config.SIGNUP_MAX_PER_HOUR


def note_signup(address):
    _signups.setdefault(address, []).append(time.time())

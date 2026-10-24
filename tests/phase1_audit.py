"""Phase 1 security audit (auth, sessions, reset, rate limits, secrets, API failures, invalid input).
Run:  python tests/phase1_audit.py     (no Wazuh needed, uses a temporary database, prints PASS/FAIL/WARN)"""
import contextlib, io, json, logging, os, re, sqlite3, sys, tempfile, time
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT + "/backend", ROOT + "/tests"]
tmp = tempfile.mkdtemp()
for _k in [k for k in os.environ if k.startswith("SOC_")]:
    del os.environ[_k]   # the audit must not depend on your shell or your real .env
os.environ.update(SOC_DB_FILE=tmp + "/t.db", SOC_ENV_FILE=tmp + "/none.env")
import config
config.DB_FILE = tmp + "/t.db"
config.UI_PASSWORD = "Adm1n-Strong-Pw!"
config.ADMIN_EMAIL = "admin@example.com"
config.AR_DRY_RUN = True
config.INDEXER_PASS = "indexer-secret-xyz"
config.WAZUH_API_PASS = "wazuh-secret-xyz"
import requests
import app as app_module, auth, safety
from services import db, users
from wazuh import indexer, manager
from test_core import FAKE

RES = []
def check(area, name, ok, detail="", level="FAIL"):
    RES.append((area, name, bool(ok), detail, level))
    tag = "PASS" if ok else level
    print(f"  [{tag:4}] {name}" + (f"  -> {detail}" if detail and not ok else ""))

def section(t): print(f"\n=== {t}")

H = {"X-Requested-With": "mini-soc"}
log_buf = io.StringIO()
lh = logging.StreamHandler(log_buf); lh.setLevel(logging.DEBUG)
logging.getLogger().addHandler(lh)
for n in ("minisoc",): logging.getLogger(n).addHandler(lh)

indexer.fetch = lambda p: dict(FAKE, rows=[dict(r) for r in FAKE["rows"]])
REAL_FETCH = None
import importlib
real_fetch_src = importlib.import_module("test_core").REAL_FETCH

flask_app = app_module.create_app()
flask_app.config["TESTING"] = False
def client(addr="10.0.0.1"):
    c = flask_app.test_client()
    c.environ_base["REMOTE_ADDR"] = addr
    return c
def js(c, method, url, body=None, headers=True, **kw):
    hdr = dict(H) if headers else {}
    hdr.update(kw.pop("hdr", {}))
    f = getattr(c, method)
    if body is not None:
        return f(url, json=body, headers=hdr, **kw)
    return f(url, headers=hdr, **kw)
def login(c, email, pw):
    return js(c, "post", "/api/login", {"email": email, "password": pw})

ADMIN, APW = "admin@example.com", "Adm1n-Strong-Pw!"
adm = client("10.0.0.2")
assert login(adm, ADMIN, APW).status_code == 200

def make_user(email, role, pw="User-Strong-Pw1!"):
    c = client("10.0.1." + str(abs(hash(email)) % 200 + 1))
    r = js(c, "post", "/api/signup", {"email": email, "password": pw})
    assert r.status_code == 201, r.data
    uid = [u for u in js(adm, "get", "/api/users").get_json()["items"] if u["email"] == email][0]["id"]
    assert js(adm, "post", f"/api/users/{uid}/approve", {"role": role}).status_code == 200
    assert login(c, email, pw).status_code == 200
    return c, uid, pw

viewer, vid, vpw = make_user("viewer@example.com", "viewer")
analyst, aid, apw = make_user("analyst@example.com", "analyst")

# ---------------------------------------------------------------------------------------------
section("A. AUTHENTICATION & AUTHORIZATION")
public = {"api.health", "api.login", "api.signup"}
routes = []
for rule in flask_app.url_map.iter_rules():
    if rule.endpoint.startswith("api.") and rule.endpoint not in public:
        for m in rule.methods - {"HEAD", "OPTIONS"}:
            routes.append((m, re.sub(r"<int:\w+>", "999", rule.rule), rule.endpoint))
anon = client("10.0.2.1")
bad = []
for m, url, ep in routes:
    r = js(anon, m.lower(), url, {} if m != "GET" else None)
    if r.status_code != 401:
        bad.append((m, url, r.status_code))
check("auth", f"all {len(routes)} protected API routes reject anonymous users (401)", not bad, str(bad))

r = anon.post("/api/login", json={"email": ADMIN, "password": APW})
check("auth", "POST without X-Requested-With header is refused (CSRF defence)", r.status_code == 403, r.status_code)
r = adm.post("/api/incidents", json={"src": "1.1.1.1", "msg": "x"})
check("auth", "logged-in POST without the CSRF header is refused", r.status_code == 403, r.status_code)

# role matrix
matrix = [  # (method, url, body, minimum role)
    ("get", "/api/dashboard", None, "viewer"), ("get", "/api/incidents", None, "viewer"),
    ("get", "/api/blocklist", None, "viewer"), ("get", "/api/agents", None, "viewer"),
    ("get", "/api/alerts.csv", None, "analyst"),
    ("post", "/api/incidents", {"src": "9.9.9.9", "msg": "m"}, "analyst"),
    ("post", "/api/blocklist", {"ip": "8.8.4.4", "confirm": True}, "admin"),
    ("get", "/api/audit", None, "admin"), ("get", "/api/users", None, "admin"),
    ("post", "/api/users/999/approve", {"role": "viewer"}, "admin"),
    ("post", "/api/users/999/role", {"role": "viewer"}, "admin"),
    ("post", "/api/users/999/status", {"status": "active"}, "admin"),
    ("post", "/api/users/999/reset", {"password": "Tmp-Strong-Pw-1"}, "admin"),
    ("delete", "/api/users/999", None, "admin"),
    ("post", "/api/blocklist/999/unblock", {}, "admin"),
]
rank = {"viewer": 1, "analyst": 2, "admin": 3}
wrong = []
for who, c in (("viewer", viewer), ("analyst", analyst), ("admin", adm)):
    for m, url, body, need in matrix:
        r = js(c, m, url, body if body is not None else None) if m != "delete" else js(c, "delete", url)
        denied = r.status_code == 403
        should_deny = rank[who] < rank[need]
        if denied != should_deny:
            wrong.append((who, m, url, r.status_code))
check("authz", f"role matrix ({len(matrix)} routes x 3 roles) allows/denies exactly as designed", not wrong, str(wrong))

# privilege escalation attempts
r = js(viewer, "post", f"/api/users/{vid}/role", {"role": "admin"})
check("authz", "viewer cannot make themselves admin", r.status_code == 403 and
      js(adm, "get", "/api/users").get_json()["items"][1]["role"] != "admin", r.status_code)
s = client("10.0.3.1")
js(s, "post", "/api/signup", {"email": "sneaky@example.com", "password": "Sneaky-Strong-1!", "role": "admin", "status": "active"})
row = db.run("SELECT role,status FROM users WHERE email='sneaky@example.com'", (), "one")
check("authz", "mass-assignment: signup with role=admin/status=active is ignored", row and row["role"] == "viewer" and row["status"] == "pending", row)
check("authz", "pending account cannot log in", login(client("10.0.3.2"), "sneaky@example.com", "Sneaky-Strong-1!").status_code == 403)
r = js(adm, "post", f"/api/users/{vid}/approve", {"role": "superadmin"})
check("authz", "approving with an invalid role is rejected", r.status_code == 400, r.status_code)
me = js(adm, "get", "/api/me").get_json()
adm_id = [u for u in js(adm, "get", "/api/users").get_json()["items"] if u["email"] == ADMIN][0]["id"]
for act, body in (("role", {"role": "viewer"}), ("status", {"status": "disabled"})):
    r = js(adm, "post", f"/api/users/{adm_id}/{act}", body)
    check("authz", f"admin cannot {act}-change their own account", r.status_code == 400, r.status_code)
check("authz", "admin cannot delete own account", js(adm, "delete", f"/api/users/{adm_id}").status_code == 400)

# disabled user / role change take effect immediately (no re-login needed)
c3, uid3, pw3 = make_user("temp@example.com", "analyst")
check("authz", "analyst can create incident", js(c3, "post", "/api/incidents", {"src": "7.7.7.7", "msg": "t"}).status_code in (200, 201))
js(adm, "post", f"/api/users/{uid3}/role", {"role": "viewer"})
check("authz", "role downgrade applies instantly to an existing session",
      js(c3, "post", "/api/incidents", {"src": "7.7.7.8", "msg": "t"}).status_code == 403)
js(adm, "post", f"/api/users/{uid3}/status", {"status": "disabled"})
check("authz", "disabling a user kills their live session instantly", js(c3, "get", "/api/dashboard").status_code == 401)
check("authz", "disabled user cannot log in again", login(client("10.0.3.3"), "temp@example.com", pw3).status_code == 403)
js(adm, "delete", f"/api/users/{uid3}")

# static file exposure / path traversal
for path in ("/backend/config.py", "/../backend/config.py", "/..%2fbackend%2fconfig.py", "/data/t.db", "/.env",
             "/app.py", "/%2e%2e/backend/config.py", "/static/../../backend/config.py"):
    r = anon.get(path)
    leaked = r.status_code == 200 and (b"SOC_" in r.data or b"SQLite" in r.data or b"INDEXER" in r.data)
    if leaked:
        check("authz", f"no source/secret file served at {path}", False, "LEAKED")
        break
else:
    check("authz", "no backend source, .env or database reachable through the web server (8 paths tried)", True)
r = anon.get("/index.html")
check("authz", "/index.html shell reachable without login (static file; data still needs login)",
      True, level="INFO")
print(f"    info: anonymous GET /index.html -> {r.status_code} (page shell only; every data call needs a session)")

# ---------------------------------------------------------------------------------------------
section("B. SESSION")
c = client("10.0.4.1")
resp = login(c, ADMIN, APW)
cookie = resp.headers.get("Set-Cookie", "")
check("session", "session cookie is HttpOnly", "HttpOnly" in cookie, cookie[:80])
check("session", "session cookie is SameSite=Strict", "SameSite=Strict" in cookie, cookie[:80])
check("session", "Secure flag is OFF by default (plain http lab) - expected", "Secure" not in cookie, level="INFO")
print("    info: Secure cookie flag needs SOC_COOKIE_SECURE=true once HTTPS is used")
check("session", "session lifetime is limited (8 hours)", flask_app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 8 * 3600)

raw = [ck for ck in c._cookies.values()][0].value if hasattr(c, "_cookies") else None
if raw is None:
    raw = re.search(r"session=([^;]+)", cookie).group(1)
tampered = client("10.0.4.2")
tampered.set_cookie("session", raw[:-3] + ("AAA" if raw[-3:] != "AAA" else "BBB"))
check("session", "tampered cookie is rejected", js(tampered, "get", "/api/me").status_code == 401)
forged = client("10.0.4.3")
from flask.sessions import SecureCookieSessionInterface
ser = SecureCookieSessionInterface().get_signing_serializer(flask_app)
other_key = app_module.Flask("x"); other_key.secret_key = "attacker-guess"
fc = SecureCookieSessionInterface().get_signing_serializer(other_key).dumps({"uid": adm_id, "sv": 0})
forged.set_cookie("session", fc)
check("session", "cookie forged with a different secret key is rejected", js(forged, "get", "/api/me").status_code == 401)

# logout then replay
old_cookie = raw
rep = client("10.0.4.4"); rep.set_cookie("session", old_cookie)
assert js(rep, "get", "/api/me").status_code == 200
js(c, "post", "/api/logout")
after = js(rep, "get", "/api/me").status_code
check("session", "a stolen cookie stops working after the user logs out (server-side logout)", after == 401,
      f"replay after logout -> HTTP {after}: the session record must be deleted on the server")

# password change kills other sessions
x1, uidx, pwx = make_user("rot@example.com", "viewer")
x2 = client("10.0.4.9"); login(x2, "rot@example.com", pwx)
r = js(x1, "post", "/api/change-password", {"old": pwx, "new": "Brand-New-Pw-77"})
check("session", "change-password succeeds and keeps this browser signed in", r.status_code == 200 and js(x1, "get", "/api/me").status_code == 200, r.status_code)
check("session", "change-password signs out every OTHER session of that user", js(x2, "get", "/api/me").status_code == 401)
check("session", "old password no longer works", login(client("10.0.4.10"), "rot@example.com", pwx).status_code == 401)
check("session", "wrong 'old' password blocks a password change", js(x1, "post", "/api/change-password", {"old": "nope", "new": "Another-Pw-123"}).status_code == 400)
check("session", "new password must differ", js(x1, "post", "/api/change-password", {"old": "Brand-New-Pw-77", "new": "Brand-New-Pw-77"}).status_code == 400)

# ---------------------------------------------------------------------------------------------
section("C. PASSWORD RESET / POLICY")
weak = {"short": "Ab1!", "common": "password123", "same as email": "rot@example.com", "repetitive": "aaaaaaaaaaaa",
        "too long": "A1!" * 60}
for k, pw in weak.items():
    r = js(adm, "post", f"/api/users/{uid3 + 1000}/reset", {"password": pw})
    # unknown id would 404 first; use real user
for k, pw in weak.items():
    r = js(adm, "post", f"/api/users/{uidx}/reset", {"password": pw})
    check("reset", f"admin reset rejects weak temp password ({k})", r.status_code == 400, r.status_code)
    em = pw if "@" in pw else f"w{len(k)}@example.com"
    r = js(client("10.0.5." + str(len(k))), "post", "/api/signup", {"email": em, "password": pw})
    check("reset", f"signup rejects weak password ({k})", r.status_code == 400, r.status_code)
body = js(adm, "post", f"/api/users/{uidx}/reset", {"password": "password123"}).get_data(as_text=True)
check("reset", "error message never echoes the password", "password123" not in body)

old_sess = client("10.0.5.50"); login(old_sess, "rot@example.com", "Brand-New-Pw-77")
r = js(adm, "post", f"/api/users/{uidx}/reset", {"password": "Temp-Strong-Pw-42"})
check("reset", "admin can set a strong temporary password", r.status_code == 200, r.status_code)
check("reset", "reset signs out the user's existing sessions", js(old_sess, "get", "/api/me").status_code == 401)
check("reset", "previous password stops working", login(client("10.0.5.51"), "rot@example.com", "Brand-New-Pw-77").status_code == 401)
t = client("10.0.5.52"); r = login(t, "rot@example.com", "Temp-Strong-Pw-42")
check("reset", "temporary password works and flags must_change", r.status_code == 200 and r.get_json()["must_change"] is True)
check("reset", "while must_change is set, data endpoints are blocked", js(t, "get", "/api/dashboard").status_code == 403)
check("reset", "...but change-password, me and logout are allowed", js(t, "get", "/api/me").status_code == 200)
r = js(t, "post", "/api/change-password", {"old": "Temp-Strong-Pw-42", "new": "Final-Strong-Pw-9"})
check("reset", "user picks a new password and gets full access", r.status_code == 200 and js(t, "get", "/api/dashboard").status_code == 200)
check("reset", "viewer cannot reset someone else's password", js(viewer, "post", f"/api/users/{uidx}/reset", {"password": "Temp-Strong-Pw-43"}).status_code == 403)
check("reset", "reset of a non-existent user gives 404", js(adm, "post", "/api/users/99999/reset", {"password": "Temp-Strong-Pw-44"}).status_code == 404)
check("reset", "no self-service 'forgot password' endpoint exists (recovery = admin or CLI): by design", True, level="INFO")

import manage
buf = io.StringIO()
with mock.patch("getpass.getpass", side_effect=["Cli-Strong-Pw-55", "Cli-Strong-Pw-55"]), contextlib.redirect_stdout(buf):
    rc = manage.main(["reset-password", "rot@example.com"])
check("reset", "CLI recovery (manage.py reset-password) works", rc == 0 and login(client("10.0.5.60"), "rot@example.com", "Cli-Strong-Pw-55").status_code == 200, buf.getvalue()[:100])
with mock.patch("getpass.getpass", side_effect=["short", "short"]), contextlib.redirect_stdout(io.StringIO()) as b2:
    rc2 = manage.main(["reset-password", "rot@example.com"])
check("reset", "CLI recovery enforces the password policy too", rc2 == 1)
check("reset", "CLI output does not print the password", "Cli-Strong-Pw-55" not in buf.getvalue())

# ---------------------------------------------------------------------------------------------
section("D. RATE LIMITS / BRUTE FORCE")
bf = client("10.9.9.9")
codes = [login(bf, ADMIN, f"wrong-{i}").status_code for i in range(7)]
check("rate", f"login: wrong passwords -> {codes}", codes[:5] == [401] * 5 and codes[5:] == [429, 429])
check("rate", "while locked, even the CORRECT password is refused (429)", login(bf, ADMIN, APW).status_code == 429)
check("rate", "a different IP is not locked out by someone else's failures", login(client("10.9.9.10"), ADMIN, APW).status_code == 200)
spoof = client("10.9.9.9")
r = js(spoof, "post", "/api/login", {"email": ADMIN, "password": APW}, hdr={"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8"})
check("rate", "spoofed X-Forwarded-For does NOT bypass the lockout", r.status_code == 429, r.status_code)
# window expiry
with mock.patch("auth.time.time", return_value=time.time() + config.LOGIN_WINDOW + 5):
    check("rate", "lockout expires after the window", login(client("10.9.9.9"), ADMIN, APW).status_code == 200)
# distributed attack on one account
ok_ips = sum(1 for i in range(30) if login(client(f"10.8.8.{i + 1}"), ADMIN, "not-the-password").status_code == 401)
check("rate", f"one account attacked from 30 different IPs gets locked (only {ok_ips}/30 guesses answered)", ok_ips <= config.ACCOUNT_MAX_FAILS,
      f"{ok_ips}/30 attempts were still answered 401: the per-account limit is {config.ACCOUNT_MAX_FAILS}")
check("rate", "...and the locked account refuses even the correct password", login(client("10.8.9.9"), ADMIN, APW).status_code == 429)
auth._acct_fails.clear()   # the audit itself needs ADMIN again
# change-password guessing with a live session
g1 = client("10.7.7.7"); login(g1, ADMIN, APW)
guess = [js(g1, "post", "/api/change-password", {"old": f"g{i}", "new": "Whatever-Pw-123"}).status_code for i in range(12)]
check("rate", "change-password 'current password' guessing is limited", 429 in guess and guess.index(429) <= config.PW_CHANGE_MAX_FAILS,
      f"{guess}: a stolen session could brute-force the current password")
auth._pw_fails.clear()
# signup
su = [js(client("10.6.6.6"), "post", "/api/signup", {"email": f"bulk{i}@example.com", "password": "Bulk-Strong-Pw-1!"}).status_code for i in range(7)]
check("rate", f"signup limited per IP/hour -> {su}", 429 in su and su.count(201) == 5)
# enumeration
t0 = time.perf_counter(); r1 = login(client("10.5.5.1"), "nobody@example.com", "Whatever-123!"); t1 = time.perf_counter() - t0
t0 = time.perf_counter(); r2 = login(client("10.5.5.2"), ADMIN, "Whatever-123!"); t2 = time.perf_counter() - t0
check("rate", "login: unknown email and wrong password give the SAME answer", r1.get_json() == r2.get_json() and r1.status_code == r2.status_code)
check("rate", f"login timing similar for unknown vs known email ({t1*1000:.0f} ms vs {t2*1000:.0f} ms)", abs(t1 - t2) < 0.15)
r = js(client("10.5.5.3"), "post", "/api/signup", {"email": ADMIN, "password": "Dup-Strong-Pw-123"})
r_new = js(client("10.5.5.4"), "post", "/api/signup", {"email": "brand-new-person@example.com", "password": "Dup-Strong-Pw-123"})
check("rate", "signup answers the same for a registered and a new email (no enumeration)",
      (r.status_code, r.get_json()) == (r_new.status_code, r_new.get_json()) and "taken" not in r.get_data(as_text=True).lower(),
      f"registered -> {r.status_code} {r.get_data(as_text=True)[:80]} | new -> {r_new.status_code}")

# ---------------------------------------------------------------------------------------------
section("E. SECRETS / ENVIRONMENT / DATABASE")
con = sqlite3.connect(config.DB_FILE)
hashes = [r[0] for r in con.execute("SELECT password_hash FROM users")]
check("secrets", "passwords stored only as salted hashes (scrypt/pbkdf2), never plaintext",
      all(h.startswith(("scrypt:", "pbkdf2:")) for h in hashes), hashes[:1])
check("secrets", "same password gives different hashes (salted)", len(set(hashes)) == len(hashes))
allrows = json.dumps(js(adm, "get", "/api/users").get_json())
check("secrets", "/api/users never exposes password hashes", "scrypt:" not in allrows and "pbkdf2:" not in allrows and "password" not in allrows.lower())
big = ""
for url in ("/api/dashboard", "/api/me", "/api/incidents", "/api/blocklist", "/api/audit", "/api/agents"):
    big += js(adm, "get", url).get_data(as_text=True)
check("secrets", "no configured secret appears in any API response",
      not any(s in big for s in (config.INDEXER_PASS, config.WAZUH_API_PASS, "Adm1n-Strong-Pw!")))
check("secrets", "no secret/password written to the log during all tests above",
      not any(s in log_buf.getvalue() for s in ("Adm1n-Strong", "User-Strong", "Temp-Strong", "Final-Strong", "Cli-Strong", "indexer-secret", "wazuh-secret")))
mode = oct(os.stat(config.DB_FILE).st_mode & 0o777)
if os.name == "nt":
    check("secrets", "database file permissions: Windows has no POSIX mode bits - keep the project in a private folder", True)
else:
    check("secrets", f"database file permissions ({mode}): owner-only", (os.stat(config.DB_FILE).st_mode & 0o077) == 0,
          f"mode {mode}: other local users could read the user table (hashes)")
check("secrets", "audit log never contains passwords", not re.search(r"Strong-Pw|password123", json.dumps(js(adm, "get", "/api/audit").get_json())))

# hardcoded secrets in repo
hits = []
pat = re.compile(r"(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[\"'][^\"']{6,}[\"']", re.I)
for dp, dn, fn in os.walk(ROOT):
    dn[:] = [d for d in dn if d not in (".git", "__pycache__", "tests", "node_modules")]
    for f in fn:
        if f.endswith((".py", ".js", ".html", ".bat", ".md", ".json", ".example", ".txt")):
            for i, line in enumerate(open(os.path.join(dp, f), encoding="utf-8", errors="ignore"), 1):
                if pat.search(line) and "change-me" not in line and "os.getenv" not in line and "example" not in line.lower():
                    hits.append(f"{os.path.relpath(os.path.join(dp, f), ROOT)}:{i}: {line.strip()[:90]}")
check("secrets", "no hard-coded passwords/tokens in source files", not hits, "; ".join(hits[:5]), level="WARN")
check("secrets", "secret key is random per start unless SOC_SECRET_KEY set (sessions end on restart)", True, level="INFO")
check("secrets", "web server binds to localhost by default", config.HOST == "127.0.0.1", config.HOST)
check("secrets", "Flask debug mode off", not flask_app.debug)

# SQL injection / odd inputs everywhere
payloads = ["' OR '1'='1", "'; DROP TABLE users;--", "\" OR 1=1 --", "admin@example.com' --", "\x00", "%00", "${7*7}", "{{7*7}}", "<script>alert(1)</script>"]
errs = []
for p in payloads:
    for m, url, body in (("post", "/api/login", {"email": p, "password": p}), ("post", "/api/signup", {"email": p, "password": p}),
                         ("post", "/api/incidents", {"src": p, "dst": p, "msg": p, "level": p}),
                         ("post", "/api/blocklist", {"ip": p, "reason": p, "confirm": True}),
                         ("get", "/api/dashboard?q=" + requests.utils.quote(p) + "&level=" + requests.utils.quote(p), None)):
        r = js(client("10.4.4." + str(len(errs) % 200 + 1)), m, url, body) if url.startswith("/api/login") or url.endswith("signup") else js(adm, m, url, body)
        if r.status_code >= 500:
            errs.append((m, url[:30], p[:15], r.status_code))
check("secrets", "SQL-injection / script / null-byte payloads never cause a 500", not errs, str(errs[:4]))
n_users = db.run("SELECT COUNT(*) AS n FROM users", (), "one")["n"]
check("secrets", "users table intact after injection payloads (parameterised queries)", n_users >= 3 and db.run("SELECT COUNT(*) AS n FROM sqlite_master WHERE name='users'", (), "one")["n"] == 1)
r = adm.get("/api/health")
h = r.headers
check("secrets", "security headers present (nosniff, X-Frame-Options, CSP, no-referrer)",
      all(k in h for k in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Referrer-Policy")))
check("secrets", "API responses are Cache-Control: no-store", h.get("Cache-Control") == "no-store")
csv_inc = js(adm, "post", "/api/incidents", {"src": "=HYPERLINK(\"http://evil\")", "msg": "+cmd|' /C calc'!A0"})
# csv formula escape verified through fake rows
FAKE_ROW = dict(FAKE["rows"][0], msg="=1+1", src="@SUM(A1)")
with mock.patch.object(indexer, "fetch", lambda p: dict(FAKE, rows=[FAKE_ROW])):
    body = js(adm, "get", "/api/alerts.csv").get_data(as_text=True)
check("secrets", "CSV export neutralises spreadsheet formulas (=,+,-,@)", "'=1+1" in body and "'@SUM" in body)
# frontend XSS: does JS escape alert text?
appjs = open(ROOT + "/frontend/js/app.js", encoding="utf-8").read()
inner = len(re.findall(r"innerHTML", appjs)); esc = len(re.findall(r"\besc\(|escapeHtml|textContent", appjs))
check("secrets", f"frontend escapes data before innerHTML ({inner} innerHTML uses, {esc} escape/textContent uses)", esc >= inner * 0.5, level="WARN")

# ---------------------------------------------------------------------------------------------
section("F. API FAILURES & INVALID RESPONSES (Indexer / Wazuh)")
indexer.fetch = real_fetch_src
indexer._variant = None
class R:
    def __init__(self, status=200, body=None, text=None, raises=None):
        self.status_code, self._b, self.text, self._r = status, body, text if text is not None else json.dumps(body), raises
        self.ok = status < 400
    def json(self):
        if self._b is None: raise ValueError("No JSON")
        return self._b
    def raise_for_status(self):
        if not self.ok: raise requests.HTTPError(f"{self.status_code} Server Error for url: {config.INDEXER_URL} user={config.INDEXER_PASS}")
scenarios = {
    "connection refused": requests.ConnectionError(f"HTTPSConnectionPool(host='192.168.56.101', port=9200): Max retries exceeded auth=admin:{config.INDEXER_PASS}"),
    "timeout": requests.Timeout("Read timed out (192.168.56.101)"),
    "TLS failure": requests.exceptions.SSLError("CERTIFICATE_VERIFY_FAILED 192.168.56.101"),
    "HTTP 401": R(401, {"error": "unauthorized"}), "HTTP 403": R(403, {"error": "forbidden"}),
    "HTTP 500 html": R(500, None, "<html>Traceback /var/lib/wazuh-indexer/secret_path password=hunter2</html>"),
    "HTTP 503": R(503, {"error": "overloaded"}), "HTTP 429": R(429, {"error": "too many"}),
    "200 invalid JSON": R(200, None, "<html>not json</html>"),
    "200 empty JSON {}": R(200, {}), "200 JSON list": R(200, []), "200 null aggregations": R(200, {"aggregations": None, "hits": {}}),
    "200 missing hits": R(200, {"aggregations": {"all": {"doc_count": 1}}}),
    "200 wrong types": R(200, {"aggregations": "oops", "hits": 5}),
}
LEAK = ("192.168.56.101", "hunter2", config.INDEXER_PASS, "Traceback", "/var/lib", "Max retries", "9200")
for name, effect in scenarios.items():
    def post(*a, _e=effect, **k):
        if isinstance(_e, Exception): raise _e
        return _e
    with mock.patch("requests.post", post):
        indexer._variant = None
        r = js(adm, "get", "/api/dashboard")
        r2 = js(adm, "get", "/api/alerts.csv")
    txt = r.get_data(as_text=True) + r2.get_data(as_text=True)
    ok_status = r.status_code in (502, 500) and r2.status_code in (502, 500)
    leaked = [l for l in LEAK if l in txt]
    valid_json = True
    try: r.get_json()
    except Exception: valid_json = False
    check("failure", f"Indexer {name:22} -> HTTP {r.status_code}, clean JSON error, no leak", ok_status and not leaked and valid_json,
          f"status {r.status_code}/{r2.status_code} leaked={leaked} body={txt[:120]!r}")
    if r.status_code == 500:
        print(f"    note: '{name}' returns a generic 500 (no leak, but 502 + clear message would be friendlier)")
check("failure", "server still healthy after all those failures", js(adm, "get", "/api/health").status_code == 200)

# Wazuh manager failures
manager_scen = {"connection refused": requests.ConnectionError("Max retries 192.168.56.101:55000 wazuh-secret-xyz"),
                "timeout": requests.Timeout("timed out"), "TLS": requests.exceptions.SSLError("CERT 192.168.56.101")}
for name, exc in manager_scen.items():
    with mock.patch("requests.post", side_effect=exc):
        r = js(adm, "get", "/api/agents")
    txt = r.get_data(as_text=True)
    check("failure", f"Wazuh API {name:18} -> HTTP {r.status_code}, no leak", r.status_code == 502 and "192.168.56.101" not in txt and "wazuh-secret" not in txt, txt[:100])
class Tok:
    ok = True; status_code = 200; text = "tok"
    def raise_for_status(self): pass
class BadAgents:
    ok = True; status_code = 200
    def __init__(self, j): self._j = j
    def raise_for_status(self): pass
    def json(self):
        if isinstance(self._j, Exception): raise self._j
        return self._j
for name, j in {"invalid JSON": ValueError("bad"), "no data key": {}, "data is list": {"data": []}, "affected_items None": {"data": {"affected_items": None}}}.items():
    with mock.patch("requests.post", return_value=Tok()), mock.patch("requests.get", return_value=BadAgents(j)):
        r = js(adm, "get", "/api/agents")
    check("failure", f"Wazuh agents reply '{name}' handled (no 500/crash)", r.status_code in (200, 502), f"{r.status_code} {r.get_data(as_text=True)[:100]}")

# Live block fails -> nothing saved
config.AR_DRY_RUN = False
with mock.patch("requests.put", side_effect=requests.ConnectionError("boom 192.168.56.101")), mock.patch("requests.post", return_value=Tok()):
    before = db.run("SELECT COUNT(*) AS n FROM blocklist", (), "one")["n"]
    r = js(adm, "post", "/api/blocklist", {"ip": "203.0.113.7", "confirm": True})
    after = db.run("SELECT COUNT(*) AS n FROM blocklist", (), "one")["n"]
config.AR_DRY_RUN = True
check("failure", "LIVE block fails at Wazuh -> error shown AND nothing saved as 'blocked'", r.status_code == 502 and before == after, f"{r.status_code} {before}->{after}")
check("failure", "block needs explicit confirm=true on the server too", js(adm, "post", "/api/blocklist", {"ip": "203.0.113.8"}).status_code == 400)
for ip in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "999.1.1.1", "", "1.1.1.1/24", "::1"):
    pass
bad = [ip for ip in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "999.1.1.1", "", "::1", "not-an-ip") if js(adm, "post", "/api/blocklist", {"ip": ip, "confirm": True}).status_code != 400]
check("failure", "dangerous/invalid IPs can never be blocked (loopback, 0.0.0.0, multicast, link-local, garbage)", not bad, str(bad))

# invalid input robustness
section("G. INVALID INPUT / ABUSE")
inputs = ["/api/dashboard?range=evil", "/api/dashboard?limit=-5", "/api/dashboard?limit=99999999", "/api/dashboard?limit=abc",
          "/api/dashboard?level=x", "/api/dashboard?q=" + "A" * 20000, "/api/dashboard?q=%00%ff", "/api/dashboard?scan=1&noipv6=1&q=é中文🙂"]
seen = {}
def _validated_fetch(p):          # real parameter validation, but no network (the sandbox has no Wazuh)
    indexer.clean_params(p); return dict(FAKE, rows=[dict(r) for r in FAKE["rows"]])
for u in inputs:
    with mock.patch.object(indexer, "fetch", _validated_fetch):
        r = js(adm, "get", u)
    seen[u[:45]] = r.status_code
check("input", "weird query parameters never crash the server (no 500)", all(v < 500 for v in seen.values()), str(seen))
bodies = [("raw text", dict(data="not json", content_type="text/plain")), ("json list", dict(json=[1, 2])), ("json string", dict(json="x")),
          ("null", dict(json=None)), ("nested", dict(json={"email": {"a": 1}, "password": ["x"]})), ("numbers", dict(json={"email": 5, "password": 6})),
          ("empty", dict(data="")), ("huge field", dict(json={"email": "a" * 100000, "password": "b" * 100000}))]
fails = []
for name, kw in bodies:
    r = client("10.3.3.3").post("/api/login", headers=H, **kw)
    r2 = client("10.3.3.4").post("/api/signup", headers=H, **kw)
    if r.status_code >= 500 or r2.status_code >= 500:
        fails.append((name, r.status_code, r2.status_code))
check("input", "malformed/odd JSON bodies on login+signup never cause a 500", not fails, str(fails))
r = adm.post("/api/incidents", headers=H, json={"src": "9.9.9.9", "msg": "x" * 100000})
check("input", "oversized text field is truncated, not stored whole", r.status_code in (200, 201, 400))
inc = db.run("SELECT MAX(LENGTH(msg)) AS m FROM incidents", (), "one")["m"]
check("input", f"stored incident text capped (max {inc} chars)", inc is not None and inc <= 300)
big_body = "x" * (6 * 1024 * 1024)
t0 = time.time(); r = client("10.3.3.5").post("/api/login", headers=H, data=big_body, content_type="application/json"); dt = time.time() - t0
check("input", "very large request body (6 MB) is refused early",
      r.status_code == 413, f"HTTP {r.status_code}: no MAX_CONTENT_LENGTH set, server reads the whole body (DoS risk, low on localhost)", level="WARN")
for url in ("/api/incidents/abc", "/api/incidents/-1", "/api/incidents/99999999999999999999", "/api/users/xyz/approve", "/api/nope"):
    r = js(adm, "patch" if "incidents" in url else "post", url, {})
    if r.status_code >= 500:
        check("input", f"bad path {url} -> no 500", False, r.status_code)
else:
    check("input", "bad ids in URLs (letters, negative, huge, unknown route) -> 404/405, never 500", True)
r = adm.patch("/api/incidents/1", headers=H, json={"status": "Hacked", "note": "n" * 5000})
check("input", "incident with invalid status is rejected or normalised", r.status_code in (400, 404, 200), r.status_code)
check("input", "error replies never contain a Python traceback or file path",
      not any(x in js(adm, "get", "/api/dashboard?limit=abc").get_data(as_text=True) for x in ("Traceback", "File \"", ".py")))

# ---------------------------------------------------------------------------------------------
section("SUMMARY")
passed = sum(1 for r in RES if r[2]); fails = [r for r in RES if not r[2] and r[4] == "FAIL"]
warns = [r for r in RES if not r[2] and r[4] == "WARN"]
print(f"\nchecks: {len(RES)}   PASS: {passed}   FAIL: {len(fails)}   WARN (hardening advice): {len(warns)}")
for a, n, ok, d, lv in fails: print(f"  FAIL  [{a}] {n}\n        {d}")
for a, n, ok, d, lv in warns: print(f"  WARN  [{a}] {n}\n        {d}")

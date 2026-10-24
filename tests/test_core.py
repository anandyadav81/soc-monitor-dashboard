"""Run from the project folder:  python -m unittest discover -s tests -v
No Wazuh needed: the Indexer call is replaced by fake data."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _isolate  # noqa: E402,F401  (must come before config: no real .env / SOC_* variables in tests)
import app as app_module  # noqa: E402
import auth  # noqa: E402
import config  # noqa: E402
from services import blocklist, incidents, users  # noqa: E402
from wazuh import indexer  # noqa: E402

REAL_FETCH = indexer.fetch
H = {"X-Requested-With": "mini-soc"}
ADMIN_PW = "Test-Admin-Pw-2026"   # must satisfy the password policy (the first-start admin password is validated now)
FAKE = {"total": 3, "matched": 1, "scans": 1, "unique": 1, "levels": ["3"], "tactics": [], "top_ips": [],
        "severity": {"critical": 0, "high": 0, "medium": 0, "low": 3}, "history": [], "categories": [], "top_dst": [], "total_all": 3, "history_all": [],
        "rows": [{"id": "a1", "time": "2026-10-07 03:46:12", "src": "192.168.56.103", "dst": "192.168.56.102",
                  "msg": "Possible Port Scan Detected", "level": "3", "sev": "low", "port": "", "proto": "",
                  "signature": "", "rule_id": "86601", "agent": "target", "tactics": [], "mitre_ids": []}]}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        config.DB_FILE = os.path.join(self.tmp.name, "t.db")
        config.UI_PASSWORD, config.AR_DRY_RUN = ADMIN_PW, True
        auth._fails.clear()
        auth._acct_fails.clear()
        auth._pw_fails.clear()
        auth._signups.clear()
        indexer.fetch = lambda params: dict(FAKE, rows=[dict(r) for r in FAKE["rows"]])
        self.app = app_module.create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        indexer.fetch = REAL_FETCH
        self.tmp.cleanup()

    def login(self, client=None, name=config.DEFAULT_ADMIN_EMAIL, pw=ADMIN_PW):
        name = name if "@" in name else name + "@example.com"   # tests say "viewer1"; the real address is viewer1@example.com
        return (client or self.client).post("/api/login", json={"email": name, "password": pw}, headers=H)

    def admin(self):
        self.login()
        return self.client

    def user_id(self, name):
        name = name if "@" in name else name + "@example.com"
        return next(u["id"] for u in self.client.get("/api/users").get_json()["items"] if u["email"] == name)

    def make_user(self, name, role):
        """Sign up as `name`, let the admin approve with `role`, return a client signed in as that user."""
        self.admin()
        c = self.app.test_client()
        self.assertEqual(c.post("/api/signup", json={"email": name + "@example.com", "password": "pass-" + name + "-12345"}, headers=H).status_code, 201)
        self.assertEqual(self.client.post(f"/api/users/{self.user_id(name)}/approve", json={"role": role}, headers=H).status_code, 200)
        self.assertEqual(self.login(c, name, "pass-" + name + "-12345").status_code, 200)
        return c


class IndexerTests(unittest.TestCase):
    def test_severity(self):
        self.assertEqual([indexer.severity(x) for x in (3, 7, 10, 13, "x")], ["low", "medium", "high", "critical", "low"])

    def test_no_filters_means_no_post_filter(self):
        body = indexer.build_body(indexer.clean_params({}), "data.src_ip")
        self.assertNotIn("post_filter", body)
        self.assertEqual(body["size"], config.MAX_ROWS)

    def test_filters_go_to_the_indexer(self):
        p = indexer.clean_params({"q": "192.168", "level": "3", "scan": "1", "noipv6": "1", "range": "24h"})
        body = indexer.build_body(p, "data.src_ip.keyword")
        pf = body["post_filter"]["bool"]
        self.assertEqual(len(pf["filter"]), 3)  # level, scan, search: they only limit the table
        self.assertEqual(pf["must_not"], [{"wildcard": {"data.src_ip.keyword": "*:*"}}])
        self.assertIn({"term": {"rule.level": 3}}, pf["filter"])
        # the time range limits the counters AND the table, so it sits in the main query
        self.assertIn({"range": {"timestamp": {"gte": "now-24h"}}}, body["query"]["bool"]["filter"])

    def test_short_ipv6_search_is_expanded_to_the_stored_form(self):
        self.assertEqual(indexer.clean_params({"q": "fe80::f17c:e8ed:889f:1366"})["q"], "fe80:0000:0000:0000:f17c:e8ed:889f:1366")
        self.assertEqual(indexer.clean_params({"q": "192.168"})["q"], "192.168")
        self.assertEqual(indexer.clean_params({"q": "port scan"})["q"], "port scan")

    def test_newest_alert_times_are_asked_for(self):
        body = indexer.build_body(indexer.clean_params({}), "data.src_ip")
        self.assertEqual(sorted(body["aggs"]["newest"]["aggs"]), ["critical", "high", "scans"])

    def test_default_range_is_24_hours_and_all_time_is_allowed(self):
        self.assertEqual(indexer.clean_params({})["range"], "24h")
        body = indexer.build_body(indexer.clean_params({"range": "all"}), "data.src_ip")
        self.assertIn({"match_all": {}}, body["query"]["bool"]["filter"])
        with self.assertRaises(ValueError):
            indexer.clean_params({"range": "forever"})

    def test_history_is_complete_and_scan_names_are_a_list(self):
        old = config.SCAN_NAMES
        config.SCAN_NAMES = ["Scan A", "Scan B"]
        try:
            body = indexer.build_body(indexer.clean_params({"scan": "1"}), "data.src_ip")
        finally:
            config.SCAN_NAMES = old
        self.assertEqual(len(body["post_filter"]["bool"]["filter"][0]["bool"]["should"]), 2)
        h = body["aggs"]["history"]["aggs"]["w"]["aggs"]["h"]["date_histogram"]
        self.assertEqual(h["min_doc_count"], 0)
        self.assertEqual((h["extended_bounds"]["max"] - h["extended_bounds"]["min"]) // 3600000, config.HISTORY_HOURS)
        self.assertIn("all_wazuh", body["aggs"])
        self.assertIn("history_all", body["aggs"])

    def test_bad_input_is_rejected(self):
        for bad in ({"level": "3 OR 1=1"}, {"range": "forever"}, {"limit": "abc"}):
            with self.assertRaises(ValueError):
                indexer.clean_params(bad)
        self.assertEqual(indexer.clean_params({"limit": "99999"})["limit"], config.LIMIT_CAP)


class StorageTests(Base):
    def test_validate(self):
        self.assertEqual(blocklist.validate(" 192.168.56.103 "), "192.168.56.103")
        for bad in ("abc", "127.0.0.1", "0.0.0.0", "224.0.0.1", "192.168.56.101", "192.168.56.1"):
            with self.assertRaises(ValueError, msg=bad):
                blocklist.validate(bad)

    def test_incident_dedupe_and_ids(self):
        a, new_a = incidents.create("1.2.3.4", "d", "scan", "3")
        b, new_b = incidents.create("1.2.3.4", "d", "scan", "3")
        c, _ = incidents.create("5.6.7.8", "d", "scan", "3")
        self.assertEqual((a, new_a, b, new_b), (a, True, a, False))
        self.assertNotEqual(a, c)
        self.assertEqual(incidents.list_all()[-1]["count"], 2)
        self.assertEqual(incidents.count_open(), 2)

    def test_same_attacker_and_message_on_two_targets_are_two_incidents(self):
        a, _ = incidents.create("1.2.3.4", "10.0.0.1", "scan", "3")
        b, new_b = incidents.create("1.2.3.4", "10.0.0.2", "scan", "3")
        c, new_c = incidents.create("1.2.3.4", "10.0.0.1", "scan", "3")
        self.assertTrue(new_b)
        self.assertNotEqual(a, b)
        self.assertEqual((c, new_c), (a, False))

    def test_incident_update(self):
        i, _ = incidents.create("1.2.3.4", "d", "scan", "3")
        self.assertTrue(incidents.update(i, "Closed", "done"))
        self.assertFalse(incidents.update(999, "Closed", ""))
        with self.assertRaises(ValueError):
            incidents.update(i, "Nonsense", "")
        self.assertEqual(incidents.count_open(), 0)


class LoginTests(Base):
    def test_first_admin_is_created_once(self):
        self.assertTrue(self.app.admin_created)
        self.assertEqual(self.login().status_code, 200)
        self.assertFalse(app_module.create_app().admin_created)  # second start: nothing new

    def test_login_is_required(self):
        self.assertEqual(self.client.get("/api/dashboard").status_code, 401)
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertEqual(self.login(pw="bad").status_code, 401)
        self.assertEqual(self.login(name="nobody").status_code, 401)

    def test_login_is_rate_limited(self):
        for _ in range(config.LOGIN_MAX_FAILS):
            self.login(pw="bad")
        self.assertEqual(self.login().status_code, 429)

    def test_changes_need_the_csrf_header(self):
        self.assertEqual(self.client.post("/api/login", json={"email": config.DEFAULT_ADMIN_EMAIL, "password": ADMIN_PW}).status_code, 403)


class AdminEmailTests(Base):
    def test_admin_email_can_be_changed_by_setting_and_restart(self):
        config.ADMIN_EMAIL = "admin2@example.com"
        try:
            self.assertFalse(app_module.create_app().admin_created)       # same database: nothing new is created
            self.assertEqual(self.login(name="admin2@example.com").status_code, 200)   # the placeholder admin moved
            self.assertEqual(self.login(name=config.DEFAULT_ADMIN_EMAIL).status_code, 401)
        finally:
            config.ADMIN_EMAIL = config.DEFAULT_ADMIN_EMAIL

    def test_database_from_the_older_username_version_is_upgraded(self):
        import sqlite3
        from werkzeug.security import generate_password_hash
        path = os.path.join(self.tmp.name, "old.db")
        con = sqlite3.connect(path)
        con.executescript("""CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT,
            role TEXT, status TEXT, must_change INTEGER DEFAULT 0, sv INTEGER DEFAULT 0, created TEXT, approved_by TEXT, approved_at TEXT);""")
        con.execute("INSERT INTO users (username,password_hash,role,status,created,approved_by,approved_at) VALUES ('admin',?,'admin','active','x','system','x')",
                    (generate_password_hash("oldpw12345"),))
        con.commit()
        con.close()
        config.DB_FILE = path
        client = app_module.create_app().test_client()
        r = client.post("/api/login", json={"email": config.DEFAULT_ADMIN_EMAIL, "password": "oldpw12345"}, headers=H)
        self.assertEqual(r.status_code, 200)


class SignupTests(Base):
    def test_signup_waits_for_approval(self):
        c = self.app.test_client()
        self.assertEqual(c.post("/api/signup", json={"email": "Rahul@Example.com", "password": "long-enough-pw1"}, headers=H).status_code, 201)
        r = self.login(c, "rahul", "long-enough-pw1")
        self.assertEqual(r.status_code, 403)
        self.assertIn("approval", r.get_json()["error"])
        self.assertEqual(c.get("/api/dashboard").status_code, 401)           # no access at all
        self.assertEqual(self.login(c, "rahul", "wrong-password-1").status_code, 401)  # pending is not revealed to guessers
        self.admin()
        pending = [u for u in self.client.get("/api/users").get_json()["items"] if u["status"] == "pending"]
        self.assertEqual([u["email"] for u in pending], ["rahul@example.com"])
        self.assertEqual(self.client.post(f"/api/users/{pending[0]['id']}/approve", json={"role": "viewer"}, headers=H).status_code, 200)
        self.assertEqual(self.login(c, "rahul", "long-enough-pw1").status_code, 200)
        self.assertEqual(c.get("/api/me").get_json()["role"], "viewer")

    def test_signup_validation(self):
        c = self.app.test_client()
        for body in ({"email": "ab", "password": "long-enough-pw1"}, {"email": "not an email@x.com", "password": "long-enough-pw1"},
                     {"email": "no-at-sign.com", "password": "long-enough-pw1"}, {"email": "okname@example.com", "password": "short"},
                     {"email": "okname@example.com", "password": "okname@example.com"}, {"email": "person@example.com", "password": "person"}):
            self.assertEqual(c.post("/api/signup", json=body, headers=H).status_code, 400, msg=body)
        self.assertEqual(c.post("/api/signup", json={"email": "okname@example.com", "password": "long-enough-pw1"}, headers=H).status_code, 201)
        self.assertEqual(c.post("/api/signup", json={"email": "OKNAME@EXAMPLE.COM", "password": "long-enough-pw1"}, headers=H).status_code, 201)  # duplicate: same answer, no leak

    def test_signup_is_rate_limited(self):
        c = self.app.test_client()
        codes = [c.post("/api/signup", json={"email": f"user{i}@example.com", "password": "long-enough-pw1"}, headers=H).status_code
                 for i in range(config.SIGNUP_MAX_PER_HOUR + 1)]
        self.assertEqual(codes[-1], 429)

    def test_passwords_are_not_stored_as_text(self):
        self.admin()
        import sqlite3
        rows = sqlite3.connect(config.DB_FILE).execute("SELECT password_hash FROM users").fetchall()
        self.assertTrue(all(ADMIN_PW not in r[0] and ":" in r[0] for r in rows))


class RoleTests(Base):
    def test_viewer_can_look_but_not_change(self):
        v = self.make_user("viewer1", "viewer")
        self.assertEqual(v.get("/api/dashboard").status_code, 200)
        self.assertEqual(v.get("/api/incidents").status_code, 200)
        self.assertEqual(v.get("/api/alerts.csv").status_code, 403)
        self.assertEqual(v.post("/api/incidents", json={"src": "1.2.3.4", "msg": "x"}, headers=H).status_code, 403)
        self.assertEqual(v.post("/api/blocklist", json={"ip": "1.2.3.4", "confirm": True}, headers=H).status_code, 403)
        self.assertEqual(v.get("/api/audit").status_code, 403)
        self.assertEqual(v.get("/api/users").status_code, 403)

    def test_analyst_handles_incidents_but_cannot_block(self):
        a = self.make_user("analyst1", "analyst")
        self.assertEqual(a.get("/api/alerts.csv").status_code, 200)
        r = a.post("/api/incidents", json={"src": "1.2.3.4", "msg": "scan"}, headers=H)
        self.assertEqual(r.status_code, 201)
        self.assertEqual(a.patch(f"/api/incidents/{r.get_json()['id']}", json={"status": "Closed"}, headers=H).status_code, 200)
        self.assertEqual(a.post("/api/blocklist", json={"ip": "1.2.3.4", "confirm": True}, headers=H).status_code, 403)
        self.assertEqual(a.post("/api/users/1/approve", json={}, headers=H).status_code, 403)

    def test_audit_shows_who_did_it(self):
        a = self.make_user("analyst1", "analyst")
        a.post("/api/incidents", json={"src": "1.2.3.4", "msg": "scan"}, headers=H)
        log = self.client.get("/api/audit").get_json()["items"]
        self.assertIn(("analyst1@example.com", "incident.create"), [(x["actor"], x["action"]) for x in log])
        self.assertIn((config.DEFAULT_ADMIN_EMAIL, "user.approve"), [(x["actor"], x["action"]) for x in log])


class UserAdminTests(Base):
    def test_disabling_signs_the_user_out_at_once(self):
        v = self.make_user("viewer1", "viewer")
        self.assertEqual(v.get("/api/dashboard").status_code, 200)
        self.client.post(f"/api/users/{self.user_id('viewer1')}/status", json={"status": "disabled"}, headers=H)
        self.assertEqual(v.get("/api/dashboard").status_code, 401)
        self.assertEqual(self.login(v, "viewer1", "pass-viewer1-12345").status_code, 403)

    def test_role_change_applies_at_once(self):
        a = self.make_user("analyst1", "analyst")
        self.client.post(f"/api/users/{self.user_id('analyst1')}/role", json={"role": "viewer"}, headers=H)
        self.assertEqual(a.post("/api/incidents", json={"src": "1.2.3.4", "msg": "x"}, headers=H).status_code, 403)

    def test_cannot_remove_the_last_admin_or_yourself(self):
        self.admin()
        me = self.user_id(config.DEFAULT_ADMIN_EMAIL)
        for path, body in ((f"/api/users/{me}/status", {"status": "disabled"}), (f"/api/users/{me}/role", {"role": "viewer"}),
                           (f"/api/users/{me}/reset", {"password": "another-long-pw1"})):
            self.assertEqual(self.client.post(path, json=body, headers=H).status_code, 400)
        self.assertEqual(self.client.delete(f"/api/users/{me}", headers=H).status_code, 400)
        with self.assertRaises(ValueError):
            users.set_role(me, "viewer", "test")  # the service itself refuses too

    def test_admin_reset_forces_a_new_password(self):
        v = self.make_user("viewer1", "viewer")
        r = self.client.post(f"/api/users/{self.user_id('viewer1')}/reset", json={"password": "temporary-pass-1"}, headers=H)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(v.get("/api/dashboard").status_code, 401)            # old session is gone
        self.assertEqual(self.login(v, "viewer1", "pass-viewer1-12345").status_code, 401)  # old password is gone
        self.assertEqual(self.login(v, "viewer1", "temporary-pass-1").status_code, 200)
        self.assertEqual(v.get("/api/dashboard").status_code, 403)            # must change first
        self.assertEqual(v.get("/api/me").status_code, 200)
        self.assertEqual(v.post("/api/change-password", json={"old": "temporary-pass-1", "new": "my-own-new-pass1"}, headers=H).status_code, 200)
        self.assertEqual(v.get("/api/dashboard").status_code, 200)

    def test_change_password_checks(self):
        v = self.make_user("viewer1", "viewer")
        bad = ({"old": "wrong", "new": "my-own-new-pass1"}, {"old": "pass-viewer1-12345", "new": "short"},
               {"old": "pass-viewer1-12345", "new": "pass-viewer1-12345"})
        for body in bad:
            self.assertEqual(v.post("/api/change-password", json=body, headers=H).status_code, 400, msg=body)

    def test_reject_deletes_a_pending_account(self):
        self.admin()
        c = self.app.test_client()
        c.post("/api/signup", json={"email": "spammer@example.com", "password": "long-enough-pw1"}, headers=H)
        self.assertEqual(self.client.delete(f"/api/users/{self.user_id('spammer')}", headers=H).status_code, 200)
        self.assertEqual(self.login(c, "spammer", "long-enough-pw1").status_code, 401)


class ApiTests(Base):
    def test_dashboard_and_csv(self):
        self.admin()
        d = self.client.get("/api/dashboard").get_json()
        self.assertEqual(d["rows"][0]["blocked"], False)
        self.assertEqual(d["ar_mode"], "dry-run")
        self.assertIn("192.168.56.103", self.client.get("/api/alerts.csv").get_data(as_text=True))

    def test_block_flow(self):
        self.admin()
        body = {"ip": "192.168.56.103", "reason": "scan"}
        self.assertEqual(self.client.post("/api/blocklist", json=body, headers=H).status_code, 400)      # no confirm
        self.assertEqual(self.client.post("/api/blocklist", json={**body, "confirm": True}, headers=H).status_code, 201)
        self.assertEqual(self.client.post("/api/blocklist", json={**body, "confirm": True}, headers=H).status_code, 400)  # twice
        self.assertEqual(self.client.post("/api/blocklist", json={"ip": "192.168.56.101", "confirm": True}, headers=H).status_code, 400)
        self.assertTrue(self.client.get("/api/dashboard").get_json()["rows"][0]["blocked"])
        bid = self.client.get("/api/blocklist").get_json()["items"][0]["id"]
        self.assertEqual(self.client.post(f"/api/blocklist/{bid}/unblock", headers=H).status_code, 200)
        self.assertEqual(self.client.post(f"/api/blocklist/{bid}/unblock", headers=H).status_code, 404)
        actions = [a["action"] for a in self.client.get("/api/audit").get_json()["items"]]
        self.assertIn("ip.block", actions)
        self.assertIn("ip.unblock", actions)

    def test_incident_api(self):
        self.admin()
        r = self.client.post("/api/incidents", json={"src": "1.2.3.4", "msg": "scan"}, headers=H)
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.client.patch(f"/api/incidents/{r.get_json()['id']}", json={"status": "Closed"}, headers=H).status_code, 200)
        self.assertEqual(self.client.patch("/api/incidents/999", json={"status": "Closed"}, headers=H).status_code, 404)
        self.assertEqual(self.client.patch(f"/api/incidents/{r.get_json()['id']}", json={"status": "x"}, headers=H).status_code, 400)


class AgentTests(Base):
    def test_agents_endpoint(self):
        from wazuh import manager
        real = manager.list_agents
        try:
            manager.list_agents = lambda: [{"id": "001", "name": "ubuntu", "status": "active", "ip": "1.1.1.1", "last_seen": ""}]
            v = self.make_user("viewer1", "viewer")
            self.assertEqual(v.get("/api/agents").get_json()["items"][0]["name"], "ubuntu")

            def boom():
                raise RuntimeError("no password")
            manager.list_agents = boom
            r = v.get("/api/agents")
            self.assertEqual(r.status_code, 502)
            self.assertNotIn("no password", r.get_data(as_text=True))   # the raw exception text is for the server log only
            self.assertIn("error", r.get_json())
        finally:
            manager.list_agents = real
        self.assertEqual(self.app.test_client().get("/api/agents").status_code, 401)

    def test_agents_not_configured_is_a_normal_answer(self):
        old = config.WAZUH_API_PASS
        config.WAZUH_API_PASS = ""
        try:
            r = self.admin().get("/api/agents")
        finally:
            config.WAZUH_API_PASS = old
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(r.get_json()["items"])
        self.assertIn("SOC_WAZUH_API_PASS", r.get_json()["message"])

    def test_list_agents_needs_the_password_and_skips_the_manager(self):
        from wazuh import manager
        old = config.WAZUH_API_PASS
        real_get, real_token = manager.requests.get, manager._token
        try:
            config.WAZUH_API_PASS = ""
            with self.assertRaises(RuntimeError):
                manager.list_agents()
            config.WAZUH_API_PASS = "x"

            class R:
                def raise_for_status(self):
                    pass

                def json(self):
                    return {"data": {"affected_items": [{"id": "000", "name": "manager", "status": "active"},
                                                        {"id": "001", "name": "ubuntu", "status": "active", "lastKeepAlive": "2026-10-14T04:00:00+00:00"}]}}
            manager.requests.get, manager._token = lambda *a, **k: R(), lambda: "token"
            self.assertEqual([a["id"] for a in manager.list_agents()], ["001"])
        finally:
            config.WAZUH_API_PASS = old
            manager.requests.get, manager._token = real_get, real_token


class IndexerLoginTests(unittest.TestCase):
    def test_wrong_indexer_password_gets_a_clear_message_without_retries(self):
        calls = []

        class Reply:
            ok, status_code = False, 401

        real = indexer.requests.post
        indexer.requests.post = lambda *a, **k: calls.append(1) or Reply()
        indexer._variant = None
        try:
            with self.assertRaises(RuntimeError) as cm:
                REAL_FETCH({})
        finally:
            indexer.requests.post = real
        self.assertIn("refused the login", str(cm.exception))
        self.assertEqual(len(calls), 1)


class FetchParsingTests(unittest.TestCase):
    """indexer.fetch with a fake Indexer: checks the fallbacks and the parsing."""

    def test_fallback_and_parse(self):
        calls = []

        class Reply:
            def __init__(self, ok, payload=None):
                self.ok, self.payload = ok, payload
                self.status_code = 200 if ok else 400

            def json(self):
                return self.payload

            def raise_for_status(self):
                if not self.ok:
                    raise RuntimeError("HTTP error")

        def each(buckets, name="h"):
            return {"w": {name: {"buckets": buckets}}}
        hour = [{"key_as_string": "2026-10-07T03:00:00.000Z", "doc_count": 2, "scan": {"doc_count": 1}}]
        good = {"hits": {"total": {"value": 2}, "hits": [{"_id": "x1", "_source": {
                    "timestamp": "2026-10-07T03:46:12.000+0000", "data": {"src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"},
                    "rule": {"description": "Possible Port Scan Detected", "level": 12, "id": "86601",
                             "mitre": {"id": ["T1046"], "tactic": ["Discovery"]}}}}]},
                "aggregations": {"all": {"doc_count": 9}, "all_wazuh": {"w": {"doc_count": 90}}, "scans": {"doc_count": 4},
                                 "unique_ips": {"value": 2},
                                 "levels": each([{"key": 3, "doc_count": 70}, {"key": 12, "doc_count": 20}], "l"),
                                 "top_ips": {"buckets": [{"key": "1.2.3.4", "doc_count": 2}]},
                                 "top_dst": {"buckets": [{"key": "5.6.7.8", "doc_count": 2}]},
                                 "tactics": each([{"key": "Discovery", "doc_count": 2}], "t"),
                                 "categories": each([{"key": "Possible Port Scan Detected", "doc_count": 2}], "c"),
                                 "history": each(hour),
                                 "history_all": each([{"key_as_string": "2026-10-07T03:00:00.000Z", "doc_count": 20}]),
                                 "newest": {"doc_count": 90, "critical": {"doc_count": 1, "t": {"value": 1760000000000.0}},
                                            "high": {"doc_count": 0, "t": {"value": None}}, "scans": {"doc_count": 4, "t": {"value": 1760000100000.0}}}}}

        def fake_post(url, json=None, **kw):
            calls.append(json)
            return Reply(len(calls) >= 2, good)  # first try fails, the .keyword field name works

        real = indexer.requests.post
        indexer.requests.post = fake_post
        indexer._variant = None
        try:
            d = REAL_FETCH({})
            self.assertEqual(len(calls), 2)
            REAL_FETCH({})
            self.assertEqual(len(calls), 3)  # the option that worked is remembered: one request this time
        finally:
            indexer.requests.post = real
            indexer._variant = None
        self.assertEqual(d["newest"], {"critical": 1760000000000.0, "high": None, "scans": 1760000100000.0})
        self.assertEqual((d["total"], d["total_all"], d["matched"], d["scans"], d["unique"]), (9, 90, 2, 4, 2))
        self.assertEqual(d["severity"], {"critical": 0, "high": 20, "medium": 0, "low": 70})  # every Wazuh alert, adds up to total_all
        self.assertEqual(d["levels"], ["3", "12"])
        self.assertEqual(d["rows"][0]["sev"], "high")
        self.assertEqual(d["rows"][0]["tactics"], ["Discovery"])
        self.assertEqual(d["tactics"][0]["name"], "Discovery")
        self.assertEqual(d["categories"][0]["name"], "Possible Port Scan Detected")
        self.assertEqual(d["history"][0]["label"], "10-07T03:00")
        self.assertEqual(d["history"][0]["scans"], 1)
        self.assertEqual(d["top_dst"][0]["ip"], "5.6.7.8")
        self.assertEqual(d["history_all"][0]["count"], 20)


if __name__ == "__main__":
    unittest.main()

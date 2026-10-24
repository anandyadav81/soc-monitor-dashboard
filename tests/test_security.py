"""Step 1 security tests. Run from the project folder:  python -m unittest discover -s tests -v
No Wazuh needed: every Wazuh answer below is a fake, and nothing here touches a firewall or the network."""
import contextlib
import io
import logging
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

BACKEND = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # so `from test_core import ...` works however the tests are started

import _isolate  # noqa: E402,F401  (must come before config: no real .env / SOC_* variables in tests)
import requests  # noqa: E402

import api  # noqa: E402
import auth  # noqa: E402
import app as app_module  # noqa: E402
import config  # noqa: E402
import manage  # noqa: E402
import safety  # noqa: E402
import selftest  # noqa: E402
from services import blocklist, db, users  # noqa: E402
from wazuh import indexer, intel, manager  # noqa: E402
from test_core import ADMIN_PW, REAL_FETCH, Base, H  # noqa: E402

INDEXER_SECRET, WAZUH_SECRET = "S3cretIndexerPw!", "S3cretWazuhPw!"
# None of these may ever appear in a response body that a browser receives.
FORBIDDEN = ("192.168", "9200", "55000", "HTTPSConnectionPool", "Max retries", "https://", "http://", "Traceback",
             INDEXER_SECRET, WAZUH_SECRET, "SOC_INDEXER", "SOC_WAZUH", "/var/ossec", "aggregations")


class FakeReply:
    def __init__(self, status=200, text="", payload=None, url="https://192.168.56.101:9200/wazuh-alerts-*/_search"):
        self.status_code, self.ok, self.text, self._payload, self.url = status, status < 400, text, payload, url

    def json(self):
        return self._payload

    def raise_for_status(self):
        if not self.ok:
            raise requests.exceptions.HTTPError(f"{self.status_code} Server Error: Internal Server Error for url: {self.url}", response=self)


class Tty(io.StringIO):
    def isatty(self):
        return True


# ======================================================================================= 1. error leakage
class RedactTests(unittest.TestCase):
    def test_secret_shapes_are_removed(self):
        cases = {
            "Authorization: Bearer abcDEF123456.xyz": "abcDEF123456",
            "Authorization: Basic dXNlcjpwYXNzd29yZA==": "dXNlcjpwYXNzd29yZA==",
            "token eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM": "eyJhbGciOi",
            "https://wazuh-wui:hunter2hunter2@10.0.0.5:55000/x": "hunter2hunter2",
            "password=hunter2hunter2&user=a": "hunter2hunter2",
            '{"password": "hunter2hunter2"}': "hunter2hunter2",
            "api_key: abcdef123456": "abcdef123456",
        }
        for text, secret in cases.items():
            out = safety.redact(text)
            self.assertNotIn(secret, out, msg=text)
            self.assertIn(safety.MASK, out, msg=text)

    def test_configured_secrets_are_removed_wherever_they_appear(self):
        with mock.patch.object(config, "INDEXER_PASS", INDEXER_SECRET), mock.patch.object(config, "WAZUH_API_PASS", WAZUH_SECRET):
            out = safety.redact(f"login failed for {INDEXER_SECRET} and also {WAZUH_SECRET}")
        self.assertNotIn(INDEXER_SECRET, out)
        self.assertNotIn(WAZUH_SECRET, out)

    def test_ordinary_text_and_addresses_survive_and_tiny_secrets_do_not_wreck_the_log(self):
        text = "Max retries exceeded with url: /agents on 192.168.56.101:55000"   # operators need this in the LOG
        self.assertEqual(safety.redact(text), text)
        with mock.patch.object(config, "INDEXER_PASS", "x"):
            self.assertEqual(safety.redact("xyz text"), "xyz text")

    def test_clip_makes_one_short_line(self):
        self.assertEqual(safety.clip("a\nb\r\nc"), "a b c")
        self.assertEqual(len(safety.clip("z" * 900)), 503)

    def test_the_logger_redacts_messages_and_tracebacks(self):
        with self.assertLogs("minisoc", level="ERROR") as cm:
            safety.log.error("upstream said Bearer aaaaaaaaaaaa")
            try:
                raise ValueError("password=hunter2hunter2")
            except ValueError as e:
                safety.log.error("boom", exc_info=e)
        text = "\n".join(cm.output)
        self.assertNotIn("aaaaaaaaaaaa", text)
        self.assertNotIn("hunter2hunter2", text)
        self.assertIn("ValueError", text)   # the diagnostics are still there

    def test_selftest_details_are_redacted_too(self):   # selftest-report.txt is meant to be shared
        def fails():
            raise requests.exceptions.SSLError(f"bad cert for https://admin:{INDEXER_SECRET}@10.0.0.1:9200")
        selftest.RESULTS.clear()
        with mock.patch.object(config, "INDEXER_PASS", INDEXER_SECRET), contextlib.redirect_stdout(io.StringIO()) as out:
            selftest.run("x", fails)
        detail = selftest.RESULTS[-1][2]
        selftest.RESULTS.clear()
        self.assertNotIn(INDEXER_SECRET, detail + out.getvalue())


class UpstreamErrorTests(Base):
    """A signed-in VIEWER (the least privileged user) must never see technical detail; the server log must."""

    def setUp(self):
        super().setUp()
        self._old = (config.INDEXER_PASS, config.WAZUH_API_PASS, config.AR_DRY_RUN)
        config.INDEXER_PASS, config.WAZUH_API_PASS = INDEXER_SECRET, WAZUH_SECRET
        indexer.fetch = REAL_FETCH
        indexer._variant = None
        self.viewer = self.make_user("viewer1", "viewer")

    def tearDown(self):
        config.INDEXER_PASS, config.WAZUH_API_PASS, config.AR_DRY_RUN = self._old
        indexer._variant = None
        super().tearDown()

    def clean(self, resp, status):
        body = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, status, msg=body)
        for bad in FORBIDDEN:
            self.assertNotIn(bad, body, msg=f"{bad!r} leaked to the browser: {body}")
        self.assertIn("error", resp.get_json())
        return resp.get_json()["error"]

    def dashboard_with(self, post):
        with mock.patch.object(requests, "post", post), self.assertLogs("minisoc", level="ERROR") as cm:
            resp = self.viewer.get("/api/dashboard")
        return resp, "\n".join(cm.output)

    def test_connection_failure(self):
        def post(*a, **k):
            raise requests.exceptions.ConnectionError("HTTPSConnectionPool(host='192.168.56.101', port=9200): Max retries exceeded with url: /wazuh-alerts-*/_search")
        resp, log = self.dashboard_with(post)
        self.assertEqual(self.clean(resp, 502), "Cannot reach the Wazuh Indexer.")
        self.assertIn("192.168.56.101", log)       # the operator still gets the diagnostics

    def test_tls_failure_is_reported_not_swallowed(self):
        def post(*a, **k):
            raise requests.exceptions.SSLError("HTTPSConnectionPool(host='192.168.56.101', port=9200): certificate verify failed: self-signed certificate")
        resp, log = self.dashboard_with(post)
        self.assertIn("TLS certificate verification failed", self.clean(resp, 502))
        self.assertIn("verification FAILED", log)
        self.assertIn("self-signed certificate", log)

    def test_timeout(self):
        def post(*a, **k):
            raise requests.exceptions.ReadTimeout("HTTPSConnectionPool(host='192.168.56.101', port=9200): Read timed out.")
        resp, _ = self.dashboard_with(post)
        self.assertEqual(self.clean(resp, 502), "The Wazuh Indexer did not answer in time.")

    def test_indexer_http_error_body_goes_to_the_log_only_and_redacted(self):
        body = '{"error":"reason: password=' + INDEXER_SECRET + ' Bearer abcdef.123456.xyzxyz"}'
        resp, log = self.dashboard_with(lambda *a, **k: FakeReply(500, text=body))
        self.assertEqual(self.clean(resp, 502), "The Wazuh Indexer returned an error.")
        self.assertIn("HTTP 500", log)
        self.assertNotIn(INDEXER_SECRET, log)
        self.assertNotIn("abcdef.123456.xyzxyz", log)

    def test_indexer_login_refused(self):
        resp, log = self.dashboard_with(lambda *a, **k: FakeReply(401, text="unauthorized"))
        self.assertIn("rejected the server's login", self.clean(resp, 502))
        self.assertIn("SOC_INDEXER_USER", log)     # the hint is for the operator's log

    def test_wazuh_refusal_text_is_not_shown_and_nothing_is_saved(self):
        config.AR_DRY_RUN = False   # mocked below: no request ever leaves this test
        refusal = {"data": {"total_failed_items": 1, "failed_items": [{"error": {"message": "Agent 001 internal path /var/ossec/etc/x not found"}}]}}
        with mock.patch.object(requests, "post", lambda *a, **k: FakeReply(200, text="tok")), \
                mock.patch.object(requests, "put", lambda *a, **k: FakeReply(200, payload=refusal)), \
                self.assertLogs("minisoc", level="ERROR") as cm:
            resp = self.client.post("/api/blocklist", json={"ip": "203.0.113.9", "reason": "t", "confirm": True}, headers=H)
        self.assertEqual(self.clean(resp, 502), "Wazuh refused the command. See the server log for the reason.")
        self.assertIn("/var/ossec", "\n".join(cm.output))
        self.assertEqual(blocklist.list_all(), [])

    def test_missing_api_password_does_not_name_settings_to_the_browser(self):
        config.AR_DRY_RUN, config.WAZUH_API_PASS = False, ""
        with self.assertLogs("minisoc", level="ERROR"):
            resp = self.client.post("/api/blocklist", json={"ip": "203.0.113.9", "confirm": True}, headers=H)
        self.assertIn("not configured", self.clean(resp, 502))

    def test_agents_transport_failure(self):
        def get(*a, **k):
            raise requests.exceptions.ConnectionError("HTTPSConnectionPool(host='192.168.56.101', port=55000): Max retries exceeded")
        with mock.patch.object(requests, "post", lambda *a, **k: FakeReply(200, text="tok")), \
                mock.patch.object(requests, "get", get), self.assertLogs("minisoc", level="ERROR") as cm:
            resp = self.viewer.get("/api/agents")
        self.assertEqual(self.clean(resp, 502), "Cannot reach the Wazuh API.")
        self.assertIn("192.168.56.101", "\n".join(cm.output))

    def test_unexpected_exceptions_become_a_plain_500_and_keyerror_is_not_a_404(self):
        for exc in (KeyError("aggregations"), IndexError("hits"), ZeroDivisionError("division by zero 192.168.56.101")):
            indexer.fetch = mock.Mock(side_effect=exc)
            with self.assertLogs("minisoc", level="ERROR") as cm:
                resp = self.viewer.get("/api/dashboard")
            self.assertEqual(self.clean(resp, 500), "Internal server error")
            self.assertIn(type(exc).__name__, "\n".join(cm.output))

    def test_plain_runtime_error_text_is_hidden(self):
        indexer.fetch = mock.Mock(side_effect=RuntimeError("secret detail 192.168.56.101"))
        with self.assertLogs("minisoc", level="ERROR"):
            resp = self.viewer.get("/api/dashboard")
        self.assertEqual(self.clean(resp, 502), "The request could not be completed. See the server log.")

    def test_intended_messages_still_work(self):
        self.assertEqual(self.client.patch("/api/incidents/999", json={"status": "Closed"}, headers=H).get_json()["error"], "Incident not found")
        self.assertEqual(self.client.post("/api/blocklist", json={"ip": "abc", "confirm": True}, headers=H).get_json()["error"], "That is not a valid IP address")
        self.assertEqual(self.viewer.post("/api/health", headers=H).status_code, 405)   # normal HTTP errors pass through


# ======================================================================================= 2. passwords
class PasswordPolicyTests(Base):
    def test_policy_rules(self):
        for pw in ("short", "x" * 129, "you@example.com", "aaaaaaaaaaaa", "abababababab", "Password123", "1234567890", "QWERTYUIOP"):
            with self.assertRaises(ValueError, msg=pw):
                users.check_password(pw, "you@example.com")
        with self.assertRaises(ValueError):    # the first part of the email, long enough to pass the length rule
            users.check_password("yourlongname", "yourlongname@example.com")
        for pw in ("pass-viewer1-12345", "correct horse battery", "Tr0ub4dor&3-long"):
            self.assertEqual(users.check_password(pw, "you@example.com"), pw)

    def test_messages_never_repeat_the_password(self):
        for pw in ("aaaaaaaaaaaa", "Password123"):
            with self.assertRaises(ValueError) as cm:
                users.check_password(pw)
            self.assertNotIn(pw, str(cm.exception))

    def test_generated_passwords_always_pass(self):
        for _ in range(300):
            users.check_password(users.generate_password())

    def test_signup_enforces_it(self):
        c = self.app.test_client()
        for i, pw in enumerate(("aaaaaaaaaaaa", "Password123", "short")):
            self.assertEqual(c.post("/api/signup", json={"email": f"u{i}@example.com", "password": pw}, headers=H).status_code, 400, msg=pw)

    def test_admin_reset_enforces_it(self):
        v = self.make_user("viewer1", "viewer")
        uid = self.user_id("viewer1")
        for pw in ("aaaaaaaaaaaa", "Password123", "short", "viewer1@example.com"):
            self.assertEqual(self.client.post(f"/api/users/{uid}/reset", json={"password": pw}, headers=H).status_code, 400, msg=pw)
        self.assertEqual(v.get("/api/dashboard").status_code, 200)   # nothing changed: the old password and session still work
        self.assertEqual(self.login(v, "viewer1", "pass-viewer1-12345").status_code, 200)

    def test_forced_change_after_reset_enforces_it(self):
        v = self.make_user("viewer1", "viewer")
        self.client.post(f"/api/users/{self.user_id('viewer1')}/reset", json={"password": "temporary-pass-1"}, headers=H)
        self.assertEqual(self.login(v, "viewer1", "temporary-pass-1").status_code, 200)
        for weak in ("aaaaaaaaaaaa", "Password123", "short"):
            self.assertEqual(v.post("/api/change-password", json={"old": "temporary-pass-1", "new": weak}, headers=H).status_code, 400, msg=weak)
        self.assertEqual(v.get("/api/dashboard").status_code, 403)   # still locked to "choose a new password"
        self.assertEqual(v.post("/api/change-password", json={"old": "temporary-pass-1", "new": "my-own-new-pass1"}, headers=H).status_code, 200)
        self.assertEqual(v.get("/api/dashboard").status_code, 200)

    def test_service_level_recovery_and_create_admin_enforce_it(self):
        self.admin()
        with self.assertRaises(ValueError):
            users.force_set_password(config.DEFAULT_ADMIN_EMAIL, "aaaaaaaaaaaa")
        with self.assertRaises(ValueError):
            users.force_set_password(config.DEFAULT_ADMIN_EMAIL, "short")
        with self.assertRaises(LookupError):
            users.force_set_password("nobody@example.com", "a-fine-password-1")
        with self.assertRaises(ValueError):
            users.force_set_password("not an email", "a-fine-password-1")
        self.assertEqual(self.login(pw=ADMIN_PW).status_code, 200)   # the failed attempts changed nothing
        before = users.count()
        with self.assertRaises(ValueError):
            users.create_admin("second@example.com", "short")
        self.assertEqual(users.count(), before)

    def test_first_start_rejects_a_weak_configured_password(self):
        config.DB_FILE = os.path.join(self.tmp.name, "fresh.db")
        config.UI_PASSWORD = "weakpw"
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                app_module.create_app()
        self.assertIn("SOC_UI_PASSWORD is not accepted", str(cm.exception))
        self.assertNotIn("weakpw", str(cm.exception))
        self.assertEqual(users.count(), 0)   # no half-created admin
        config.UI_PASSWORD = "A-good-first-admin-pw1"
        with contextlib.redirect_stdout(io.StringIO()):
            app = app_module.create_app()
        self.assertTrue(app.admin_created)


class ManageRecoveryTests(Base):
    """backend/manage.py is the recovery path: it must still work, and must apply the same rules."""

    def run_manage(self, *argv, passwords=()):
        with mock.patch("getpass.getpass", side_effect=list(passwords)), contextlib.redirect_stdout(io.StringIO()) as out:
            rc = manage.main(list(argv))
        return rc, out.getvalue()

    def test_recovery_with_a_good_password_works(self):
        rc, _ = self.run_manage("reset-password", config.DEFAULT_ADMIN_EMAIL, passwords=["Recovered-Admin-Pw-9"] * 2)
        self.assertEqual(rc, 0)
        self.assertEqual(self.login(pw="Recovered-Admin-Pw-9").status_code, 200)
        self.assertEqual(self.login(pw=ADMIN_PW).status_code, 401)

    def test_weak_password_is_refused_and_nothing_changes(self):
        for weak in ("aaaaaaaaaaaa", "short", "Password123", config.DEFAULT_ADMIN_EMAIL):
            rc, out = self.run_manage("reset-password", config.DEFAULT_ADMIN_EMAIL, passwords=[weak, weak])
            self.assertEqual(rc, 1, msg=weak)
            self.assertIn("Error:", out)
            self.assertNotIn(weak, out)
        self.assertEqual(self.login(pw=ADMIN_PW).status_code, 200)

    def test_mismatch_and_unknown_user_are_refused(self):
        self.assertEqual(self.run_manage("reset-password", config.DEFAULT_ADMIN_EMAIL, passwords=["Recovered-Admin-Pw-9", "different-one-123"])[0], 1)
        self.assertEqual(self.run_manage("reset-password", "nobody@example.com", passwords=["Recovered-Admin-Pw-9"] * 2)[0], 1)
        self.assertEqual(self.login(pw=ADMIN_PW).status_code, 200)

    def test_a_disabled_or_forced_to_change_admin_can_still_be_recovered(self):
        db.run("UPDATE users SET status='disabled', must_change=1 WHERE email=?", (config.DEFAULT_ADMIN_EMAIL,))
        self.assertEqual(self.login(pw=ADMIN_PW).status_code, 403)
        self.assertEqual(self.run_manage("reset-password", config.DEFAULT_ADMIN_EMAIL, passwords=["Recovered-Admin-Pw-9"] * 2)[0], 0)
        self.assertEqual(self.login(pw="Recovered-Admin-Pw-9").status_code, 200)
        self.assertEqual(self.client.get("/api/dashboard").status_code, 200)   # no forced change after CLI recovery

    def test_list_still_works(self):
        rc, out = self.run_manage("list")
        self.assertEqual(rc, 0)
        self.assertIn(config.DEFAULT_ADMIN_EMAIL, out)


# ======================================================================================= 3. TLS
class TlsTests(Base):
    def setUp(self):
        super().setUp()
        self._warnings = list(config.CONFIG_WARNINGS)

    def tearDown(self):
        config.CONFIG_WARNINGS[:] = self._warnings
        super().tearDown()

    def flag(self, value, default=True):
        env = {} if value is None else {"SOC_TEST_FLAG": value}
        with mock.patch.dict(os.environ, env, clear=False):
            if value is None:
                os.environ.pop("SOC_TEST_FLAG", None)
            return config._flag("SOC_TEST_FLAG", default)

    def test_flag_parsing_is_strict(self):
        for v in (None, "", "   ", "tru", "enabled", "maybe"):
            self.assertIs(self.flag(v), True, msg=repr(v))    # unset / empty / unrecognised: the secure default stays
        for v in ("true", "TRUE", " 1 ", "yes", "on"):
            self.assertIs(self.flag(v, default=False), True, msg=repr(v))
        for v in ("false", "FALSE", " 0 ", "no", "off"):
            self.assertIs(self.flag(v), False, msg=repr(v))

    def test_unrecognised_value_is_reported_without_echoing_it(self):
        before = list(config.CONFIG_WARNINGS)
        try:
            self.flag("enabled-ish")
            self.assertEqual(len(config.CONFIG_WARNINGS), len(before) + 1)
            self.assertNotIn("enabled-ish", config.CONFIG_WARNINGS[-1])
        finally:
            config.CONFIG_WARNINGS[:] = before

    def import_config(self, **env):
        clean = {k: v for k, v in os.environ.items() if not k.startswith("SOC_")}
        clean.update(env, PYTHONDONTWRITEBYTECODE="1", SOC_ENV_FILE=_isolate.NO_ENV_FILE)   # a real .env must not change the result
        code = "import config; print(config.INDEXER_VERIFY, config.WAZUH_VERIFY, config.COOKIE_SECURE, config.AR_DRY_RUN)"
        out = subprocess.run([sys.executable, "-c", code], cwd=BACKEND, env=clean, capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, msg=out.stderr)
        return out.stdout.split()

    def test_real_config_import_keeps_verification_on_unless_clearly_told_otherwise(self):
        self.assertEqual(self.import_config(), ["True", "True", "False", "True"])
        for value in ("", "yes", "1", "True ", "tru", "enabled"):   # all of these used to switch verification OFF
            self.assertEqual(self.import_config(SOC_VERIFY_TLS=value, SOC_WAZUH_VERIFY_TLS=value)[:2], ["True", "True"], msg=repr(value))
        self.assertEqual(self.import_config(SOC_VERIFY_TLS="false", SOC_WAZUH_VERIFY_TLS="false")[:2], ["False", "False"])
        self.assertEqual(self.import_config(SOC_VERIFY_TLS="false", SOC_CA_BUNDLE="/some/ca.pem")[0], "/some/ca.pem")  # a CA file wins
        self.assertEqual(self.import_config(SOC_COOKIE_SECURE="1")[2], "True")
        for value in ("0", "no", "off", "", "nonsense"):   # Active Response stays in dry run for anything but exactly "false"
            self.assertEqual(self.import_config(SOC_AR_DRY_RUN=value)[3], "True", msg=repr(value))
        self.assertEqual(self.import_config(SOC_AR_DRY_RUN="false")[3], "False")

    def test_every_request_passes_the_configured_verify_setting(self):
        seen = []

        def record(kind):
            def fn(*a, **k):
                seen.append((kind, k.get("verify")))
                if kind == "post-token":
                    return FakeReply(200, text="tok")
                raise requests.exceptions.ConnectionError("down")
            return fn
        for verify in (True, "/etc/ssl/lab-ca.pem"):
            seen.clear()
            with mock.patch.object(config, "INDEXER_VERIFY", verify), mock.patch.object(config, "WAZUH_VERIFY", verify), \
                    mock.patch.object(config, "WAZUH_API_PASS", "x-api-pass"), self.assertLogs("minisoc", level="ERROR"):
                with mock.patch.object(requests, "post", record("post")):
                    with self.assertRaises(requests.RequestException):
                        REAL_FETCH({})                                  # Indexer
                with mock.patch.object(requests, "post", record("post-token")), mock.patch.object(requests, "get", record("get")), \
                        mock.patch.object(requests, "put", record("put")):
                    with self.assertRaises(RuntimeError):
                        manager.list_agents()                           # token (post) + agents (get)
                    with self.assertRaises(RuntimeError):
                        manager._active_response("!firewall-drop", "203.0.113.9")   # token (post) + active-response (put)
            self.assertEqual({kind for kind, _ in seen}, {"post", "post-token", "get", "put"})
            self.assertTrue(all(v == verify for _, v in seen), msg=seen)

    def test_nothing_in_the_backend_disables_verification_or_hides_the_warning(self):
        banned = re.compile(r"verify\s*=\s*False|disable_warnings|InsecureRequestWarning|filterwarnings|simplefilter|CERT_NONE|check_hostname\s*=\s*False")
        checked = 0
        for root, _, files in os.walk(BACKEND):
            for name in files:
                if name.endswith(".py"):
                    checked += 1
                    with open(os.path.join(root, name), encoding="utf-8") as f:
                        for n, line in enumerate(f, 1):
                            self.assertIsNone(banned.search(line.split("#")[0]), msg=f"{name}:{n}: {line.strip()}")
        self.assertGreater(checked, 10)

    def test_a_missing_ca_file_stops_startup_instead_of_failing_vaguely(self):
        with mock.patch.object(config, "CA_BUNDLE", os.path.join(self.tmp.name, "missing.pem")):
            with self.assertRaises(SystemExit) as cm:
                app_module.create_app()
        self.assertIn("SOC_CA_BUNDLE", str(cm.exception))
        ca = os.path.join(self.tmp.name, "ca.pem")
        open(ca, "w").close()
        with mock.patch.object(config, "CA_BUNDLE", ca):
            app_module.create_app()   # an existing file starts normally

    def test_config_warnings_are_printed_at_startup(self):
        with mock.patch.object(config, "CONFIG_WARNINGS", ["SOC_VERIFY_TLS has a value that is not true/false, so the default (true) is used."]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            app_module.create_app()
        self.assertIn("not true/false", out.getvalue())


# ======================================================================================= 3b. .env file
class DotenvTests(unittest.TestCase):
    """The .env file keeps the lab settings across restarts, without ever overriding the real environment."""

    def _load(self, text, env=None):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".env")
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            with mock.patch.dict(os.environ, env or {}, clear=False):
                before = set(os.environ)
                n = config.load_dotenv(path)
                loaded = {k: os.environ[k] for k in set(os.environ) - before}
                for k in loaded:
                    del os.environ[k]
                return n, loaded

    def test_reads_values_quotes_comments_and_export(self):
        n, got = self._load('# comment\n\nSOC_A_TEST=one\nSOC_B_TEST="two words"\nexport SOC_C_TEST=\'three\'\nSOC_D_TEST = four\n')
        self.assertEqual(got, {"SOC_A_TEST": "one", "SOC_B_TEST": "two words", "SOC_C_TEST": "three", "SOC_D_TEST": "four"})
        self.assertEqual(n, 4)

    def test_real_environment_wins(self):
        n, got = self._load("SOC_E_TEST=from-file\n", env={"SOC_E_TEST": "from-shell"})
        self.assertEqual(n, 0)
        self.assertEqual(got, {})

    def test_empty_and_foreign_names_are_skipped(self):
        n, got = self._load("SOC_F_TEST=\nPATH_X_TEST=1\nnot a setting\nSOC_G_TEST=ok\n")
        self.assertEqual(got, {"SOC_G_TEST": "ok"})

    def test_missing_file_is_fine(self):
        self.assertEqual(config.load_dotenv(os.path.join(tempfile.gettempdir(), "no-such-dir-xyz", ".env")), 0)

    def test_utf8_bom_from_windows_notepad(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".env")
            with open(path, "w", encoding="utf-8-sig") as f:
                f.write("SOC_H_TEST=bom-ok\n")
            try:
                self.assertEqual(config.load_dotenv(path), 1)
                self.assertEqual(os.environ["SOC_H_TEST"], "bom-ok")
            finally:
                os.environ.pop("SOC_H_TEST", None)


# ======================================================================================= 3c. robustness (found by the Phase 1 audit)
class RobustnessTests(Base):
    """Odd input and odd upstream replies must give a clean 4xx/502, never a 500 and never a technical detail."""

    def test_non_object_json_bodies_are_treated_as_empty_not_500(self):
        for payload in ([1, 2], "text", 5, None, [{"email": "a"}]):
            for url in ("/api/login", "/api/signup"):
                r = self.client.post(url, json=payload, headers=H)
                self.assertLess(r.status_code, 500, msg=f"{url} {payload!r} -> {r.status_code}")
        admin = self.admin()
        for url in ("/api/incidents", "/api/blocklist", "/api/change-password"):
            r = admin.post(url, json=["not", "an", "object"], headers=H)
            self.assertLess(r.status_code, 500, msg=url)

    def test_huge_ids_in_urls_are_404_not_500(self):
        admin = self.admin()
        big = "9" * 25
        for method, url in (("patch", f"/api/incidents/{big}"), ("post", f"/api/users/{big}/approve"),
                            ("post", f"/api/users/{big}/reset"), ("delete", f"/api/users/{big}"),
                            ("post", f"/api/blocklist/{big}/unblock")):
            r = getattr(admin, method)(url, json={}, headers=H)
            self.assertIn(r.status_code, (400, 404), msg=f"{method} {url} -> {r.status_code}")

    def test_oversized_request_body_is_refused(self):
        r = self.client.post("/api/login", data="x" * (2 * 1024 * 1024), content_type="application/json", headers=H)
        self.assertEqual(r.status_code, 413)

    def test_unreadable_indexer_replies_become_a_clean_502(self):
        indexer.fetch = REAL_FETCH
        indexer._variant = None
        self.admin()

        class Reply:
            status_code, ok, text = 200, True, "<html>secret-path /var/lib/x</html>"

            def __init__(self, data):
                self.data = data

            def raise_for_status(self):
                pass

            def json(self):
                if isinstance(self.data, Exception):
                    raise self.data
                return self.data
        for data in (ValueError("No JSON"), {}, [], {"aggregations": None, "hits": {}}, {"aggregations": "x", "hits": 5}):
            indexer._variant = None
            with mock.patch.object(requests, "post", return_value=Reply(data)), self.assertLogs("minisoc", level="ERROR"):
                r = self.client.get("/api/dashboard")
            self.assertEqual(r.status_code, 502, msg=repr(data))
            body = r.get_data(as_text=True)
            self.assertNotIn("secret-path", body)
            self.assertNotIn("No JSON", body)
            self.assertIn("cannot read", r.get_json()["error"])

    def test_agent_list_with_null_or_wrong_shape_does_not_crash(self):
        old = config.WAZUH_API_PASS
        config.WAZUH_API_PASS = "pw"
        self.admin()

        class Tok:
            ok, status_code, text = True, 200, "tok"

            def raise_for_status(self):
                pass

        class Agents:
            ok, status_code = True, 200

            def __init__(self, j):
                self.j = j

            def raise_for_status(self):
                pass

            def json(self):
                return self.j
        try:
            for j in ({"data": {"affected_items": None}}, {"data": {"affected_items": "x"}}, {"data": {"affected_items": [1, None, "a"]}}):
                with mock.patch.object(requests, "post", return_value=Tok()), mock.patch.object(requests, "get", return_value=Agents(j)):
                    r = self.client.get("/api/agents")
                self.assertIn(r.status_code, (200, 502), msg=repr(j))
        finally:
            config.WAZUH_API_PASS = old


# ======================================================================================= 4. admin password exposure
class ListHandler(logging.Handler):
    """Collects everything written to the server log (after redaction), at any level."""

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(self.format(record))


class AdminPasswordExposureTests(Base):
    KNOWN = "Known-Random-Pw-9x"

    def start(self, stdout, *, configured="", db_name="fresh.db"):
        """Run main() like `python backend/app.py` would (the web server itself is replaced by a no-op).
        Returns (app, stderr text, server-log text)."""
        config.DB_FILE = os.path.join(self.tmp.name, db_name)
        config.UI_PASSWORD = configured
        real, made, handler = app_module.create_app, [], ListHandler()

        def spy(**kw):
            made.append(real(**kw))
            return made[-1]
        safety.log.addHandler(handler)
        try:
            with mock.patch.object(app_module.Flask, "run"), mock.patch.object(app_module, "create_app", spy), \
                    mock.patch.object(users, "generate_password", return_value=self.KNOWN), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()) as err:
                app_module.main()
        finally:
            safety.log.removeHandler(handler)
        return made[0], err.getvalue(), "\n".join(handler.lines)

    def test_a_password_you_chose_is_never_printed_anywhere(self):
        chosen = "Chosen-Secret-Pw-77"
        for i, stdout in enumerate((io.StringIO(), Tty())):    # redirected output AND a terminal
            app, err, logs = self.start(stdout, configured=chosen, db_name=f"chosen{i}.db")
            self.assertNotIn(chosen, stdout.getvalue() + err + logs)
            self.assertEqual(app.admin_password, "")
            self.assertEqual(self.login(app.test_client(), pw=chosen).status_code, 200)

    def test_random_password_is_not_shown_when_output_is_redirected(self):
        out = io.StringIO()
        app, err, logs = self.start(out)
        self.assertNotIn(self.KNOWN, out.getvalue() + err + logs)
        self.assertIn("NOT shown", out.getvalue())
        self.assertIn("manage.py reset-password", out.getvalue())
        self.assertEqual(app.admin_password, "")
        # the admin exists, and the documented recovery path gives access
        with mock.patch("getpass.getpass", side_effect=["Recovered-Admin-Pw-9"] * 2), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(manage.main(["reset-password", config.DEFAULT_ADMIN_EMAIL]), 0)
        self.assertEqual(self.login(app.test_client(), pw="Recovered-Admin-Pw-9").status_code, 200)

    def test_random_password_is_shown_once_on_an_interactive_terminal_and_then_forgotten(self):
        out = Tty()
        app, err, logs = self.start(out)
        self.assertEqual(out.getvalue().count(self.KNOWN), 1)
        self.assertNotIn(self.KNOWN, err + logs)           # on the terminal only, never in a log
        self.assertEqual(app.admin_password, "")           # cleared from memory after it was shown
        self.assertEqual(self.login(app.test_client(), pw=self.KNOWN).status_code, 200)

    def test_create_app_alone_never_keeps_or_prints_a_password(self):
        config.DB_FILE = os.path.join(self.tmp.name, "fresh2.db")
        config.UI_PASSWORD = ""
        with mock.patch.object(users, "generate_password", return_value=self.KNOWN), contextlib.redirect_stdout(io.StringIO()) as out:
            app = app_module.create_app()                  # what a WSGI server would call
        self.assertNotIn(self.KNOWN, out.getvalue())
        self.assertEqual((app.admin_password, app.admin_password_random), ("", True))

    def test_passwords_are_not_in_the_audit_log_or_the_database_as_text(self):
        self.admin()
        import sqlite3
        con = sqlite3.connect(config.DB_FILE)
        dump = "\n".join(str(r) for t in ("audit", "users") for r in con.execute(f"SELECT * FROM {t}"))
        self.assertNotIn(ADMIN_PW, dump)


# ======================================================================================= 5. authentication and authorization
class AuthRegressionTests(Base):
    PUBLIC = {"api.health", "api.login", "api.signup"}

    def routes(self):
        for rule in self.app.url_map.iter_rules():
            if rule.endpoint.startswith("api."):
                url = re.sub(r"<[^>]+>", "1", rule.rule)
                for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
                    yield rule.endpoint, method, url

    def test_only_health_login_and_signup_are_public(self):
        self.assertEqual(api.PUBLIC, self.PUBLIC)
        anon, seen = self.app.test_client(), 0
        for endpoint, method, url in self.routes():
            seen += 1
            if endpoint not in self.PUBLIC:
                self.assertEqual(anon.open(url, method=method, headers=H, json={}).status_code, 401, msg=f"{method} {url}")
        self.assertGreater(seen, 20)

    def test_every_changing_route_needs_the_csrf_header(self):
        anon = self.app.test_client()
        for endpoint, method, url in self.routes():
            if method not in ("GET", "HEAD", "OPTIONS"):
                self.assertEqual(anon.open(url, method=method, json={}).status_code, 403, msg=f"{method} {url}")

    ANALYST = (("GET", "/api/alerts.csv"), ("POST", "/api/incidents"), ("PATCH", "/api/incidents/1"))
    ADMIN = (("POST", "/api/blocklist"), ("POST", "/api/blocklist/1/unblock"), ("GET", "/api/audit"), ("GET", "/api/users"),
             ("POST", "/api/users/1/approve"), ("POST", "/api/users/1/role"), ("POST", "/api/users/1/status"),
             ("POST", "/api/users/1/reset"), ("DELETE", "/api/users/1"))
    ANY_USER = (("GET", "/api/dashboard"), ("GET", "/api/incidents"), ("GET", "/api/agents"), ("GET", "/api/blocklist"), ("GET", "/api/me"),
                ("GET", "/api/mitre"), ("GET", "/api/threat"), ("GET", "/api/vulns"), ("GET", "/api/geo"))

    def test_role_matrix_is_complete_and_unchanged(self):
        routed = {(m, u) for _, m, u in self.routes()}
        listed = set(self.ANALYST + self.ADMIN + self.ANY_USER) | {("POST", "/api/logout"), ("POST", "/api/change-password"),
                                                                    ("GET", "/api/health"), ("POST", "/api/login"), ("POST", "/api/signup")}
        self.assertEqual(routed, listed, msg="a route was added or removed: put it in the role matrix")
        viewer, analyst = self.make_user("viewer1", "viewer"), self.make_user("analyst1", "analyst")
        self.addCleanup(setattr, manager, "list_agents", manager.list_agents)
        manager.list_agents = lambda: []   # never reach a real Wazuh from a test
        for name, fake in (("mitre", {}), ("threat", {"items": []}), ("vulns", {}), ("geo", {})):
            self.addCleanup(setattr, intel, name, getattr(intel, name))
            setattr(intel, name, lambda *a, _fake=fake, **k: _fake)
        body = {"src": "1.2.3.4", "msg": "x", "ip": "1.2.3.4", "confirm": True, "role": "viewer", "status": "active", "password": "another-long-pw1"}
        for method, url in self.ANALYST + self.ADMIN:
            self.assertEqual(viewer.open(url, method=method, headers=H, json=body).status_code, 403, msg=f"viewer {method} {url}")
        for method, url in self.ADMIN:
            self.assertEqual(analyst.open(url, method=method, headers=H, json=body).status_code, 403, msg=f"analyst {method} {url}")
        for method, url in self.ANALYST:
            self.assertNotEqual(analyst.open(url, method=method, headers=H, json=body).status_code, 403, msg=f"analyst {method} {url}")
        for method, url in self.ANY_USER:
            self.assertEqual(viewer.open(url, method=method, headers=H).status_code, 200, msg=f"viewer {method} {url}")

    def test_user_who_must_change_the_password_can_reach_only_three_routes(self):
        v = self.make_user("viewer1", "viewer")
        self.client.post(f"/api/users/{self.user_id('viewer1')}/reset", json={"password": "temporary-pass-1"}, headers=H)
        self.login(v, "viewer1", "temporary-pass-1")
        for method, url in self.ANY_USER[:4] + self.ANALYST + self.ADMIN:
            self.assertEqual(v.open(url, method=method, headers=H, json={}).status_code, 403, msg=f"{method} {url}")
        self.assertEqual(v.get("/api/me").status_code, 200)

    def test_changing_the_password_signs_out_other_sessions_but_not_this_one(self):
        a = self.make_user("viewer1", "viewer")
        b = self.app.test_client()
        self.assertEqual(self.login(b, "viewer1", "pass-viewer1-12345").status_code, 200)
        self.assertEqual(a.post("/api/change-password", json={"old": "pass-viewer1-12345", "new": "my-own-new-pass1"}, headers=H).status_code, 200)
        self.assertEqual(a.get("/api/dashboard").status_code, 200)
        self.assertEqual(b.get("/api/dashboard").status_code, 401)

    def test_login_does_not_reveal_which_emails_exist(self):
        wrong_pw = self.login(pw="wrong-password-1")
        unknown = self.login(name="nobody@example.com", pw="wrong-password-1")
        self.assertEqual((wrong_pw.status_code, wrong_pw.get_json()), (unknown.status_code, unknown.get_json()))

    def test_session_cookie_flags(self):
        cookie = self.login().headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        with mock.patch.object(config, "COOKIE_SECURE", True):
            secure = app_module.create_app().test_client().post("/api/login", json={"email": config.DEFAULT_ADMIN_EMAIL, "password": ADMIN_PW}, headers=H)
        self.assertIn("Secure", secure.headers.get("Set-Cookie", ""))

    def test_login_is_rate_limited_and_a_good_password_after_the_limit_is_still_refused(self):
        for _ in range(config.LOGIN_MAX_FAILS):
            self.login(pw="bad-password-1")
        self.assertEqual(self.login().status_code, 429)


class Phase2HardeningTests(Base):
    """Server-side logout, per-account lockout, change-password guess limit, silent duplicate signup, .env override report."""
    EMAIL = config.DEFAULT_ADMIN_EMAIL

    def login_from(self, addr, pw=ADMIN_PW, email=None):
        c = self.app.test_client()
        c.environ_base["REMOTE_ADDR"] = addr
        r = c.post("/api/login", json={"email": email or self.EMAIL, "password": pw}, headers=H)
        return c, r

    def test_logout_kills_a_copied_cookie(self):
        c, r = self.login_from("10.1.0.1")
        self.assertEqual(r.status_code, 200)
        cookie = c.get_cookie("session").value
        thief = self.app.test_client()
        thief.set_cookie("session", cookie)
        self.assertEqual(thief.get("/api/me").status_code, 200)
        c.post("/api/logout", headers=H)
        self.assertEqual(thief.get("/api/me").status_code, 401)

    def test_logout_only_ends_this_session(self):
        a, _ = self.login_from("10.1.0.2")
        b, _ = self.login_from("10.1.0.3")
        a.post("/api/logout", headers=H)
        self.assertEqual(b.get("/api/me").status_code, 200)

    def test_session_expires_on_the_server(self):
        import time as _t
        c, _ = self.login_from("10.1.0.4")
        with mock.patch("services.users.time.time", return_value=_t.time() + config.SESSION_HOURS * 3600 + 5):
            self.assertEqual(c.get("/api/me").status_code, 401)

    def test_old_cookie_without_session_id_is_refused(self):
        from flask.sessions import SecureCookieSessionInterface
        ser = SecureCookieSessionInterface().get_signing_serializer(self.app)
        row = users._by_email(self.EMAIL)
        c = self.app.test_client()
        c.set_cookie("session", ser.dumps({"uid": row["id"], "sv": row["sv"]}))
        self.assertEqual(c.get("/api/me").status_code, 401)

    def test_one_account_is_locked_even_when_attacked_from_many_addresses(self):
        codes = [self.login_from(f"10.2.0.{i}", pw="wrong-pw-123")[1].status_code for i in range(config.ACCOUNT_MAX_FAILS + 3)]
        self.assertEqual(codes[:config.ACCOUNT_MAX_FAILS], [401] * config.ACCOUNT_MAX_FAILS)
        self.assertEqual(set(codes[config.ACCOUNT_MAX_FAILS:]), {429})
        self.assertEqual(self.login_from("10.2.1.1")[1].status_code, 429)   # the right password is refused while locked

    def test_account_lockout_expires(self):
        import time as _t
        for i in range(config.ACCOUNT_MAX_FAILS):
            self.login_from(f"10.2.2.{i}", pw="wrong-pw-123")
        with mock.patch("auth.time.time", return_value=_t.time() + config.LOGIN_WINDOW + 5):
            self.assertEqual(self.login_from("10.2.3.1")[1].status_code, 200)

    def test_account_lockout_looks_the_same_for_unknown_emails(self):
        codes = [self.login_from(f"10.2.4.{i}", pw="x-wrong-pw-1", email="ghost@example.com")[1].status_code
                 for i in range(config.ACCOUNT_MAX_FAILS + 1)]
        self.assertEqual(codes, [401] * config.ACCOUNT_MAX_FAILS + [429])

    def test_change_password_guessing_is_limited(self):
        c, _ = self.login_from("10.3.0.1")
        codes = [c.post("/api/change-password", json={"old": f"guess-{i}", "new": "Whatever-Pw-123"}, headers=H).status_code
                 for i in range(config.PW_CHANGE_MAX_FAILS + 2)]
        self.assertEqual(codes[:config.PW_CHANGE_MAX_FAILS], [400] * config.PW_CHANGE_MAX_FAILS)
        self.assertEqual(codes[config.PW_CHANGE_MAX_FAILS:], [429, 429])
        r = c.post("/api/change-password", json={"old": ADMIN_PW, "new": "Whatever-Pw-123"}, headers=H)
        self.assertEqual(r.status_code, 429)   # even the right current password waits

    def test_change_password_counter_resets_after_success(self):
        c, _ = self.login_from("10.3.0.2")
        for i in range(config.PW_CHANGE_MAX_FAILS - 1):
            c.post("/api/change-password", json={"old": f"guess-{i}", "new": "Whatever-Pw-123"}, headers=H)
        self.assertEqual(c.post("/api/change-password", json={"old": ADMIN_PW, "new": "Fresh-Strong-Pw-9"}, headers=H).status_code, 200)
        for i in range(config.PW_CHANGE_MAX_FAILS - 1):
            self.assertEqual(c.post("/api/change-password", json={"old": f"again-{i}", "new": "Another-Pw-1234"}, headers=H).status_code, 400)

    def test_duplicate_signup_looks_exactly_like_a_new_one(self):
        c = self.app.test_client()
        new = c.post("/api/signup", json={"email": "fresh1@example.com", "password": "long-enough-pw1"}, headers=H)
        dup = c.post("/api/signup", json={"email": self.EMAIL, "password": "long-enough-pw1"}, headers=H)
        self.assertEqual((new.status_code, new.get_json()), (dup.status_code, dup.get_json()))
        self.assertNotIn("taken", dup.get_data(as_text=True).lower())
        self.assertEqual(users._by_email(self.EMAIL)["role"], "admin")   # the existing account was not touched
        self.assertNotEqual(users._by_email(self.EMAIL)["status"], "pending")

    def test_forwarded_for_is_ignored_without_a_proxy_and_used_with_one(self):
        hdr = dict(H, **{"X-Forwarded-For": "203.0.113.7"})
        for hops, expect in ((0, "10.9.0.1"), (1, "203.0.113.7")):
            with mock.patch.object(config, "PROXY_HOPS", hops):
                app = app_module.create_app()
            seen = []
            orig = auth.try_login
            with mock.patch.object(auth, "try_login", side_effect=lambda e, p, a: (seen.append(a), orig(e, p, a))[1]):
                c = app.test_client()
                c.environ_base["REMOTE_ADDR"] = "10.9.0.1"
                c.post("/api/login", json={"email": self.EMAIL, "password": "wrong-pw-123"}, headers=hdr)
            self.assertEqual(seen, [expect], msg=f"hops={hops}")

    def test_hsts_only_over_https_setting(self):
        self.assertNotIn("Strict-Transport-Security", self.client.get("/api/health").headers)
        with mock.patch.object(config, "COOKIE_SECURE", True):
            r = app_module.create_app().test_client().get("/api/health")
        self.assertIn("max-age=", r.headers.get("Strict-Transport-Security", ""))

    def test_database_file_is_owner_only_on_posix(self):
        if os.name == "nt":
            self.skipTest("POSIX mode bits only")
        self.assertEqual(os.stat(config.DB_FILE).st_mode & 0o077, 0)

    def test_shell_variable_that_beats_env_file_is_reported_by_name_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".env")
            with open(path, "w", encoding="utf-8") as f:
                f.write("SOC_PORT=7001\nSOC_HOST=10.0.0.5\nSOC_SCAN_NAMES=A\n")
            with mock.patch.dict(os.environ, {"SOC_PORT": "9999", "SOC_HOST": "10.0.0.5"}, clear=False):
                os.environ.pop("SOC_SCAN_NAMES", None)
                over = []
                n = config.load_dotenv(path, over)
                self.assertEqual(over, ["SOC_PORT"])        # different value -> reported; same value -> not
                self.assertEqual(os.environ["SOC_PORT"], "9999")   # the shell value still wins (documented behaviour)
                self.assertEqual(n, 1)
                os.environ.pop("SOC_SCAN_NAMES", None)


if __name__ == "__main__":
    unittest.main()

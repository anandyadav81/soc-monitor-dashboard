"""Self-test against YOUR real Wazuh. Every line says PASS, WARN, FAIL or SKIP. Nothing is guessed.

Run it from the project folder, with the same settings as the server (SOC_INDEXER_URL, SOC_INDEXER_PASS,
SOC_WAZUH_API_PASS, SOC_VERIFY_TLS ...):

    python backend/selftest.py                read-only checks (safe)
    python backend/selftest.py --live-block   also sends ONE real block of the harmless address 192.0.2.123

It does not print passwords. It writes selftest-report.txt in the project folder; review it for hostnames, IP addresses and diagnostics before sharing it.
"""
import argparse
import ipaddress
import os
import platform
import secrets
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone

import requests

import config
from safety import redact
from wazuh import indexer, manager

TEST_IP = "192.0.2.123"  # TEST-NET-1: reserved for documentation, no real machine uses it
RESULTS = []
_token = {}


def record(status, name, detail=""):
    detail = redact(detail)  # passwords / tokens never reach the console or selftest-report.txt
    RESULTS.append((status, name, detail))
    print(f"[{status:4}] {name}" + (f": {detail}" if detail else ""))


def run(name, fn):
    try:
        status, detail = fn()
    except requests.exceptions.SSLError as e:
        status, detail = "FAIL", "TLS certificate problem. Prefer setting SOC_CA_BUNDLE to a trusted CA file; only disable SOC_VERIFY_TLS in an isolated self-signed lab. " + str(e)[:120]
    except requests.exceptions.ConnectionError as e:
        status, detail = "FAIL", "cannot connect (is the VM on? right address?): " + str(e)[:140]
    except requests.exceptions.Timeout:
        status, detail = "FAIL", "no answer within 15 seconds"
    except Exception as e:  # a failed check must never stop the other checks
        status, detail = "FAIL", f"{type(e).__name__}: {str(e)[:200]}"
    record(status, name, detail)


def idx_get(path, **kw):
    return requests.get(config.INDEXER_URL + path, auth=(config.INDEXER_USER, config.INDEXER_PASS),
                        verify=config.INDEXER_VERIFY, timeout=15, **kw)


def idx_post(path, body):
    return requests.post(config.INDEXER_URL + path, json=body, auth=(config.INDEXER_USER, config.INDEXER_PASS),
                         verify=config.INDEXER_VERIFY, timeout=15)


def mgr_get(path, **params):
    if "t" not in _token:
        _token["t"] = manager._token()
    r = requests.get(config.WAZUH_API_URL + path, params=params, headers={"Authorization": "Bearer " + _token["t"]},
                     verify=config.WAZUH_VERIFY, timeout=15)
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------- settings and Indexer
def check_settings():
    tls = "checked with SOC_CA_BUNDLE" if config.CA_BUNDLE else ("checked" if config.VERIFY_TLS else "NOT checked")
    return "PASS", (f"Indexer {config.INDEXER_URL} as {config.INDEXER_USER}; Manager API {config.WAZUH_API_URL} as {config.WAZUH_API_USER} "
                    f"(API password set: {bool(config.WAZUH_API_PASS)}); TLS {tls}; Active Response {'DRY RUN' if config.AR_DRY_RUN else 'LIVE'}, agent {config.AR_AGENT_ID}")


def check_indexer_up():
    r = idx_get("/")
    if r.status_code in (401, 403):
        return "FAIL", f"login refused (HTTP {r.status_code}). Check SOC_INDEXER_USER and SOC_INDEXER_PASS"
    r.raise_for_status()
    v = r.json().get("version", {})
    return "PASS", f"{v.get('distribution', 'elasticsearch')} {v.get('number', '?')}"


def check_alert_counts():
    r = idx_get(f"/{config.ALERT_INDEX}/_count")
    r.raise_for_status()
    total = r.json()["count"]
    s = idx_post(f"/{config.ALERT_INDEX}/_count", {"query": {"term": {"rule.groups": "suricata"}}})
    s.raise_for_status()
    suricata = s.json()["count"]
    if not total:
        return "WARN", f"the index {config.ALERT_INDEX} is empty"
    if not suricata:
        return "WARN", f"{total} alerts, but none in the 'suricata' group: the Suricata cards will stay at 0"
    return "PASS", f"{total} alerts in total, {suricata} of them Suricata (all time)"


FIELDS = ["timestamp", "rule.level", "rule.groups", "rule.description", "rule.mitre.tactic", "data.src_ip", "data.dest_ip",
          "data.alert.signature", "data.alert.category", "agent.name"]
CORE = {"timestamp", "rule.level", "rule.groups", "data.src_ip"}


def check_fields():
    r = idx_get(f"/{config.ALERT_INDEX}/_field_caps", params={"fields": ",".join(FIELDS)})
    r.raise_for_status()
    caps, lines, missing_core = r.json().get("fields", {}), [], []
    for f in FIELDS:
        c = caps.get(f)
        if not c:
            lines.append(f"{f}=missing")
            if f in CORE:
                missing_core.append(f)
            continue
        lines.append(f + "=" + "/".join(f"{t}{'' if v.get('aggregatable') else ' (cannot be counted)'}" for t, v in sorted(c.items())))
    if missing_core:
        return "FAIL", "fields the dashboard needs are missing: " + ", ".join(missing_core)
    return "PASS", "; ".join(lines)


# ---------------------------------------------------------------- the dashboard's own query
def check_dashboard_query():
    d = indexer.fetch({})
    problems = []
    if d["total_all"] < d["total"]:
        problems.append(f"Total ({d['total_all']}) is smaller than Suricata ({d['total']})")
    if sum(d["severity"].values()) != d["total_all"]:
        problems.append(f"severity adds up to {sum(d['severity'].values())}, not {d['total_all']}")
    hist = d["history"]
    if len(hist) not in (168, 169):
        problems.append(f"the graph has {len(hist)} points, expected 168 or 169 (one per hour for 7 days)")
    else:
        hours = [int(x["label"][6:8]) for x in hist]
        if any((b - a) % 24 != 1 for a, b in zip(hours, hours[1:])):
            problems.append("the graph has hours missing")
        if hist[-1]["label"][6:8] != f"{datetime.now(timezone.utc).hour:02d}":
            problems.append(f"the last graph point is {hist[-1]['label']} UTC, not the current hour")
    note = f"variant used: {'with' if indexer._variant and indexer._variant[0] else 'WITHOUT'} MITRE/alert-type panels, ip field {indexer._variant[1] if indexer._variant else '?'}"
    if indexer._variant and not indexer._variant[0]:
        problems.append("the Indexer rejected the MITRE tactic / alert type fields, so those two panels stay empty")
    summary = (f"last 24 hours: Total {d['total_all']}, Suricata {d['total']}, port scans {d['scans']}, attacker IPs {d['unique']}, "
               f"MITRE tactics {len(d['tactics'])}, alert types {len(d['categories'])}; {note}. "
               f"COMPARE: Wazuh dashboard > Threat Hunting > Last 24 hours > Total should be close to {d['total_all']}")
    return ("FAIL" if any("smaller" in p or "adds up" in p or "graph has" in p or "hours missing" in p for p in problems) else
            "WARN" if problems else "PASS"), "; ".join(problems + [summary])


def check_ranges():
    counts = {}
    for rng in ("1h", "24h", "7d", "30d", "all"):
        counts[rng] = indexer.fetch({"range": rng})["total_all"]
    order = list(counts.values())
    text = ", ".join(f"{k}={v}" for k, v in counts.items())
    if order != sorted(order):
        return "FAIL", "a longer time range shows FEWER alerts than a shorter one: " + text
    return "PASS", text


def check_filters():
    base = indexer.fetch({"range": "all", "limit": 50})
    rows = base["rows"]
    if not rows:
        return "WARN", "no Suricata alerts to test the filters with"
    out = []
    ip = rows[0]["src"]
    got = indexer.fetch({"range": "all", "q": ip})["rows"]
    if not got or not all(r["src"].startswith(ip) or r["dst"].startswith(ip) for r in got):
        return "FAIL", f"searching for {ip} returned {len(got)} rows that do not all match"
    out.append(f"search {ip}: {len(got)} rows")
    level = rows[0]["level"]
    got = indexer.fetch({"range": "all", "level": level})["rows"]
    if not got or any(r["level"] != level for r in got):
        return "FAIL", f"level filter {level} returned wrong rows"
    out.append(f"level {level}: {len(got)} rows")
    if any(":" in r["src"] for r in indexer.fetch({"range": "all", "noipv6": True})["rows"]):
        return "FAIL", "'Hide IPv6' still shows IPv6 addresses"
    out.append("hide IPv6 ok")
    v6 = next((r["src"] for r in rows if ":" in r["src"]), None)
    if v6:
        short = ipaddress.ip_address(v6).compressed
        found = indexer.fetch({"range": "all", "q": short})["rows"]
        if not found:
            return "FAIL", f"searching the short IPv6 form {short} finds nothing"
        out.append(f"short IPv6 {short} found")
    indexer.fetch({"range": "all", "scan": True})
    out.append("port-scan filter ok")
    return "PASS", "; ".join(out)


# ---------------------------------------------------------------- Wazuh Manager API
def need_api():
    if not config.WAZUH_API_PASS:
        return ("SKIP", "SOC_WAZUH_API_PASS is not set (it is the password of the Wazuh API user, often wazuh-wui)")
    return None


def check_api_login():
    if need_api():
        return need_api()
    try:
        _token["t"] = manager._token()
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code in (401, 403):
            return "FAIL", f"login refused (HTTP {e.response.status_code}). Check SOC_WAZUH_API_USER and SOC_WAZUH_API_PASS"
        raise
    return "PASS", "login to the Wazuh API works"


def check_manager_version():
    if need_api() or "t" not in _token:
        return "SKIP", "needs a working API login"
    v = mgr_get("/manager/info")["data"]["affected_items"][0].get("version", "?")
    if str(v).lstrip("v").startswith("5"):
        return "WARN", f"Wazuh {v}: active response works differently in 5.x (see its migration guide). Block IP was written for 4.x"
    return "PASS", f"Wazuh {v}"


def check_agents():
    if need_api() or "t" not in _token:
        return "SKIP", "needs a working API login"
    agents = manager.list_agents()
    text = ", ".join(f"{a['id']} {a['name']} ({a['status']})" for a in agents) or "no agents"
    mine = next((a for a in agents if a["id"] == config.AR_AGENT_ID), None)
    if not agents:
        return "WARN", "no agents registered"
    if not mine:
        return "WARN", f"SOC_AR_AGENT_ID={config.AR_AGENT_ID} is not an agent. Agents: {text}"
    if mine["status"] != "active":
        return "WARN", f"the agent used for blocking ({mine['id']} {mine['name']}) is {mine['status']}. Agents: {text}"
    return "PASS", f"{text}. Blocking would use agent {mine['id']} ({mine['name']})"


def check_command_config():
    if need_api() or "t" not in _token:
        return "SKIP", "needs a working API login"
    try:
        found = "firewall-drop" in str(mgr_get("/manager/configuration", section="command"))
    except requests.exceptions.HTTPError as e:
        return "WARN", f"could not read the command list (HTTP {e.response.status_code if e.response is not None else '?'})"
    return ("PASS", "firewall-drop is defined on the manager") if found else \
        ("WARN", "firewall-drop is not in the manager's command list. The '!firewall-drop' script call may still work: test with --live-block")


# ---------------------------------------------------------------- the whole app on real data
def check_app():
    tmp = tempfile.mkdtemp()
    old = (config.DB_FILE, config.UI_PASSWORD, config.ADMIN_EMAIL)
    try:
        config.DB_FILE, config.UI_PASSWORD, config.ADMIN_EMAIL = os.path.join(tmp, "selftest.db"), secrets.token_urlsafe(12), config.DEFAULT_ADMIN_EMAIL
        import app as app_module
        c, h = app_module.create_app().test_client(), {"X-Requested-With": "mini-soc"}
        r = c.post("/api/login", json={"email": config.ADMIN_EMAIL, "password": config.UI_PASSWORD}, headers=h)
        if r.status_code != 200:
            return "FAIL", f"the test login failed (HTTP {r.status_code})"
        t0 = time.time()
        d = c.get("/api/dashboard")
        ms = round((time.time() - t0) * 1000)
        if d.status_code != 200:
            return "FAIL", f"/api/dashboard answered HTTP {d.status_code}: {d.get_json().get('error', '')[:160]}"
        data = d.get_json()
        want = ["total", "total_all", "scans", "unique", "severity", "history", "history_all", "newest", "rows", "top_ips", "tactics", "categories"]
        absent = [k for k in want if k not in data]
        if absent:
            return "FAIL", "the dashboard answer misses: " + ", ".join(absent)
        csv = c.get("/api/alerts.csv")
        ag = c.get("/api/agents")
        bl = c.get("/api/blocklist")
        bad = [n for n, x in (("csv", csv), ("blocklist", bl)) if x.status_code != 200]
        if bad:
            return "FAIL", "HTTP error from: " + ", ".join(bad)
        speed = f"/api/dashboard took {ms} ms, {len(d.get_data())//1024} kB"
        if ag.status_code != 200:  # the agents panel is optional: the rest of the app still works
            return "WARN", speed + f"; /api/agents answered HTTP {ag.status_code}: {ag.get_json().get('error', '')[:120]}"
        return ("WARN" if ms > 3000 else "PASS"), speed + (" (slow: use a longer auto refresh)" if ms > 3000 else "")
    finally:
        config.DB_FILE, config.UI_PASSWORD, config.ADMIN_EMAIL = old
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- one real block (only when asked)
def check_live_block(args):
    if not args.live_block:
        return "SKIP", "not asked for (add --live-block to test a real block of a harmless address)"
    if need_api():
        return need_api()
    print(f"\n  This sends a REAL '{config.AR_COMMAND}' for {TEST_IP} to agent {config.AR_AGENT_ID}: one DROP rule in that machine's firewall.")
    print(f"  {TEST_IP} is a documentation address, so no real traffic is affected. You remove the rule yourself afterwards.")
    try:
        answer = input("  Type yes to send it: ").strip().lower()
    except EOFError:
        answer = ""
    if answer != "yes":
        return "SKIP", "you did not type yes"
    manager._active_response(config.AR_COMMAND, TEST_IP)
    return "PASS", (f"Wazuh accepted the command. That is not proof that the firewall changed: check ON THE AGENT "
                    f"'sudo iptables -L INPUT -n | grep {TEST_IP}' (a DROP line must show). Remove it with "
                    f"'sudo iptables -D INPUT -s {TEST_IP} -j DROP' (and the same with FORWARD if it is listed there)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live-block", action="store_true", help="also send one real block of 192.0.2.123 (asks first)")
    args = ap.parse_args()
    print(f"Mini SOC self-test, {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
    for name, fn in [("settings", check_settings), ("Indexer reachable", check_indexer_up), ("alerts in the Indexer", check_alert_counts),
                     ("Indexer fields", check_fields), ("dashboard query", check_dashboard_query), ("time ranges", check_ranges),
                     ("search and filters", check_filters), ("Wazuh API login", check_api_login), ("Wazuh version", check_manager_version),
                     ("agents", check_agents), ("firewall-drop command", check_command_config), ("whole app on real data", check_app),
                     ("live block", lambda: check_live_block(args))]:
        run(name, fn)
    count = {s: sum(1 for r in RESULTS if r[0] == s) for s in ("PASS", "WARN", "FAIL", "SKIP")}
    summary = "  ".join(f"{k} {v}" for k, v in count.items())
    print(f"\nSummary: {summary}")
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "selftest-report.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"Mini SOC self-test {datetime.now().strftime('%Y-%m-%d %H:%M')}  Python {platform.python_version()}  {platform.system()}\n")
        f.write("No passwords are written to this file.\n\n")
        for s, n, d in RESULTS:
            f.write(f"[{s}] {n}: {d}\n")
        f.write(f"\nSummary: {summary}\n")
    print(f"A copy was written to {path}")
    return 1 if count["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())

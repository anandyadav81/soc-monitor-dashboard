"""Read-only queries for the MITRE ATT&CK, Threat Intelligence, Vulnerabilities pages and the attack-origins panel.
Everything here only READS from the Wazuh Indexer. Nothing is written or blocked from this file."""
import ipaddress
import math
import os

import requests

import config
from safety import UpstreamError, log

VULN_INDEX = "wazuh-states-vulnerabilities-*"
_src_field = "data.src_ip"      # remembered once we know which field name the Indexer accepts
_geo_cache = {}                 # ip -> country name (only used when SOC_GEOIP_ONLINE=true)


def _range(value):
    value = value or "24h"
    if value != "all" and value not in config.RANGES:
        raise ValueError("Time range must be one of: " + ", ".join(list(config.RANGES) + ["all"]))
    return value


def _time_filter(rng):
    return [] if rng == "all" else [{"range": {"timestamp": {"gte": config.RANGES[rng]}}}]


def _post(index, body):
    r = requests.post(f"{config.INDEXER_URL}/{index}/_search", json=body, verify=config.INDEXER_VERIFY,
                      timeout=20, auth=(config.INDEXER_USER, config.INDEXER_PASS))
    if r.status_code in (401, 403):
        raise UpstreamError(f"Indexer refused the login ({r.status_code})",
                            public="The Wazuh Indexer refused the dashboard's login. Check SOC_INDEXER_PASS.")
    return r


def _by_src(make_body):
    """Run a query that groups by attacker IP. Tries the field names the Indexer might use."""
    global _src_field
    r = None
    for field in dict.fromkeys([_src_field, "data.src_ip", "data.src_ip.keyword"]):
        r = _post(config.ALERT_INDEX, make_body(field))
        if r.ok:
            _src_field = field
            return r.json()
    log.error("Indexer rejected the attacker-IP query: %s", r.text[:300])
    r.raise_for_status()


def _scope(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    return "public" if a.is_global else "private"  # anything not routable on the internet counts as private / lab


def _risk(count, level, targets):
    """A simple 0-100 score: how many alerts + how severe + how many different targets."""
    volume = min(40, int(8 * math.log10(count + 1)))
    severity = 40 if level >= 13 else 30 if level >= 10 else 20 if level >= 7 else 10
    return min(100, volume + severity + min(20, 5 * targets))


# ---------- MITRE ATT&CK ----------
def mitre(rng):
    rng = _range(rng)
    body = {"size": 0, "track_total_hits": True,
            "query": {"bool": {"filter": _time_filter(rng) + [{"exists": {"field": "rule.mitre.id"}}]}},
            "aggs": {"tactics": {"terms": {"field": "rule.mitre.tactic", "size": 20}},
                     "techniques": {"terms": {"field": "rule.mitre.id", "size": 40},
                                    "aggs": {"name": {"terms": {"field": "rule.mitre.technique", "size": 1}},
                                             "tac": {"terms": {"field": "rule.mitre.tactic", "size": 3}}}}}}
    r = _post(config.ALERT_INDEX, body)
    r.raise_for_status()
    d = r.json()
    ag = d.get("aggregations", {})
    techniques = []
    for b in ag.get("techniques", {}).get("buckets", []):
        names = b["name"]["buckets"]
        techniques.append({"id": b["key"], "name": names[0]["key"] if names else "",
                           "tactics": [t["key"] for t in b["tac"]["buckets"]], "count": b["doc_count"]})
    return {"range": rng, "total": d["hits"]["total"]["value"],
            "tactics": [{"name": b["key"], "count": b["doc_count"]} for b in ag.get("tactics", {}).get("buckets", [])],
            "techniques": techniques}


# ---------- Threat intelligence (what the lab itself has seen) ----------
def threat(rng, limit=25):
    rng = _range(rng)

    def make(field):
        return {"size": 0,
                "query": {"bool": {"filter": _time_filter(rng) + [{"term": {"rule.groups": "suricata"}}]}},
                "aggs": {"ips": {"terms": {"field": field, "size": limit}, "aggs": {
                    "first": {"min": {"field": "timestamp"}}, "last": {"max": {"field": "timestamp"}},
                    "targets": {"cardinality": {"field": field.replace("src_ip", "dest_ip")}},
                    "lvl": {"max": {"field": "rule.level"}},
                    "sigs": {"terms": {"field": "rule.description", "size": 3}}}}}}

    d = _by_src(make)
    items = []
    for b in d.get("aggregations", {}).get("ips", {}).get("buckets", []):
        level = int(b["lvl"]["value"] or 0)
        targets = int(b["targets"]["value"] or 0)
        risk = _risk(b["doc_count"], level, targets)
        items.append({"ip": b["key"], "scope": _scope(b["key"]), "count": b["doc_count"], "targets": targets,
                      "level": level, "risk": risk,
                      "sev": "critical" if risk >= 85 else "high" if risk >= 65 else "medium" if risk >= 40 else "low",
                      "first": b["first"].get("value_as_string"), "last": b["last"].get("value_as_string"),
                      "signatures": [s["key"] for s in b["sigs"]["buckets"]]})
    items.sort(key=lambda i: (i["risk"], i["count"]), reverse=True)
    return {"range": rng, "items": items}


# ---------- Vulnerabilities (Wazuh Vulnerability Detection results) ----------
def vulns():
    body = {"size": 100, "track_total_hits": True,
            "sort": [{"vulnerability.score.base": {"order": "desc", "unmapped_type": "float"}}],
            "_source": ["vulnerability.id", "vulnerability.severity", "vulnerability.score.base",
                        "vulnerability.description", "package.name", "package.version", "agent.name"],
            "aggs": {"sev": {"terms": {"field": "vulnerability.severity", "size": 10}}}}
    r = _post(VULN_INDEX, body)
    if r.status_code == 404:
        return {"available": False, "message": "No vulnerability data found in the Indexer "
                "(index wazuh-states-vulnerabilities-*). Vulnerability Detection is probably not enabled on the Wazuh Manager."}
    r.raise_for_status()
    d = r.json()
    items = []
    for hit in d["hits"]["hits"]:
        s = hit["_source"]
        v, p, a = s.get("vulnerability", {}), s.get("package", {}), s.get("agent", {})
        sev = str(v.get("severity", "")).lower()
        items.append({"cve": v.get("id", ""), "sev": sev if sev in ("critical", "high", "medium", "low") else "low",
                      "score": (v.get("score") or {}).get("base"), "package": p.get("name", ""),
                      "version": p.get("version", ""), "agent": a.get("name", ""),
                      "desc": str(v.get("description", ""))[:220]})
    sev_counts = {b["key"].lower(): b["doc_count"] for b in d.get("aggregations", {}).get("sev", {}).get("buckets", [])}
    return {"available": True, "total": d["hits"]["total"]["value"], "severity": sev_counts, "items": items}


# ---------- Attack origins (country per attacker IP) ----------
def _online():
    return os.getenv("SOC_GEOIP_ONLINE", "").strip().lower() in ("1", "true", "yes", "on")


def _lookup(ip):
    """Country of a PUBLIC ip using the free ip-api.com service (only when SOC_GEOIP_ONLINE=true)."""
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", params={"fields": "status,country"}, timeout=3)
        name = r.json().get("country") if r.ok and r.json().get("status") == "success" else None
    except (requests.RequestException, ValueError):
        return None
    _geo_cache[ip] = name or "Unknown country"
    return _geo_cache[ip]


def geo(rng):
    rng = _range(rng)

    def make(field):
        return {"size": 0, "query": {"bool": {"filter": _time_filter(rng) + [{"term": {"rule.groups": "suricata"}}]}},
                "aggs": {"ips": {"terms": {"field": field, "size": 50}}}}

    d = _by_src(make)
    online, counts, lookups = _online(), {}, 0
    for b in d.get("aggregations", {}).get("ips", {}).get("buckets", []):
        ip, n = b["key"], b["doc_count"]
        if _scope(ip) != "public":
            name = "Private / lab network"
        elif online:
            if ip not in _geo_cache:
                lookups += 1
            name = _lookup(ip) if (ip in _geo_cache or lookups <= 15) else None
            name = name or "Not looked up yet"
        else:
            name = "Public IPs (country lookup is off)"
        counts[name] = counts.get(name, 0) + n
    note = "" if online else ("Country lookup is off. Set SOC_GEOIP_ONLINE=true in .env to look up public attacker IPs "
                              "(they are sent to ip-api.com).")
    return {"range": rng, "online": online, "note": note,
            "countries": sorted(({"name": k, "count": v} for k, v in counts.items()), key=lambda c: -c["count"])}
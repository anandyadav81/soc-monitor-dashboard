"""Talks to the Wazuh Indexer. Nothing else in the project does this.

Filters (search, level, time range, port scans, IPv6) are sent to the Indexer, so they search ALL stored
alerts, not only the latest rows. The cards and the graph always show the whole data set and ignore your
filters (that is what `post_filter` does: it filters the table rows but not the counters).
The TIME RANGE (last hour, 24 hours ... all time) limits the counters and the table together, like the time
picker in the Wazuh dashboard. "total_all" counts every Wazuh alert; "total" counts only Suricata alerts.
Severity, MITRE tactics and alert types look at every Wazuh alert; attacker IPs and port scans at Suricata.
"""
import ipaddress
import time

import requests

import config
from safety import UpstreamError, clip, log

# TLS: certificates are verified (config.INDEXER_VERIFY). Warnings are NOT silenced: if verification was
# switched off on purpose, requests/urllib3 keep warning, and app.py prints a start-up warning as well.

_variant = None  # the (with_mitre, ip field) option that worked last time; tried first on the next refresh

FIELDS = ["timestamp", "data.src_ip", "data.dest_ip", "data.dest_port", "data.proto", "data.alert.signature",
          "rule.description", "rule.level", "rule.id", "rule.mitre.id", "rule.mitre.tactic", "agent.name"]


def severity(level):
    """Wazuh rule level -> critical / high / medium / low."""
    try:
        n = int(level)
    except (TypeError, ValueError):
        return "low"
    if n >= config.SEV_CRITICAL:
        return "critical"
    if n >= config.SEV_HIGH:
        return "high"
    if n >= config.SEV_MEDIUM:
        return "medium"
    return "low"


def clean_params(raw):
    """Validate what the browser sent. Raises ValueError with a message the user can read."""
    p = {"q": str(raw.get("q", "")).strip()[:100], "level": str(raw.get("level", "")).strip(),
         "scan": bool(raw.get("scan")), "noipv6": bool(raw.get("noipv6")), "range": raw.get("range") or "24h"}
    try:  # Wazuh stores IPv6 in the long form; a short form typed by the user is expanded so the search finds it
        addr = ipaddress.ip_address(p["q"])
        if addr.version == 6:
            p["q"] = addr.exploded
    except ValueError:
        pass
    if p["level"] and not p["level"].isdigit():
        raise ValueError("Level must be a number")
    if p["range"] != "all" and p["range"] not in config.RANGES:
        raise ValueError("Range must be one of: all, " + ", ".join(config.RANGES))
    try:
        limit = int(raw.get("limit") or config.MAX_ROWS)
    except (TypeError, ValueError):
        raise ValueError("Limit must be a number")
    p["limit"] = max(1, min(limit, config.LIMIT_CAP))
    return p


def _scan_filter():
    names = config.SCAN_NAMES
    if len(names) == 1:
        return {"match_phrase": {"data.alert.signature": names[0]}}
    return {"bool": {"minimum_should_match": 1, "should": [{"match_phrase": {"data.alert.signature": n}} for n in names]}}


def build_body(p, ip_field, with_mitre=True):
    """The Indexer query. Pure function (no network) so it can be tested."""
    dst_field = ip_field.replace("src_ip", "dest_ip")
    in_range = {"range": {"timestamp": {"gte": config.RANGES[p["range"]]}}} if p["range"] != "all" else {"match_all": {}}
    keep, drop = [], []
    if p["level"]:
        keep.append({"term": {"rule.level": int(p["level"])}})
    if p["scan"]:
        keep.append(_scan_filter())
    if p["noipv6"]:
        drop.append({"wildcard": {ip_field: "*:*"}})
    if p["q"]:
        keep.append({"bool": {"minimum_should_match": 1, "should": [
            {"match_phrase": {"rule.description": p["q"]}},
            {"match_phrase": {"data.alert.signature": p["q"]}},
            {"prefix": {ip_field: p["q"]}},
            {"prefix": {dst_field: p["q"]}}]}})
    suricata = {"term": {"rule.groups": "suricata"}}
    last_week = {"range": {"timestamp": {"gte": config.HISTORY}}}

    def everything(inner=None):
        """A counter over EVERY Wazuh alert in the time range (not only Suricata)."""
        w = {"filter": in_range}
        if inner:
            w["aggs"] = inner
        return {"global": {}, "aggs": {"w": w}}

    # One point for every hour of the last week, also hours with no alerts (extended_bounds), so
    # "the last 24 points" always means "the last 24 hours". The graph ignores the time range picker.
    top_hour = int(time.time() // 3600 * 3600 * 1000)
    hourly = {"date_histogram": {"field": "timestamp", "fixed_interval": config.BUCKET, "min_doc_count": 0,
                                 "extended_bounds": {"min": top_hour - config.HISTORY_HOURS * 3600 * 1000, "max": top_hour}}}
    def newest(flt):
        return {"filter": flt, "aggs": {"t": {"max": {"field": "timestamp"}}}}

    aggs = {
        "all": {"filter": {"match_all": {}}},                      # Suricata alerts in the time range
        "all_wazuh": everything(),                                 # every alert in the time range
        "levels": everything({"l": {"terms": {"field": "rule.level", "size": 20}}}),
        "scans": {"filter": _scan_filter()},
        "unique_ips": {"cardinality": {"field": ip_field}},
        "top_ips": {"terms": {"field": ip_field, "size": 8}},
        "top_dst": {"terms": {"field": dst_field, "size": 8}},
        "history": {"global": {}, "aggs": {"w": {"filter": {"bool": {"filter": [suricata, last_week]}},
                                                 "aggs": {"h": {**hourly, "aggs": {"scan": {"filter": _scan_filter()}}}}}}},
        "history_all": {"global": {}, "aggs": {"w": {"filter": last_week, "aggs": {"h": hourly}}}},
        # time of the newest alert of each kind: this is what makes the bell ring
        "newest": {"global": {}, "aggs": {
            "critical": newest({"range": {"rule.level": {"gte": config.SEV_CRITICAL}}}),
            "high": newest({"range": {"rule.level": {"gte": config.SEV_HIGH, "lt": config.SEV_CRITICAL}}}),
            "scans": newest({"bool": {"filter": [suricata, _scan_filter()]}})}},
    }
    if with_mitre:
        # Optional panels. If the Indexer does not know these fields, fetch() retries without them.
        aggs["tactics"] = everything({"t": {"terms": {"field": "rule.mitre.tactic", "size": 10}}})
        aggs["categories"] = everything({"c": {"terms": {"field": "rule.description", "size": 10}}})
    body = {"size": p["limit"], "track_total_hits": True, "sort": [{"timestamp": "desc"}], "_source": FIELDS,
            "query": {"bool": {"filter": [suricata, in_range]}}, "aggs": aggs}
    if keep or drop:
        body["post_filter"] = {"bool": {"filter": keep, "must_not": drop}}
    return body


def _row(hit):
    s = hit["_source"]
    d, r = s.get("data", {}), s.get("rule", {})
    tactics = r.get("mitre", {}).get("tactic", [])
    ids = r.get("mitre", {}).get("id", [])
    return {
        "id": hit.get("_id", ""),
        "time": s.get("timestamp", "")[:19].replace("T", " "),
        "src": d.get("src_ip", "-"), "dst": d.get("dest_ip", "-"),
        "port": str(d.get("dest_port", "")), "proto": d.get("proto", ""),
        "msg": r.get("description", ""), "signature": d.get("alert", {}).get("signature", ""),
        "level": str(r.get("level", "")), "sev": severity(r.get("level")),
        "rule_id": str(r.get("id", "")), "agent": s.get("agent", {}).get("name", ""),
        "tactics": tactics if isinstance(tactics, list) else [tactics],
        "mitre_ids": ids if isinstance(ids, list) else [ids],
    }


def fetch(params):
    """Return alert totals, graph data and the matching alerts as plain Python data."""
    p = clean_params(params)
    url = f"{config.INDEXER_URL}/{config.ALERT_INDEX}/_search"
    global _variant
    reply = None
    # The field name differs between setups, and old data may have no MITRE field: try the options in turn.
    # The option that worked is remembered, so the next refresh needs one request, not several.
    options = [(m, f) for m in (True, False) for f in ("data.src_ip", "data.src_ip.keyword")]
    if _variant in options:
        options.remove(_variant)
        options.insert(0, _variant)
    for with_mitre, field in options:
        reply = requests.post(url, json=build_body(p, field, with_mitre), verify=config.INDEXER_VERIFY,
                              timeout=20, auth=(config.INDEXER_USER, config.INDEXER_PASS))
        if reply.status_code in (401, 403):  # wrong login: trying other options will not help
            detail = f"The Wazuh Indexer refused the login (HTTP {reply.status_code}). Check SOC_INDEXER_USER and SOC_INDEXER_PASS."
            log.error(detail)  # the server log gets the hint; the browser only gets the fixed text below
            raise UpstreamError(detail, public="The Wazuh Indexer rejected the server's login. The administrator must check the server log.")
        if reply.ok:
            _variant = (with_mitre, field)
            break
    if not reply.ok:  # keep the Indexer's own explanation in the server log only (redacted and shortened)
        log.error("Wazuh Indexer answered HTTP %s to the alert query: %s", reply.status_code, clip(getattr(reply, "text", "")))
    reply.raise_for_status()
    try:
        return _summarize(reply.json())
    except (ValueError, KeyError, IndexError, TypeError, AttributeError) as e:
        # A 200 answer that is not JSON, or lacks the fields we need. Without this a ValueError would be shown
        # to the browser as a "bad input" error (HTTP 400) and the rest as a vague 500.
        log.error("The Wazuh Indexer sent a reply this dashboard cannot read (%s): %s", type(e).__name__, clip(getattr(reply, "text", "")))
        raise UpstreamError("Unreadable Indexer reply: " + type(e).__name__,
                            public="The Wazuh Indexer sent an answer this dashboard cannot read. The administrator must check the server log.")


def _summarize(j):
    """Turn the Indexer's JSON answer into the plain data the dashboard shows."""
    a = j["aggregations"]
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    levels = a["levels"]["w"]["l"]["buckets"]
    for b in levels:
        sev[severity(b["key"])] += b["doc_count"]
    return {
        "total": a["all"]["doc_count"],
        "total_all": a.get("all_wazuh", {}).get("w", {}).get("doc_count", a["all"]["doc_count"]),
        "matched": j["hits"]["total"]["value"],
        "scans": a["scans"]["doc_count"],
        "unique": a["unique_ips"]["value"],
        "levels": sorted((str(b["key"]) for b in levels), key=int),
        "severity": sev,
        "tactics": [{"name": b["key"], "count": b["doc_count"]} for b in a.get("tactics", {}).get("w", {}).get("t", {}).get("buckets", [])],
        "categories": [{"name": b["key"], "count": b["doc_count"]} for b in a.get("categories", {}).get("w", {}).get("c", {}).get("buckets", [])],
        "top_ips": [{"ip": b["key"], "count": b["doc_count"]} for b in a["top_ips"]["buckets"]],
        "top_dst": [{"ip": b["key"], "count": b["doc_count"]} for b in a.get("top_dst", {}).get("buckets", [])],
        "history": [{"label": b["key_as_string"][5:16], "count": b["doc_count"], "scans": b.get("scan", {}).get("doc_count", 0)}
                    for b in a["history"]["w"]["h"]["buckets"]],
        "history_all": [{"label": b["key_as_string"][5:16], "count": b["doc_count"]}
                        for b in a.get("history_all", {}).get("w", {}).get("h", {}).get("buckets", [])],
        "newest": {k: a.get("newest", {}).get(k, {}).get("t", {}).get("value") for k in ("critical", "high", "scans")},
        "rows": [_row(h) for h in j["hits"]["hits"]],
    }

"""Talks to the Wazuh Manager API (port 55000) to run Active Response. Nothing else does this."""
import requests

import config
from safety import UpstreamError, clip, log, log_request_failure, public_reason

# TLS: certificates are verified (config.WAZUH_VERIFY). Warnings are NOT silenced (see indexer.py).
SERVICE = "Wazuh API"


def _transport_failed(what, exc):
    """A request to the Wazuh API failed: log the technical cause (redacted) and give the browser a fixed sentence."""
    log_request_failure(f"Wazuh API {what}", exc)
    return UpstreamError(f"Wazuh API {what} failed: {type(exc).__name__}", public=public_reason(exc, SERVICE))


def _token():
    r = requests.post(f"{config.WAZUH_API_URL}/security/user/authenticate", params={"raw": "true"},
                      auth=(config.WAZUH_API_USER, config.WAZUH_API_PASS), verify=config.WAZUH_VERIFY, timeout=10)
    r.raise_for_status()
    return r.text.strip()


def _active_response(command, ip):
    """Ask the Wazuh manager to run an Active Response command on the agent. Raises RuntimeError on failure."""
    if not config.WAZUH_API_PASS:
        log.error("Block/unblock requested but SOC_WAZUH_API_PASS is not set, so the Wazuh API cannot be used.")
        raise UpstreamError("SOC_WAZUH_API_PASS is not set", public="The Wazuh API is not configured on the server. See the server log.")
    try:
        r = requests.put(f"{config.WAZUH_API_URL}/active-response", params={"agents_list": config.AR_AGENT_ID},
                         headers={"Authorization": "Bearer " + _token()}, verify=config.WAZUH_VERIFY, timeout=15,
                         json={"command": command, "alert": {"data": {"srcip": ip}}})
        j = r.json()
    except (requests.RequestException, ValueError) as e:
        raise _transport_failed("active-response request", e)
    j = j if isinstance(j, dict) else {}
    data = j.get("data") if isinstance(j.get("data"), dict) else {}
    if not r.ok or data.get("total_failed_items", 1) != 0:
        failed = data.get("failed_items") or [{}]
        first = failed[0] if isinstance(failed[0], dict) else {}
        err = first.get("error") if isinstance(first.get("error"), dict) else {}
        # Wazuh's own explanation can contain internal paths and names: server log only.
        log.error("Wazuh refused the active-response command (HTTP %s): %s", r.status_code,
                  clip(err.get("message") or j.get("detail") or "no reason given"))
        raise UpstreamError("Wazuh refused the command", public="Wazuh refused the command. See the server log for the reason.")


class NotConfigured(RuntimeError):
    """The Wazuh API password is not set. A normal situation in a new setup, not a failure."""


def list_agents():
    """Read-only: the agents Wazuh knows about (the manager itself, id 000, is left out)."""
    if not config.WAZUH_API_PASS:
        raise NotConfigured("Agents need SOC_WAZUH_API_PASS (the Wazuh API password). It is not set.")
    try:
        r = requests.get(f"{config.WAZUH_API_URL}/agents", params={"select": "id,name,status,ip,lastKeepAlive", "limit": 500},
                         headers={"Authorization": "Bearer " + _token()}, verify=config.WAZUH_VERIFY, timeout=15)
        r.raise_for_status()
        items = r.json()["data"]["affected_items"]
        if not isinstance(items, list):
            raise TypeError("affected_items is not a list")
        items = [a for a in items if isinstance(a, dict)]
    except (requests.RequestException, ValueError, KeyError, TypeError) as e:
        raise _transport_failed("agent list request", e)
    return [{"id": a.get("id", ""), "name": a.get("name", ""), "status": a.get("status", ""), "ip": a.get("ip", ""),
             "last_seen": a.get("lastKeepAlive", "")} for a in items if a.get("id") != "000"]


def block_ip(ip):
    if config.AR_DRY_RUN:
        return {"mode": "dry-run", "message": "Dry run: recorded only, no firewall was changed."}
    _active_response(config.AR_COMMAND, ip)
    return {"mode": "live", "message": f"{config.AR_COMMAND} sent to agent {config.AR_AGENT_ID}."}


def unblock_ip(ip):
    if config.AR_DRY_RUN:
        return {"mode": "dry-run", "message": "Dry run: nothing to remove."}
    if config.AR_UNBLOCK_COMMAND:
        _active_response(config.AR_UNBLOCK_COMMAND, ip)
        return {"mode": "live", "message": "Unblock command sent."}
    return {"mode": "live", "message": f"Marked removed here only. Delete the DROP rule on the agent: sudo iptables -D INPUT -s {ip} -j DROP"}

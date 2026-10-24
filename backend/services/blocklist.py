"""Blocked IPs: safety checks, Wazuh Active Response, and the saved list."""
import ipaddress
from datetime import datetime

import config
from services import audit, db
from wazuh import manager


def validate(ip):
    """Return the clean IP text, or raise ValueError saying why it can not be blocked."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise ValueError("That is not a valid IP address")
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
        raise ValueError("This kind of address can never be blocked")
    if str(addr) in config.PROTECTED_IPS:
        raise ValueError(f"{addr} is a protected address (lab machine or this PC)")
    return str(addr)


def block(ip, reason, actor):
    ip = validate(ip)
    if db.run("SELECT id FROM blocklist WHERE ip=? AND status='Active'", (ip,), "one"):
        raise ValueError(f"{ip} is already blocked")
    result = manager.block_ip(ip)  # raises RuntimeError if Wazuh fails: then nothing is saved
    new_id = db.run(
        "INSERT INTO blocklist (ip,reason,created,actor,status,mode,result,removed) VALUES (?,?,?,?,?,?,?,'')",
        (ip, reason[:200], datetime.now().strftime("%Y-%m-%d %H:%M"), actor, "Active", result["mode"], result["message"]), "id")
    audit.log(actor, "ip.block", ip, f"{result['mode']}: {reason[:100]}")
    return {"id": new_id, "ip": ip, **result}


def unblock(block_id, actor):
    row = db.run("SELECT * FROM blocklist WHERE id=? AND status='Active'", (block_id,), "one")
    if not row:
        raise LookupError("No active block with this id")
    result = manager.unblock_ip(row["ip"])
    db.run("UPDATE blocklist SET status='Removed', removed=?, result=? WHERE id=?",
           (datetime.now().strftime("%Y-%m-%d %H:%M"), result["message"], block_id))
    audit.log(actor, "ip.unblock", row["ip"], result["mode"])
    return {"id": block_id, "ip": row["ip"], **result}


def list_all():
    return db.run("SELECT * FROM blocklist ORDER BY id DESC", (), "all")


def active_ips():
    return [r["ip"] for r in db.run("SELECT ip FROM blocklist WHERE status='Active'", (), "all")]

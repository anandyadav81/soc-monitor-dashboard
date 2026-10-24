"""Incident storage (SQLite)."""
from datetime import datetime

from services import audit, db

STATUSES = ["Open", "Investigating", "Escalated", "Closed", "False positive"]
DONE = ("Closed", "False positive")


def create(src, dst, msg, level, actor="system"):
    """One open incident per attacker + target + alert type. A repeat only raises its count.
    Returns (incident id, True if it is a new incident)."""
    row = db.run("SELECT id FROM incidents WHERE src=? AND dst=? AND msg=? AND status NOT IN (?,?)",
                 (src, dst, msg) + DONE, "one")
    if row:
        db.run("UPDATE incidents SET count=count+1 WHERE id=?", (row["id"],))
        return row["id"], False
    new_id = db.run(
        "INSERT INTO incidents (created,src,dst,msg,level,status,note,count) VALUES (?,?,?,?,?,?,?,1)",
        (datetime.now().strftime("%Y-%m-%d %H:%M"), src, dst, msg, level, "Open", ""), "id")
    audit.log(actor, "incident.create", f"#{new_id}", f"{src}: {msg}")
    return new_id, True


def list_all():
    return db.run("SELECT * FROM incidents ORDER BY id DESC", (), "all")


def update(incident_id, status, note, actor="system"):
    """Returns False when the incident does not exist. Raises ValueError for a wrong status."""
    if status not in STATUSES:
        raise ValueError("Status must be one of: " + ", ".join(STATUSES))
    changed = db.run("UPDATE incidents SET status=?, note=? WHERE id=?", (status, note[:500], incident_id), "count")
    if changed:
        audit.log(actor, "incident.update", f"#{incident_id}", f"status={status}")
    return bool(changed)


def count_open():
    return db.run("SELECT COUNT(*) AS n FROM incidents WHERE status NOT IN (?,?)", DONE, "one")["n"]

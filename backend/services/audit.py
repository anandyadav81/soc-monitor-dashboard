"""Who did what and when. Every change made from the dashboard is written here."""
from datetime import datetime

from services import db


def log(actor, action, target="", detail=""):
    db.run("INSERT INTO audit (ts,actor,action,target,detail) VALUES (?,?,?,?,?)",
           (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), actor, action, str(target)[:100], str(detail)[:300]))


def recent(limit=200):
    return db.run("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,), "all")

"""The API. The frontend only talks to these URLs; it never touches the Indexer, Wazuh or the DB."""
import csv
import io

import requests
from flask import Blueprint, Response, g, jsonify, request, session
from werkzeug.exceptions import HTTPException

import auth
import config
import safety
from safety import UpstreamError
from services import audit, blocklist, incidents, users
from wazuh import indexer, intel, manager

bp = Blueprint("api", __name__, url_prefix="/api")
SAFE = ("GET", "HEAD", "OPTIONS")
PUBLIC = {"api.health", "api.login", "api.signup"}
FIRST_LOGIN = {"api.me", "api.change_password", "api.logout"}  # all a user may do while a new password is required


@bp.before_request
def guard():
    # Every change must carry this header. A web page on another site can not add it (basic CSRF defence).
    if request.method not in SAFE and request.headers.get("X-Requested-With") != "mini-soc":
        return jsonify(error="Missing request header"), 403
    if request.endpoint in PUBLIC:
        return None
    user = auth.current_user()
    if not user:
        return jsonify(error="Login required"), 401
    if user["must_change"] and request.endpoint not in FIRST_LOGIN:
        return jsonify(error="Change your password first (My account tab)"), 403
    g.user = user
    return None


@bp.after_request
def no_cache(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.errorhandler(ValueError)
def bad_input(e):
    return jsonify(error=str(e)), 400


@bp.errorhandler(LookupError)
def not_found(e):
    return jsonify(error=str(e.args[0]) if e.args else "Not found"), 404


# What the browser may see after a failure is decided here, in one place. Exception texts, URLs, hosts, ports,
# upstream replies and credentials are NEVER sent to the browser; the technical detail goes to the server log
# (through the redacting logger in safety.py).
@bp.errorhandler(UpstreamError)
def upstream_failed(e):
    return jsonify(error=e.public), 502   # already logged where it happened (wazuh/*.py)


@bp.errorhandler(RuntimeError)
def runtime_failed(e):
    safety.log.error("Unexpected RuntimeError on %s %s: %s", request.method, request.path, safety.clip(e))
    return jsonify(error="The request could not be completed. See the server log."), 502


@bp.errorhandler(requests.RequestException)
def indexer_down(e):
    safety.log_request_failure("Wazuh Indexer request", e)
    return jsonify(error=safety.public_reason(e, "Wazuh Indexer")), 502


def unexpected(e):
    """Anything nobody planned for (also KeyError/IndexError, which would otherwise be reported as a 404 that
    names the missing key). HTTP errors such as a wrong method keep their normal answer."""
    if isinstance(e, HTTPException):
        return e
    safety.log.error("Unhandled error on %s %s", request.method, request.path, exc_info=e)
    return jsonify(error="Internal server error"), 500


for _exc in (Exception, KeyError, IndexError):
    bp.register_error_handler(_exc, unexpected)


def _body():
    """The JSON object sent by the browser. A list, a string, a number or no body at all counts as 'nothing'."""
    b = request.get_json(silent=True)
    return b if isinstance(b, dict) else {}


@bp.errorhandler(OverflowError)
def number_too_big(e):  # an id larger than the database can hold (e.g. /api/incidents/99999999999999999999)
    return jsonify(error="Not found"), 404


def _params(limit=None):
    a = request.args
    return {"q": a.get("q", ""), "level": a.get("level", ""), "scan": a.get("scan") == "1",
            "noipv6": a.get("noipv6") == "1", "range": a.get("range", ""), "limit": limit or a.get("limit")}


def _not_self(uid):
    if uid == g.user["id"]:
        raise ValueError("You cannot do this to your own account")


# ---------- public ----------
@bp.get("/health")
def health():
    return jsonify(status="ok")


@bp.post("/login")
def login():
    b = _body()
    ok, msg, code, user = auth.try_login(b.get("email", ""), b.get("password", ""), request.remote_addr)
    if not ok:
        return jsonify(error=msg), code
    audit.log(user["email"], "login")
    return jsonify(ok=True, must_change=bool(user["must_change"]))


@bp.post("/signup")
def signup():
    """Anyone may ask for an account. It has NO access until an admin approves it."""
    if not auth.allow_signup(request.remote_addr):
        return jsonify(error="Too many sign-up requests from this address. Try again later."), 429
    b = _body()
    users.signup(b.get("email", ""), b.get("password", ""))   # a duplicate email is silently ignored (no leak)
    auth.note_signup(request.remote_addr)
    return jsonify(ok=True, message="Request received. An admin must approve the account before you can sign in. "
                                    "If this email already has an account, nothing changes."), 201


# ---------- any signed-in user ----------
@bp.get("/me")
def me():
    return jsonify(email=g.user["email"], role=g.user["role"], must_change=bool(g.user["must_change"]))


@bp.post("/logout")
def logout():
    audit.log(auth.actor(), "logout")
    users.end_session(session.get("sid"))   # server-side: a copied cookie stops working too
    session.clear()
    return jsonify(ok=True)


@bp.post("/change-password")
def change_password():
    b = _body()
    uid = g.user["id"]
    if auth.pw_locked(uid):   # a stolen session must not be able to guess the current password
        return jsonify(error="Too many wrong attempts. Wait a few minutes."), 429
    try:
        session["sv"] = users.change_password(uid, str(b.get("old", "")), str(b.get("new", "")))
    except users.WrongCurrentPassword:
        auth.note_pw_fail(uid)
        raise
    auth.clear_pw_fail(uid)
    return jsonify(ok=True)


@bp.get("/dashboard")
def dashboard():
    data = indexer.fetch(_params())
    blocked = set(blocklist.active_ips())
    for r in data["rows"]:
        r["blocked"] = r["src"] in blocked
    return jsonify({**data, "loaded": len(data["rows"]), "open_incidents": incidents.count_open(),
                    "blocked": sorted(blocked), "ar_mode": "dry-run" if config.AR_DRY_RUN else "live"})


@bp.get("/incidents")
def incidents_list():
    return jsonify(items=incidents.list_all(), statuses=incidents.STATUSES)


@bp.get("/agents")
def agents():
    try:
        return jsonify(items=manager.list_agents())
    except manager.NotConfigured as e:  # answer normally, so the browser console stays clean
        return jsonify(items=None, message=str(e))

@bp.get("/mitre")
def mitre_page():
    return jsonify(intel.mitre(request.args.get("range")))


@bp.get("/threat")
def threat_page():
    data = intel.threat(request.args.get("range"))
    blocked = set(blocklist.active_ips())
    for i in data["items"]:
        i["blocked"] = i["ip"] in blocked
    return jsonify(data)


@bp.get("/vulns")
def vulns_page():
    return jsonify(intel.vulns())


@bp.get("/geo")
def geo_panel():
    return jsonify(intel.geo(request.args.get("range")))


@bp.get("/blocklist")
def blocklist_list():
    return jsonify(items=blocklist.list_all(), ar_mode="dry-run" if config.AR_DRY_RUN else "live",
                   protected=config.PROTECTED_IPS, unblock_auto=bool(config.AR_UNBLOCK_COMMAND))


# ---------- analyst and admin ----------
@bp.get("/alerts.csv")
@auth.require("analyst")
def alerts_csv():
    def safe(v):  # stops spreadsheet formula injection
        v = str(v)
        return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "attacker_ip", "target_ip", "description", "level", "severity"])
    for r in indexer.fetch(_params(config.CSV_ROWS))["rows"]:
        w.writerow([safe(r[k]) for k in ("time", "src", "dst", "msg", "level", "sev")])
    audit.log(auth.actor(), "alerts.export")
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=alerts.csv"})


@bp.post("/incidents")
@auth.require("analyst")
def incidents_create():
    b = _body()
    g_ = lambda k: str(b.get(k, ""))[:300]
    if not g_("msg") or not g_("src"):
        raise ValueError("src and msg are required")
    new_id, created = incidents.create(g_("src"), g_("dst"), g_("msg"), g_("level"), auth.actor())
    return jsonify(id=new_id, created=created), 201 if created else 200


@bp.patch("/incidents/<int:incident_id>")
@auth.require("analyst")
def incidents_update(incident_id):
    b = _body()
    if not incidents.update(incident_id, b.get("status", "Open"), str(b.get("note", "")), auth.actor()):
        raise LookupError("Incident not found")
    return jsonify(ok=True)


# ---------- admin only ----------
@bp.post("/blocklist")
@auth.require("admin")
def blocklist_add():
    b = _body()
    if b.get("confirm") is not True:  # the browser asks the admin first; the server insists too
        raise ValueError("Confirmation is required to block an IP")
    return jsonify(blocklist.block(b.get("ip", ""), str(b.get("reason", "")), auth.actor())), 201


@bp.post("/blocklist/<int:block_id>/unblock")
@auth.require("admin")
def blocklist_remove(block_id):
    return jsonify(blocklist.unblock(block_id, auth.actor()))


@bp.get("/audit")
@auth.require("admin")
def audit_list():
    return jsonify(items=audit.recent())


@bp.get("/users")
@auth.require("admin")
def users_list():
    return jsonify(items=users.list_all(), roles=users.ROLES)


@bp.post("/users/<int:uid>/approve")
@auth.require("admin")
def users_approve(uid):
    users.approve(uid, str(_body().get("role", "viewer")), auth.actor())
    return jsonify(ok=True)


@bp.post("/users/<int:uid>/role")
@auth.require("admin")
def users_role(uid):
    _not_self(uid)
    users.set_role(uid, str(_body().get("role", "")), auth.actor())
    return jsonify(ok=True)


@bp.post("/users/<int:uid>/status")
@auth.require("admin")
def users_status(uid):
    _not_self(uid)
    users.set_status(uid, str(_body().get("status", "")), auth.actor())
    return jsonify(ok=True)


@bp.post("/users/<int:uid>/reset")
@auth.require("admin")
def users_reset(uid):
    _not_self(uid)
    users.reset_password(uid, str(_body().get("password", "")), auth.actor())
    return jsonify(ok=True)


@bp.delete("/users/<int:uid>")
@auth.require("admin")
def users_delete(uid):
    _not_self(uid)
    users.delete(uid, auth.actor())
    return jsonify(ok=True)

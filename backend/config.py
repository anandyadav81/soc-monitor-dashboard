"""All settings in one place.
Change a value here, or set an environment variable (no code edit needed).
Example (PowerShell):  $env:SOC_INDEXER_PASS = "newpassword"   (or put it in the .env file in the project folder)
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))  # the backend folder


def load_dotenv(path, overridden=None):
    """Load SOC_* settings from a .env file into the environment. Returns how many were set.
    overridden: optional list; the NAME of every setting that the real environment (shell / Windows) already
    had with a DIFFERENT value than the .env file is appended to it (values are never read out or printed).
    Rules (so it can never surprise you): a variable that is ALREADY set in the real environment wins, empty
    values are skipped (an empty line cannot blank a default), only names starting with SOC_ are read, and
    values are never printed or logged. The .env file is git-ignored: keep real passwords only there."""
    try:
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
    except OSError:
        return 0
    count = 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        name = name.strip()
        if name.lower().startswith("export "):
            name = name[7:].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if name.startswith("SOC_") and value:
            if name not in os.environ:
                os.environ[name] = value
                count += 1
            elif overridden is not None and os.environ[name] != value:
                overridden.append(name)
    return count


# The project folder is the parent of backend/. Settings placed in <project>/.env survive restarts, VS Code F5 and
# start.bat. Override the location with SOC_ENV_FILE.
ENV_FILE = os.getenv("SOC_ENV_FILE") or os.path.join(os.path.dirname(HERE), ".env")
CONFIG_WARNINGS = []   # shown at start-up by app.py (never silent)
# SOC_* settings that were already in the real environment BEFORE .env was read. They win over .env, so they
# are listed at every start (names only): a forgotten shell/Windows variable can no longer silently change the
# database file or a password.
ENV_FROM_SHELL = sorted(k for k in os.environ if k.startswith("SOC_") and k != "SOC_ENV_FILE")
ENV_OVERRIDES = []
ENV_LOADED = load_dotenv(ENV_FILE, ENV_OVERRIDES)
if ENV_OVERRIDES:
    CONFIG_WARNINGS.append(
        "These settings come from your shell/Windows and OVERRIDE the different value in .env: "
        + ", ".join(sorted(set(ENV_OVERRIDES)))
        + ". If that is not what you want: PowerShell  Remove-Item Env:NAME  (this window) and "
          "[Environment]::SetEnvironmentVariable('NAME', $null, 'User')  (permanent).")


def _list(name, default):
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


def _flag(name, default):
    """Read a true/false setting STRICTLY. Clear values (true/false, 1/0, yes/no, on/off) are honoured.
    An unset, empty or unrecognised value keeps the default and is reported, so a typo or an empty variable
    can never flip a security setting by accident (before, anything but exactly "true" turned TLS checks off)."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in ("true", "1", "yes", "on"):
        return True
    if value in ("false", "0", "no", "off"):
        return False
    CONFIG_WARNINGS.append(f"{name} has a value that is not true/false, so the default ({str(default).lower()}) is used.")
    return default


# ---- Wazuh Indexer (where the alerts are stored) ----
INDEXER_URL = os.getenv("SOC_INDEXER_URL", "https://192.168.56.101:9200")
INDEXER_USER = os.getenv("SOC_INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("SOC_INDEXER_PASS", "")  # no insecure fallback: must be set explicitly (see .env.example)
VERIFY_TLS = _flag("SOC_VERIFY_TLS", True)   # secure default; explicitly set false only in an isolated self-signed lab.
CA_BUNDLE = os.getenv("SOC_CA_BUNDLE", "")   # path to your CA certificate file; if set, certificates are checked against it
INDEXER_VERIFY = CA_BUNDLE or VERIFY_TLS
ALERT_INDEX = "wazuh-alerts-*"

# ---- What the dashboard counts and shows ----
# Suricata signatures counted as a port scan (comma separated in SOC_SCAN_NAMES, e.g. "Possible Port Scan Detected,ET SCAN")
SCAN_NAMES = _list("SOC_SCAN_NAMES", "Possible Port Scan Detected")
SCAN_NAME = SCAN_NAMES[0]
MAX_ROWS = 200                              # default number of latest alerts returned
LIMIT_CAP = 500                             # largest number a request may ask for
CSV_ROWS = 1000                             # rows in the CSV export
HISTORY = "now-7d"                          # graph range
HISTORY_HOURS = 24 * 7                      # the same range in hours (the graph always has this many points)
BUCKET = "1h"                               # graph point size (the screen shows 24 hours or 7 days)
RANGES = {"1h": "now-1h", "24h": "now-24h", "7d": "now-7d", "30d": "now-30d"}  # "all" = no limit

# Wazuh rule level -> severity name (Suricata alerts are often level 3 = low; custom rules can raise it)
SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM = 13, 10, 7

# ---- Login (email + password) ----
# The first time the server starts it creates the admin account with SOC_ADMIN_EMAIL and SOC_UI_PASSWORD.
# If the password is empty, a random one is created. It is shown only on an interactive terminal and is never
# written to a log; when output is redirected, set your own with: python backend/manage.py reset-password <email>
DEFAULT_ADMIN_EMAIL = "admin@minisoc.local"
ADMIN_EMAIL = os.getenv("SOC_ADMIN_EMAIL", DEFAULT_ADMIN_EMAIL)  # set your own, e.g. you@example.com
# After that, passwords live (hashed) in the database; change them in the app or with backend/manage.py.
UI_PASSWORD = os.getenv("SOC_UI_PASSWORD", "")
SECRET_KEY = os.getenv("SOC_SECRET_KEY", "")        # empty = random per start (everyone logs in again after restart)
COOKIE_SECURE = _flag("SOC_COOKIE_SECURE", False)  # default off so plain-HTTP local development keeps working; set SOC_COOKIE_SECURE=true once the app is served over HTTPS
LOGIN_MAX_FAILS, LOGIN_WINDOW = 5, 300              # 5 wrong passwords per 5 minutes per address
ACCOUNT_MAX_FAILS = 10                              # wrong passwords per LOGIN_WINDOW for ONE account, from any address (stops a spread-out attack)
PW_CHANGE_MAX_FAILS = 5                             # wrong "current password" guesses per LOGIN_WINDOW for one signed-in user
SESSION_HOURS = 8                                   # how long a login stays valid (server-side, and the cookie)
SIGNUP_MAX_PER_HOUR = 5                             # new accounts one address may request per hour

# ---- Block IP through Wazuh Active Response ----
# DRY RUN is ON by default: the dashboard records the block but changes no firewall.
# Turn it off only after you tested the Wazuh API:  $env:SOC_AR_DRY_RUN = "false"
AR_DRY_RUN = os.getenv("SOC_AR_DRY_RUN", "true").lower() != "false"
WAZUH_API_URL = os.getenv("SOC_WAZUH_API_URL", "https://192.168.56.101:55000")
WAZUH_API_USER = os.getenv("SOC_WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.getenv("SOC_WAZUH_API_PASS", "")
WAZUH_VERIFY_TLS = _flag("SOC_WAZUH_VERIFY_TLS", True)
WAZUH_VERIFY = CA_BUNDLE or WAZUH_VERIFY_TLS
AR_AGENT_ID = os.getenv("SOC_AR_AGENT_ID", "001")   # the agent whose firewall drops the traffic (Target-Ubuntu)
AR_COMMAND = os.getenv("SOC_AR_COMMAND", "!firewall-drop")
AR_UNBLOCK_COMMAND = os.getenv("SOC_AR_UNBLOCK_COMMAND", "")  # optional custom "delete" command; empty = unblock is manual

# These addresses can never be blocked (the lab itself and this PC). Kali .103 is NOT listed on purpose:
# it is the attacker you test against.
PROTECTED_IPS = _list("SOC_PROTECTED_IPS", "192.168.56.1,192.168.56.101,192.168.56.102")

# ---- Storage and server ----
DB_FILE = os.getenv("SOC_DB_FILE", os.path.normpath(os.path.join(HERE, "..", "data", "incidents.db")))  # the data/ folder
# Behind a reverse proxy (Nginx/Caddy) every visitor would look like the proxy's address, and the per-address limits
# would lock everybody out together. Set this to the number of proxies in front (normally 1) so the real address from
# X-Forwarded-For is used. Leave 0 when the app is reached directly: then that header is ignored (it can be forged).
try:
    PROXY_HOPS = max(0, min(5, int(os.getenv("SOC_PROXY_HOPS", "0") or 0)))
except ValueError:
    PROXY_HOPS = 0
    CONFIG_WARNINGS.append("SOC_PROXY_HOPS is not a number, so 0 (no proxy) is used.")
HOST = os.getenv("SOC_HOST", "127.0.0.1")   # 127.0.0.1 = only this PC
PORT = int(os.getenv("SOC_PORT", "5000"))

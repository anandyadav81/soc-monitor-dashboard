"""Safe error handling: what the browser may see, and what may be written to the server log.

Rule of thumb used everywhere in the backend:
  * the BROWSER gets a short fixed sentence (UpstreamError.public / public_reason), never an exception text,
    a URL, a host or port, an upstream reply, a token or a password;
  * the SERVER LOG gets the technical detail, but always through redact() and clip(), so a password or token
    that slips into an exception message is not written out.
"""
import logging
import re
import sys

import requests

import config

log = logging.getLogger("minisoc")

MASK = "[REDACTED]"
_MIN_SECRET = 4   # a shorter "secret" would blank out ordinary words in the log

# Order matters: the specific shapes first, the generic key=value shape last.
_PATTERNS = [
    (re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}"), r"\1 " + MASK),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), MASK),               # JWT (Wazuh API token)
    (re.compile(r"(?i)(://)[^/\s:@]*:[^/\s@]*@"), r"\1" + MASK + "@"),                              # user:password@host
    (re.compile(r"(?i)\b(password|passwd|pwd|pass|token|secret|api[_-]?key|authorization)(\"?\s*[:=]\s*\"?'?)[^\s,;\"'&}]+"),
     r"\1\2" + MASK),
]


def _configured_secrets():
    """The real secret values of this server, read at call time (so a changed setting is covered)."""
    values = (getattr(config, n, "") for n in ("INDEXER_PASS", "WAZUH_API_PASS", "UI_PASSWORD", "SECRET_KEY"))
    return [v for v in values if isinstance(v, str) and len(v) >= _MIN_SECRET]


def redact(text):
    """Remove passwords, tokens and credentials from a piece of text. Safe to call on anything."""
    text = str(text)
    for secret in sorted(_configured_secrets(), key=len, reverse=True):
        text = text.replace(secret, MASK)
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


def clip(text, limit=500):
    """One line, at most `limit` characters. Use it on anything that came from an upstream service
    (also stops a reply from forging extra log lines with line breaks)."""
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + "..."


class _RedactingFilter(logging.Filter):
    """Applied to the whole 'minisoc' logger: nothing logged through it leaves the process unredacted."""

    def filter(self, record):
        record.msg, record.args = redact(record.getMessage()), ()
        if record.exc_info and not record.exc_text:
            record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
        elif record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


log.addFilter(_RedactingFilter())


def setup_logging():
    """Send the server log to stderr (once). Called from create_app()."""
    if not log.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        log.propagate = False


class UpstreamError(RuntimeError):
    """A Wazuh service failed. str(e) is for the server log only; e.public is the ONLY text the browser gets."""

    def __init__(self, detail, public="The Wazuh service could not complete the request. See the server log."):
        super().__init__(detail)
        self.public = public


def public_reason(exc, service="Wazuh service"):
    """A fixed, safe sentence for a failed request to `service`. Never contains URLs, hosts, ports or upstream text."""
    if isinstance(exc, requests.exceptions.SSLError):
        return ("TLS certificate verification failed for the connection to the " + service +
                ". The administrator must check the server log and the TLS / CA settings.")
    if isinstance(exc, (requests.exceptions.JSONDecodeError, ValueError, KeyError, TypeError)):
        return "The " + service + " sent an answer that could not be understood."
    if isinstance(exc, requests.exceptions.Timeout):          # before ConnectionError: ConnectTimeout is both
        return "The " + service + " did not answer in time."
    if isinstance(exc, requests.exceptions.HTTPError):
        return "The " + service + " returned an error."
    return "Cannot reach the " + service + "."


def log_request_failure(what, exc):
    """Log a failed upstream request with its technical cause, and say it plainly when it is a TLS problem."""
    if isinstance(exc, requests.exceptions.SSLError):
        log.error("%s: TLS certificate verification FAILED (verification stays on, nothing was sent insecurely): %s. "
                  "Set SOC_CA_BUNDLE to your CA file (preferred); only in an isolated lab with a self-signed "
                  "certificate set SOC_VERIFY_TLS / SOC_WAZUH_VERIFY_TLS to false.", what, clip(exc))
    else:
        log.error("%s failed: %s: %s", what, type(exc).__name__, clip(exc))

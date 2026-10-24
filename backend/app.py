"""Start here:  python backend/app.py
Serves the API (/api/...) and the frontend folder (/)."""
import os
import secrets
import sys
from datetime import timedelta

from flask import Flask, redirect
from werkzeug.middleware.proxy_fix import ProxyFix

import api
import auth
import config
import safety
from services import users


def create_app(reveal_admin_password=False):
    """reveal_admin_password: keep a randomly generated first-start admin password in memory so main() can show it
    on an interactive terminal. Default False: the password is then never shown, printed or logged anywhere."""
    safety.setup_logging()
    app = Flask(__name__, static_folder="../frontend", static_url_path="")
    app.secret_key = config.SECRET_KEY or secrets.token_hex(32)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                      SESSION_COOKIE_SECURE=config.COOKIE_SECURE, PERMANENT_SESSION_LIFETIME=timedelta(hours=config.SESSION_HOURS))
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024   # nothing this app receives is bigger than a few KB; refuse more (HTTP 413)
    if config.PROXY_HOPS:   # trust X-Forwarded-For/Proto only from this many proxies we run ourselves
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=config.PROXY_HOPS, x_proto=config.PROXY_HOPS)
    app.register_blueprint(api.bp)

    # Printed on every start, under any server (not only `python backend/app.py`), so a missing or
    # insecure setting is never silent.
    if config.ENV_LOADED:
        print(f"  Loaded {config.ENV_LOADED} setting(s) from {config.ENV_FILE} (values are never printed).")
    if config.ENV_FROM_SHELL:   # names only; these beat .env, so a forgotten one is visible at every start
        print("  Also set in your shell/Windows (not from .env): " + ", ".join(config.ENV_FROM_SHELL))
    print("  Database: " + config.DB_FILE)
    if not config.INDEXER_PASS:
        print("  WARNING: SOC_INDEXER_PASS is not set. Set it before the dashboard can reach the Wazuh Indexer; "
              "see .env.example. There is no built-in default password.")
    if config.INDEXER_VERIFY is False or (config.WAZUH_API_PASS and config.WAZUH_VERIFY is False):
        print("  WARNING: TLS certificates are not checked. Outside a lab set SOC_CA_BUNDLE (your CA file) or "
              "SOC_VERIFY_TLS / SOC_WAZUH_VERIFY_TLS to true.")
    if config.COOKIE_SECURE and not config.SECRET_KEY:   # HTTPS = a real deployment: sessions need one stable key
        print("  WARNING: SOC_SECRET_KEY is not set. Everybody is signed out at every restart, and several server "
              "workers would each use a different key. Set a long random value (python -c \"import secrets;print(secrets.token_hex(32))\").")
    for warning in config.CONFIG_WARNINGS:   # e.g. a TLS switch with a value that is neither true nor false
        print("  WARNING: " + warning)
    if config.CA_BUNDLE and not os.path.isfile(config.CA_BUNDLE):
        # Verification would fail on every request anyway; say so now instead of failing later with a vague error.
        raise SystemExit("SOC_CA_BUNDLE is set but the file does not exist: " + config.CA_BUNDLE)

    # First start only: create the admin account. Every other user signs up and waits for approval.
    try:
        admin_email = users.clean_email(config.ADMIN_EMAIL)
    except ValueError:
        raise SystemExit("SOC_ADMIN_EMAIL is not a valid email address: " + config.ADMIN_EMAIL)
    users.ensure_admin_email(admin_email)
    app.admin_email, app.admin_created, app.admin_password, app.admin_password_random = admin_email, False, "", False
    if users.count() == 0:
        random_pw = not config.UI_PASSWORD
        password = users.generate_password() if random_pw else config.UI_PASSWORD
        try:
            users.create_admin(admin_email, password)   # the same password rules as everywhere else
        except ValueError as e:   # the text names the rule that failed; it never contains the password
            raise SystemExit("SOC_UI_PASSWORD is not accepted: " + str(e) + ". Set a different one, or leave it empty.")
        app.admin_created, app.admin_password_random = True, random_pw
        if random_pw and reveal_admin_password:
            app.admin_password = password   # only so main() can show it on a terminal; main() clears it
        elif random_pw:
            print("  First start: admin account created with a random password that is NOT shown (output may be logged). "
                  "Set your own with: python backend/manage.py reset-password " + admin_email)

    @app.get("/")
    def home():
        if not auth.current_user():
            return redirect("/login.html")
        return app.send_static_file("index.html")

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if config.COOKIE_SECURE:   # served over HTTPS: tell browsers never to fall back to plain http
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
        return resp

    return app


def main():
    # A random password is shown only when output goes to an interactive terminal. If stdout is redirected (a log
    # file, a service manager, a pipe) it is NOT shown, because that output is kept or shared. A password you chose
    # yourself (SOC_UI_PASSWORD) is never printed at all.
    app = create_app(reveal_admin_password=sys.stdout.isatty())
    print(f"\n  Mini SOC  ->  http://{config.HOST}:{config.PORT}")
    if app.admin_created:
        if app.admin_password:
            print("  First start: admin account created.")
            print(f"    Email: {app.admin_email}    Password: {app.admin_password}   (random, shown only now, never written to a log; change it after you sign in)")
            app.admin_password = ""
        elif not app.admin_password_random:
            print(f"  First start: admin account created. Email: {app.admin_email}    Password: the value of SOC_UI_PASSWORD")
    else:
        print("  Sign in with your email and password. Locked out? python backend/manage.py reset-password <your email>")
    print("  Block IP mode: " + ("DRY RUN (no firewall is changed)" if config.AR_DRY_RUN else "LIVE (Wazuh Active Response)"))
    print()
    app.run(host=config.HOST, port=config.PORT)


if __name__ == "__main__":
    main()

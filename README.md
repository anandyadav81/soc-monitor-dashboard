# SOC Monitor Dashboard

A lab-focused Security Operations Center (SOC) dashboard that brings Wazuh and Suricata alert information into one interface. It is built with a Python/Flask backend and a browser-based frontend, with incident tracking and analyst-focused views for a home lab or portfolio demonstration.

> **Project status:** This is a lab/portfolio project, not a production-ready managed SOC service. The **AI Analysis** section is marked *Soon* in the current UI and should be treated as planned rather than an implemented AI capability.

## Screenshots

These are screenshots from the actual project. Email addresses and detected IP addresses have been blurred where identified; review them before publishing in case any sensitive text was missed.

### Dashboard overview

![SOC Dashboard overview](screenshots/dashboard-overview.png)

### Incidents and endpoint agents

![Incident management](screenshots/incidents.png)

![Endpoint agents](screenshots/endpoint-agents.png)

### Threat intelligence and MITRE ATT&CK

![Threat Intelligence](screenshots/threat-intelligence.png)

![MITRE ATT&CK](screenshots/mitre-attack.png)

### Response playbooks and reports

![Response playbooks](screenshots/response-playbooks.png)

![Reports](screenshots/reports.png)

### Lab detection evidence

![Wazuh custom rules](screenshots/wazuh-custom-rules.png)

![Suricata alert evidence](screenshots/suricata-alert-evidence.png)

![ICMP flood detection](screenshots/icmp-flood-detection.png)

![NULL scan detection](screenshots/null-scan-detection.png)

![Telegram alert notifications](screenshots/telegram-notifications.png)

## Features shown in the project

- **Security dashboard:** alert totals, severity breakdown, alert trends, top alert types and recent events.
- **Wazuh + Suricata monitoring:** combined views for endpoint and network security alerts.
- **Incident management:** create and track incidents, view attacker/target information, and update incident status.
- **Endpoint agents:** view Wazuh agent status.
- **Threat intelligence view:** summarize observed lab attacker IPs, alert counts and risk information. This is based on the lab's own telemetry; it is not a claim of external reputation validation.
- **MITRE ATT&CK view:** display alert-associated tactics and techniques when tags are present in the source rules.
- **Response playbooks:** step-by-step guidance for common alert types; commands should be reviewed before use.
- **Reports and audit log:** review activity and summarize alert/incident information.
- **Accounts and roles:** admin/analyst/viewer controls are available in the application.
- **Active Response:** IP blocking integration is configurable and uses dry-run mode by default. Live blocking requires deliberate configuration and testing in an isolated lab.

## Architecture

```text
Wazuh Indexer ── alert data ──┐
                             ├── Flask backend/API ── Web frontend
Wazuh Manager API ─ agent data┘          │
                                        ├── local SQLite database
Suricata ── alerts via Wazuh ────────────┘   (incidents, blocklist, audit data)
```

The browser communicates with the Flask application; it does not connect directly to the Indexer or local database.

## Requirements

- Windows 10/11 (the commands below use PowerShell)
- Python 3.12 recommended
- A reachable Wazuh Indexer for live alert data
- Wazuh Manager API credentials if you want agent information and Active Response integration

## Setup and run (Windows / VS Code)

Open a terminal in the project root—the `soc-dashboard` folder containing `backend`, `frontend`, `requirements.txt` and `start.bat`.

### 1. Create a virtual environment and install dependencies

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

If PowerShell blocks virtual-environment activation, run this in the current terminal and activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### 2. Configure your local environment

Open `.env` and set values for **your own lab**. At minimum, configure the Wazuh Indexer URL and replace the `change-me` password placeholder with your real Indexer password:

```dotenv
SOC_INDEXER_URL=https://YOUR-WAZUH-HOST:9200
SOC_INDEXER_USER=admin
SOC_INDEXER_PASS=YOUR_INDEXER_PASSWORD
SOC_ADMIN_EMAIL=admin@example.com
SOC_UI_PASSWORD=
SOC_VERIFY_TLS=true
SOC_WAZUH_API_URL=https://YOUR-WAZUH-HOST:55000
SOC_WAZUH_API_USER=wazuh-wui
SOC_WAZUH_API_PASS=YOUR_WAZUH_API_PASSWORD
SOC_WAZUH_VERIFY_TLS=true
SOC_AR_DRY_RUN=true
SOC_HOST=127.0.0.1
SOC_PORT=5000
```

Keep real credentials only in `.env`. Do not put passwords, tokens, private keys, or real environment values in `.env.example` or screenshots. TLS verification should remain enabled; for a self-signed certificate in an isolated lab, configure a trusted CA where possible instead of disabling verification.

### 3. Start the dashboard

```powershell
python backend/app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser. Sign in with the admin account configured for your local environment. Keep the terminal open while using the app; press `Ctrl+C` to stop it.

The app creates its local SQLite database under `data/` when needed. Database files contain local runtime state and should not be committed.

### Optional launcher

You can also run:

```powershell
.\start.bat
```

The launcher installs the listed requirements and starts the application. The virtual-environment approach above is recommended so you know which Python installation is being used.

## Tests

With the virtual environment activated, run the project's automated tests from the repository root:

```powershell
python -m unittest discover -s tests -v
python tests/phase1_audit.py
```

These tests do not replace a live connectivity check against your own Wazuh deployment. Review any self-test report locally before sharing it, because diagnostic output can contain IP addresses, hostnames or other environment details.

## Security notes before publishing

- Do **not** upload `.env`, `.venv/`, local database files, logs, backups or self-test reports.
- Check `git status` and `git check-ignore` before the first commit.
- Review screenshots at full size; blur email addresses, internal IPs, hostnames, chat details and any credentials that may remain visible.
- Keep Active Response in dry-run mode until you have verified the Wazuh API and tested blocking/unblocking in an isolated lab.
- Do not expose the development server to the public internet. A production deployment needs a proper HTTPS-capable server, secure secrets management and deployment-specific hardening.

## Project structure

```text
soc-dashboard/
├── backend/          # Flask app, API, authentication, services and Wazuh integrations
├── frontend/         # HTML, CSS and JavaScript interface
├── data/             # Local SQLite runtime data (not for Git)
├── tests/             # Automated tests and audit checks
├── screenshots/      # Portfolio screenshots used by this README
├── .env.example      # Configuration template with placeholders
├── .gitignore        # Excludes local secrets, databases and generated files
├── requirements.txt  # Python dependencies
└── start.bat         # Optional Windows launcher
```

## License

See [LICENSE](LICENSE) in the repository.

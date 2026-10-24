@echo off
REM Starts Mini SOC on Windows. SOC_INDEXER_PASS must be set first - see README, section Run it.
REM First start: with SOC_UI_PASSWORD set, that password is used (and never printed). Without it a random admin password is
REM shown in this window only, never written to a log. If it was not shown: python backend\manage.py reset-password you@example.com
cd /d "%~dp0"
if not defined SOC_INDEXER_PASS echo.
if not defined SOC_INDEXER_PASS echo  WARNING: SOC_INDEXER_PASS is not set. The dashboard will start but cannot read alerts.
if not defined SOC_INDEXER_PASS echo  See README.md, section Run it. This script never stores or prints the password.
if not defined SOC_INDEXER_PASS echo.
pip install -r requirements.txt
python backend\app.py
pause

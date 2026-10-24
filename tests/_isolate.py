"""Imported FIRST by every test file. The tests must give the same result on every PC, so they never read the
real settings: SOC_* variables from your shell are removed, and the project's real .env file is not loaded
(SOC_ENV_FILE points to a file that does not exist). Your real .env stays untouched and is only used by the app."""
import os
import tempfile

for _name in [k for k in os.environ if k.startswith("SOC_")]:
    del os.environ[_name]

NO_ENV_FILE = os.path.join(tempfile.gettempdir(), "mini-soc-tests-no-such.env")
os.environ["SOC_ENV_FILE"] = NO_ENV_FILE

"""
Smoke tests for all exporter scripts.

Runs every exporter's main() under moto AWS mocking with STRATUSSCAN_AUTO_RUN=1.

Pass:  main() returns normally, or calls sys.exit(0) / sys.exit(None) — graceful
       success or graceful skip (no resources / service unavailable in partition).
Skip:  moto raises NotImplementedError — the API is not yet mocked; documented
       limitation, not a script bug.
Fail:  main() calls sys.exit() with a non-zero code, or raises an unhandled exception.

Scope: structural correctness only — scripts run and exit cleanly against an empty,
mocked AWS environment. Data correctness (field values, column completeness) is out
of scope here and addressed by the comprehensive audit (Issue #163).
"""

import importlib.util
import logging
import sys
from pathlib import Path

import pytest
import utils  # imported here so monkeypatch can patch utils attributes by reference
from moto import mock_aws

# Shared null logger — absorbs all log calls without writing files or to stderr.
_NULL_LOGGER = logging.getLogger("stratusscan-smoke")
_NULL_LOGGER.addHandler(logging.NullHandler())
_NULL_LOGGER.propagate = False

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"

# Orchestrators launch sub-scripts as subprocesses — those subprocess calls are
# not intercepted by in-process moto mocking, so they cannot pass this test by
# design. output_archive.py makes no AWS calls and is not an exporter.
# services_in_use_export.py does a lazy `from smart_scan.mapping import ...`
# inside create_recommendations_sheet(); when run directly, Python adds scripts/
# to sys.path so smart_scan resolves to the package. Our importlib loader does
# not replicate that, so smart_scan.py at the project root shadows the package.
# This is a test-only path issue — the script works correctly when invoked
# directly. Tracked separately for architectural cleanup.
_EXCLUDED = {
    "compute_resources.py",
    "database_resources.py",
    "network_resources.py",
    "storage_resources.py",
    "output_archive.py",
    "services_in_use_export.py",
}

EXPORTER_SCRIPTS = sorted(
    p
    for p in SCRIPTS_DIR.glob("*.py")
    if not p.name.startswith("_") and p.name not in _EXCLUDED
)


@pytest.fixture(autouse=True)
def _smoke_env(monkeypatch):
    """Fake AWS credentials, CI mode, and suppressed file logging for every smoke test."""
    for key, val in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "STRATUSSCAN_AUTO_RUN": "1",
        "STRATUSSCAN_REGIONS": "us-east-1",
    }.items():
        monkeypatch.setenv(key, val)
    # Suppress file-based logging: patch both setup_logging (to avoid creating
    # log files for 100+ test runs) and utils.logger (which starts as None and
    # is set by setup_logging — save functions crash if it stays None).
    monkeypatch.setattr(utils, "logger", _NULL_LOGGER)
    monkeypatch.setattr(utils, "setup_logging", lambda *a, **kw: _NULL_LOGGER)


def _load_script(script_path: Path):
    """Load a script as a fresh module to prevent cross-test state leakage."""
    module_name = f"_smoke_{script_path.stem}"
    sys.modules.pop(module_name, None)
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.smoke
@pytest.mark.parametrize("script_path", EXPORTER_SCRIPTS, ids=lambda p: p.stem)
@mock_aws
def test_exporter_smoke(script_path, monkeypatch):
    """Exporter completes or gracefully skips without crashing under moto."""
    monkeypatch.setattr(sys, "argv", [script_path.name])
    mod = _load_script(script_path)
    try:
        mod.main()
    except SystemExit as e:
        assert e.code in (0, None), (
            f"{script_path.name} exited with code {e.code} — expected 0 (graceful)"
        )
    except NotImplementedError:
        pytest.skip(f"moto does not fully implement APIs used by {script_path.name}")

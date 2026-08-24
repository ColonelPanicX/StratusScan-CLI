#!/usr/bin/env python3
"""
Integration tests for the headless --run-all orchestrator (_run_full_audit in
stratusscan.py).

Uses tiny fake *_export.py subprocesses (stdlib only) that append a manifest
record, so the test drives the real subprocess loop, manifest read, report
build, report save, and exit-code logic without touching AWS.
"""

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import stratusscan  # noqa: E402
import utils  # noqa: E402

pd = pytest.importorskip("pandas")


WRITTEN_EXPORTER = '''\
import os, json
mp = os.environ["STRATUSSCAN_RUN_MANIFEST"]
name = os.environ.get("STRATUSSCAN_CURRENT_EXPORTER", "")
with open(mp, "a", encoding="utf-8") as f:
    f.write(json.dumps({
        "exporter": name, "resource": name, "rows": 7, "status": "written",
        "file": "out/%s.xlsx" % name, "sheets": None,
        "account_id": os.environ.get("STRATUSSCAN_ACCOUNT_ID"),
        "regions": os.environ.get("STRATUSSCAN_REGIONS"),
    }) + "\\n")
'''

FAILING_EXPORTER = "import sys; sys.exit(1)\n"


@pytest.fixture
def audit_env(tmp_path, monkeypatch):
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    out_dir = tmp_path / "output"
    out_dir.mkdir()

    monkeypatch.setattr(utils, "validate_aws_credentials", lambda: (True, "123456789012", "TESTACCT"))
    monkeypatch.setattr(utils, "get_scripts_dir", lambda: scripts_dir)
    monkeypatch.setattr(utils, "get_output_dir", lambda: out_dir)
    monkeypatch.setattr(utils, "logger", logging.getLogger("test-orchestrator"))

    def fake_config_value(key, default=None, section=None):
        return {"format": "xlsx", "skip_empty_exports": True,
                "destination": "local", "s3": {"bucket": "", "prefix": "stratusscan/"}}.get(key, default)
    monkeypatch.setattr(utils, "config_value", fake_config_value)
    monkeypatch.setenv("STRATUSSCAN_OUTPUT_DESTINATION", "local")

    return scripts_dir, out_dir


def _write(scripts_dir, name, body):
    (scripts_dir / name).write_text(body)


class TestRunFullAudit:
    def test_happy_path_builds_report_and_exits_zero(self, audit_env):
        scripts_dir, out_dir = audit_env
        _write(scripts_dir, "alpha_export.py", WRITTEN_EXPORTER)
        _write(scripts_dir, "zeta_export.py", FAILING_EXPORTER)

        with pytest.raises(SystemExit) as exc:
            stratusscan._run_full_audit("us-east-1,us-west-2", "local")
        assert exc.value.code == 0  # at least one exporter succeeded

        reports = list(out_dir.glob("*audit-run-report*.xlsx"))
        assert len(reports) == 1

        df = pd.read_excel(reports[0])
        rows = {r["Exporter"]: r for r in df.to_dict("records")}
        assert rows["alpha_export.py"]["Status"] == utils.RUN_STATUS_OK
        assert rows["alpha_export.py"]["Assets"] == 7
        assert rows["zeta_export.py"]["Status"] == utils.RUN_STATUS_FAILED

        # The per-run manifest was written next to the report
        assert list(out_dir.glob("*audit-run-manifest*.jsonl"))

    def test_all_failed_exits_one(self, audit_env):
        scripts_dir, out_dir = audit_env
        _write(scripts_dir, "alpha_export.py", FAILING_EXPORTER)

        with pytest.raises(SystemExit) as exc:
            stratusscan._run_full_audit(None, "local")
        assert exc.value.code == 1

    def test_no_exporters_exits_one(self, audit_env):
        # empty scripts dir
        with pytest.raises(SystemExit) as exc:
            stratusscan._run_full_audit(None, "local")
        assert exc.value.code == 1

    def test_output_s3_without_bucket_exits_two(self, audit_env):
        scripts_dir, _ = audit_env
        _write(scripts_dir, "alpha_export.py", WRITTEN_EXPORTER)
        with pytest.raises(SystemExit) as exc:
            stratusscan._run_full_audit(None, "s3")
        assert exc.value.code == 2

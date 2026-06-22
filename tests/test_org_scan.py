#!/usr/bin/env python3
"""
Tests for organization-wide scanning (--org-scan):
- utils.list_organization_accounts (active filter)
- utils.verify_assume_role (assume-role preflight)
- utils.build_org_summary_dataframe (roll-up)
- stratusscan._run_org_audit (per-account reports + summary, role-failed skip)
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


# --- list_organization_accounts ------------------------------------------------

class _FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class _FakeOrgClient:
    def __init__(self, pages):
        self._pages = pages

    def get_paginator(self, name):
        assert name == "list_accounts"
        return _FakePaginator(self._pages)


class TestListOrganizationAccounts:
    PAGES = [{
        "Accounts": [
            {"Id": "111111111111", "Name": "Audit", "Email": "a@x", "Status": "ACTIVE"},
            {"Id": "222222222222", "Name": "Prod", "Email": "p@x", "Status": "ACTIVE"},
            {"Id": "333333333333", "Name": "Old", "Email": "o@x", "Status": "SUSPENDED"},
        ]
    }]

    def test_active_only_filters_suspended(self, monkeypatch):
        monkeypatch.setattr(utils, "get_boto3_client", lambda *a, **k: _FakeOrgClient(self.PAGES))
        accounts = utils.list_organization_accounts(active_only=True)
        ids = [a["id"] for a in accounts]
        assert ids == ["111111111111", "222222222222"]
        assert accounts[0]["name"] == "Audit"

    def test_include_inactive(self, monkeypatch):
        monkeypatch.setattr(utils, "get_boto3_client", lambda *a, **k: _FakeOrgClient(self.PAGES))
        assert len(utils.list_organization_accounts(active_only=False)) == 3


# --- verify_assume_role --------------------------------------------------------

class TestVerifyAssumeRole:
    def test_success(self, monkeypatch):
        class _STS:
            def get_caller_identity(self):
                return {"Account": "222222222222"}
        monkeypatch.setattr(utils, "get_boto3_client", lambda *a, **k: _STS())
        ok, err = utils.verify_assume_role("arn:aws:iam::222222222222:role/Scan")
        assert ok is True and err is None

    def test_failure_returns_error(self, monkeypatch):
        def _boom(*a, **k):
            raise Exception("AccessDenied: not authorized to assume role")
        monkeypatch.setattr(utils, "get_boto3_client", _boom)
        ok, err = utils.verify_assume_role("arn:aws:iam::333333333333:role/Scan")
        assert ok is False
        assert "AccessDenied" in err


# --- build_org_summary_dataframe ----------------------------------------------

class TestOrgSummary:
    def test_rollup_rows_and_columns(self):
        summaries = [
            {"account_id": "222", "account_name": "Prod", "status": utils.ACCOUNT_STATUS_SCANNED,
             "exporters": 2, "ok": 1, "empty": 1, "no_output": 0, "failed": 0,
             "total_assets": 7, "report": "s3://b/prod.xlsx", "detail": ""},
            {"account_id": "333", "account_name": "Dev", "status": utils.ACCOUNT_STATUS_ROLE_FAILED,
             "exporters": 0, "ok": 0, "empty": 0, "no_output": 0, "failed": 0,
             "total_assets": 0, "report": "", "detail": "AccessDenied"},
        ]
        df = utils.build_org_summary_dataframe(summaries)
        assert list(df["Account"]) == ["Dev", "Prod"]  # sorted
        prod = {r["Account"]: r for r in df.to_dict("records")}["Prod"]
        assert prod["Status"] == utils.ACCOUNT_STATUS_SCANNED
        assert prod["Total Assets"] == 7
        assert prod["Report"] == "s3://b/prod.xlsx"
        for col in ("Account ID", "Status", "With Data", "Failed", "Total Assets", "Report"):
            assert col in df.columns

    def test_empty_inputs(self):
        df = utils.build_org_summary_dataframe([])
        assert df.empty and "Status" in df.columns


# --- _run_org_audit integration ------------------------------------------------

WRITTEN_EXPORTER = '''\
import os, json
mp = os.environ["STRATUSSCAN_RUN_MANIFEST"]
name = os.environ.get("STRATUSSCAN_CURRENT_EXPORTER", "")
with open(mp, "a", encoding="utf-8") as f:
    f.write(json.dumps({"exporter": name, "resource": name, "rows": 7,
                        "status": "written", "file": "x.xlsx", "sheets": None,
                        "account_id": os.environ.get("STRATUSSCAN_ACCOUNT_ID")}) + "\\n")
'''


@pytest.fixture
def org_env(tmp_path, monkeypatch):
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    (scripts_dir / "alpha_export.py").write_text(WRITTEN_EXPORTER)
    out_dir = tmp_path / "output"
    out_dir.mkdir()

    monkeypatch.setattr(utils, "validate_aws_credentials", lambda: (True, "111111111111", "AUDIT"))
    monkeypatch.setattr(utils, "detect_partition", lambda *a, **k: "aws")
    monkeypatch.setattr(utils, "get_scripts_dir", lambda: scripts_dir)
    monkeypatch.setattr(utils, "get_output_dir", lambda: out_dir)
    monkeypatch.setattr(utils, "logger", logging.getLogger("test-org"))

    monkeypatch.setattr(utils, "list_organization_accounts", lambda active_only=True: [
        {"id": "222222222222", "name": "Prod", "email": "", "status": "ACTIVE"},
        {"id": "333333333333", "name": "Dev", "email": "", "status": "ACTIVE"},
    ])

    # Prod assumable, Dev not (StackSet not yet rolled out there).
    def fake_verify(role_arn, region_name=None):
        return ("222222222222" in role_arn, None if "222222222222" in role_arn else "AccessDenied")
    monkeypatch.setattr(utils, "verify_assume_role", fake_verify)

    def fake_config_value(key, default=None, section=None):
        return {"format": "xlsx", "skip_empty_exports": True,
                "destination": "local", "s3": {"bucket": "", "prefix": "stratusscan/"}}.get(key, default)
    monkeypatch.setattr(utils, "config_value", fake_config_value)
    monkeypatch.setenv("STRATUSSCAN_OUTPUT_DESTINATION", "local")

    return out_dir


class TestRunOrgAudit:
    def test_per_account_reports_and_summary(self, org_env):
        out_dir = org_env
        with pytest.raises(SystemExit) as exc:
            stratusscan._run_org_audit("us-east-1", "local", "ScanRole", None)
        assert exc.value.code == 0  # at least one account scanned

        # Prod (assumable) got a per-account run report; Dev (role failed) did not.
        prod_reports = list(out_dir.glob("Prod-222222222222-audit-run-report*.xlsx"))
        dev_reports = list(out_dir.glob("Dev-333333333333-audit-run-report*.xlsx"))
        assert len(prod_reports) == 1
        assert dev_reports == []

        summaries = list(out_dir.glob("*org-audit-summary*.xlsx"))
        assert len(summaries) == 1
        df = pd.read_excel(summaries[0])
        rows = {r["Account"]: r for r in df.to_dict("records")}
        assert rows["Prod"]["Status"] == utils.ACCOUNT_STATUS_SCANNED
        assert rows["Prod"]["Total Assets"] == 7
        assert rows["Dev"]["Status"] == utils.ACCOUNT_STATUS_ROLE_FAILED

    def test_all_role_failed_exits_one(self, org_env, monkeypatch):
        monkeypatch.setattr(utils, "verify_assume_role", lambda role_arn, region_name=None: (False, "AccessDenied"))
        with pytest.raises(SystemExit) as exc:
            stratusscan._run_org_audit("us-east-1", "local", "ScanRole", None)
        assert exc.value.code == 1

    def test_exclude_accounts(self, org_env):
        out_dir = org_env
        with pytest.raises(SystemExit):
            stratusscan._run_org_audit("us-east-1", "local", "ScanRole", "222222222222")
        # Prod excluded → only Dev considered (role-failed) → no Prod report
        assert list(out_dir.glob("Prod-*audit-run-report*.xlsx")) == []

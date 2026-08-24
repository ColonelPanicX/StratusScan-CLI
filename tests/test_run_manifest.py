#!/usr/bin/env python3
"""
Tests for empty-export suppression and the per-run manifest in utils.py
(headless --run-all safety layer).

Covers:
- skip_empty_exports: empty data writes no file; returns the truthy sentinel
- non-empty exports still write and return a real path
- skip_empty=False writes empty files (opt-out)
- multi-sheet: all-empty suppressed, partial written
- run manifest (STRATUSSCAN_RUN_MANIFEST) records written/empty rows + context
- manifest absent when the env var is unset
"""

import logging
import sys
from pathlib import Path

import pytest

try:
    import utils
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    import utils

pd = pytest.importorskip("pandas")


@pytest.fixture
def out_dir(tmp_path, monkeypatch):
    """Isolate exports to a tmp dir and make delivery a no-op passthrough."""
    d = tmp_path / "output"
    d.mkdir()
    # save_* use the module-global `logger`, which is None until setup_logging();
    # inject one so the save path doesn't AttributeError in the test process.
    monkeypatch.setattr(utils, "logger", logging.getLogger("test-run-manifest"))
    monkeypatch.setattr(utils, "get_output_dir", lambda: d)
    # deliver_output is exercised by the S3 tests; here we want the local path back.
    monkeypatch.setattr(utils, "deliver_output", lambda p: p)
    return d


def _config(monkeypatch, *, fmt="xlsx", skip_empty=True):
    def fake_config_value(key, default=None, section=None):
        return {"format": fmt, "skip_empty_exports": skip_empty}.get(key, default)
    monkeypatch.setattr(utils, "config_value", fake_config_value)


def _files(d):
    return sorted(p.name for p in d.iterdir())


class TestSkipEmptySingle:
    def test_empty_df_suppressed(self, out_dir, monkeypatch):
        _config(monkeypatch, skip_empty=True)
        result = utils.save_dataframe_to_excel(pd.DataFrame(), "acct-ec2-export-01.01.2026.xlsx")
        assert result == utils.EMPTY_EXPORT_SENTINEL
        assert result  # truthy → exporters' `if output_path:` success path holds
        assert _files(out_dir) == []

    def test_nonempty_df_written(self, out_dir, monkeypatch):
        _config(monkeypatch, skip_empty=True)
        df = pd.DataFrame({"InstanceId": ["i-1", "i-2"]})
        result = utils.save_dataframe_to_excel(df, "acct-ec2-export-01.01.2026.xlsx")
        assert result != utils.EMPTY_EXPORT_SENTINEL
        assert _files(out_dir) == ["acct-ec2-export-01.01.2026.xlsx"]

    def test_skip_empty_disabled_writes_empty(self, out_dir, monkeypatch):
        _config(monkeypatch, skip_empty=False)
        result = utils.save_dataframe_to_excel(pd.DataFrame(), "acct-ec2-export-01.01.2026.xlsx")
        assert result != utils.EMPTY_EXPORT_SENTINEL
        assert _files(out_dir) == ["acct-ec2-export-01.01.2026.xlsx"]

    def test_empty_csv_suppressed(self, out_dir, monkeypatch):
        _config(monkeypatch, fmt="csv", skip_empty=True)
        result = utils.save_dataframe_to_excel(pd.DataFrame(), "acct-ec2-export-01.01.2026.xlsx")
        assert result == utils.EMPTY_EXPORT_SENTINEL
        assert _files(out_dir) == []


class TestSkipEmptyMulti:
    def test_all_sheets_empty_suppressed(self, out_dir, monkeypatch):
        _config(monkeypatch, skip_empty=True)
        sheets = {"VPCs": pd.DataFrame(), "Subnets": pd.DataFrame()}
        result = utils.save_multiple_dataframes_to_excel(sheets, "acct-vpc-export-01.01.2026.xlsx")
        assert result == utils.EMPTY_EXPORT_SENTINEL
        assert _files(out_dir) == []

    def test_partial_data_written(self, out_dir, monkeypatch):
        _config(monkeypatch, skip_empty=True)
        sheets = {"VPCs": pd.DataFrame({"VpcId": ["vpc-1"]}), "Subnets": pd.DataFrame()}
        result = utils.save_multiple_dataframes_to_excel(sheets, "acct-vpc-export-01.01.2026.xlsx")
        assert result != utils.EMPTY_EXPORT_SENTINEL
        assert _files(out_dir) == ["acct-vpc-export-01.01.2026.xlsx"]


class TestRunManifest:
    def test_records_written_export(self, out_dir, monkeypatch, tmp_path):
        _config(monkeypatch, skip_empty=True)
        manifest = tmp_path / "manifest.jsonl"
        monkeypatch.setenv("STRATUSSCAN_RUN_MANIFEST", str(manifest))
        monkeypatch.setenv("STRATUSSCAN_CURRENT_EXPORTER", "ec2_export.py")
        monkeypatch.setenv("STRATUSSCAN_ACCOUNT_ID", "123456789012")
        monkeypatch.setenv("STRATUSSCAN_ACCOUNT_NAME", "PROD")
        monkeypatch.setenv("STRATUSSCAN_REGIONS", "us-east-1,us-west-2")

        df = pd.DataFrame({"InstanceId": ["i-1", "i-2", "i-3"]})
        utils.save_dataframe_to_excel(df, "PROD-ec2-export-01.01.2026.xlsx")

        records = utils.read_run_manifest(str(manifest))
        assert len(records) == 1
        r = records[0]
        assert r["exporter"] == "ec2_export.py"
        assert r["account_id"] == "123456789012"
        assert r["account_name"] == "PROD"
        assert r["regions"] == "us-east-1,us-west-2"
        assert r["rows"] == 3
        assert r["status"] == "written"
        assert r["file"] is not None

    def test_records_empty_export(self, out_dir, monkeypatch, tmp_path):
        _config(monkeypatch, skip_empty=True)
        manifest = tmp_path / "manifest.jsonl"
        monkeypatch.setenv("STRATUSSCAN_RUN_MANIFEST", str(manifest))
        monkeypatch.setenv("STRATUSSCAN_CURRENT_EXPORTER", "ec2_export.py")

        utils.save_dataframe_to_excel(pd.DataFrame(), "PROD-ec2-export-01.01.2026.xlsx")

        records = utils.read_run_manifest(str(manifest))
        assert len(records) == 1
        assert records[0]["status"] == "empty"
        assert records[0]["rows"] == 0
        assert records[0]["file"] is None

    def test_multi_sheet_records_per_sheet_counts(self, out_dir, monkeypatch, tmp_path):
        _config(monkeypatch, skip_empty=True)
        manifest = tmp_path / "manifest.jsonl"
        monkeypatch.setenv("STRATUSSCAN_RUN_MANIFEST", str(manifest))

        sheets = {"VPCs": pd.DataFrame({"VpcId": ["vpc-1", "vpc-2"]}), "Subnets": pd.DataFrame({"SubnetId": ["s-1"]})}
        utils.save_multiple_dataframes_to_excel(sheets, "PROD-vpc-export-01.01.2026.xlsx")

        records = utils.read_run_manifest(str(manifest))
        assert len(records) == 1
        assert records[0]["rows"] == 3
        assert records[0]["sheets"] == {"VPCs": 2, "Subnets": 1}

    def test_no_manifest_when_env_unset(self, out_dir, monkeypatch, tmp_path):
        _config(monkeypatch, skip_empty=True)
        monkeypatch.delenv("STRATUSSCAN_RUN_MANIFEST", raising=False)
        manifest = tmp_path / "manifest.jsonl"

        utils.save_dataframe_to_excel(pd.DataFrame({"x": [1]}), "PROD-ec2-export-01.01.2026.xlsx")
        assert not manifest.exists()

    def test_read_missing_manifest_returns_empty(self, tmp_path):
        assert utils.read_run_manifest(str(tmp_path / "nope.jsonl")) == []

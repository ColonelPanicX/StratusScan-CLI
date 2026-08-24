#!/usr/bin/env python3
"""
Tests for the run-report builder (utils.build_run_report_dataframe) and the
STRATUSSCAN_OUTPUT_DESTINATION override in resolve_s3_destination.

The report merges per-script execution results with per-save manifest records
into the four auditor-facing outcomes: OK, EMPTY, NO OUTPUT, FAILED.
"""

import sys
from pathlib import Path

import pytest

try:
    import utils
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    import utils

pytest.importorskip("pandas")


def _rows_by_exporter(df):
    return {r["Exporter"]: r for r in df.to_dict("records")}


class TestBuildRunReport:
    def _build(self):
        executor_results = [
            {"script": "ec2_export.py", "success": True, "return_code": 0, "duration_seconds": 3.2, "error_message": None},
            {"script": "vpc_export.py", "success": True, "return_code": 0, "duration_seconds": 1.0, "error_message": None},
            {"script": "rds_export.py", "success": True, "return_code": 0, "duration_seconds": 2.0, "error_message": None},
            {"script": "iam_export.py", "success": False, "return_code": 1, "duration_seconds": 0.5, "error_message": "boom"},
        ]
        manifest_records = [
            {"exporter": "ec2_export.py", "rows": 5, "status": "written", "file": "s3://b/ec2.xlsx", "sheets": None, "regions": "us-east-1"},
            {"exporter": "vpc_export.py", "rows": 0, "status": "empty", "file": None, "sheets": {"VPCs": 0, "Subnets": 0}, "regions": "us-east-1"},
            # rds_export.py: ran clean but never saved → NO OUTPUT
            # iam_export.py: failed before/while saving → FAILED
        ]
        return utils.build_run_report_dataframe(executor_results, manifest_records)

    def test_status_classification(self):
        rows = _rows_by_exporter(self._build())
        assert rows["ec2_export.py"]["Status"] == utils.RUN_STATUS_OK
        assert rows["vpc_export.py"]["Status"] == utils.RUN_STATUS_EMPTY
        assert rows["rds_export.py"]["Status"] == utils.RUN_STATUS_NO_OUTPUT
        assert rows["iam_export.py"]["Status"] == utils.RUN_STATUS_FAILED

    def test_asset_counts(self):
        rows = _rows_by_exporter(self._build())
        assert rows["ec2_export.py"]["Assets"] == 5
        assert rows["vpc_export.py"]["Assets"] == 0
        assert rows["rds_export.py"]["Assets"] == 0

    def test_output_file_only_for_written(self):
        rows = _rows_by_exporter(self._build())
        assert rows["ec2_export.py"]["Output File"] == "s3://b/ec2.xlsx"
        assert rows["vpc_export.py"]["Output File"] == ""
        assert rows["rds_export.py"]["Output File"] == ""

    def test_failed_detail_carries_error(self):
        rows = _rows_by_exporter(self._build())
        assert "boom" in rows["iam_export.py"]["Detail"]

    def test_sheets_rendered(self):
        rows = _rows_by_exporter(self._build())
        assert rows["vpc_export.py"]["Sheets"] == "VPCs:0, Subnets:0"

    def test_sorted_by_exporter(self):
        df = self._build()
        assert list(df["Exporter"]) == sorted(df["Exporter"])

    def test_empty_inputs_yield_empty_frame_with_columns(self):
        df = utils.build_run_report_dataframe([], [])
        assert df.empty
        assert "Status" in df.columns and "Assets" in df.columns


class TestOutputDestinationOverride:
    def _config(self, monkeypatch, destination, bucket):
        def fake(key, default=None, section=None):
            return {
                "destination": destination,
                "s3": {"bucket": bucket, "prefix": "stratusscan/"},
            }.get(key, default)
        monkeypatch.setattr(utils, "config_value", fake)
        for var in ("STRATUSSCAN_OUTPUT_DESTINATION", "STRATUSSCAN_S3_BUCKET", "STRATUSSCAN_S3_PREFIX"):
            monkeypatch.delenv(var, raising=False)

    def test_env_forces_s3(self, monkeypatch):
        self._config(monkeypatch, destination="local", bucket="cfg-bucket")
        monkeypatch.setenv("STRATUSSCAN_OUTPUT_DESTINATION", "s3")
        assert utils.resolve_s3_destination()["enabled"] is True

    def test_env_forces_local_over_config_s3(self, monkeypatch):
        self._config(monkeypatch, destination="s3", bucket="cfg-bucket")
        monkeypatch.setenv("STRATUSSCAN_OUTPUT_DESTINATION", "local")
        assert utils.resolve_s3_destination()["enabled"] is False

    def test_env_forces_local_over_bucket_env(self, monkeypatch):
        self._config(monkeypatch, destination="local", bucket="")
        monkeypatch.setenv("STRATUSSCAN_S3_BUCKET", "env-bucket")
        monkeypatch.setenv("STRATUSSCAN_OUTPUT_DESTINATION", "local")
        # explicit local wins even though a bucket env is set
        assert utils.resolve_s3_destination()["enabled"] is False

    def test_s3_force_without_bucket_not_enabled(self, monkeypatch):
        self._config(monkeypatch, destination="local", bucket="")
        monkeypatch.setenv("STRATUSSCAN_OUTPUT_DESTINATION", "s3")
        assert utils.resolve_s3_destination()["enabled"] is False

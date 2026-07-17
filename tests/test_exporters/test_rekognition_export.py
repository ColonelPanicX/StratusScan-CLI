#!/usr/bin/env python3
"""
Tests for rekognition_export.py.

Covers:
- collect_projects() per-item guarding and region-scope failure propagation
- main()'s failed-scope tracking, always-written Summary sheet, and
  exit-code behavior

moto's Amazon Rekognition support does not implement ``describe_projects``
(custom model projects) as of moto 5.1 -- calling it against ``mock_aws``
raises ``NotImplementedError`` unconditionally, so it cannot be used to
build realistic collection-success or collection-failure fixtures. These
tests drive the module through monkeypatched boto3 clients / module
functions instead, mirroring the approach already used for
tests/test_exporters/test_globalaccelerator_export.py.

See .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import rekognition_export  # noqa: E402
from rekognition_export import _scan_projects_region, collect_projects  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture(autouse=True)
def patch_output_dir(tmp_path, monkeypatch):
    """Redirect get_output_dir() to a temp directory for every test."""
    monkeypatch.setattr(rekognition_export.utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


def _fake_rekognition_client(projects=None):
    """Build a MagicMock standing in for a boto3 Rekognition client."""
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"ProjectDescriptions": projects or []}]
    client.get_paginator.return_value = paginator
    return client


class TestScanProjectsRegion:
    """Happy-path collection."""

    def test_collects_projects(self, monkeypatch):
        project = {
            "ProjectArn": "arn:aws:rekognition:us-east-1:123456789012:project/good-project/1699999999999",
            "Status": "CREATED",
            "CreationTimestamp": datetime(2024, 1, 1, tzinfo=timezone.utc),
        }
        client = _fake_rekognition_client(projects=[project])
        monkeypatch.setattr(rekognition_export.utils, "get_boto3_client", lambda *a, **kw: client)

        rows = _scan_projects_region(REGION)

        arns = {row["Project ARN"] for row in rows}
        assert project["ProjectArn"] in arns

    def test_empty_region_returns_empty_list(self, monkeypatch):
        client = _fake_rekognition_client(projects=[])
        monkeypatch.setattr(rekognition_export.utils, "get_boto3_client", lambda *a, **kw: client)

        rows = _scan_projects_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region -- and, for scripts like
    this one that always build a non-empty Summary sheet, the loss was
    additionally hidden inside a complete-looking workbook (Tier-3 PARTIAL).
    """

    # -- (a) Per-item guard ---------------------------------------------

    def test_malformed_project_is_skipped_not_fatal(self, monkeypatch):
        """One project that fails to process must not discard the whole region."""
        good = {
            "ProjectArn": "arn:aws:rekognition:us-east-1:123456789012:project/good-project/1699999999999",
            "Status": "CREATED",
            "CreationTimestamp": datetime(2024, 1, 1, tzinfo=timezone.utc),
        }
        bad = {
            "ProjectArn": "arn:aws:rekognition:us-east-1:123456789012:project/bad-project/1699999999999",
            "Status": "CREATED",
            "CreationTimestamp": datetime(2024, 1, 1, tzinfo=timezone.utc),
        }

        client = _fake_rekognition_client(projects=[good, bad])
        monkeypatch.setattr(rekognition_export.utils, "get_boto3_client", lambda *a, **kw: client)

        original = rekognition_export._build_project_row

        def raise_for_bad(project, region):
            if "bad-project" in project.get("ProjectArn", ""):
                raise KeyError("SomeUnexpectedField")
            return original(project, region)

        monkeypatch.setattr(rekognition_export, "_build_project_row", raise_for_bad)

        rows = _scan_projects_region(REGION)

        arns = {row["Project ARN"] for row in rows}
        assert good["ProjectArn"] in arns, "healthy project was lost when a sibling failed"
        assert bad["ProjectArn"] not in arns, "malformed project should have been skipped"

    # -- (b) Region-scope failure propagation ----------------------------

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Something broke"}},
                "DescribeProjects",
            )

        client = MagicMock()
        client.get_paginator.side_effect = boom
        monkeypatch.setattr(rekognition_export.utils, "get_boto3_client", lambda *a, **kw: client)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_projects_region(REGION)

    def test_collect_projects_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them -- this is what lets main() write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeProjects",
            )

        monkeypatch.setattr(rekognition_export, "_scan_projects_region", boom)

        projects, failed_regions = collect_projects([REGION])

        assert projects == []
        assert [r for r, _ in failed_regions] == [REGION]

    # -- (c) main(): failure surfaced, non-zero exit, marker written -----

    def test_main_failure_exits_nonzero_and_reports_despite_summary_sheet(self, monkeypatch, tmp_path):
        """
        A projects-scope failure must exit non-zero and call
        utils.report_collection_failures -- even though this script always
        builds a non-empty Summary sheet and would otherwise write a
        complete-looking workbook (the Tier-3 PARTIAL failure mode).
        """
        monkeypatch.setattr(rekognition_export.utils, "ensure_dependencies", lambda *a, **kw: True)
        monkeypatch.setattr(rekognition_export.utils, "detect_partition", lambda *a, **kw: "aws")
        monkeypatch.setattr(
            rekognition_export.utils, "is_service_available_in_partition", lambda *a, **kw: True
        )
        monkeypatch.setattr(
            rekognition_export.utils,
            "print_script_banner",
            lambda *a, **kw: ("123456789012", "test-account"),
        )
        monkeypatch.setattr(rekognition_export.utils, "mask_account_id", lambda *a, **kw: "1234****9012")
        monkeypatch.setattr(rekognition_export.utils, "prompt_region_selection", lambda *a, **kw: [REGION])

        monkeypatch.setattr(rekognition_export, "collect_projects", lambda regions: ([], [(REGION, "boom")]))
        monkeypatch.setattr(rekognition_export, "collect_project_versions", lambda regions: [])
        monkeypatch.setattr(rekognition_export, "collect_collections", lambda regions: [])
        monkeypatch.setattr(rekognition_export, "collect_stream_processors", lambda regions: [])

        monkeypatch.setattr(rekognition_export.utils, "create_export_filename", lambda *a, **kw: "fake.xlsx")
        monkeypatch.setattr(
            rekognition_export.utils, "save_multiple_dataframes_to_excel", lambda *a, **kw: str(tmp_path / "fake.xlsx")
        )

        calls = {}

        def fake_report(account_name, resource_type, failed_scopes):
            calls["account_name"] = account_name
            calls["resource_type"] = resource_type
            calls["failed_scopes"] = failed_scopes
            return "fake-marker.txt"

        monkeypatch.setattr(rekognition_export.utils, "report_collection_failures", fake_report)

        with pytest.raises(SystemExit) as exc_info:
            rekognition_export.main()

        assert exc_info.value.code == 1
        assert calls.get("account_name") == "test-account"
        assert calls.get("resource_type") == "rekognition"
        assert calls.get("failed_scopes") == [(REGION, "boom")]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

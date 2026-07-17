#!/usr/bin/env python3
"""
Moto-based tests for stepfunctions_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Unlike the Tier-1/Tier-2 exporters, stepfunctions_export.py already writes a
forced Summary sheet, so a workbook always lands even when a scope collection
fails. The fix under test here is *additive*: on any state-machine-region
failure, ALSO write the FAILED marker and exit non-zero; a genuinely-empty
account (every region succeeded, nothing found) stays exit 0 with no marker.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import stepfunctions_export  # noqa: E402
from stepfunctions_export import _scan_state_machines_region  # noqa: E402

REGION = "us-east-1"
ROLE_ARN = "arn:aws:iam::123456789012:role/test-role"
DEFINITION = (
    '{"Comment": "test", "StartAt": "A", '
    '"States": {"A": {"Type": "Pass", "End": true}}}'
)


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_state_machine(client, name):
    """Create a Step Functions state machine named ``name``."""
    return client.create_state_machine(
        name=name,
        definition=DEFINITION,
        roleArn=ROLE_ARN,
    )


class TestScanStateMachinesRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_state_machines(self):
        client = boto3.client("stepfunctions", region_name=REGION)
        _create_state_machine(client, "web-workflow")

        rows = _scan_state_machines_region(REGION)

        names = {row["State Machine Name"] for row in rows}
        assert "web-workflow" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("stepfunctions", region_name=REGION)  # region exists, none created

        rows = _scan_state_machines_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty (or zero-row)
    result, indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One state machine that fails to process must not discard the whole region."""
        client = boto3.client("stepfunctions", region_name=REGION)
        _create_state_machine(client, "good-workflow")
        _create_state_machine(client, "bad-workflow")

        original = stepfunctions_export._build_state_machine_row

        def raise_for_bad(sm_summary, region, sfn_client):
            if sm_summary.get("name") == "bad-workflow":
                raise KeyError("SomeUnexpectedField")
            return original(sm_summary, region, sfn_client)

        monkeypatch.setattr(stepfunctions_export, "_build_state_machine_row", raise_for_bad)

        rows = _scan_state_machines_region(REGION)

        names = {row["State Machine Name"] for row in rows}
        assert "good-workflow" in names, "healthy state machine was lost when a sibling failed"
        assert "bad-workflow" not in names, "malformed state machine should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListStateMachines",
            )

        monkeypatch.setattr(stepfunctions_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_state_machines_region(REGION)

    @mock_aws
    def test_collect_state_machines_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1
        even though the Summary sheet is always written.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListStateMachines",
            )

        monkeypatch.setattr(stepfunctions_export, "_scan_state_machines_region", boom)

        state_machines, failed_regions = stepfunctions_export.collect_state_machines([REGION])

        assert state_machines == []
        assert [r for r, _ in failed_regions] == [REGION]

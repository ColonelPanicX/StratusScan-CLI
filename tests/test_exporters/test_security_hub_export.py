#!/usr/bin/env python3
"""
Moto-based tests for security_hub_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's securityhub support covers ``enable_security_hub``,
``describe_hub``, ``batch_import_findings``, and ``get_findings`` (including
the Filters used by this exporter), so the happy-path / malformed-item /
region-failure tests below run against real moto behavior. Where moto does
not model a specific AWS error condition (e.g. a mid-scan throttling error),
the test monkeypatches the boto3 client call directly instead of working
around moto with a hand-rolled fake.
"""

import datetime
import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import security_hub_export  # noqa: E402
from security_hub_export import collect_security_hub_findings  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _import_finding(client, finding_id, severity="HIGH"):
    """Enable Security Hub (if needed) and import a single active/new finding."""
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "GeneratorId": "gen-1",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {"Label": severity, "Normalized": 70},
        "Title": f"Test finding {finding_id}",
        "Description": "desc",
        "Resources": [{"Type": "AwsEc2Instance", "Id": "i-1234"}],
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
    }
    client.batch_import_findings(Findings=[finding])


class TestCollectSecurityHubFindings:
    """Happy-path collection and the not-enabled skip."""

    @mock_aws
    def test_collects_findings(self):
        client = boto3.client("securityhub", region_name=REGION)
        client.enable_security_hub()
        _import_finding(client, "finding-1")

        findings, cap_reached = collect_security_hub_findings(REGION)

        ids = {f["Finding ID"] for f in findings}
        assert "finding-1" in ids
        assert cap_reached is False

    @mock_aws
    def test_hub_not_enabled_returns_empty_not_error(self):
        # No enable_security_hub() call — describe_hub() raises
        # InvalidAccessException, which is a legitimate disabled state.
        boto3.client("securityhub", region_name=REGION)

        findings, cap_reached = collect_security_hub_findings(REGION)

        assert findings == []
        assert cap_reached is False


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty/disabled region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One finding that fails to process must not discard the whole region."""
        client = boto3.client("securityhub", region_name=REGION)
        client.enable_security_hub()
        _import_finding(client, "good-finding")
        _import_finding(client, "bad-finding")

        original = security_hub_export._build_finding_row

        def raise_for_bad(finding, region):
            if finding.get("Id") == "bad-finding":
                raise KeyError("SomeUnexpectedField")
            return original(finding, region)

        monkeypatch.setattr(security_hub_export, "_build_finding_row", raise_for_bad)

        findings, cap_reached = collect_security_hub_findings(REGION)

        ids = {f["Finding ID"] for f in findings}
        assert "good-finding" in ids, "healthy finding was lost when a sibling failed"
        assert "bad-finding" not in ids, "malformed finding should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A real Security Hub API failure (not "hub not enabled") must propagate
        (so the caller can record a FAILED region) rather than being swallowed
        into an empty list.
        """
        client = boto3.client("securityhub", region_name=REGION)
        client.enable_security_hub()

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "GetFindings",
            )

        monkeypatch.setattr(client, "get_paginator", boom)
        monkeypatch.setattr(security_hub_export.utils, "get_boto3_client", lambda *a, **k: client)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_security_hub_findings(REGION)

    @mock_aws
    def test_hub_not_enabled_is_not_a_failed_region(self, monkeypatch):
        """
        Security Hub not being enabled in a region is a legitimate disabled
        state, not a collection failure — it must NOT be reported as a failed
        region via scan_regions_concurrent(collect_failures=True).
        """
        boto3.client("securityhub", region_name=REGION)  # not enabled

        results, failed_regions = security_hub_export.utils.scan_regions_concurrent(
            [REGION],
            collect_security_hub_findings,
            collect_failures=True,
        )

        assert failed_regions == []
        assert results == [([], False)]

    @mock_aws
    def test_collection_surfaces_failed_regions_via_scanner(self, monkeypatch):
        """
        The scope collector must surface failures through
        scan_regions_concurrent(collect_failures=True), not drop them — this
        is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "GetFindings",
            )

        monkeypatch.setattr(security_hub_export, "collect_security_hub_findings", boom)

        results, failed_regions = security_hub_export.utils.scan_regions_concurrent(
            [REGION],
            security_hub_export.collect_security_hub_findings,
            collect_failures=True,
        )

        assert results == []
        assert [r for r, _ in failed_regions] == [REGION]

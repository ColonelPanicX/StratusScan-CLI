#!/usr/bin/env python3
"""
Tests for apprunner_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

NOTE: moto has no AWS App Runner support at all (not even ``list_services``
returns "Not yet implemented" as of moto 5.1.21). Every test here therefore
monkeypatches ``utils.get_boto3_client`` to return a fake App Runner client
instead of using ``@mock_aws`` — there is no moto backend to mock against.
"""

import sys
from pathlib import Path
from typing import Any

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import apprunner_export  # noqa: E402
from apprunner_export import _scan_apprunner_services_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakeApprunnerClient:
    """
    Minimal stand-in for a boto3 App Runner client.

    ``list_services`` returns the fixed ``summaries`` in a single page.
    ``describe_service`` raises for any service name in ``fail_names``
    (simulating a per-item describe failure) and otherwise returns an empty
    (but valid) ``Service`` body.
    """

    def __init__(self, summaries: list[dict[str, Any]], fail_names: set = frozenset()):
        self.summaries = summaries
        self.fail_names = fail_names

    def list_services(self, **kwargs):
        return {"ServiceSummaryList": self.summaries, "NextToken": None}

    def describe_service(self, **kwargs):
        service_arn = kwargs["ServiceArn"]
        name = service_arn.split("/")[-1] if "/" in service_arn else service_arn
        if name in self.fail_names:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "InternalFailure", "Message": "boom"}},
                "DescribeService",
            )
        return {"Service": {}}


def _summary(name: str) -> dict[str, Any]:
    return {
        "ServiceArn": f"arn:aws:apprunner:{REGION}:123456789012:service/{name}",
        "ServiceName": name,
        "ServiceId": name,
        "ServiceUrl": f"{name}.example.com",
        "Status": "RUNNING",
    }


class TestScanApprunnerServicesRegion:
    """Happy-path collection."""

    def test_collects_services(self, monkeypatch):
        client = _FakeApprunnerClient([_summary("web-service")])
        monkeypatch.setattr(apprunner_export.utils, "get_boto3_client", lambda *a, **k: client)

        rows = _scan_apprunner_services_region(REGION)

        names = {row["Service Name"] for row in rows}
        assert "web-service" in names

    def test_empty_region_returns_empty_list(self, monkeypatch):
        client = _FakeApprunnerClient([])
        monkeypatch.setattr(apprunner_export.utils, "get_boto3_client", lambda *a, **k: client)

        rows = _scan_apprunner_services_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region. apprunner_export.py is a
    Tier-3 PARTIAL case: it already writes a forced Summary sheet, so a
    workbook always lands — the fix adds failed-scope tracking so a scope
    failure ALSO writes a ``*-apprunner-FAILED-*.txt`` marker and exits
    non-zero, instead of silently reporting a zero-row Services sheet as if
    the account genuinely had none.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One service whose describe_service fails must not discard the whole region."""
        client = _FakeApprunnerClient(
            [_summary("good-service"), _summary("bad-service")],
            fail_names={"bad-service"},
        )
        monkeypatch.setattr(apprunner_export.utils, "get_boto3_client", lambda *a, **k: client)

        rows = _scan_apprunner_services_region(REGION)

        names = {row["Service Name"] for row in rows}
        assert "good-service" in names, "healthy service was lost when a sibling failed"
        assert "bad-service" not in names, "malformed service should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure (e.g. list_services itself failing) must
        propagate (so the caller can record a FAILED region) rather than
        being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListServices",
            )

        monkeypatch.setattr(apprunner_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_apprunner_services_region(REGION)

    def test_collect_apprunner_services_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures,
        not drop them — this is what lets export write a FAILED marker +
        exit 1 (while the forced Summary sheet still lands).
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListServices",
            )

        monkeypatch.setattr(apprunner_export, "_scan_apprunner_services_region", boom)

        services, failed_regions = apprunner_export.collect_apprunner_services([REGION])

        assert services == []
        assert [r for r, _ in failed_regions] == [REGION]

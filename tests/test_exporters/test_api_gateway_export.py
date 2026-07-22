#!/usr/bin/env python3
"""
Moto-based tests for api_gateway_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import api_gateway_export  # noqa: E402
from api_gateway_export import scan_rest_apis_in_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_rest_api(client, name):
    """Create a REST API named ``name``."""
    return client.create_rest_api(name=name, description=f"{name} desc")


class TestScanRestApisInRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_rest_apis(self):
        client = boto3.client("apigateway", region_name=REGION)
        _create_rest_api(client, "web-api")

        rows = scan_rest_apis_in_region(REGION)

        names = {row["API Name"] for row in rows}
        assert "web-api" in names

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("apigateway", region_name=REGION)  # region exists, no APIs

        rows = scan_rest_apis_in_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One REST API that fails to process must not discard the whole region."""
        client = boto3.client("apigateway", region_name=REGION)
        _create_rest_api(client, "good-api")
        _create_rest_api(client, "bad-api")

        original = api_gateway_export._build_rest_api_row

        def raise_for_bad(item, region):
            if item.get("name") == "bad-api":
                raise KeyError("SomeUnexpectedField")
            return original(item, region)

        monkeypatch.setattr(api_gateway_export, "_build_rest_api_row", raise_for_bad)

        rows = scan_rest_apis_in_region(REGION)

        names = {row["API Name"] for row in rows}
        assert "good-api" in names, "healthy REST API was lost when a sibling failed"
        assert "bad-api" not in names, "malformed REST API should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "GetRestApis",
            )

        monkeypatch.setattr(api_gateway_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            scan_rest_apis_in_region(REGION)

    @mock_aws
    def test_collect_rest_apis_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "GetRestApis",
            )

        monkeypatch.setattr(api_gateway_export, "scan_rest_apis_in_region", boom)

        apis, failed_regions = api_gateway_export.collect_rest_apis([REGION])

        assert apis == []
        assert [r for r, _ in failed_regions] == [REGION]

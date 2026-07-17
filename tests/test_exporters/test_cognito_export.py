#!/usr/bin/env python3
"""
Tests for cognito_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto's cognito-idp backend depends on ``joserfc``, which is not
installed in this environment (``ModuleNotFoundError: No module named
'joserfc'`` when moto's cognitoidp models module is imported). Tests that
need actual user pool data therefore monkeypatch a fake cognito-idp client
(paginator + describe_user_pool) instead of using ``@mock_aws`` for those
calls. Tests that only need a region-level API failure to propagate use
``@mock_aws`` + monkeypatched ``utils.get_boto3_client`` as before, since
those never touch the cognitoidp backend.
"""

import sys
from pathlib import Path

import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import cognito_export  # noqa: E402
from cognito_export import scan_user_pools_in_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakePaginator:
    """Minimal stand-in for a boto3 paginator over a single page."""

    def __init__(self, page):
        self._page = page

    def paginate(self, **kwargs):
        return iter([self._page])


class _FakeCognitoClient:
    """Minimal stand-in for a cognito-idp client, keyed by pool ID."""

    def __init__(self, pools_by_id):
        self._pools_by_id = pools_by_id

    def get_paginator(self, operation_name):
        assert operation_name == "list_user_pools"
        summaries = [{"Id": pid, "Name": p["Name"]} for pid, p in self._pools_by_id.items()]
        return _FakePaginator({"UserPools": summaries})

    def describe_user_pool(self, UserPoolId):  # noqa: N803 - mirrors the boto3 cognito-idp API
        if UserPoolId not in self._pools_by_id:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}},
                "DescribeUserPool",
            )
        return {"UserPool": self._pools_by_id[UserPoolId]}


def _install_fake_client(monkeypatch, pools_by_id):
    """Patch utils.get_boto3_client so cognito_export gets the fake client."""
    fake_client = _FakeCognitoClient(pools_by_id)

    def fake_get_boto3_client(service, region_name=None, **kwargs):
        assert service == "cognito-idp"
        return fake_client

    monkeypatch.setattr(cognito_export.utils, "get_boto3_client", fake_get_boto3_client)
    return fake_client


class TestScanUserPoolsInRegion:
    """Happy-path collection."""

    def test_collects_user_pools(self, monkeypatch):
        _install_fake_client(monkeypatch, {"pool-1": {"Id": "pool-1", "Name": "web-pool"}})

        rows = scan_user_pools_in_region(REGION)

        names = {row["Pool Name"] for row in rows}
        assert "web-pool" in names

    def test_empty_region_returns_empty_list(self, monkeypatch):
        _install_fake_client(monkeypatch, {})  # region exists, no pools

        rows = scan_user_pools_in_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One user pool that fails to describe/build must not discard the whole region."""
        _install_fake_client(
            monkeypatch,
            {
                "pool-good": {"Id": "pool-good", "Name": "good-pool"},
                "pool-bad": {"Id": "pool-bad", "Name": "bad-pool"},
            },
        )

        original = cognito_export._build_user_pool_row

        def raise_for_bad(pool, region):
            if pool.get("Name") == "bad-pool":
                raise KeyError("SomeUnexpectedField")
            return original(pool, region)

        monkeypatch.setattr(cognito_export, "_build_user_pool_row", raise_for_bad)

        rows = scan_user_pools_in_region(REGION)

        names = {row["Pool Name"] for row in rows}
        assert "good-pool" in names, "healthy user pool was lost when a sibling failed"
        assert "bad-pool" not in names, "malformed user pool should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListUserPools",
            )

        monkeypatch.setattr(cognito_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            scan_user_pools_in_region(REGION)

    @mock_aws
    def test_collect_user_pools_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListUserPools",
            )

        monkeypatch.setattr(cognito_export, "scan_user_pools_in_region", boom)

        pools, failed_regions = cognito_export.collect_user_pools([REGION])

        assert pools == []
        assert [r for r, _ in failed_regions] == [REGION]

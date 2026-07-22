#!/usr/bin/env python3
"""
Moto-based tests for waf_export.py.

Focus: the silent-collection-failure contract (Tier-2c) for the primary
REGIONAL scope, collect_web_acls()/collect_web_acls_from_region(). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

moto's WAFv2 support does not cover list_web_acls/get_web_acl well enough
to inject pagination or per-item errors, so all three regression cases
below monkeypatch the wafv2 client (or the collector functions) directly
rather than relying on moto.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import waf_export  # noqa: E402
from waf_export import collect_web_acls_from_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakeWafv2Client:
    """
    Minimal stand-in for a wafv2 client used by the regression tests below,
    since moto's WAFv2 support does not cover list_web_acls/get_web_acl
    error injection or NextMarker pagination for the scenarios exercised
    here. ``list_web_acls`` returns the fixed ``web_acls`` summary list (no
    NextMarker, i.e. a single page); ``get_web_acl`` raises for the name
    given in ``error_for`` and otherwise returns an empty-but-valid WebACL.
    """

    def __init__(self, web_acls, error_for=None):
        self._web_acls = web_acls
        self._error_for = error_for

    def list_web_acls(self, **kwargs):
        return {"WebACLs": self._web_acls}

    def get_web_acl(self, **kwargs):
        name = kwargs.get("Name")
        if self._error_for and name == self._error_for:
            raise KeyError("SomeUnexpectedField")
        return {"WebACL": {"DefaultAction": {"Allow": {}}}}


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 audit: exporters silently lost data
    because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One web ACL that fails to process must not discard the whole region."""
        fake_client = _FakeWafv2Client(
            web_acls=[
                {"Name": "good-acl", "Id": "good-id", "ARN": f"arn:aws:wafv2:{REGION}:123456789012:regional/webacl/good-acl/good-id"},
                {"Name": "bad-acl", "Id": "bad-id", "ARN": f"arn:aws:wafv2:{REGION}:123456789012:regional/webacl/bad-acl/bad-id"},
            ],
            error_for="bad-acl",
        )
        monkeypatch.setattr(waf_export.utils, "get_boto3_client", lambda *a, **kw: fake_client)

        rows = collect_web_acls_from_region(REGION, scope="REGIONAL")

        names = {row["Name"] for row in rows}
        assert "good-acl" in names, "healthy web ACL was lost when a sibling failed"
        assert "bad-acl" not in names, "malformed web ACL should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListWebACLs",
            )

        monkeypatch.setattr(waf_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_web_acls_from_region(REGION, scope="REGIONAL")

    def test_collect_web_acls_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region, scope="REGIONAL"):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListWebACLs",
            )

        monkeypatch.setattr(waf_export, "collect_web_acls_from_region", boom)

        web_acls, failed_regions = waf_export.collect_web_acls([REGION], scope="REGIONAL")

        assert web_acls == []
        assert [r for r, _ in failed_regions] == [REGION]

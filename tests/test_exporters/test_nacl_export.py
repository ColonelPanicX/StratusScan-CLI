#!/usr/bin/env python3
"""
Moto-based tests for nacl_export.py.

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
import nacl_export  # noqa: E402
from nacl_export import get_nacl_data  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_nacl(client, vpc_id, name):
    """Create a Network ACL named ``name`` (via a Name tag) in ``vpc_id``."""
    resp = client.create_network_acl(VpcId=vpc_id)
    nacl_id = resp["NetworkAcl"]["NetworkAclId"]
    client.create_tags(Resources=[nacl_id], Tags=[{"Key": "Name", "Value": name}])
    return nacl_id


class TestGetNaclData:
    """Happy-path collection."""

    @mock_aws
    def test_collects_nacls(self):
        client = boto3.client("ec2", region_name=REGION)
        vpc = client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        _create_nacl(client, vpc, "web-nacl")

        rows = get_nacl_data(REGION)

        names = {row["NACL Name"] for row in rows}
        assert "web-nacl" in names

    @mock_aws
    def test_no_custom_nacls_returns_only_defaults(self):
        """
        A region with no custom NACLs still has moto's default-VPC default NACL.
        Genuinely-empty here means "nothing but the default" — never an error.
        """
        boto3.client("ec2", region_name=REGION)  # region exists, no custom NACLs

        rows = get_nacl_data(REGION)

        assert all(row["Is Default"] == "Yes" for row in rows)


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 audit: exporters silently lost data
    because a collection error was swallowed to an empty list, indistinguishable
    from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One NACL that fails to process must not discard the whole region."""
        client = boto3.client("ec2", region_name=REGION)
        vpc = client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        _create_nacl(client, vpc, "good-nacl")
        _create_nacl(client, vpc, "bad-nacl")

        original = nacl_export._build_nacl_row

        def raise_for_bad(nacl, region):
            if nacl.get("NetworkAclId") and _tag_name(nacl) == "bad-nacl":
                raise KeyError("SomeUnexpectedField")
            return original(nacl, region)

        def _tag_name(nacl):
            for tag in nacl.get("Tags", []):
                if tag.get("Key") == "Name":
                    return tag.get("Value")
            return None

        monkeypatch.setattr(nacl_export, "_build_nacl_row", raise_for_bad)

        rows = get_nacl_data(REGION)

        names = {row["NACL Name"] for row in rows}
        assert "good-nacl" in names, "healthy NACL was lost when a sibling failed"
        assert "bad-nacl" not in names, "malformed NACL should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeNetworkAcls",
            )

        monkeypatch.setattr(nacl_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            get_nacl_data(REGION)

    @mock_aws
    def test_scan_regions_concurrent_surfaces_failed_regions(self, monkeypatch):
        """
        With ``collect_failures=True``, a region whose collector raises must be
        reported back as a failed region, not dropped — this is what lets
        ``main()`` write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeNetworkAcls",
            )

        monkeypatch.setattr(nacl_export, "get_nacl_data", boom)

        results, failed_regions = nacl_export.utils.scan_regions_concurrent(
            regions=[REGION],
            scan_function=lambda r: nacl_export.get_nacl_data(r),
            show_progress=False,
            collect_failures=True,
        )

        assert results == []
        assert [r for r, _ in failed_regions] == [REGION]

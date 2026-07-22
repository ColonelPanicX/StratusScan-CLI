#!/usr/bin/env python3
"""
Moto-based tests for route_tables_export.py.

Covers:
- get_route_tables()
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import route_tables_export  # noqa: E402
from route_tables_export import get_route_tables  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_route_table(ec2, vpc_id, name):
    """Create a route table tagged with a Name for identification in tests."""
    response = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "route-table",
                "Tags": [{"Key": "Name", "Value": name}],
            }
        ],
    )
    return response["RouteTable"]["RouteTableId"]


class TestGetRouteTables:
    """Tests for get_route_tables()."""

    @mock_aws
    def test_created_route_table_appears_in_results(self):
        """A newly created route table is returned by the collector."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        rt_id = _create_route_table(ec2, vpc_id, "test-rt")

        result = get_route_tables(REGION)

        assert isinstance(result, list)
        assert any(row["Route Table ID"] == rt_id for row in result)

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        _create_route_table(ec2, vpc_id, "col-check-rt")

        result = get_route_tables(REGION)

        assert len(result) >= 1
        row = result[0]
        for col in ("Route Table ID", "VPC ID", "Region", "Route Destination", "Target"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_region_with_no_custom_route_tables_still_returns_a_list(self):
        """
        A region with no explicitly-created route tables still returns a list
        (moto provisions a default VPC with a main route table), not None.
        """
        result = get_route_tables(REGION)
        assert isinstance(result, list)


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15.2026 audit: exporter data silently lost
    because a collection error was swallowed to an empty list, indistinguishable
    from a genuinely empty region. See
    .collab/audit/07.15.2026-rds-silent-collection-failure.md and
    .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """
        One route table that fails to process must not discard the whole
        region's results — the healthy route table is still collected.
        """
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        good_rt_id = _create_route_table(ec2, vpc_id, "good-rt")
        bad_rt_id = _create_route_table(ec2, vpc_id, "bad-rt")

        original = route_tables_export._build_route_entries

        def raise_for_bad(route_table, region):
            if route_table.get("RouteTableId") == bad_rt_id:
                raise KeyError("SomeMalformedField")
            return original(route_table, region)

        monkeypatch.setattr(route_tables_export, "_build_route_entries", raise_for_bad)

        result = get_route_tables(REGION)

        ids = {row["Route Table ID"] for row in result}
        assert good_rt_id in ids, "healthy route table was lost when a sibling failed"
        assert bad_rt_id not in ids, "malformed route table should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeRouteTables",
            )

        monkeypatch.setattr(route_tables_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            get_route_tables(REGION)

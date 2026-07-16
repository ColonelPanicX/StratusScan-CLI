#!/usr/bin/env python3
"""
Moto-based tests for security_groups_export.py.

Covers:
- get_security_group_rules()
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import security_groups_export  # noqa: E402
from security_groups_export import get_security_group_rules  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_sg(ec2, name, vpc_id, with_ingress=True):
    sg = ec2.create_security_group(GroupName=name, Description=f"{name} desc", VpcId=vpc_id)
    if with_ingress:
        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
    return sg["GroupId"]


class TestGetSecurityGroupRules:
    """Tests for get_security_group_rules()."""

    @mock_aws
    def test_created_sg_appears_in_results(self):
        """A newly created security group with a rule is returned by the collector."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        sg_id = _create_sg(ec2, "test-sg", vpc["VpcId"])

        result = get_security_group_rules(REGION)

        assert isinstance(result, list)
        assert any(row["SG ID"] == sg_id for row in result)

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        _create_sg(ec2, "col-check-sg", vpc["VpcId"])

        result = get_security_group_rules(REGION)

        assert len(result) >= 1
        row = result[0]
        for col in ("Rule ID", "SG Name", "SG ID", "VPC", "Direction", "Region"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_sg_with_no_rules_gets_placeholder_row(self):
        """A security group with no ingress/egress-only-default rules still yields a row."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        sg_id = _create_sg(ec2, "no-ingress-sg", vpc["VpcId"], with_ingress=False)

        result = get_security_group_rules(REGION)

        # moto always gives a default egress rule, so this SG should have an
        # Outbound row rather than the N/A placeholder — just confirm it appears.
        assert any(row["SG ID"] == sg_id for row in result)


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the silent-collection-failure sweep (07.16.2026 audit):
    a collection error was swallowed to an empty list, indistinguishable from a
    genuinely empty region. See
    .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """
        One security group that fails to process must not discard the whole
        region's results — the healthy security group is still collected.
        """
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        good_id = _create_sg(ec2, "good-sg", vpc["VpcId"])
        bad_id = _create_sg(ec2, "bad-sg", vpc["VpcId"])

        original = security_groups_export._build_sg_rule_rows

        def raise_for_bad(sg, *args, **kwargs):
            if sg.get("GroupId") == bad_id:
                raise KeyError("SomeMalformedField")
            return original(sg, *args, **kwargs)

        monkeypatch.setattr(security_groups_export, "_build_sg_rule_rows", raise_for_bad)

        result = get_security_group_rules(REGION)

        ids = {row["SG ID"] for row in result}
        assert good_id in ids, "healthy security group was lost when a sibling failed"
        assert bad_id not in ids, "malformed security group should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeSecurityGroups",
            )

        monkeypatch.setattr(security_groups_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            get_security_group_rules(REGION)

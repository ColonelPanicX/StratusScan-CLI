#!/usr/bin/env python3
"""
Tests for compute_optimizer_export.py.

Focus: the silent-collection-failure contract (Tier-2a / compute). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

moto has no AWS Compute Optimizer support, so unlike the autoscaling/lambda
regression suites (which use @mock_aws against real moto-backed resources),
all three cases here monkeypatch a fake compute-optimizer client or the
collector functions directly. No real AWS resources are involved.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import compute_optimizer_export  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 audit: exporters silently lost data
    because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.

    Exercised against the EC2 recommendations scope
    (get_ec2_recommendations / _build_ec2_recommendation_row /
    collect_ec2_recommendations) as the representative of this file's five
    identically-shaped scope collectors.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One recommendation that fails to process must not discard the
        whole region's results."""
        good_item = {
            "instanceArn": "arn:aws:ec2:us-east-1:123456789012:instance/i-good",
            "currentInstanceType": "t3.micro",
            "finding": "Overprovisioned",
            "recommendationOptions": [],
            "utilizationMetrics": [],
        }
        bad_item = {
            "instanceArn": "arn:aws:ec2:us-east-1:123456789012:instance/i-bad",
        }

        class FakeComputeOptimizerClient:
            def get_ec2_instance_recommendations(self, **kwargs):
                return {"instanceRecommendations": [good_item, bad_item]}

        monkeypatch.setattr(
            compute_optimizer_export.utils,
            "get_boto3_client",
            lambda service, region_name=None: FakeComputeOptimizerClient(),
        )

        original = compute_optimizer_export._build_ec2_recommendation_row

        def raise_for_bad(recommendation, region):
            if recommendation is bad_item:
                raise KeyError("SomeUnexpectedField")
            return original(recommendation, region)

        monkeypatch.setattr(
            compute_optimizer_export, "_build_ec2_recommendation_row", raise_for_bad
        )

        rows = compute_optimizer_export.get_ec2_recommendations(REGION)

        instance_ids = {row["Instance ID"] for row in rows}
        assert "i-good" in instance_ids, "healthy recommendation was lost when a sibling failed"
        assert "i-bad" not in instance_ids, "malformed recommendation should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record
        a FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "GetEc2InstanceRecommendations",
            )

        monkeypatch.setattr(compute_optimizer_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            compute_optimizer_export.get_ec2_recommendations(REGION)

    def test_collect_ec2_recommendations_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures,
        not drop them — this is what lets export write a FAILED marker and
        exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "GetEc2InstanceRecommendations",
            )

        monkeypatch.setattr(compute_optimizer_export, "get_ec2_recommendations", boom)

        recs, failed_regions = compute_optimizer_export.collect_ec2_recommendations([REGION])

        assert recs == []
        assert [r for r, _ in failed_regions] == [REGION]

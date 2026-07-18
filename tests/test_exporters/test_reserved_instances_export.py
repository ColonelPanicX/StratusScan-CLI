#!/usr/bin/env python3
"""
Tests for reserved_instances_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL) for the EC2
Reserved Instances scope. See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

NOTE: moto's EC2 backend does not implement ``describe_reserved_instances``
(it raises ``NotImplementedError`` as of moto 5.1.21), so ``@mock_aws``
cannot be used for this scope. These tests instead monkeypatch
``utils.get_boto3_client`` with a minimal fake EC2 client, mirroring the
monkeypatch approach used for the region-failure cases in
test_autoscaling_export.py.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import reserved_instances_export  # noqa: E402
from reserved_instances_export import _scan_ec2_ri_region  # noqa: E402

REGION = "us-east-1"


class _FakeEC2Client:
    """Minimal fake EC2 client exposing only describe_reserved_instances."""

    def __init__(self, reserved_instances=None, error=None):
        self._reserved_instances = reserved_instances or []
        self._error = error

    def describe_reserved_instances(self):
        if self._error is not None:
            raise self._error
        return {"ReservedInstances": self._reserved_instances}


def _ri(reservation_id, instance_type="m5.large"):
    return {
        "ReservedInstancesId": reservation_id,
        "InstanceType": instance_type,
        "InstanceCount": 1,
        "State": "active",
    }


class TestScanEc2RiRegion:
    """Happy-path collection."""

    def test_collects_ris(self, monkeypatch):
        fake_client = _FakeEC2Client(reserved_instances=[_ri("ri-good")])
        monkeypatch.setattr(
            reserved_instances_export.utils, "get_boto3_client", lambda *a, **kw: fake_client
        )

        rows = _scan_ec2_ri_region(REGION)

        reservation_ids = {row["ReservationID"] for row in rows}
        assert "ri-good" in reservation_ids

    def test_empty_region_returns_empty_list(self, monkeypatch):
        fake_client = _FakeEC2Client(reserved_instances=[])
        monkeypatch.setattr(
            reserved_instances_export.utils, "get_boto3_client", lambda *a, **kw: fake_client
        )

        rows = _scan_ec2_ri_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 audit: exporters silently lost data
    because a collection error was swallowed into an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One RI that fails to process must not discard the whole region."""
        fake_client = _FakeEC2Client(reserved_instances=[_ri("ri-good"), _ri("ri-bad")])
        monkeypatch.setattr(
            reserved_instances_export.utils, "get_boto3_client", lambda *a, **kw: fake_client
        )

        original = reserved_instances_export._build_ec2_ri_row

        def raise_for_bad(ri, region):
            if ri.get("ReservedInstancesId") == "ri-bad":
                raise KeyError("SomeUnexpectedField")
            return original(ri, region)

        monkeypatch.setattr(reserved_instances_export, "_build_ec2_ri_row", raise_for_bad)

        rows = _scan_ec2_ri_region(REGION)

        reservation_ids = {row["ReservationID"] for row in rows}
        assert "ri-good" in reservation_ids, "healthy RI was lost when a sibling failed"
        assert "ri-bad" not in reservation_ids, "malformed RI should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """
        error = botocore.exceptions.ClientError(
            {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
            "DescribeReservedInstances",
        )
        fake_client = _FakeEC2Client(error=error)
        monkeypatch.setattr(
            reserved_instances_export.utils, "get_boto3_client", lambda *a, **kw: fake_client
        )

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_ec2_ri_region(REGION)

    def test_collect_ec2_reserved_instances_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeReservedInstances",
            )

        monkeypatch.setattr(reserved_instances_export, "_scan_ec2_ri_region", boom)

        ris, failed_regions = reserved_instances_export.collect_ec2_reserved_instances([REGION])

        assert ris == []
        assert [r for r, _ in failed_regions] == [REGION]
        # Error messages are prefixed with the scope name so multiple failed
        # RI scopes can be told apart once merged into one failed_regions list.
        assert failed_regions[0][1].startswith("EC2 RI:")

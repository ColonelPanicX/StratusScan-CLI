#!/usr/bin/env python3
"""
Tests for ec2_capacity_reservations_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note on moto: the moto version pinned in this repo (5.1.21) does not
implement the EC2 Capacity Reservations API — ``create_capacity_reservation``
and ``describe_capacity_reservations`` both raise ``NotImplementedError``
under ``@mock_aws``. All tests here therefore monkeypatch
``utils.get_boto3_client`` directly with a minimal fake client instead of
using ``@mock_aws``.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import ec2_capacity_reservations_export  # noqa: E402
from ec2_capacity_reservations_export import _scan_capacity_reservations_region  # noqa: E402

REGION = "us-east-1"


class _FakePaginator:
    """Minimal stand-in for a boto3 paginator."""

    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class _FakeCapacityReservationsClient:
    """Minimal EC2 client stand-in for describe_capacity_reservations."""

    def __init__(self, reservations):
        self._reservations = reservations

    def get_paginator(self, operation_name):
        assert operation_name == 'describe_capacity_reservations'
        return _FakePaginator([{'CapacityReservations': self._reservations}])


def _reservation(reservation_id, **overrides):
    row = {
        'CapacityReservationId': reservation_id,
        'CapacityReservationArn': f'arn:aws:ec2:{REGION}::capacity-reservation/{reservation_id}',
        'InstanceType': 't3.micro',
        'AvailabilityZone': f'{REGION}a',
        'State': 'active',
        'TotalInstanceCount': 2,
        'AvailableInstanceCount': 1,
        'Tags': [{'Key': 'Name', 'Value': reservation_id}],
    }
    row.update(overrides)
    return row


class TestScanCapacityReservationsRegion:
    """Happy-path collection."""

    def test_collects_reservations(self, monkeypatch):
        client = _FakeCapacityReservationsClient([_reservation('cr-111')])
        monkeypatch.setattr(
            ec2_capacity_reservations_export.utils, 'get_boto3_client', lambda *a, **k: client
        )

        rows = _scan_capacity_reservations_region(REGION)

        ids = {row['CapacityReservationId'] for row in rows}
        assert ids == {'cr-111'}

    def test_empty_region_returns_empty_list(self, monkeypatch):
        client = _FakeCapacityReservationsClient([])
        monkeypatch.setattr(
            ec2_capacity_reservations_export.utils, 'get_boto3_client', lambda *a, **k: client
        )

        rows = _scan_capacity_reservations_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 blast-radius audit: this exporter was
    classified Tier-3 PARTIAL — a forced Summary sheet meant the workbook
    always landed, but a region-level collection error still silently
    collapsed into a 0-row "All Reservations" sheet, indistinguishable from a
    genuinely empty account.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One malformed reservation must not discard the whole region."""
        client = _FakeCapacityReservationsClient(
            [_reservation('cr-good'), _reservation('cr-bad')]
        )
        monkeypatch.setattr(
            ec2_capacity_reservations_export.utils, 'get_boto3_client', lambda *a, **k: client
        )

        original = ec2_capacity_reservations_export._build_reservation_row

        def raise_for_bad(cr, region):
            if cr.get('CapacityReservationId') == 'cr-bad':
                raise KeyError('SomeUnexpectedField')
            return original(cr, region)

        monkeypatch.setattr(
            ec2_capacity_reservations_export, '_build_reservation_row', raise_for_bad
        )

        rows = _scan_capacity_reservations_region(REGION)

        ids = {row['CapacityReservationId'] for row in rows}
        assert 'cr-good' in ids, "healthy reservation was lost when a sibling failed"
        assert 'cr-bad' not in ids, "malformed reservation should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeCapacityReservations",
            )

        monkeypatch.setattr(ec2_capacity_reservations_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_capacity_reservations_region(REGION)

    def test_collect_capacity_reservations_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures,
        not drop them — this is what lets export write a FAILED marker and
        exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeCapacityReservations",
            )

        monkeypatch.setattr(
            ec2_capacity_reservations_export, "_scan_capacity_reservations_region", boom
        )

        reservations, failed_regions = ec2_capacity_reservations_export.collect_capacity_reservations(
            [REGION]
        )

        assert reservations == []
        assert [r for r, _ in failed_regions] == [REGION]

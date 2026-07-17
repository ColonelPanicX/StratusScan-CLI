#!/usr/bin/env python3
"""
Moto-based tests for guardduty_export.py.

Focus: the silent-collection-failure contract (Tier-2). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import guardduty_export  # noqa: E402
from guardduty_export import collect_detectors_from_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _create_detector(client):
    """Create a GuardDuty detector and return its ID."""
    response = client.create_detector(Enable=True)
    return response["DetectorId"]


class TestCollectDetectorsFromRegion:
    """Happy-path collection."""

    @mock_aws
    def test_collects_detectors(self):
        client = boto3.client("guardduty", region_name=REGION)
        detector_id = _create_detector(client)

        rows = collect_detectors_from_region(REGION)

        detector_ids = {row["Detector ID"] for row in rows}
        assert detector_id in detector_ids

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        boto3.client("guardduty", region_name=REGION)  # region exists, no detectors

        rows = collect_detectors_from_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    @mock_aws
    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One detector that fails to process must not discard the whole region."""
        client = boto3.client("guardduty", region_name=REGION)
        good_id = _create_detector(client)
        bad_id = _create_detector(client)

        original = guardduty_export._build_detector_row

        def raise_for_bad(detector, detector_id, region):
            if detector_id == bad_id:
                raise KeyError("SomeUnexpectedField")
            return original(detector, detector_id, region)

        monkeypatch.setattr(guardduty_export, "_build_detector_row", raise_for_bad)

        rows = collect_detectors_from_region(REGION)

        detector_ids = {row["Detector ID"] for row in rows}
        assert good_id in detector_ids, "healthy detector was lost when a sibling failed"
        assert bad_id not in detector_ids, "malformed detector should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListDetectors",
            )

        monkeypatch.setattr(guardduty_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            collect_detectors_from_region(REGION)

    @mock_aws
    def test_collect_detectors_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListDetectors",
            )

        monkeypatch.setattr(guardduty_export, "collect_detectors_from_region", boom)

        detectors, failed_regions = guardduty_export.collect_detectors([REGION])

        assert detectors == []
        assert [r for r, _ in failed_regions] == [REGION]

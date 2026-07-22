#!/usr/bin/env python3
"""
Tests for license_manager_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

moto's License Manager support is limited — ``list_license_configurations``
returns a "Not yet implemented" 404 under ``@mock_aws`` (verified against
moto 5.1.21) — so these tests drive ``_scan_license_configurations_region``
through a monkeypatched ``utils.get_boto3_client`` returning a
``MagicMock``-backed fake client/paginator rather than real moto-backed
License Manager state. This mirrors the approach used in
tests/test_exporters/test_savings_plans_export.py for the same moto gap.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import license_manager_export  # noqa: E402
from license_manager_export import _scan_license_configurations_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


def _fake_lm_client(configs=None):
    """Build a MagicMock standing in for a boto3 license-manager client."""
    client = MagicMock()
    pages = [{"LicenseConfigurations": configs or []}]
    client.get_paginator.return_value.paginate.return_value = pages
    return client


def _config(config_id):
    return {
        "LicenseConfigurationId": config_id,
        "LicenseConfigurationArn": f"arn:aws:license-manager:{REGION}:123456789012:license-configuration:{config_id}",
        "Name": config_id,
        "Description": "test config",
        "LicenseCountingType": "vCPU",
        "LicenseCount": 10,
        "LicenseCountHardLimit": False,
        "ConsumedLicenses": 2,
        "Status": "AVAILABLE",
        "OwnerAccountId": "123456789012",
    }


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One license configuration that fails to process must not discard
        the whole region's results."""
        good = _config("good-config")
        bad = _config("bad-config")

        client = _fake_lm_client(configs=[good, bad])
        monkeypatch.setattr(
            license_manager_export.utils, "get_boto3_client", lambda *a, **kw: client
        )

        original = license_manager_export._build_config_row

        def raise_for_bad(item, region):
            if item.get("LicenseConfigurationId") == "bad-config":
                raise KeyError("SomeUnexpectedField")
            return original(item, region)

        monkeypatch.setattr(license_manager_export, "_build_config_row", raise_for_bad)

        rows = _scan_license_configurations_region(REGION)

        ids = {row["LicenseConfigurationId"] for row in rows}
        assert "good-config" in ids, "healthy configuration was lost when a sibling failed"
        assert "bad-config" not in ids, "malformed configuration should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListLicenseConfigurations",
            )

        monkeypatch.setattr(license_manager_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_license_configurations_region(REGION)

    def test_collect_license_configurations_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures,
        not drop them — this is what lets ``_run_export`` write a FAILED
        marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "ListLicenseConfigurations",
            )

        monkeypatch.setattr(license_manager_export, "_scan_license_configurations_region", boom)

        configs, failed_regions = license_manager_export.collect_license_configurations([REGION])

        assert configs == []
        assert [r for r, _ in failed_regions] == [REGION]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

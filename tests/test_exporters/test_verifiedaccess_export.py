#!/usr/bin/env python3
"""
Tests for verifiedaccess_export.py.

Regression coverage for issue #208: the exporter created its client with the
non-existent boto3 service name 'verifiedaccess'. Verified Access APIs live
under 'ec2'. Because every collector is wrapped in @aws_error_handler, the
invalid client surfaced as a silently empty export rather than a crash — so the
import-only smoke test never caught it. These tests assert every collector
creates its client with a *real* boto3 service.

Also covers the Tier-3 silent-collection-failure fix (07.16.2026 audit): the
primary scope (Verified Access Instances) must raise on a region-level API
error rather than swallow it, so ``collect_verified_access_instances_all_regions``
can surface a failed region instead of reporting "no instances". See
TestSilentCollectionFailureRegression below.

Note: moto (as of this test's authoring) does not implement any of the
describe_verified_access_* EC2 actions, so these tests monkeypatch
``utils.get_boto3_client`` with a MagicMock instead of using ``@mock_aws``.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions
import botocore.session
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import verifiedaccess_export as va  # noqa: E402

REGION = "us-east-1"

# Every collector and how to invoke it (collect_access_logs_config needs the
# already-collected instances list).
COLLECTORS = [
    ("_scan_verified_access_instances_region", lambda f: f(REGION)),
    ("collect_trust_providers", lambda f: f(REGION)),
    ("collect_verified_access_groups", lambda f: f(REGION)),
    ("collect_verified_access_endpoints", lambda f: f(REGION)),
    ("collect_access_logs_config", lambda f: f(REGION, [])),
]


def _empty_client():
    """A mock client that yields no resources for any paginated/direct call."""
    m = MagicMock()
    m.get_paginator.return_value.paginate.return_value = []
    m.describe_verified_access_instance_logging_configurations.return_value = {}
    return m


@pytest.mark.parametrize("fn_name,invoke", COLLECTORS)
def test_collectors_use_valid_boto3_service(monkeypatch, fn_name, invoke):
    """Each collector must build its client from a real boto3 service (issue #208)."""
    valid_services = set(botocore.session.get_session().get_available_services())
    requested = []

    def spy(service, region_name=None, **kwargs):
        requested.append(service)
        return _empty_client()

    monkeypatch.setattr(va.utils, "get_boto3_client", spy)

    invoke(getattr(va, fn_name))

    assert requested, f"{fn_name} never created a client"
    invalid = [s for s in requested if s not in valid_services]
    assert not invalid, (
        f"{fn_name} created a client with invalid boto3 service(s): {invalid}. "
        "Verified Access APIs live under 'ec2'."
    )
    # Verified Access is specifically an EC2 API surface.
    assert all(s == "ec2" for s in requested), (
        f"{fn_name} should use the 'ec2' client; got {requested}"
    )


def test_collect_instances_parses_data(monkeypatch):
    """With the corrected client, instance data is parsed end to end."""
    page = {
        "VerifiedAccessInstances": [
            {
                "VerifiedAccessInstanceId": "vai-0123456789abcdef0",
                "Description": "prod zero-trust",
                "VerifiedAccessTrustProviders": [{"VerifiedAccessTrustProviderId": "vatp-1"}],
                "Tags": [{"Key": "env", "Value": "prod"}],
            }
        ]
    }
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [page]

    captured = {}

    def spy(service, region_name=None, **kwargs):
        captured["service"] = service
        return client

    monkeypatch.setattr(va.utils, "get_boto3_client", spy)

    rows = va._scan_verified_access_instances_region(REGION)

    assert captured["service"] == "ec2"
    assert len(rows) == 1
    assert rows[0]["Instance ID"] == "vai-0123456789abcdef0"
    assert rows[0]["Trust Provider Count"] == 1
    assert rows[0]["Tags"] == "env=prod"


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.

    Tier-3 nuance: verifiedaccess_export.py always writes a forced Summary
    sheet (a workbook always lands), so these tests only cover the primary
    scope's failure-propagation contract — not the always-on export itself.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One instance that fails to process must not discard the whole region."""
        page = {
            "VerifiedAccessInstances": [
                {"VerifiedAccessInstanceId": "vai-good", "Tags": []},
                {"VerifiedAccessInstanceId": "vai-bad", "Tags": []},
            ]
        }
        client = MagicMock()
        client.get_paginator.return_value.paginate.return_value = [page]
        monkeypatch.setattr(
            va.utils, "get_boto3_client", lambda service, region_name=None, **kw: client
        )

        original = va._build_instance_row

        def raise_for_bad(instance, region):
            if instance.get("VerifiedAccessInstanceId") == "vai-bad":
                raise KeyError("SomeUnexpectedField")
            return original(instance, region)

        monkeypatch.setattr(va, "_build_instance_row", raise_for_bad)

        rows = va._scan_verified_access_instances_region(REGION)

        ids = {row["Instance ID"] for row in rows}
        assert "vai-good" in ids, "healthy instance was lost when a sibling failed"
        assert "vai-bad" not in ids, "malformed instance should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(service, region_name=None, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeVerifiedAccessInstances",
            )

        monkeypatch.setattr(va.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            va._scan_verified_access_instances_region(REGION)

    def test_collect_instances_all_regions_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures,
        not drop them — this is what lets export write a FAILED marker +
        exit 1 while the forced Summary sheet still lands.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeVerifiedAccessInstances",
            )

        monkeypatch.setattr(va, "_scan_verified_access_instances_region", boom)

        instances, failed_regions = va.collect_verified_access_instances_all_regions([REGION])

        assert instances == []
        assert [r for r, _ in failed_regions] == [REGION]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

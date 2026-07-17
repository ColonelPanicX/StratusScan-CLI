#!/usr/bin/env python3
"""
Moto-based tests for ssm_fleet_export.py.

Focus: the silent-collection-failure contract (Tier-2). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note: moto 5.1.21 does not implement SSM's ``describe_instance_information``
or ``list_compliance_items`` (both raise "action has not been implemented"),
so the managed-instances and patch-compliance scope tests fake the SSM
client / scan functions via ``monkeypatch`` instead of relying on
``@mock_aws`` state. ``describe_parameters`` IS implemented by moto, so the
parameters scope also gets one real ``@mock_aws`` happy-path test.
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import ssm_fleet_export  # noqa: E402
from ssm_fleet_export import _scan_managed_instances_region  # noqa: E402

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class _FakePaginator:
    """Minimal paginator stand-in yielding pre-built pages."""

    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class _FakeSSMClient:
    """
    Minimal SSM client stand-in for ``describe_instance_information``.

    moto does not implement this action, so the managed-instances scope is
    exercised against this fake instead of ``@mock_aws``.
    """

    def __init__(self, instances=None):
        self._instances = instances or []

    def get_paginator(self, operation_name):
        assert operation_name == 'describe_instance_information'
        return _FakePaginator([{'InstanceInformationList': self._instances}])


def _instance(instance_id, ping_status='Online'):
    return {
        'InstanceId': instance_id,
        'PingStatus': ping_status,
        'PlatformType': 'Linux',
    }


class TestScanManagedInstancesRegion:
    """Happy-path collection."""

    def test_collects_instances(self, monkeypatch):
        fake_client = _FakeSSMClient(instances=[_instance('i-good')])
        monkeypatch.setattr(ssm_fleet_export.utils, 'get_boto3_client', lambda *a, **kw: fake_client)

        rows = _scan_managed_instances_region(REGION)

        ids = {row['Instance ID'] for row in rows}
        assert 'i-good' in ids

    def test_empty_region_returns_empty_list(self, monkeypatch):
        fake_client = _FakeSSMClient(instances=[])
        monkeypatch.setattr(ssm_fleet_export.utils, 'get_boto3_client', lambda *a, **kw: fake_client)

        rows = _scan_managed_instances_region(REGION)

        assert rows == []


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently
    lost data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.

    ssm_fleet_export has three region-scanned scope collectors (managed
    instances, patch compliance, parameters) whose failures must all
    accumulate into one combined ``failed_regions`` list.
    """

    # -- Primary scope: managed instances -----------------------------------

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One instance that fails to process must not discard the whole region."""
        fake_client = _FakeSSMClient(instances=[_instance('good-i'), _instance('bad-i')])
        monkeypatch.setattr(ssm_fleet_export.utils, 'get_boto3_client', lambda *a, **kw: fake_client)

        original = ssm_fleet_export._build_instance_row

        def raise_for_bad(instance, region):
            if instance.get('InstanceId') == 'bad-i':
                raise KeyError('SomeUnexpectedField')
            return original(instance, region)

        monkeypatch.setattr(ssm_fleet_export, '_build_instance_row', raise_for_bad)

        rows = _scan_managed_instances_region(REGION)

        ids = {row['Instance ID'] for row in rows}
        assert 'good-i' in ids, "healthy instance was lost when a sibling failed"
        assert 'bad-i' not in ids, "malformed instance should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeInstanceInformation",
            )

        monkeypatch.setattr(ssm_fleet_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_managed_instances_region(REGION)

    def test_collect_managed_instances_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeInstanceInformation",
            )

        monkeypatch.setattr(ssm_fleet_export, "_scan_managed_instances_region", boom)

        instances, failed_regions = ssm_fleet_export.collect_managed_instances([REGION])

        assert instances == []
        assert [r for r, _ in failed_regions] == [REGION]

    # -- Second scope: patch compliance --------------------------------------

    def test_scan_patch_compliance_region_api_failure_raises(self, monkeypatch):
        """
        A failure while listing instances (the region-level API call) must
        propagate. Per-instance list_compliance_items lookups stay
        best-effort (see docstring on _scan_patch_compliance_region).
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeInstanceInformation",
            )

        monkeypatch.setattr(ssm_fleet_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            ssm_fleet_export._scan_patch_compliance_region(REGION)

    def test_collect_patch_compliance_surfaces_failed_regions(self, monkeypatch):
        """The patch-compliance scope must also surface region failures."""

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeInstanceInformation",
            )

        monkeypatch.setattr(ssm_fleet_export, "_scan_patch_compliance_region", boom)

        compliance, failed_regions = ssm_fleet_export.collect_patch_compliance([REGION])

        assert compliance == []
        assert [r for r, _ in failed_regions] == [REGION]

    # -- Third scope: parameters ---------------------------------------------

    @mock_aws
    def test_scan_ssm_parameters_region_collects_real_moto_parameters(self):
        """Happy path: describe_parameters IS implemented by moto."""
        client = boto3.client("ssm", region_name=REGION)
        client.put_parameter(Name="/app/config", Value="v1", Type="String")

        rows = ssm_fleet_export._scan_ssm_parameters_region(REGION)

        names = {row["Parameter Name"] for row in rows}
        assert "/app/config" in names

    def test_scan_ssm_parameters_region_api_failure_raises(self, monkeypatch):
        """Parameters scope: a region-level API failure must propagate."""

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "DescribeParameters",
            )

        monkeypatch.setattr(ssm_fleet_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            ssm_fleet_export._scan_ssm_parameters_region(REGION)

    def test_collect_ssm_parameters_surfaces_failed_regions(self, monkeypatch):
        """The parameters scope must also surface region failures."""

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "DescribeParameters",
            )

        monkeypatch.setattr(ssm_fleet_export, "_scan_ssm_parameters_region", boom)

        parameters, failed_regions = ssm_fleet_export.collect_ssm_parameters([REGION])

        assert parameters == []
        assert [r for r, _ in failed_regions] == [REGION]

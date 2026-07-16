#!/usr/bin/env python3
"""
Moto-based tests for kms_export.py.

Covers:
- scan_kms_keys_in_region()
- scan_kms_aliases_in_region()
- scan_kms_grants_in_region()
"""

import sys
from pathlib import Path

import boto3
import botocore
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import kms_export  # noqa: E402
from kms_export import (  # noqa: E402
    scan_kms_aliases_in_region,
    scan_kms_grants_in_region,
    scan_kms_keys_in_region,
)

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


class TestScanKmsKeysInRegion:
    """Tests for scan_kms_keys_in_region()."""

    @mock_aws
    def test_created_key_appears_in_results(self):
        """A newly created KMS key is returned by the collector."""
        kms = boto3.client("kms", region_name=REGION)
        created = kms.create_key(Description="test-key")
        key_id = created["KeyMetadata"]["KeyId"]

        result = scan_kms_keys_in_region(REGION, ACCOUNT_ID)

        assert isinstance(result, list)
        assert any(row["Key ID"] == key_id for row in result)

    @mock_aws
    def test_result_contains_expected_columns(self):
        """Each row contains the expected column keys."""
        kms = boto3.client("kms", region_name=REGION)
        kms.create_key(Description="col-check-key")

        result = scan_kms_keys_in_region(REGION, ACCOUNT_ID)

        assert len(result) >= 1
        row = result[0]
        for col in ("Key ID", "Key State", "Region", "Key Manager"):
            assert col in row, f"Missing column: {col}"

    @mock_aws
    def test_empty_region_returns_empty_list(self):
        """Region with no customer-created KMS keys still returns a list."""
        result = scan_kms_keys_in_region(REGION, ACCOUNT_ID)
        assert isinstance(result, list)


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.16.2026 blast-radius audit: KMS collectors
    swallowed region-level errors into empty lists, indistinguishable from a
    genuinely empty region/account. See
    .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

    All three KMS collectors (keys, aliases, grants) are per-region top-level
    scans -- each produces its own independent sheet -- so all three are
    treated as scope-level collectors here and must raise on a region-level
    failure. Per-item processing (a single key's metadata, a single alias, a
    single key's grants) is guarded separately and degrades gracefully.
    """

    @mock_aws
    def test_malformed_key_is_skipped_not_fatal(self, monkeypatch):
        """
        One key that fails to process must not discard the whole region's
        results -- the healthy key is still collected.
        """
        kms = boto3.client("kms", region_name=REGION)
        good = kms.create_key(Description="good-key")["KeyMetadata"]["KeyId"]
        bad = kms.create_key(Description="bad-key")["KeyMetadata"]["KeyId"]

        original = kms_export._build_key_row

        def raise_for_bad(kms_client, key, region):
            if key.get("KeyId") == bad:
                raise KeyError("SomeUnexpectedField")
            return original(kms_client, key, region)

        monkeypatch.setattr(kms_export, "_build_key_row", raise_for_bad)

        result = scan_kms_keys_in_region(REGION, ACCOUNT_ID)

        ids = {row["Key ID"] for row in result}
        assert good in ids, "healthy key was lost when a sibling failed"
        assert bad not in ids, "malformed key should have been skipped"

    @mock_aws
    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure while listing keys must propagate (so the
        caller can record a FAILED region) rather than being swallowed into
        an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListKeys",
            )

        monkeypatch.setattr(kms_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            scan_kms_keys_in_region(REGION, ACCOUNT_ID)

    @mock_aws
    def test_alias_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        scan_kms_aliases_in_region is also a per-region top-level collector
        (its own independent list_aliases scan) -- a region-level failure
        must propagate rather than collapse into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListAliases",
            )

        monkeypatch.setattr(kms_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            scan_kms_aliases_in_region(REGION)

    @mock_aws
    def test_grant_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        scan_kms_grants_in_region's initial key listing is also a per-region
        top-level operation -- a failure there must propagate rather than
        collapse into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "ListKeys",
            )

        monkeypatch.setattr(kms_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            scan_kms_grants_in_region(REGION)

    @mock_aws
    def test_grant_per_key_failure_degrades_gracefully(self, monkeypatch):
        """
        Unlike the region-level key/alias listing, a single key's grants
        failing to list is per-item enrichment scoped to that one key -- it
        must be logged and skipped, not raised, so the rest of the region's
        grants are still collected.
        """
        kms = boto3.client("kms", region_name=REGION)
        good_key = kms.create_key(Description="good-key")["KeyMetadata"]["KeyId"]
        bad_key = kms.create_key(Description="bad-key")["KeyMetadata"]["KeyId"]

        real_client = boto3.client("kms", region_name=REGION)

        class GrantFailureClient:
            """Proxies a real KMS client but fails list_grants for one key."""

            def __init__(self, real, bad_key_id):
                self._real = real
                self._bad_key_id = bad_key_id

            def get_paginator(self, operation_name):
                if operation_name == "list_grants":
                    real_paginator = self._real.get_paginator("list_grants")
                    bad_key_id = self._bad_key_id

                    class _Wrapped:
                        def paginate(self, **kwargs):
                            if kwargs.get("KeyId") == bad_key_id:
                                raise botocore.exceptions.ClientError(
                                    {
                                        "Error": {
                                            "Code": "NotFoundException",
                                            "Message": "boom",
                                        }
                                    },
                                    "ListGrants",
                                )
                            return real_paginator.paginate(**kwargs)

                    return _Wrapped()
                return self._real.get_paginator(operation_name)

            def __getattr__(self, name):
                return getattr(self._real, name)

        monkeypatch.setattr(
            kms_export.utils,
            "get_boto3_client",
            lambda *args, **kwargs: GrantFailureClient(real_client, bad_key),
        )

        # Must not raise -- per-key grant failures degrade gracefully.
        result = scan_kms_grants_in_region(REGION)

        assert isinstance(result, list)
        assert all(row["Key ID"] != bad_key for row in result)
        _ = good_key  # good_key had no grants created; presence isn't asserted

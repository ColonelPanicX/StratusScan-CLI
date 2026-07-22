#!/usr/bin/env python3
"""
Tests for xray_export.py.

Focus: the silent-collection-failure contract (Tier-3 PARTIAL). See
.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md

Note on moto: moto's X-Ray backend requires the optional ``aws_xray_sdk``
package, which is not a project dependency (StratusScan keeps runtime deps
minimal per the CloudShell-first design principle in CLAUDE.md) and is not
installed in this environment. ``@mock_aws`` cannot be used for X-Ray here,
so these tests monkeypatch ``utils.get_boto3_client`` with a lightweight fake
client instead of exercising real botocore/moto plumbing.
"""

import sys
from pathlib import Path

import botocore
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import xray_export  # noqa: E402
from xray_export import _scan_sampling_rules_region  # noqa: E402

REGION = "us-east-1"


class _FakeXrayClient:
    """
    Stand-in for the boto3 X-Ray client.

    moto's xray backend requires ``aws_xray_sdk`` (not installed / not a
    project dependency), so ``get_sampling_rules`` is stubbed directly rather
    than mocked via ``@mock_aws``.
    """

    def __init__(self, rule_records=None, error=None):
        self._rule_records = rule_records or []
        self._error = error

    def get_sampling_rules(self, **kwargs):
        if self._error is not None:
            raise self._error
        return {"SamplingRuleRecords": self._rule_records}


def _rule_record(name):
    return {
        "SamplingRule": {
            "RuleName": name,
            "RuleARN": f"arn:aws:xray:{REGION}:123456789012:sampling-rule/{name}",
            "Priority": 1000,
            "FixedRate": 0.05,
            "ReservoirSize": 1,
            "ServiceName": "*",
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "ResourceARN": "*",
            "Version": 1,
        },
        "CreatedAt": "N/A",
        "ModifiedAt": "N/A",
    }


class TestSilentCollectionFailureRegression:
    """
    Regression tests for the 07.15 / 07.16.2026 audits: exporters silently lost
    data because a collection error was swallowed to an empty list,
    indistinguishable from a genuinely empty region.
    """

    def test_malformed_item_is_skipped_not_fatal(self, monkeypatch):
        """One sampling rule that fails to process must not discard the whole region."""
        fake_client = _FakeXrayClient(
            rule_records=[_rule_record("good-rule"), _rule_record("bad-rule")]
        )
        monkeypatch.setattr(xray_export.utils, "get_boto3_client", lambda *a, **k: fake_client)

        original = xray_export._build_sampling_rule_row

        def raise_for_bad(rule_record, region):
            if rule_record["SamplingRule"]["RuleName"] == "bad-rule":
                raise KeyError("SomeUnexpectedField")
            return original(rule_record, region)

        monkeypatch.setattr(xray_export, "_build_sampling_rule_row", raise_for_bad)

        rows = _scan_sampling_rules_region(REGION)

        names = {row["Rule Name"] for row in rows}
        assert "good-rule" in names, "healthy sampling rule was lost when a sibling failed"
        assert "bad-rule" not in names, "malformed sampling rule should have been skipped"

    def test_region_api_failure_raises_not_empty(self, monkeypatch):
        """
        A region-level API failure must propagate (so the caller can record a
        FAILED region) rather than being swallowed into an empty list.
        """

        def boom(*args, **kwargs):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
                "GetSamplingRules",
            )

        monkeypatch.setattr(xray_export.utils, "get_boto3_client", boom)

        with pytest.raises(botocore.exceptions.ClientError):
            _scan_sampling_rules_region(REGION)

    def test_collect_sampling_rules_surfaces_failed_regions(self, monkeypatch):
        """
        The scope wrapper must return failed regions via collect_failures, not
        drop them — this is what lets export write a FAILED marker + exit 1.
        """

        def boom(region):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}},
                "GetSamplingRules",
            )

        monkeypatch.setattr(xray_export, "_scan_sampling_rules_region", boom)

        rules, failed_regions = xray_export.collect_sampling_rules([REGION])

        assert rules == []
        assert [r for r, _ in failed_regions] == [REGION]

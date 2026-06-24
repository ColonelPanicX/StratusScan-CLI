#!/usr/bin/env python3
"""
Tests for smart_scan.bill_crosscheck — the Cost Explorer ground-truth
cross-check (issue #209).
"""

import datetime
import os
import sys
from unittest.mock import MagicMock

import pytest

scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../..", "scripts"))
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from smart_scan import bill_crosscheck as bc  # noqa: E402


class TestLastFullMonth:
    def test_mid_month(self):
        start, end = bc._last_full_month(datetime.date(2026, 3, 15))
        assert start == "2026-02-01"
        assert end == "2026-03-01"

    def test_january_rolls_to_december(self):
        start, end = bc._last_full_month(datetime.date(2026, 1, 5))
        assert start == "2025-12-01"
        assert end == "2026-01-01"


class TestMapCeService:
    def test_canonical_full_name(self):
        # CE often emits the full canonical name directly.
        assert bc.map_ce_service("Amazon Relational Database Service") == (
            "Amazon Relational Database Service",
            False,
        )

    def test_suffixed_name_strips_to_base(self):
        canonical, ignored = bc.map_ce_service("Amazon Elastic Compute Cloud - Compute")
        assert canonical == "Amazon Elastic Compute Cloud"
        assert ignored is False

    def test_short_alias_with_suffix(self):
        # "EC2 - Other" -> "EC2" -> alias -> canonical.
        canonical, ignored = bc.map_ce_service("EC2 - Other")
        assert canonical == "Amazon Elastic Compute Cloud"
        assert ignored is False

    @pytest.mark.parametrize(
        "name",
        ["Tax", "AWS Support (Business)", "Refund", "AWS Premium Support", "AWS Cost Explorer"],
    )
    def test_billing_line_items_are_ignored(self, name):
        canonical, ignored = bc.map_ce_service(name)
        assert ignored is True
        assert canonical is None

    def test_unmappable_real_service_returns_none_not_ignored(self):
        canonical, ignored = bc.map_ce_service("Some Brand New Service")
        assert canonical is None
        assert ignored is False


class TestReconcile:
    def test_buckets_classify_correctly(self):
        spend = {
            "Amazon Relational Database Service": 120.0,  # billed + discovered
            "Amazon Simple Storage Service": 5.0,         # billed, NOT discovered
            "Tax": 9.99,                                  # ignored line item
            "Some Brand New Service": 3.0,                # unmapped real spend
            "Amazon Elastic Compute Cloud": 0.0,          # zero -> dropped
        }
        discovered = {"Amazon RDS"}  # alias for RDS canonical

        result = bc.reconcile(spend, discovered)

        assert [r["service"] for r in result["confirmed"]] == [
            "Amazon Relational Database Service"
        ]
        assert [r["service"] for r in result["not_collected"]] == [
            "Amazon Simple Storage Service"
        ]
        assert [r["ce_service"] for r in result["unmapped"]] == ["Some Brand New Service"]
        assert [r["ce_service"] for r in result["ignored"]] == ["Tax"]

    def test_not_collected_includes_exporters(self):
        result = bc.reconcile({"Amazon Simple Storage Service": 10.0}, set())
        row = result["not_collected"][0]
        assert "s3_export.py" in row["exporters"]

    def test_min_cost_filter(self):
        spend = {"Amazon Simple Storage Service": 0.50}
        result = bc.reconcile(spend, set(), min_cost=1.0)
        assert result["not_collected"] == []

    def test_sorted_by_cost_desc(self):
        spend = {
            "Amazon Simple Storage Service": 5.0,
            "Amazon Relational Database Service": 50.0,
        }
        result = bc.reconcile(spend, set())
        costs = [r["monthly_cost"] for r in result["not_collected"]]
        assert costs == sorted(costs, reverse=True)


class TestGetServiceSpend:
    def test_govcloud_is_unavailable(self, monkeypatch):
        monkeypatch.setattr(bc.utils, "is_service_available_in_partition", lambda *a, **k: False)
        with pytest.raises(bc.BillCrossCheckUnavailable, match="GovCloud"):
            bc.get_service_spend(partition="aws-us-gov")

    def test_access_denied_becomes_skip(self, monkeypatch):
        monkeypatch.setattr(bc.utils, "is_service_available_in_partition", lambda *a, **k: True)
        monkeypatch.setattr(bc.utils, "get_partition_default_region", lambda *a, **k: "us-east-1")

        client = MagicMock()
        err = Exception("denied")
        err.response = {"Error": {"Code": "AccessDeniedException"}}
        client.get_cost_and_usage.side_effect = err
        monkeypatch.setattr(bc.utils, "get_boto3_client", lambda *a, **k: client)

        with pytest.raises(bc.BillCrossCheckUnavailable, match="ce:GetCostAndUsage"):
            bc.get_service_spend(partition="aws")

    def test_aggregates_grouped_costs(self, monkeypatch):
        monkeypatch.setattr(bc.utils, "is_service_available_in_partition", lambda *a, **k: True)
        monkeypatch.setattr(bc.utils, "get_partition_default_region", lambda *a, **k: "us-east-1")

        client = MagicMock()
        client.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "Groups": [
                        {"Keys": ["Amazon Relational Database Service"],
                         "Metrics": {"BlendedCost": {"Amount": "12.50"}}},
                        {"Keys": ["Amazon Simple Storage Service"],
                         "Metrics": {"BlendedCost": {"Amount": "3.25"}}},
                    ]
                }
            ]
        }
        monkeypatch.setattr(bc.utils, "get_boto3_client", lambda *a, **k: client)

        spend = bc.get_service_spend(partition="aws")
        assert spend == {
            "Amazon Relational Database Service": 12.50,
            "Amazon Simple Storage Service": 3.25,
        }


class TestRunCrosscheck:
    def test_skip_is_status_tagged_not_raised(self, monkeypatch):
        monkeypatch.setattr(bc.utils, "is_service_available_in_partition", lambda *a, **k: False)
        result = bc.run_crosscheck({"Amazon RDS"}, partition="aws-us-gov")
        assert result["status"] == bc.STATUS_SKIPPED
        assert "GovCloud" in result["reason"]

    def test_ok_result_has_buckets_and_period(self, monkeypatch):
        monkeypatch.setattr(
            bc, "get_service_spend",
            lambda **k: {"Amazon Simple Storage Service": 7.0},
        )
        result = bc.run_crosscheck(
            {"Amazon RDS"}, partition="aws", reference_date=datetime.date(2026, 3, 10)
        )
        assert result["status"] == bc.STATUS_OK
        assert result["period"] == {"start": "2026-02-01", "end": "2026-03-01"}
        assert result["not_collected"][0]["service"] == "Amazon Simple Storage Service"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

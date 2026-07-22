"""
Bill Cross-Check — reconcile Cost Explorer spend against discovered services.

Service discovery probes a fixed catalog of APIs. Spend is the one signal that
does not lie about what is actually running: almost anything live in AWS shows
up on the bill. This module queries Cost Explorer for per-service spend over the
last full month and reconciles it against the services discovery found, so an
audit can surface "spend detected, never collected" gaps.

Design (issue #209):
- Cost Explorer (`ce`) is us-east-1 only and unavailable in GovCloud — the
  cross-check skips cleanly (with a reason) outside the commercial partition.
- Needs `ce:GetCostAndUsage` (read-only). Missing permission is a clean skip,
  not a failure — billing perms must never sink an audit run.
- Every CE service with spend is surfaced. Known non-resource billing line
  items (tax, support, refunds, credits) are filtered to an "ignored" bucket;
  anything we cannot map to a known service is reported as "unmapped" rather
  than hidden, so nothing silently disappears.

This module is library code: it returns structured results and logs via
utils.log_* — it never prints.
"""

import datetime
import sys
from pathlib import Path
from typing import Any, Optional

try:
    import utils
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent))
    import utils

from .mapping import SERVICE_SCRIPT_MAP, get_canonical_service_name, get_scripts_for_service


class BillCrossCheckUnavailable(Exception):
    """Raised when the bill cross-check cannot run (skip, not a failure)."""

# Cost Explorer line items that are not collectable AWS resources. Matched as
# lowercase substrings against the CE service name. Kept deliberately tight to
# avoid suppressing real services.
_IGNORED_LINE_ITEM_FRAGMENTS = (
    "tax",
    "refund",
    "credit",
    "aws support",
    "premium support",
    "aws cost explorer",
    "savings plans negation",
    "savings plans for",  # the netting line item, not the Savings Plans service
)

# Status constants for the cross-check result.
STATUS_OK = "ok"
STATUS_SKIPPED = "skipped"


def _last_full_month(reference_date: Optional[datetime.date] = None) -> tuple[str, str]:
    """Return (start, end) ISO dates spanning the last full calendar month.

    Cost Explorer's TimePeriod end is exclusive, so end is the first day of the
    current month and start is the first day of the previous month.
    """
    today = reference_date or datetime.date.today()
    first_of_this_month = today.replace(day=1)
    last_month_end = first_of_this_month  # exclusive
    prev = first_of_this_month - datetime.timedelta(days=1)
    last_month_start = prev.replace(day=1)
    return last_month_start.isoformat(), last_month_end.isoformat()


def map_ce_service(ce_name: str) -> tuple[Optional[str], bool]:
    """Map a Cost Explorer service name to a canonical StratusScan service.

    Returns (canonical_name_or_None, is_ignored_line_item).
      - (canonical, False): mapped to a known service in SERVICE_SCRIPT_MAP
      - (None, True):       a non-resource billing line item (tax/support/...)
      - (None, False):      real spend we could not map to a known service
    """
    low = ce_name.lower().strip()
    if any(frag in low for frag in _IGNORED_LINE_ITEM_FRAGMENTS):
        return None, True

    # CE often suffixes the service ("Amazon Elastic Compute Cloud - Compute",
    # "EC2 - Other"). Try the full name first, then the part before " - ".
    for candidate in (ce_name, ce_name.split(" - ")[0].strip()):
        canonical = get_canonical_service_name(candidate)
        if canonical in SERVICE_SCRIPT_MAP:
            return canonical, False

    return None, False


def reconcile(
    spend: dict[str, float],
    discovered_services: set[str],
    min_cost: float = 0.0,
) -> dict[str, list[dict[str, Any]]]:
    """Reconcile per-service CE spend against discovered services.

    Args:
        spend: CE service name -> cost for the period.
        discovered_services: service names discovery found in use (catalog names).
        min_cost: ignore spend at or below this amount (default: keep all > 0).

    Returns a dict with four buckets, each a list of row dicts:
        confirmed       - spend AND discovered (collected)
        not_collected   - spend mapped to a known service that was NOT discovered
        unmapped        - real spend we could not map to any known service
        ignored         - non-resource billing line items (tax/support/...)
    """
    # Normalise discovered names to canonical for comparison.
    discovered_canonical = {get_canonical_service_name(s) for s in discovered_services}

    confirmed: list[dict[str, Any]] = []
    not_collected: list[dict[str, Any]] = []
    unmapped: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []

    for ce_name, cost in sorted(spend.items(), key=lambda kv: kv[1], reverse=True):
        if cost <= min_cost:
            continue
        canonical, is_ignored = map_ce_service(ce_name)
        if is_ignored:
            ignored.append({"ce_service": ce_name, "monthly_cost": round(cost, 2)})
            continue
        if canonical is None:
            unmapped.append({"ce_service": ce_name, "monthly_cost": round(cost, 2)})
            continue
        row = {
            "ce_service": ce_name,
            "service": canonical,
            "monthly_cost": round(cost, 2),
            "exporters": get_scripts_for_service(canonical),
        }
        if canonical in discovered_canonical:
            confirmed.append(row)
        else:
            not_collected.append(row)

    return {
        "confirmed": confirmed,
        "not_collected": not_collected,
        "unmapped": unmapped,
        "ignored": ignored,
    }


def get_service_spend(
    partition: Optional[str] = None,
    reference_date: Optional[datetime.date] = None,
) -> dict[str, float]:
    """Query Cost Explorer for per-service blended cost over the last full month.

    Returns a dict of CE service name -> cost. Raises BillCrossCheckUnavailable
    when the cross-check cannot run (GovCloud, missing permission, API error)
    with a human-readable reason — callers should treat that as a clean skip.
    """
    if partition is None:
        partition = utils.detect_partition()

    if not utils.is_service_available_in_partition("ce", partition):
        raise BillCrossCheckUnavailable(
            "Cost Explorer is not available in this partition (GovCloud)."
        )

    region = utils.get_partition_default_region(partition)
    client = utils.get_boto3_client("ce", region_name=region)

    start, end = _last_full_month(reference_date)

    try:
        spend: dict[str, float] = {}
        next_token: Optional[str] = None
        while True:
            kwargs: dict[str, Any] = {
                "TimePeriod": {"Start": start, "End": end},
                "Granularity": "MONTHLY",
                "Metrics": ["BlendedCost"],
                "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}],
            }
            if next_token:
                kwargs["NextPageToken"] = next_token
            response = client.get_cost_and_usage(**kwargs)
            for result in response.get("ResultsByTime", []):
                for group in result.get("Groups", []):
                    name = group["Keys"][0]
                    amount = float(group["Metrics"]["BlendedCost"]["Amount"])
                    spend[name] = spend.get(name, 0.0) + amount
            next_token = response.get("NextPageToken")
            if not next_token:
                break
        return spend
    except Exception as e:  # noqa: BLE001 - classify and re-raise as skip reason
        code = ""
        resp = getattr(e, "response", None)
        if isinstance(resp, dict):
            code = resp.get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "AccessDenied", "UnauthorizedOperation"):
            raise BillCrossCheckUnavailable(
                "Missing Cost Explorer permission — grant ce:GetCostAndUsage "
                "(read-only) to enable the bill cross-check."
            ) from e
        raise BillCrossCheckUnavailable(f"Cost Explorer query failed: {e}") from e


def run_crosscheck(
    discovered_services: set[str],
    partition: Optional[str] = None,
    reference_date: Optional[datetime.date] = None,
    min_cost: float = 0.0,
) -> dict[str, Any]:
    """Run the full bill cross-check, returning a status-tagged result.

    Never raises: an unavailable cross-check returns {"status": "skipped",
    "reason": ...} so callers can record it without special-casing.
    """
    try:
        spend = get_service_spend(partition=partition, reference_date=reference_date)
    except BillCrossCheckUnavailable as e:
        utils.log_warning(f"Bill cross-check skipped: {e}")
        return {"status": STATUS_SKIPPED, "reason": str(e)}

    buckets = reconcile(spend, discovered_services, min_cost=min_cost)
    start, end = _last_full_month(reference_date)
    buckets.update({
        "status": STATUS_OK,
        "period": {"start": start, "end": end},
        "total_services_billed": len(spend),
    })
    if buckets["not_collected"]:
        names = ", ".join(r["service"] for r in buckets["not_collected"])
        utils.log_warning(
            f"Bill cross-check: {len(buckets['not_collected'])} service(s) with "
            f"spend were not collected by discovery: {names}"
        )
    return buckets

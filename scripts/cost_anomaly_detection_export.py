#!/usr/bin/env python3
"""
Cost Anomaly Detection Export Script

Exports AWS Cost Anomaly Detection configuration and anomalies:
- Anomaly monitors (definitions, filters, thresholds)
- Anomaly subscriptions (alert configurations)
- Detected anomalies (past 90 days)
- Root cause analysis
- Impact assessment
- Feedback tracking

Features:
- Complete monitor inventory
- Subscription and alert configurations
- Historical anomaly data (90-day window)
- Root cause breakdown by service/region/account
- Impact categorization (high/medium/low)
- Monitor type classification
- SNS and email notification tracking
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Standard utils import pattern
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils
args = utils.parse_script_args("Export AWS Cost Anomaly Detection monitors and alerts to Excel")

utils.setup_logging('cost-anomaly-detection-export')


def _build_monitor_row(monitor: dict[str, Any]) -> dict[str, Any]:
    """
    Build the export row for a single anomaly monitor.

    Extracted so per-item processing can be wrapped in try/except by the
    caller: a malformed monitor entry must not sink the whole account-scope
    collection. Every field is read with ``.get()`` and a safe default for
    the same reason.

    Args:
        monitor: A single AnomalyMonitors entry from get_anomaly_monitors.

    Returns:
        dict: The assembled monitor row.
    """
    monitor_spec = monitor.get('MonitorSpecification', {})

    return {
        'MonitorName': monitor.get('MonitorName', 'N/A'),
        'MonitorARN': monitor.get('MonitorArn', 'N/A'),
        'MonitorType': monitor.get('MonitorType', 'N/A'),
        'CreationDate': monitor.get('CreationDate'),
        'LastEvaluatedDate': monitor.get('LastEvaluatedDate', 'N/A'),
        'LastUpdatedDate': monitor.get('LastUpdatedDate', 'N/A'),
        'DimensionalValueCount': monitor.get('DimensionalValueCount', 0),
        'MonitorDimension': monitor.get('MonitorDimension', 'N/A'),
        'Expression': parse_monitor_expression(monitor_spec),
        'ExpressionJSON': json.dumps(monitor_spec, indent=2) if monitor_spec else 'N/A',
    }


def _build_subscription_row(subscription: dict[str, Any], account_id: str) -> dict[str, Any]:
    """
    Build the export row for a single anomaly subscription.

    Extracted so per-item processing can be wrapped in try/except by the
    caller: a malformed subscription entry must not sink the whole
    account-scope collection. Every field is read with ``.get()`` and a
    safe default for the same reason.

    Args:
        subscription: A single AnomalySubscriptions entry from
            get_anomaly_subscriptions.
        account_id: The AWS account ID, used as a fallback when a
            subscription entry has no AccountId of its own.

    Returns:
        dict: The assembled subscription row.
    """
    subscribers = subscription.get('Subscribers', [])
    subscriber_list = []
    for sub in subscribers:
        sub_type = sub.get('Type', 'UNKNOWN')
        sub_address = sub.get('Address', 'N/A')
        subscriber_list.append(f"{sub_type}: {sub_address}")

    return {
        'SubscriptionName': subscription.get('SubscriptionName', 'N/A'),
        'SubscriptionARN': subscription.get('SubscriptionArn', 'N/A'),
        'AccountID': subscription.get('AccountId', account_id),
        'MonitorARNs': ', '.join(subscription.get('MonitorArnList', [])),
        'NumberOfMonitors': len(subscription.get('MonitorArnList', [])),
        'Frequency': subscription.get('Frequency', 'N/A'),
        'Subscribers': ', '.join(subscriber_list) if subscriber_list else 'N/A',
        'NumberOfSubscribers': len(subscribers),
        'Threshold': subscription.get('Threshold', 'N/A'),
        'ThresholdExpression': json.dumps(subscription.get('ThresholdExpression', {}), indent=2) if subscription.get('ThresholdExpression') else 'N/A',
    }


def get_anomaly_monitors() -> list[dict[str, Any]]:
    """
    Get all anomaly monitors.

    Not wrapped in ``aws_error_handler`` and does not swallow errors to an
    empty list: a swallowed error here would be indistinguishable from a
    genuinely empty account (no monitors configured), producing silent data
    loss (see the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits). Cost Anomaly Detection is a global, account-scope service
    (Cost Explorer, us-east-1 home region) -- not multi-region (see
    scripts/iam_export.py for the account-scope reference pattern this
    follows; scripts/shield_export.py for the closest existing example).
    Account-scope failures (client creation, pagination) are allowed to
    raise so the caller (``_run_export``) can record this scope as *failed*
    rather than *empty*. Per-monitor errors are contained internally
    (logged and skipped).

    Returns:
        list: List of built anomaly monitor row dictionaries.

    Raises:
        Exception: Any AWS/pagination error for the account scope (caller
            records it as a failed scope; it is never masked as empty).
    """
    home_region = utils.get_partition_default_region()
    ce = utils.get_boto3_client('ce', region_name=home_region)

    raw_monitors = []
    next_token = None

    while True:
        params = {'MaxResults': 100}
        if next_token:
            params['NextPageToken'] = next_token

        response = ce.get_anomaly_monitors(**params)
        raw_monitors.extend(response.get('AnomalyMonitors', []))

        next_token = response.get('NextPageToken')
        if not next_token:
            break

    monitors = []
    skipped = 0

    for monitor in raw_monitors:
        try:
            monitors.append(_build_monitor_row(monitor))
        except Exception as e:
            skipped += 1
            monitor_name = monitor.get('MonitorName', 'Unknown') if isinstance(monitor, dict) else 'Unknown'
            utils.log_error(f"Skipping anomaly monitor '{monitor_name}' due to a processing error", e)
            continue

    if skipped:
        utils.log_warning(
            f"{skipped} of {len(raw_monitors)} anomaly monitor(s) were skipped due to "
            "processing errors (see log above); the remaining monitors were still collected."
        )

    return monitors


def get_anomaly_subscriptions(account_id: str) -> list[dict[str, Any]]:
    """
    Get all anomaly subscriptions.

    Not wrapped in ``aws_error_handler`` and does not swallow errors to an
    empty list: a swallowed error here would be indistinguishable from a
    genuinely empty account (no subscriptions configured), producing silent
    data loss (see the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits). Cost Anomaly Detection is a global, account-scope service
    (Cost Explorer, us-east-1 home region) -- not multi-region (see
    scripts/iam_export.py for the account-scope reference pattern this
    follows). Account-scope failures (client creation, pagination) are
    allowed to raise so the caller (``_run_export``) can record this scope
    as *failed* rather than *empty*. Per-subscription errors are contained
    internally (logged and skipped).

    Args:
        account_id: The AWS account ID, passed through to
            ``_build_subscription_row`` as an AccountId fallback.

    Returns:
        list: List of built anomaly subscription row dictionaries.

    Raises:
        Exception: Any AWS/pagination error for the account scope (caller
            records it as a failed scope; it is never masked as empty).
    """
    home_region = utils.get_partition_default_region()
    ce = utils.get_boto3_client('ce', region_name=home_region)

    raw_subscriptions = []
    next_token = None

    while True:
        params = {'MaxResults': 100}
        if next_token:
            params['NextPageToken'] = next_token

        response = ce.get_anomaly_subscriptions(**params)
        raw_subscriptions.extend(response.get('AnomalySubscriptions', []))

        next_token = response.get('NextPageToken')
        if not next_token:
            break

    subscriptions = []
    skipped = 0

    for subscription in raw_subscriptions:
        try:
            subscriptions.append(_build_subscription_row(subscription, account_id))
        except Exception as e:
            skipped += 1
            subscription_name = subscription.get('SubscriptionName', 'Unknown') if isinstance(subscription, dict) else 'Unknown'
            utils.log_error(f"Skipping anomaly subscription '{subscription_name}' due to a processing error", e)
            continue

    if skipped:
        utils.log_warning(
            f"{skipped} of {len(raw_subscriptions)} anomaly subscription(s) were skipped due to "
            "processing errors (see log above); the remaining subscriptions were still collected."
        )

    return subscriptions


@utils.aws_error_handler("Retrieving Anomalies", default_return=[])
def get_anomalies(start_date: str, end_date: str, monitor_arn: str = None) -> list[dict[str, Any]]:
    """Get anomalies for a time period."""
    # Cost Explorer is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    ce = utils.get_boto3_client('ce', region_name=home_region)

    anomalies = []
    next_token = None

    while True:
        params = {
            'DateInterval': {
                'StartDate': start_date,
                'EndDate': end_date
            },
            'MaxResults': 100
        }

        if monitor_arn:
            params['MonitorArn'] = monitor_arn

        if next_token:
            params['NextPageToken'] = next_token

        response = ce.get_anomalies(**params)

        for anomaly in response.get('Anomalies', []):
            anomalies.append(anomaly)

        next_token = response.get('NextPageToken')
        if not next_token:
            break

    return anomalies


def parse_monitor_expression(expression: dict) -> str:
    """Parse monitor expression into human-readable format."""
    if not expression:
        return "N/A"

    # Handle different expression types
    if 'Dimensions' in expression:
        dim = expression['Dimensions']
        key = dim.get('Key', 'Unknown')
        values = ', '.join(dim.get('Values', []))
        match_options = ', '.join(dim.get('MatchOptions', []))
        return f"Dimension: {key} = [{values}] (Match: {match_options})"

    elif 'Tags' in expression:
        tag = expression['Tags']
        key = tag.get('Key', 'Unknown')
        values = ', '.join(tag.get('Values', []))
        match_options = ', '.join(tag.get('MatchOptions', []))
        return f"Tag: {key} = [{values}] (Match: {match_options})"

    elif 'CostCategories' in expression:
        cc = expression['CostCategories']
        key = cc.get('Key', 'Unknown')
        values = ', '.join(cc.get('Values', []))
        return f"CostCategory: {key} = [{values}]"

    elif 'And' in expression:
        return f"AND expression with {len(expression['And'])} conditions"

    elif 'Or' in expression:
        return f"OR expression with {len(expression['Or'])} conditions"

    elif 'Not' in expression:
        return "NOT expression"

    else:
        return "Complex Expression (see JSON)"


def classify_impact(impact: dict) -> str:
    """Classify anomaly impact level."""
    try:
        max_impact = float(impact.get('MaxImpact', 0))
        total_impact = float(impact.get('TotalImpact', 0))

        # Use total impact for classification
        impact_value = total_impact if total_impact > 0 else max_impact

        if impact_value >= 1000:
            return f"HIGH (${impact_value:,.2f})"
        elif impact_value >= 100:
            return f"MEDIUM (${impact_value:,.2f})"
        elif impact_value > 0:
            return f"LOW (${impact_value:,.2f})"
        else:
            return "MINIMAL"
    except Exception:
        return "UNKNOWN"


def _run_export(account_id: str, account_name: str) -> None:
    """
    Collect Cost Anomaly Detection data and write the Excel export.

    Cost Anomaly Detection is a global, account-scope service (Cost
    Explorer, accessed via the partition-aware home region) -- not
    multi-region, so failures are tracked per account-scope collector
    rather than via ``utils.scan_regions_concurrent`` (see
    scripts/iam_export.py for the account-scope reference pattern;
    scripts/shield_export.py and scripts/lambda_export.py for the finalize
    shape this follows). The PRIMARY scopes are ``get_anomaly_monitors()``
    and ``get_anomaly_subscriptions()`` -- a real API error on either scope
    is recorded in ``failed_scopes`` and surfaced via
    ``utils.report_collection_failures`` plus a non-zero exit; it must
    never be silently collapsed into "no monitors configured" / "no
    subscriptions configured" (see
    .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).
    Anomalies (the 90-day detection history) is enrichment -- it degrades
    gracefully via its own ``aws_error_handler`` decorator and a failure
    there does not fail the whole export. The Summary sheet (and the rest
    of the workbook) is always written, even when a primary scope failed,
    so a partial export is never silently indistinguishable from a
    complete one.
    """
    utils.log_info(f"Exporting Cost Anomaly Detection data for account: {account_name} ({utils.mask_account_id(account_id)})")
    utils.log_info("Cost Anomaly Detection is global (accessed via us-east-1)...")

    failed_scopes = []

    # STEP 1: Anomaly monitors (PRIMARY scope -- a real API error here must
    # propagate to failed_scopes, never collapse into an empty list that
    # reads as "no monitors configured").
    utils.log_info("Retrieving anomaly monitors...")
    try:
        monitors = get_anomaly_monitors()
    except Exception as e:
        failed_scopes.append(('anomaly_monitors', str(e)))
        utils.log_error(f"Anomaly monitors collection failed: {e}")
        monitors = []
    else:
        if monitors:
            utils.log_info(f"Found {len(monitors)} anomaly monitor(s)")
        else:
            utils.log_info("No anomaly monitors found.")

    # STEP 2: Anomaly subscriptions (PRIMARY scope -- same reasoning as
    # monitors above).
    utils.log_info("Retrieving anomaly subscriptions...")
    try:
        subscriptions = get_anomaly_subscriptions(account_id)
    except Exception as e:
        failed_scopes.append(('anomaly_subscriptions', str(e)))
        utils.log_error(f"Anomaly subscriptions collection failed: {e}")
        subscriptions = []
    else:
        if subscriptions:
            utils.log_info(f"Found {len(subscriptions)} anomaly subscription(s)")
        else:
            utils.log_info("No anomaly subscriptions found.")

    # STEP 3: Anomalies for the past 90 days (enrichment -- degrades
    # gracefully via its own aws_error_handler decorator; a failure here
    # does not fail the whole export).
    end_date = datetime.now(timezone.utc).date()
    start_date = end_date - timedelta(days=90)

    utils.log_info(f"Retrieving anomalies from {start_date} to {end_date} (90 days)...")
    all_anomalies = get_anomalies(
        start_date=start_date.strftime('%Y-%m-%d'),
        end_date=end_date.strftime('%Y-%m-%d')
    )

    if all_anomalies:
        utils.log_info(f"Found {len(all_anomalies)} anomaly/anomalies")
    else:
        utils.log_info("No anomalies detected in the past 90 days")

    # Monitors and subscriptions are already built rows (see
    # _build_monitor_row / _build_subscription_row inside their
    # collectors above) -- no further per-item processing needed here.
    df_monitors = utils.prepare_dataframe_for_export(pd.DataFrame(monitors))
    df_subscriptions = utils.prepare_dataframe_for_export(pd.DataFrame(subscriptions))

    # Process anomalies
    anomaly_data = []
    root_cause_data = []

    for anomaly in all_anomalies:
        anomaly_id = anomaly.get('AnomalyId', 'N/A')
        impact = anomaly.get('Impact', {})

        anomaly_data.append({
            'AnomalyID': anomaly_id,
            'MonitorARN': anomaly.get('MonitorArn', 'N/A'),
            'AnomalyStartDate': anomaly.get('AnomalyStartDate', 'N/A'),
            'AnomalyEndDate': anomaly.get('AnomalyEndDate', 'N/A'),
            'DimensionValue': anomaly.get('DimensionValue', 'N/A'),
            'MaxImpact': impact.get('MaxImpact', 0),
            'TotalImpact': impact.get('TotalImpact', 0),
            'TotalActualSpend': impact.get('TotalActualSpend', 0),
            'TotalExpectedSpend': impact.get('TotalExpectedSpend', 0),
            'TotalImpactPercentage': impact.get('TotalImpactPercentage', 0),
            'ImpactClassification': classify_impact(impact),
            'AnomalyScore': anomaly.get('AnomalyScore', {}).get('CurrentScore', 0),
            'MaxScore': anomaly.get('AnomalyScore', {}).get('MaxScore', 0),
            'Feedback': anomaly.get('Feedback', 'NO'),
            'RootCauseCount': len(anomaly.get('RootCauses', [])),
        })

        # Process root causes
        for root_cause in anomaly.get('RootCauses', []):
            root_cause_data.append({
                'AnomalyID': anomaly_id,
                'Service': root_cause.get('Service', 'N/A'),
                'Region': root_cause.get('Region', 'N/A'),
                'LinkedAccount': root_cause.get('LinkedAccount', 'N/A'),
                'LinkedAccountName': root_cause.get('LinkedAccountName', 'N/A'),
                'UsageType': root_cause.get('UsageType', 'N/A'),
                'RootCauseImpact': root_cause.get('Impact', 0),
                'RootCauseImpactPercentage': root_cause.get('ImpactPercentage', 0),
            })

    df_anomalies = utils.prepare_dataframe_for_export(pd.DataFrame(anomaly_data))
    df_root_causes = utils.prepare_dataframe_for_export(pd.DataFrame(root_cause_data))

    # Create summary
    summary_data = []
    summary_data.append({'Metric': 'Total Monitors', 'Value': len(monitors)})
    summary_data.append({'Metric': 'Total Subscriptions', 'Value': len(subscriptions)})
    summary_data.append({'Metric': 'Anomalies (90 days)', 'Value': len(all_anomalies)})

    if not df_anomalies.empty:
        total_impact = df_anomalies['TotalImpact'].sum()
        avg_impact = df_anomalies['TotalImpact'].mean()
        max_impact = df_anomalies['MaxImpact'].max()

        summary_data.append({'Metric': 'Total Anomaly Impact ($)', 'Value': f"${total_impact:,.2f}"})
        summary_data.append({'Metric': 'Average Anomaly Impact ($)', 'Value': f"${avg_impact:,.2f}"})
        summary_data.append({'Metric': 'Maximum Single Impact ($)', 'Value': f"${max_impact:,.2f}"})

    df_summary = utils.prepare_dataframe_for_export(pd.DataFrame(summary_data))

    # Create high-impact anomalies view
    df_high_impact = pd.DataFrame()
    if not df_anomalies.empty:
        df_high_impact = df_anomalies[df_anomalies['TotalImpact'] >= 100].sort_values(
            'TotalImpact', ascending=False
        )

    # Export to Excel
    filename = utils.create_export_filename(account_name, 'cost-anomaly-detection', 'all')

    sheets = {
        'Summary': df_summary,
        'Monitors': df_monitors,
        'Subscriptions': df_subscriptions,
        'Anomalies': df_anomalies,
        'High Impact Anomalies': df_high_impact,
        'Root Causes': df_root_causes,
    }

    # The workbook (including the always-present Summary sheet) is written
    # unconditionally -- even when a primary scope failed above -- so a
    # partial export is never lost, only ever unmarked (see
    # .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).
    utils.save_multiple_dataframes_to_excel(sheets, filename)

    # Log summary
    utils.log_info(f"  Monitors: {len(monitors)}")
    utils.log_info(f"  Subscriptions: {len(subscriptions)}")
    utils.log_info(f"  Anomalies (90 days): {len(all_anomalies)}")

    if not df_high_impact.empty:
        utils.log_warning(f"  {len(df_high_impact)} high-impact anomaly/anomalies detected (>$100)")

    has_any_data = bool(monitors or subscriptions or all_anomalies)

    if failed_scopes:
        utils.log_error("Cost Anomaly Detection export completed with failures — data is incomplete.")
    elif not has_any_data:
        # Genuinely empty: both primary scopes succeeded and there is
        # simply nothing configured/detected. Exit 0, no marker.
        utils.log_warning("No Cost Anomaly Detection data was collected. Nothing to export.")
    else:
        utils.log_success("Cost Anomaly Detection export completed successfully!")

    # If either primary scope failed, make it loud: write a marker and exit
    # non-zero, even though the Summary sheet (and any partial data) was
    # already written above. A partial export that looks complete is
    # exactly the failure mode this guards against.
    if failed_scopes:
        utils.report_collection_failures(account_name, 'cost-anomaly-detection', failed_scopes)
        print(
            "\nERROR: Cost Anomaly Detection export completed with failures — data is "
            "incomplete. See the *-cost-anomaly-detection-FAILED-*.txt marker in the "
            "output directory."
        )
        sys.exit(1)


def main():
    """Main execution function — 2-step state machine (confirm -> export) for global service."""
    try:
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return
        global pd
        import pandas as pd
        account_id, account_name = utils.print_script_banner("AWS COST ANOMALY DETECTION EXPORT")

        # GovCloud availability guard — Cost Explorer is not available in GovCloud
        partition = utils.detect_partition()
        if not utils.is_service_available_in_partition("ce", partition):
            utils.log_warning("Cost Anomaly Detection (Cost Explorer) is not available in AWS GovCloud. Skipping.")
            sys.exit(0)

        step = 1

        while True:
            if step == 1:
                msg = "Ready to export Cost Anomaly Detection data (global service, us-east-1)."
                result = utils.prompt_confirmation(msg)
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                step = 2

            elif step == 2:
                _run_export(account_id, account_name)
                break

    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

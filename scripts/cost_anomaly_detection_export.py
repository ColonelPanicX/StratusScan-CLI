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

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
import json
import pandas as pd

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

utils.setup_logging('cost-anomaly-detection-export')


@utils.aws_error_handler("Retrieving Anomaly Monitors", default_return=[])
def get_anomaly_monitors() -> List[Dict[str, Any]]:
    """Get all anomaly monitors."""
    # Cost Explorer is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    ce = utils.get_boto3_client('ce', region_name=home_region)

    monitors = []
    next_token = None

    while True:
        params = {'MaxResults': 100}
        if next_token:
            params['NextPageToken'] = next_token

        response = ce.get_anomaly_monitors(**params)

        for monitor in response.get('AnomalyMonitors', []):
            monitors.append(monitor)

        next_token = response.get('NextPageToken')
        if not next_token:
            break

    return monitors


@utils.aws_error_handler("Retrieving Anomaly Subscriptions", default_return=[])
def get_anomaly_subscriptions() -> List[Dict[str, Any]]:
    """Get all anomaly subscriptions."""
    # Cost Explorer is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    ce = utils.get_boto3_client('ce', region_name=home_region)

    subscriptions = []
    next_token = None

    while True:
        params = {'MaxResults': 100}
        if next_token:
            params['NextPageToken'] = next_token

        response = ce.get_anomaly_subscriptions(**params)

        for subscription in response.get('AnomalySubscriptions', []):
            subscriptions.append(subscription)

        next_token = response.get('NextPageToken')
        if not next_token:
            break

    return subscriptions


@utils.aws_error_handler("Retrieving Anomalies", default_return=[])
def get_anomalies(start_date: str, end_date: str, monitor_arn: str = None) -> List[Dict[str, Any]]:
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


def parse_monitor_expression(expression: Dict) -> str:
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


def classify_impact(impact: Dict) -> str:
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
    """Collect Cost Anomaly Detection data and write the Excel export."""
    utils.log_info(f"Exporting Cost Anomaly Detection data for account: {account_name} ({utils.mask_account_id(account_id)})")
    utils.log_info("Cost Anomaly Detection is global (accessed via us-east-1)...")

    # Get anomaly monitors
    utils.log_info("Retrieving anomaly monitors...")
    monitors = get_anomaly_monitors()

    if monitors:
        utils.log_info(f"Found {len(monitors)} anomaly monitor(s)")
    else:
        utils.log_warning("No anomaly monitors found.")

    # Get anomaly subscriptions
    utils.log_info("Retrieving anomaly subscriptions...")
    subscriptions = get_anomaly_subscriptions()

    if subscriptions:
        utils.log_info(f"Found {len(subscriptions)} anomaly subscription(s)")
    else:
        utils.log_warning("No anomaly subscriptions found.")

    # Get anomalies for the past 90 days
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

    # Process monitors
    monitor_data = []
    for monitor in monitors:
        monitor_spec = monitor.get('MonitorSpecification', {})

        monitor_data.append({
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
        })

    df_monitors = utils.prepare_dataframe_for_export(pd.DataFrame(monitor_data))

    # Process subscriptions
    subscription_data = []
    for subscription in subscriptions:
        # Get subscriber details
        subscribers = subscription.get('Subscribers', [])
        subscriber_list = []
        for sub in subscribers:
            sub_type = sub.get('Type', 'UNKNOWN')
            sub_address = sub.get('Address', 'N/A')
            subscriber_list.append(f"{sub_type}: {sub_address}")

        subscription_data.append({
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
        })

    df_subscriptions = utils.prepare_dataframe_for_export(pd.DataFrame(subscription_data))

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

    utils.save_multiple_dataframes_to_excel(sheets, filename)

    # Log summary
    utils.log_export_summary(
        total_items=len(monitors) + len(subscriptions) + len(all_anomalies),
        item_type='Cost Anomaly Detection Items',
        filename=filename
    )

    utils.log_info(f"  Monitors: {len(monitors)}")
    utils.log_info(f"  Subscriptions: {len(subscriptions)}")
    utils.log_info(f"  Anomalies (90 days): {len(all_anomalies)}")

    if not df_high_impact.empty:
        utils.log_warning(f"  {len(df_high_impact)} high-impact anomaly/anomalies detected (>$100)")

    utils.log_success("Cost Anomaly Detection export completed successfully!")


def main():
    """Main execution function — 2-step state machine (confirm -> export) for global service."""
    try:
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

#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS EventBridge Export Tool
Date: NOV-09-2025

Description:
This script exports AWS EventBridge information into an Excel file with multiple
worksheets. The output includes event buses, rules, targets, and archive configurations.

Features:
- Event buses (custom and default) with policies
- Event rules with event patterns and schedules
- Rule targets with input transformations
- Event archives for replay capabilities
- Schema registries and schemas
"""

import sys
import datetime
import json
from pathlib import Path
from typing import List, Dict, Any

# Add path to import utils module
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()

    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))

    try:
        import utils
    except ImportError:
        print("ERROR: Could not import the utils module. Make sure utils.py in the StratusScan directory.")
        sys.exit(1)


def _scan_event_buses_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for EventBridge event buses."""
    buses_data = []
    if not utils.is_aws_region(region):
        return buses_data

    try:
        events_client = utils.get_boto3_client('events', region_name=region)
        paginator = events_client.get_paginator('list_event_buses')

        for page in paginator.paginate():
            for bus in page.get('EventBuses', []):
                buses_data.append({
                    'Region': region,
                    'Event Bus Name': bus.get('Name', 'N/A'),
                    'Event Bus ARN': bus.get('Arn', 'N/A'),
                    'Has Policy': 'Yes' if bus.get('Policy') else 'No'
                })
    except Exception as e:
        utils.log_error(f"Error scanning event buses in {region}", e)

    return buses_data


@utils.aws_error_handler("Collecting event buses", default_return=[])
def collect_event_buses(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect EventBridge event bus information from AWS regions."""
    print("\n=== COLLECTING EVENT BUSES ===")
    results = utils.scan_regions_concurrent(regions, _scan_event_buses_region)
    all_buses = [b for result in results for b in result]
    utils.log_success(f"Total event buses collected: {len(all_buses)}")
    return all_buses


def _scan_event_rules_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for EventBridge rules."""
    rules_data = []
    if not utils.is_aws_region(region):
        return rules_data

    try:
        events_client = utils.get_boto3_client('events', region_name=region)
        buses_response = events_client.list_event_buses()

        for bus in buses_response.get('EventBuses', []):
            bus_name = bus.get('Name', 'default')
            try:
                paginator = events_client.get_paginator('list_rules')
                for page in paginator.paginate(EventBusName=bus_name):
                    for rule in page.get('Rules', []):
                        event_pattern = rule.get('EventPattern', None)
                        schedule_expression = rule.get('ScheduleExpression', None)
                        rule_type = 'Event Pattern' if event_pattern else 'Schedule' if schedule_expression else 'Unknown'

                        rules_data.append({
                            'Region': region,
                            'Event Bus': bus_name,
                            'Rule Name': rule.get('Name', 'N/A'),
                            'State': rule.get('State', 'UNKNOWN'),
                            'Rule Type': rule_type,
                            'Schedule Expression': schedule_expression if schedule_expression else 'N/A',
                            'Has Event Pattern': 'Yes' if event_pattern else 'No',
                            'Description': rule.get('Description', 'N/A'),
                            'Managed By': rule.get('ManagedBy', 'Customer'),
                            'Role ARN': rule.get('RoleArn', 'N/A'),
                            'Rule ARN': rule.get('Arn', 'N/A')
                        })
            except Exception as e:
                utils.log_warning(f"Could not get rules for bus {bus_name}: {e}")
    except Exception as e:
        utils.log_error(f"Error scanning event rules in {region}", e)

    return rules_data


@utils.aws_error_handler("Collecting event rules", default_return=[])
def collect_event_rules(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect EventBridge rule information from AWS regions."""
    print("\n=== COLLECTING EVENT RULES ===")
    results = utils.scan_regions_concurrent(regions, _scan_event_rules_region)
    all_rules = [r for result in results for r in result]
    utils.log_success(f"Total event rules collected: {len(all_rules)}")
    return all_rules


def _scan_rule_targets_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for EventBridge rule targets."""
    targets_data = []
    if not utils.is_aws_region(region):
        return targets_data

    try:
        events_client = utils.get_boto3_client('events', region_name=region)
        buses_response = events_client.list_event_buses()

        for bus in buses_response.get('EventBuses', []):
            bus_name = bus.get('Name', 'default')
            try:
                rules_response = events_client.list_rules(EventBusName=bus_name)
                for rule in rules_response.get('Rules', []):
                    rule_name = rule.get('Name', '')
                    try:
                        targets_response = events_client.list_targets_by_rule(Rule=rule_name, EventBusName=bus_name)
                        for target in targets_response.get('Targets', []):
                            target_arn = target.get('Arn', 'N/A')

                            # Determine target type from ARN
                            target_type = 'Unknown'
                            if ':lambda:' in target_arn:
                                target_type = 'Lambda'
                            elif ':sqs:' in target_arn:
                                target_type = 'SQS'
                            elif ':sns:' in target_arn:
                                target_type = 'SNS'
                            elif ':kinesis:' in target_arn:
                                target_type = 'Kinesis'
                            elif ':states:' in target_arn:
                                target_type = 'Step Functions'
                            elif ':events:' in target_arn:
                                target_type = 'Event Bus'
                            elif ':logs:' in target_arn:
                                target_type = 'CloudWatch Logs'

                            retry_policy = target.get('RetryPolicy', {})
                            targets_data.append({
                                'Region': region,
                                'Event Bus': bus_name,
                                'Rule Name': rule_name,
                                'Target ID': target.get('Id', 'N/A'),
                                'Target Type': target_type,
                                'Target ARN': target_arn,
                                'Role ARN': target.get('RoleArn', 'N/A'),
                                'Has Input Transformer': 'Yes' if target.get('InputTransformer') else 'No',
                                'Has Dead Letter Queue': 'Yes' if target.get('DeadLetterConfig') else 'No',
                                'Max Retry Attempts': retry_policy.get('MaximumRetryAttempts', 'Default'),
                                'Max Event Age (seconds)': retry_policy.get('MaximumEventAgeInSeconds', 'Default')
                            })
                    except Exception as e:
                        utils.log_warning(f"Could not get targets for rule {rule_name}: {e}")
            except Exception as e:
                utils.log_warning(f"Could not process bus {bus_name}: {e}")
    except Exception as e:
        utils.log_error(f"Error scanning rule targets in {region}", e)

    return targets_data


@utils.aws_error_handler("Collecting rule targets", default_return=[])
def collect_rule_targets(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect EventBridge rule target information from AWS regions."""
    print("\n=== COLLECTING RULE TARGETS ===")
    results = utils.scan_regions_concurrent(regions, _scan_rule_targets_region)
    all_targets = [t for result in results for t in result]
    utils.log_success(f"Total rule targets collected: {len(all_targets)}")
    return all_targets


def export_eventbridge_data(account_id: str, account_name: str):
    """
    Export EventBridge information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect event buses
    buses = collect_event_buses(regions)
    if buses:
        data_frames['Event Buses'] = pd.DataFrame(buses)

    # STEP 2: Collect event rules
    rules = collect_event_rules(regions)
    if rules:
        data_frames['Event Rules'] = pd.DataFrame(rules)

    # STEP 3: Collect rule targets
    targets = collect_rule_targets(regions)
    if targets:
        data_frames['Rule Targets'] = pd.DataFrame(targets)

    # STEP 4: Create summary
    if buses or rules or targets:
        summary_data = []

        total_buses = len(buses)
        total_rules = len(rules)
        total_targets = len(targets)

        # Rules by state
        enabled_rules = sum(1 for r in rules if r['State'] == 'ENABLED')
        disabled_rules = sum(1 for r in rules if r['State'] == 'DISABLED')

        # Rules by type
        pattern_rules = sum(1 for r in rules if r['Rule Type'] == 'Event Pattern')
        schedule_rules = sum(1 for r in rules if r['Rule Type'] == 'Schedule')

        summary_data.append({'Metric': 'Total Event Buses', 'Value': total_buses})
        summary_data.append({'Metric': 'Total Event Rules', 'Value': total_rules})
        summary_data.append({'Metric': 'Enabled Rules', 'Value': enabled_rules})
        summary_data.append({'Metric': 'Disabled Rules', 'Value': disabled_rules})
        summary_data.append({'Metric': 'Event Pattern Rules', 'Value': pattern_rules})
        summary_data.append({'Metric': 'Schedule Rules', 'Value': schedule_rules})
        summary_data.append({'Metric': 'Total Rule Targets', 'Value': total_targets})

        data_frames['Summary'] = pd.DataFrame(summary_data)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No EventBridge data was collected. Nothing to export.")
        print("\nNo EventBridge resources found in the selected region(s).")
        return

    # STEP 5: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 6: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'eventbridge',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("EventBridge data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")

            # Summary of exported data
            for sheet_name, df in data_frames.items():
                utils.log_info(f"  - {sheet_name}: {len(df)} records")
                print(f"  - {sheet_name}: {len(df)} records")
        else:
            utils.log_error("Error creating Excel file. Please check the logs.")

    except Exception as e:
        utils.log_error("Error creating Excel file", e)


def main():
    # Initialize logging
    utils.setup_logging("eventbridge-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("eventbridge-export.py", "AWS EventBridge Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS EVENTBRIDGE EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            if not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
                print("Exiting script...")
                sys.exit(0)

        # Export EventBridge data
        export_eventbridge_data(account_id, account_name)

        print("\nEventBridge export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("eventbridge-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

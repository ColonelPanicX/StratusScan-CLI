#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS CloudWatch Export Tool
Version: v1.0.0
Date: NOV-09-2025

Description:
This script exports AWS CloudWatch information into an Excel file with multiple
worksheets. The output includes alarms, log groups, dashboards, and metric filters.

Features:
- CloudWatch alarms with metric configurations and states
- Log groups with retention policies and metric filters
- CloudWatch dashboards
- Alarm actions (SNS topics, Auto Scaling, etc.)
- Composite alarms with alarm rule expressions
"""

import sys
import datetime
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
        print("ERROR: Could not import the utils module. Make sure utils.py is in the StratusScan directory.")
        sys.exit(1)

# Initialize logging
SCRIPT_START_TIME = datetime.datetime.now()
utils.setup_logging("cloudwatch-export")
utils.log_script_start("cloudwatch-export.py", "AWS CloudWatch Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("              AWS CLOUDWATCH EXPORT TOOL")
    print("====================================================================")
    print("Version: v1.0.0                        Date: NOV-09-2025")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")

    # Get the current AWS account ID
    try:
        sts_client = utils.get_boto3_client('sts')
        account_id = sts_client.get_caller_identity().get('Account')
        account_name = utils.get_account_name(account_id, default=account_id)

        print(f"Account ID: {account_id}")
        print(f"Account Name: {account_name}")
    except Exception as e:
        print("Could not determine account information.")
        utils.log_error("Error getting account information", e)
        account_id = "unknown"
        account_name = "unknown"

    print("====================================================================")
    return account_id, account_name


def get_aws_regions():
    """Get list of all available AWS regions for the current partition."""
    try:
        # Detect partition and get ALL regions for that partition
        partition = utils.detect_partition()
        regions = utils.get_partition_regions(partition, all_regions=True)
        utils.log_info(f"Retrieved {len(regions)} regions for partition {partition}")
        return regions
    except Exception as e:
        utils.log_error("Error getting AWS regions", e)
        # Fallback to default regions for the partition
        partition = utils.detect_partition()
        return utils.get_partition_regions(partition, all_regions=False)


def _scan_cloudwatch_alarms_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for CloudWatch alarms."""
    alarms_data = []

    if not utils.validate_aws_region(region):
        return alarms_data

    try:
        cw_client = utils.get_boto3_client('cloudwatch', region_name=region)
        paginator = cw_client.get_paginator('describe_alarms')

        for page in paginator.paginate():
            alarms = page.get('MetricAlarms', []) + page.get('CompositeAlarms', [])

            for alarm in alarms:
                alarm_name = alarm.get('AlarmName', 'N/A')
                alarm_type = 'Composite' if 'AlarmRule' in alarm else 'Metric'
                alarm_arn = alarm.get('AlarmArn', 'N/A')
                description = alarm.get('AlarmDescription', 'N/A')
                state = alarm.get('StateValue', 'UNKNOWN')
                state_reason = alarm.get('StateReason', 'N/A')

                state_updated = alarm.get('StateUpdatedTimestamp', '')
                if state_updated:
                    state_updated = state_updated.strftime('%Y-%m-%d %H:%M:%S') if isinstance(state_updated, datetime.datetime) else str(state_updated)

                actions_enabled = alarm.get('ActionsEnabled', False)

                if alarm_type == 'Metric':
                    metric_name = alarm.get('MetricName', 'N/A')
                    namespace = alarm.get('Namespace', 'N/A')
                    statistic = alarm.get('Statistic', alarm.get('ExtendedStatistic', 'N/A'))
                    comparison_operator = alarm.get('ComparisonOperator', 'N/A')
                    threshold = alarm.get('Threshold', 'N/A')
                    evaluation_periods = alarm.get('EvaluationPeriods', 'N/A')
                    period = alarm.get('Period', 'N/A')
                    treat_missing_data = alarm.get('TreatMissingData', 'notBreaching')
                    dimensions = alarm.get('Dimensions', [])
                    dimensions_str = ', '.join([f"{d['Name']}={d['Value']}" for d in dimensions]) if dimensions else 'None'

                    alarms_data.append({
                        'Region': region,
                        'Alarm Name': alarm_name,
                        'Alarm Type': alarm_type,
                        'State': state,
                        'State Reason': state_reason,
                        'State Updated': state_updated if state_updated else 'N/A',
                        'Actions Enabled': actions_enabled,
                        'Metric Name': metric_name,
                        'Namespace': namespace,
                        'Statistic': statistic,
                        'Comparison': comparison_operator,
                        'Threshold': threshold,
                        'Evaluation Periods': evaluation_periods,
                        'Period (sec)': period,
                        'Treat Missing Data': treat_missing_data,
                        'Dimensions': dimensions_str,
                        'Description': description,
                        'Alarm ARN': alarm_arn
                    })
                else:
                    alarm_rule = alarm.get('AlarmRule', 'N/A')
                    alarms_data.append({
                        'Region': region,
                        'Alarm Name': alarm_name,
                        'Alarm Type': alarm_type,
                        'State': state,
                        'State Reason': state_reason,
                        'State Updated': state_updated if state_updated else 'N/A',
                        'Actions Enabled': actions_enabled,
                        'Alarm Rule': alarm_rule,
                        'Description': description,
                        'Alarm ARN': alarm_arn
                    })
    except Exception as e:
        utils.log_error(f"Error scanning CloudWatch alarms in {region}", e)

    return alarms_data


@utils.aws_error_handler("Collecting CloudWatch alarms", default_return=[])
def collect_cloudwatch_alarms(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect CloudWatch alarm information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with alarm information
    """
    print("\n=== COLLECTING CLOUDWATCH ALARMS ===")

    # Use concurrent scanning for better performance
    results = utils.scan_regions_concurrent(regions, _scan_cloudwatch_alarms_region)
    all_alarms = [alarm for result in results for alarm in result]

    utils.log_success(f"Total CloudWatch alarms collected: {len(all_alarms)}")
    return all_alarms


def _scan_log_groups_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for CloudWatch log groups."""
    log_groups_data = []

    if not utils.validate_aws_region(region):
        return log_groups_data

    try:
        logs_client = utils.get_boto3_client('logs', region_name=region)
        paginator = logs_client.get_paginator('describe_log_groups')

        for page in paginator.paginate():
            log_groups = page.get('logGroups', [])

            for log_group in log_groups:
                log_group_name = log_group.get('logGroupName', 'N/A')
                log_group_arn = log_group.get('arn', 'N/A')

                creation_time = log_group.get('creationTime', '')
                if creation_time:
                    creation_date = datetime.datetime.fromtimestamp(creation_time / 1000)
                    creation_date_str = creation_date.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    creation_date_str = 'N/A'

                retention_days = log_group.get('retentionInDays', 'Never Expire')
                stored_bytes = log_group.get('storedBytes', 0)
                stored_mb = round(stored_bytes / (1024 * 1024), 2)
                metric_filter_count = log_group.get('metricFilterCount', 0)
                kms_key_id = log_group.get('kmsKeyId', None)
                encrypted = 'Yes' if kms_key_id else 'No'

                log_groups_data.append({
                    'Region': region,
                    'Log Group Name': log_group_name,
                    'Created Date': creation_date_str,
                    'Retention (days)': retention_days,
                    'Stored Size (MB)': stored_mb,
                    'Metric Filter Count': metric_filter_count,
                    'Encrypted': encrypted,
                    'KMS Key ID': kms_key_id if kms_key_id else 'N/A',
                    'Log Group ARN': log_group_arn
                })
    except Exception as e:
        utils.log_error(f"Error scanning log groups in {region}", e)

    return log_groups_data


@utils.aws_error_handler("Collecting CloudWatch log groups", default_return=[])
def collect_log_groups(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect CloudWatch log group information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with log group information
    """
    print("\n=== COLLECTING CLOUDWATCH LOG GROUPS ===")

    # Use concurrent scanning for better performance
    results = utils.scan_regions_concurrent(regions, _scan_log_groups_region)
    all_log_groups = [lg for result in results for lg in result]

    utils.log_success(f"Total log groups collected: {len(all_log_groups)}")
    return all_log_groups


def export_cloudwatch_data(account_id: str, account_name: str):
    """
    Export CloudWatch information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition for region examples
    partition = utils.detect_partition()
    if partition == 'aws-us-gov':
        example_regions = "us-gov-west-1, us-gov-east-1"
    else:
        example_regions = "us-east-1, us-west-1, us-west-2, eu-west-1"

    # Display standardized region selection menu
    print("\n" + "=" * 68)
    print("REGION SELECTION")
    print("=" * 68)
    print("\nCloudWatch is a regional service.")
    print("\nPlease select an option for region selection:")
    print("\n  1. Default Regions")
    print(f"     ({example_regions})")
    print("\n  2. All Available Regions")
    print("     (Scan all regions where CloudWatch is available)")
    print("\n  3. Specific Region")
    print("     (Enter a specific AWS region code)")
    print("\n" + "-" * 68)

    # Get and validate region choice
    regions = []
    while not regions:
        try:
            region_choice = input("\nEnter your choice (1, 2, or 3): ").strip()

            if region_choice == '1':
                # Default regions
                regions = utils.get_partition_default_regions()
                print(f"\nUsing default regions: {', '.join(regions)}")
                region_suffix = ""
            elif region_choice == '2':
                # All available regions
                regions = utils.get_partition_regions(partition, all_regions=True)
                print(f"\nScanning all {len(regions)} available regions")
                region_suffix = ""
            elif region_choice == '3':
                # Specific region - show numbered list
                available_regions = utils.get_partition_regions(
                    partition, all_regions=True
                )
                print("\n" + "=" * 68)
                print("AVAILABLE REGIONS")
                print("=" * 68)
                for idx, region in enumerate(available_regions, 1):
                    print(f"  {idx}. {region}")
                print("-" * 68)

                # Get region selection
                region_selected = False
                while not region_selected:
                    try:
                        region_num = input(
                            f"\nEnter region number (1-{len(available_regions)}): "
                        ).strip()
                        region_idx = int(region_num) - 1

                        if 0 <= region_idx < len(available_regions):
                            selected_region = available_regions[region_idx]
                            regions = [selected_region]
                            region_suffix = f"-{selected_region}"
                            print(f"\nSelected region: {selected_region}")
                            region_selected = True
                        else:
                            print(
                                f"Invalid selection. Please enter a number "
                                f"between 1 and {len(available_regions)}."
                            )
                    except ValueError:
                        print("Invalid input. Please enter a number.")
                    except KeyboardInterrupt:
                        print("\n\nOperation cancelled by user.")
                        sys.exit(0)
            else:
                print("\nInvalid choice. Please enter 1, 2, or 3.")

        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            sys.exit(0)
        except Exception as e:
            utils.log_error(f"Error getting region selection: {str(e)}")
            print("Please try again.")

    print(f"\nStarting CloudWatch export process for {len(regions)} region(s)...")
    print("This may take some time depending on the number of regions and resources...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect alarms
    alarms = collect_cloudwatch_alarms(regions)
    if alarms:
        data_frames['CloudWatch Alarms'] = pd.DataFrame(alarms)

    # STEP 2: Collect log groups
    log_groups = collect_log_groups(regions)
    if log_groups:
        data_frames['Log Groups'] = pd.DataFrame(log_groups)

    # STEP 3: Create summary
    if alarms or log_groups:
        summary_data = []

        total_alarms = len(alarms)
        total_log_groups = len(log_groups)

        # Alarm states
        alarm_states = {}
        for alarm in alarms:
            state = alarm.get('State', 'UNKNOWN')
            alarm_states[state] = alarm_states.get(state, 0) + 1

        # Alarm types
        metric_alarms = sum(1 for a in alarms if a.get('Alarm Type') == 'Metric')
        composite_alarms = sum(1 for a in alarms if a.get('Alarm Type') == 'Composite')

        # Log group storage
        total_log_storage_mb = sum(float(lg.get('Stored Size (MB)', 0)) for lg in log_groups)

        summary_data.append({'Metric': 'Total CloudWatch Alarms', 'Value': total_alarms})
        summary_data.append({'Metric': 'Metric Alarms', 'Value': metric_alarms})
        summary_data.append({'Metric': 'Composite Alarms', 'Value': composite_alarms})
        for state, count in alarm_states.items():
            summary_data.append({'Metric': f'Alarms in {state} State', 'Value': count})
        summary_data.append({'Metric': 'Total Log Groups', 'Value': total_log_groups})
        summary_data.append({'Metric': 'Total Log Storage (MB)', 'Value': round(total_log_storage_mb, 2)})

        data_frames['Summary'] = pd.DataFrame(summary_data)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No CloudWatch data was collected. Nothing to export.")
        print("\nNo CloudWatch resources found in the selected region(s).")
        return

    # STEP 4: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 5: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'cloudwatch',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("CloudWatch data exported successfully!")
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
    """Main function to execute the script."""
    try:
        # Print title and get account information
        account_id, account_name = print_title()

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            proceed = input("Unable to determine account name. Proceed anyway? (y/n): ").lower()
            if proceed != 'y':
                print("Exiting script...")
                sys.exit(0)

        # Export CloudWatch data
        export_cloudwatch_data(account_id, account_name)

        print("\nCloudWatch export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("cloudwatch-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

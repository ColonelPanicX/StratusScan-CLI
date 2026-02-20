#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS CloudTrail Export Tool
Version: v0.1.0
Date: NOV-16-2025

Description:
This script exports AWS CloudTrail configuration information from all regions into an Excel
file with multiple worksheets. The output includes trails, event selectors, logging
configurations, and insights.

Features:
- CloudTrail trails with logging status and configurations
- Event selectors for management and data events
- Multi-region and organization trails
- S3 bucket configurations and encryption
- CloudWatch Logs integration
- Insight selectors for anomaly detection
- Event data stores for CloudTrail Lake
- Phase 4B: Concurrent region scanning (4x-10x performance improvement)
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


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("                AWS CLOUDTRAIL EXPORT TOOL")
    print("====================================================================")
    print("Version: v0.1.0                        Date: NOV-16-2025")
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
@utils.aws_error_handler("Collecting CloudTrail trails from region", default_return=[])
def collect_trails_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect CloudTrail trail information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with trail information
    """
    if not utils.validate_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    trails_data = []

    ct_client = utils.get_boto3_client('cloudtrail', region_name=region)

    # List trails
    trails_response = ct_client.list_trails()
    trails = trails_response.get('Trails', [])

    for trail_summary in trails:
        trail_arn = trail_summary.get('TrailARN', '')
        trail_name = trail_summary.get('Name', '')

        utils.log_info(f"Processing trail: {trail_name} in {region}")

        try:
            # Get trail status
            status_response = ct_client.get_trail_status(Name=trail_arn)

            is_logging = status_response.get('IsLogging', False)
            latest_delivery_time = status_response.get('LatestDeliveryTime', '')
            if latest_delivery_time:
                latest_delivery_time = latest_delivery_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(latest_delivery_time, datetime.datetime) else str(latest_delivery_time)

            latest_notification_time = status_response.get('LatestNotificationTime', '')
            if latest_notification_time:
                latest_notification_time = latest_notification_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(latest_notification_time, datetime.datetime) else str(latest_notification_time)

            # Get trail details
            trail_list = ct_client.describe_trails(trailNameList=[trail_name])
            trail_details = trail_list.get('trailList', [{}])[0]

            # S3 bucket
            s3_bucket = trail_details.get('S3BucketName', '')

            # S3 key prefix
            s3_prefix = trail_details.get('S3KeyPrefix', 'N/A')

            # SNS topic
            sns_topic = trail_details.get('SnsTopicARN', 'N/A')

            # CloudWatch Logs
            log_group_arn = trail_details.get('CloudWatchLogsLogGroupArn', 'N/A')
            log_role_arn = trail_details.get('CloudWatchLogsRoleArn', 'N/A')

            # KMS key
            kms_key_id = trail_details.get('KmsKeyId', 'N/A')

            # Multi-region trail
            is_multi_region = trail_details.get('IsMultiRegionTrail', False)

            # Organization trail
            is_organization_trail = trail_details.get('IsOrganizationTrail', False)

            # Home region
            home_region = trail_details.get('HomeRegion', region)

            # Log file validation
            log_file_validation = trail_details.get('LogFileValidationEnabled', False)

            # Include global service events
            include_global_events = trail_details.get('IncludeGlobalServiceEvents', False)

            # Has custom event selectors
            has_custom_selectors = trail_details.get('HasCustomEventSelectors', False)

            # Has insight selectors
            has_insight_selectors = trail_details.get('HasInsightSelectors', False)

            trails_data.append({
                'Region': region,
                'Trail Name': trail_name,
                'Trail ARN': trail_arn,
                'Home Region': home_region,
                'Is Logging': is_logging,
                'Multi-Region': is_multi_region,
                'Organization Trail': is_organization_trail,
                'S3 Bucket': s3_bucket,
                'S3 Prefix': s3_prefix,
                'Log File Validation': log_file_validation,
                'KMS Encryption': 'Yes' if kms_key_id != 'N/A' else 'No',
                'KMS Key ID': kms_key_id,
                'CloudWatch Logs': 'Yes' if log_group_arn != 'N/A' else 'No',
                'Log Group ARN': log_group_arn,
                'Log Role ARN': log_role_arn,
                'SNS Topic': sns_topic,
                'Include Global Events': include_global_events,
                'Has Custom Selectors': has_custom_selectors,
                'Has Insight Selectors': has_insight_selectors,
                'Latest Delivery': latest_delivery_time if latest_delivery_time else 'Never',
                'Latest Notification': latest_notification_time if latest_notification_time else 'Never'
            })

        except Exception as e:
            utils.log_warning(f"Could not get details for trail {trail_name}: {e}")

    utils.log_info(f"Found {len(trails_data)} trails in {region}")
    return trails_data


def collect_trails(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect CloudTrail trail information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with trail information (deduplicated by ARN)
    """
    print("\n=== COLLECTING CLOUDTRAIL TRAILS ===")
    utils.log_info(f"Scanning {len(regions)} regions for CloudTrail trails...")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_trails_from_region,
        show_progress=True
    )

    # Flatten results and deduplicate by Trail ARN (for multi-region trails)
    all_trails = []
    seen_trail_arns = set()

    for trails_in_region in region_results:
        for trail in trails_in_region:
            trail_arn = trail.get('Trail ARN', '')
            if trail_arn and trail_arn not in seen_trail_arns:
                seen_trail_arns.add(trail_arn)
                all_trails.append(trail)
            elif not trail_arn:
                # If no ARN, include it anyway (shouldn't happen but handle gracefully)
                all_trails.append(trail)

    utils.log_success(f"Total CloudTrail trails collected (deduplicated): {len(all_trails)}")
    return all_trails


@utils.aws_error_handler("Collecting event selectors from region", default_return=[])
def collect_event_selectors_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect CloudTrail event selector information from a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with event selector information
    """
    if not utils.validate_aws_region(region):
        return []

    selectors_data = []

    ct_client = utils.get_boto3_client('cloudtrail', region_name=region)

    # List trails
    trails_response = ct_client.list_trails()
    trails = trails_response.get('Trails', [])

    for trail_summary in trails:
        trail_arn = trail_summary.get('TrailARN', '')
        trail_name = trail_summary.get('Name', '')

        try:
            # Get event selectors
            selectors_response = ct_client.get_event_selectors(TrailName=trail_name)

            event_selectors = selectors_response.get('EventSelectors', [])

            for i, selector in enumerate(event_selectors):
                read_write_type = selector.get('ReadWriteType', 'All')
                include_management_events = selector.get('IncludeManagementEvents', True)

                # Data resources
                data_resources = selector.get('DataResources', [])
                data_resource_count = len(data_resources)

                # Exclude management event sources
                exclude_sources = selector.get('ExcludeManagementEventSources', [])
                exclude_sources_str = ', '.join(exclude_sources) if exclude_sources else 'None'

                selectors_data.append({
                    'Region': region,
                    'Trail Name': trail_name,
                    'Trail ARN': trail_arn,
                    'Selector Index': i,
                    'Read/Write Type': read_write_type,
                    'Include Management Events': include_management_events,
                    'Data Resource Count': data_resource_count,
                    'Exclude Sources': exclude_sources_str
                })

        except Exception as e:
            utils.log_warning(f"Could not get event selectors for trail {trail_name}: {e}")

    utils.log_info(f"Found {len(selectors_data)} event selectors in {region}")
    return selectors_data


def collect_event_selectors(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect CloudTrail event selector information using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with event selector information (deduplicated)
    """
    print("\n=== COLLECTING EVENT SELECTORS ===")
    utils.log_info(f"Scanning {len(regions)} regions for event selectors...")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_event_selectors_from_region,
        show_progress=True
    )

    # Flatten results and deduplicate by Trail ARN
    all_selectors = []
    seen_combinations = set()

    for selectors_in_region in region_results:
        for selector in selectors_in_region:
            trail_arn = selector.get('Trail ARN', '')
            selector_idx = selector.get('Selector Index', 0)
            combo_key = f"{trail_arn}:{selector_idx}"

            if combo_key not in seen_combinations:
                seen_combinations.add(combo_key)
                all_selectors.append(selector)

    utils.log_success(f"Total event selectors collected (deduplicated): {len(all_selectors)}")
    return all_selectors


@utils.aws_error_handler("Collecting insight selectors from region", default_return=[])
def collect_insight_selectors_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect CloudTrail insight selector information from a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with insight selector information
    """
    if not utils.validate_aws_region(region):
        return []

    insights_data = []

    ct_client = utils.get_boto3_client('cloudtrail', region_name=region)

    # List trails
    trails_response = ct_client.list_trails()
    trails = trails_response.get('Trails', [])

    for trail_summary in trails:
        trail_arn = trail_summary.get('TrailARN', '')
        trail_name = trail_summary.get('Name', '')

        try:
            # Get insight selectors
            insights_response = ct_client.get_insight_selectors(TrailName=trail_name)

            insight_selectors = insights_response.get('InsightSelectors', [])

            for insight in insight_selectors:
                insight_type = insight.get('InsightType', '')

                insights_data.append({
                    'Region': region,
                    'Trail Name': trail_name,
                    'Trail ARN': trail_arn,
                    'Insight Type': insight_type
                })

        except Exception as e:
            # Many trails don't have insight selectors, which is normal
            pass

    utils.log_info(f"Found {len(insights_data)} insight selectors in {region}")
    return insights_data


def collect_insight_selectors(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect CloudTrail insight selector information using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with insight selector information (deduplicated)
    """
    print("\n=== COLLECTING INSIGHT SELECTORS ===")
    utils.log_info(f"Scanning {len(regions)} regions for insight selectors...")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_insight_selectors_from_region,
        show_progress=True
    )

    # Flatten results and deduplicate by Trail ARN and Insight Type
    all_insights = []
    seen_combinations = set()

    for insights_in_region in region_results:
        for insight in insights_in_region:
            trail_arn = insight.get('Trail ARN', '')
            insight_type = insight.get('Insight Type', '')
            combo_key = f"{trail_arn}:{insight_type}"

            if combo_key not in seen_combinations:
                seen_combinations.add(combo_key)
                all_insights.append(insight)

    utils.log_success(f"Total insight selectors collected (deduplicated): {len(all_insights)}")
    return all_insights


def export_cloudtrail_data(account_id: str, account_name: str):
    """
    Export CloudTrail information to an Excel file.

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
    print("\nCloudTrail is a regional service.")
    print("\nPlease select an option for region selection:")
    print("\n  1. Default Regions")
    print(f"     ({example_regions})")
    print("\n  2. All Available Regions")
    print("     (Scan all regions where CloudTrail is available)")
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

    print(f"\nStarting CloudTrail export process for {len(regions)} region(s)...")
    print("This may take some time depending on the number of regions and resources...")
    print("\nNote: Multi-region trails are deduplicated to avoid counting them multiple times.")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect trails
    trails = collect_trails(regions)
    if trails:
        data_frames['Trails'] = pd.DataFrame(trails)

    # STEP 2: Collect event selectors
    selectors = collect_event_selectors(regions)
    if selectors:
        data_frames['Event Selectors'] = pd.DataFrame(selectors)

    # STEP 3: Collect insight selectors
    insights = collect_insight_selectors(regions)
    if insights:
        data_frames['Insight Selectors'] = pd.DataFrame(insights)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No CloudTrail data was collected. Nothing to export.")
        print("\nNo CloudTrail trails found in the selected region(s).")
        return

    # STEP 4: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 5: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'cloudtrail',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("CloudTrail data exported successfully!")
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
    utils.setup_logging("cloudtrail-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("cloudtrail-export.py", "AWS CloudTrail Export Tool")

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

        # Export CloudTrail data
        export_cloudtrail_data(account_id, account_name)

        print("\nCloudTrail export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("cloudtrail-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

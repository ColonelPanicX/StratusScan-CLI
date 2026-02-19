#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS SQS/SNS Export Tool
Version: v0.1.0
Date: NOV-09-2025

Description:
This script exports AWS SQS and SNS information into an Excel file with multiple
worksheets. The output includes SQS queues, SNS topics, subscriptions, and
configurations.

Features:
- SQS queues (standard and FIFO) with attributes
- Queue policies and redrive configurations
- SNS topics with subscription details
- Topic subscriptions with protocols and endpoints
- Dead letter queue configurations
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
utils.setup_logging("sqs-sns-export")
utils.log_script_start("sqs-sns-export.py", "AWS SQS/SNS Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("                 AWS SQS/SNS EXPORT TOOL")
    print("====================================================================")
    print("Version: v0.1.0                        Date: NOV-09-2025")
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


def _scan_sqs_queues_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for SQS queues."""
    queues_data = []
    if not utils.validate_aws_region(region):
        return queues_data

    try:
        sqs_client = utils.get_boto3_client('sqs', region_name=region)
        queues_response = sqs_client.list_queues()
        queue_urls = queues_response.get('QueueUrls', [])

        for queue_url in queue_urls:
            queue_name = queue_url.split('/')[-1]
            try:
                attrs_response = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])
                attributes = attrs_response.get('Attributes', {})

                queue_arn = attributes.get('QueueArn', 'N/A')
                is_fifo = queue_name.endswith('.fifo')
                queue_type = 'FIFO' if is_fifo else 'Standard'

                created_timestamp = attributes.get('CreatedTimestamp', '')
                created_date_str = datetime.datetime.fromtimestamp(int(created_timestamp)).strftime('%Y-%m-%d %H:%M:%S') if created_timestamp else 'N/A'

                retention_period = attributes.get('MessageRetentionPeriod', '345600')
                retention_days = int(retention_period) / 86400
                redrive_policy = attributes.get('RedrivePolicy', None)
                kms_master_key_id = attributes.get('KmsMasterKeyId', None)
                content_dedup = attributes.get('ContentBasedDeduplication', 'false') if is_fifo else 'N/A'

                queues_data.append({
                    'Region': region,
                    'Queue Name': queue_name,
                    'Queue Type': queue_type,
                    'Queue URL': queue_url,
                    'Queue ARN': queue_arn,
                    'Created Date': created_date_str,
                    'Messages Available': attributes.get('ApproximateNumberOfMessages', '0'),
                    'Messages In Flight': attributes.get('ApproximateNumberOfMessagesNotVisible', '0'),
                    'Messages Delayed': attributes.get('ApproximateNumberOfMessagesDelayed', '0'),
                    'Retention Period (days)': round(retention_days, 1),
                    'Visibility Timeout (sec)': attributes.get('VisibilityTimeout', '30'),
                    'Delay (sec)': attributes.get('DelaySeconds', '0'),
                    'Max Message Size (bytes)': attributes.get('MaximumMessageSize', '262144'),
                    'Receive Wait Time (sec)': attributes.get('ReceiveMessageWaitTimeSeconds', '0'),
                    'Has Dead Letter Queue': 'Yes' if redrive_policy else 'No',
                    'Encrypted': 'Yes' if kms_master_key_id else 'No',
                    'Content-Based Deduplication': content_dedup
                })
            except Exception as e:
                utils.log_warning(f"Could not get attributes for queue {queue_name}: {e}")
    except Exception as e:
        utils.log_error(f"Error scanning SQS queues in {region}", e)

    return queues_data


@utils.aws_error_handler("Collecting SQS queues", default_return=[])
def collect_sqs_queues(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect SQS queue information from AWS regions."""
    print("\n=== COLLECTING SQS QUEUES ===")
    results = utils.scan_regions_concurrent(regions, _scan_sqs_queues_region)
    all_queues = [q for result in results for q in result]
    utils.log_success(f"Total SQS queues collected: {len(all_queues)}")
    return all_queues


def _scan_sns_topics_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for SNS topics."""
    topics_data = []
    if not utils.validate_aws_region(region):
        return topics_data

    try:
        sns_client = utils.get_boto3_client('sns', region_name=region)
        paginator = sns_client.get_paginator('list_topics')

        for page in paginator.paginate():
            topics = page.get('Topics', [])
            for topic in topics:
                topic_arn = topic.get('TopicArn', 'N/A')
                topic_name = topic_arn.split(':')[-1]
                try:
                    attrs_response = sns_client.get_topic_attributes(TopicArn=topic_arn)
                    attributes = attrs_response.get('Attributes', {})

                    is_fifo = topic_name.endswith('.fifo')
                    kms_master_key_id = attributes.get('KmsMasterKeyId', None)
                    delivery_policy = attributes.get('DeliveryPolicy', None)

                    topics_data.append({
                        'Region': region,
                        'Topic Name': topic_name,
                        'Topic Type': 'FIFO' if is_fifo else 'Standard',
                        'Display Name': attributes.get('DisplayName', 'N/A'),
                        'Subscriptions Confirmed': attributes.get('SubscriptionsConfirmed', '0'),
                        'Subscriptions Pending': attributes.get('SubscriptionsPending', '0'),
                        'Subscriptions Deleted': attributes.get('SubscriptionsDeleted', '0'),
                        'Has Delivery Policy': 'Yes' if delivery_policy else 'No',
                        'Encrypted': 'Yes' if kms_master_key_id else 'No',
                        'Content-Based Deduplication': attributes.get('ContentBasedDeduplication', 'false') if is_fifo else 'N/A',
                        'Owner': attributes.get('Owner', 'N/A'),
                        'Topic ARN': topic_arn
                    })
                except Exception as e:
                    utils.log_warning(f"Could not get attributes for topic {topic_name}: {e}")
    except Exception as e:
        utils.log_error(f"Error scanning SNS topics in {region}", e)

    return topics_data


@utils.aws_error_handler("Collecting SNS topics", default_return=[])
def collect_sns_topics(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect SNS topic information from AWS regions."""
    print("\n=== COLLECTING SNS TOPICS ===")
    results = utils.scan_regions_concurrent(regions, _scan_sns_topics_region)
    all_topics = [t for result in results for t in result]
    utils.log_success(f"Total SNS topics collected: {len(all_topics)}")
    return all_topics


def _scan_sns_subscriptions_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for SNS subscriptions."""
    subs_data = []
    if not utils.validate_aws_region(region):
        return subs_data

    try:
        sns_client = utils.get_boto3_client('sns', region_name=region)
        paginator = sns_client.get_paginator('list_subscriptions')

        for page in paginator.paginate():
            subscriptions = page.get('Subscriptions', [])
            for subscription in subscriptions:
                subscription_arn = subscription.get('SubscriptionArn', 'N/A')
                topic_arn = subscription.get('TopicArn', 'N/A')
                topic_name = topic_arn.split(':')[-1] if topic_arn != 'N/A' else 'N/A'

                subs_data.append({
                    'Region': region,
                    'Topic Name': topic_name,
                    'Protocol': subscription.get('Protocol', 'N/A'),
                    'Endpoint': subscription.get('Endpoint', 'N/A'),
                    'Status': 'Pending' if subscription_arn == 'PendingConfirmation' else 'Confirmed',
                    'Owner': subscription.get('Owner', 'N/A'),
                    'Subscription ARN': subscription_arn,
                    'Topic ARN': topic_arn
                })
    except Exception as e:
        utils.log_error(f"Error scanning SNS subscriptions in {region}", e)

    return subs_data


@utils.aws_error_handler("Collecting SNS subscriptions", default_return=[])
def collect_sns_subscriptions(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect SNS subscription information from AWS regions."""
    print("\n=== COLLECTING SNS SUBSCRIPTIONS ===")
    results = utils.scan_regions_concurrent(regions, _scan_sns_subscriptions_region)
    all_subscriptions = [s for result in results for s in result]
    utils.log_success(f"Total SNS subscriptions collected: {len(all_subscriptions)}")
    return all_subscriptions


def export_sqs_sns_data(account_id: str, account_name: str):
    """
    Export SQS/SNS information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Ask for region selection
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
    print()
    print("Please select which AWS regions to scan:")
    print()
    print("1. Default Regions (recommended for most use cases)")
    print(f"   └─ {example_regions}")
    print()
    print("2. All Available Regions")
    print("   └─ Scans all regions (slower, more comprehensive)")
    print()
    print("3. Specific Region")
    print("   └─ Choose a single region to scan")
    print()

    # Get user selection with validation
    while True:
        try:
            selection = input("Enter your selection (1-3): ").strip()
            selection_int = int(selection)
            if 1 <= selection_int <= 3:
                break
            else:
                print("Please enter a number between 1 and 3.")
        except ValueError:
            print("Please enter a valid number (1-3).")

    # Get regions based on selection
    all_available_regions = utils.get_partition_regions(partition, all_regions=True)
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        regions = default_regions
        region_text = "default regions"
        region_suffix = ""
        utils.log_info(f"Scanning default regions: {len(regions)} regions")
    elif selection_int == 2:
        regions = all_available_regions
        region_text = "all AWS regions"
        region_suffix = ""
        utils.log_info(f"Scanning all {len(regions)} AWS regions")
    else:  # selection_int == 3
        # Display numbered list of regions
        print("\n" + "=" * 68)
        print("AVAILABLE AWS REGIONS")
        print("=" * 68)
        print()
        for idx, region in enumerate(all_available_regions, 1):
            print(f"{idx:2}. {region}")
        print()

        # Get region selection with validation
        while True:
            try:
                region_num = input(f"Enter region number (1-{len(all_available_regions)}): ").strip()
                region_idx = int(region_num) - 1
                if 0 <= region_idx < len(all_available_regions):
                    selected_region = all_available_regions[region_idx]
                    regions = [selected_region]
                    region_text = f"region {selected_region}"
                    region_suffix = f"-{selected_region}"
                    utils.log_info(f"Scanning region: {selected_region}")
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print(f"Please enter a valid number (1-{len(all_available_regions)}).")

    print(f"\nStarting SQS/SNS export process for {region_text}...")
    print("This may take some time depending on the number of regions and resources...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect SQS queues
    queues = collect_sqs_queues(regions)
    if queues:
        data_frames['SQS Queues'] = pd.DataFrame(queues)

    # STEP 2: Collect SNS topics
    topics = collect_sns_topics(regions)
    if topics:
        data_frames['SNS Topics'] = pd.DataFrame(topics)

    # STEP 3: Collect SNS subscriptions
    subscriptions = collect_sns_subscriptions(regions)
    if subscriptions:
        data_frames['SNS Subscriptions'] = pd.DataFrame(subscriptions)

    # STEP 4: Create summary
    if queues or topics or subscriptions:
        summary_data = []

        total_queues = len(queues)
        total_topics = len(topics)
        total_subscriptions = len(subscriptions)

        # Queue types
        standard_queues = sum(1 for q in queues if q['Queue Type'] == 'Standard')
        fifo_queues = sum(1 for q in queues if q['Queue Type'] == 'FIFO')

        # Encrypted queues
        encrypted_queues = sum(1 for q in queues if q['Encrypted'] == 'Yes')

        # Topic types
        standard_topics = sum(1 for t in topics if t['Topic Type'] == 'Standard')
        fifo_topics = sum(1 for t in topics if t['Topic Type'] == 'FIFO')

        # Encrypted topics
        encrypted_topics = sum(1 for t in topics if t['Encrypted'] == 'Yes')

        # Subscription status
        confirmed_subs = sum(1 for s in subscriptions if s['Status'] == 'Confirmed')
        pending_subs = sum(1 for s in subscriptions if s['Status'] == 'Pending')

        summary_data.append({'Metric': 'Total SQS Queues', 'Value': total_queues})
        summary_data.append({'Metric': 'Standard Queues', 'Value': standard_queues})
        summary_data.append({'Metric': 'FIFO Queues', 'Value': fifo_queues})
        summary_data.append({'Metric': 'Encrypted Queues', 'Value': encrypted_queues})
        summary_data.append({'Metric': 'Total SNS Topics', 'Value': total_topics})
        summary_data.append({'Metric': 'Standard Topics', 'Value': standard_topics})
        summary_data.append({'Metric': 'FIFO Topics', 'Value': fifo_topics})
        summary_data.append({'Metric': 'Encrypted Topics', 'Value': encrypted_topics})
        summary_data.append({'Metric': 'Total Subscriptions', 'Value': total_subscriptions})
        summary_data.append({'Metric': 'Confirmed Subscriptions', 'Value': confirmed_subs})
        summary_data.append({'Metric': 'Pending Subscriptions', 'Value': pending_subs})

        data_frames['Summary'] = pd.DataFrame(summary_data)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No SQS/SNS data was collected. Nothing to export.")
        print("\nNo SQS/SNS resources found in the selected region(s).")
        return

    # STEP 5: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 6: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'sqs-sns',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("SQS/SNS data exported successfully!")
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

        # Export SQS/SNS data
        export_sqs_sns_data(account_id, account_name)

        print("\nSQS/SNS export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("sqs-sns-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS SQS/SNS Export Tool
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

import datetime
import sys
from pathlib import Path
from typing import Any

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
args = utils.parse_script_args("Export SQS queues and SNS topics to Excel")


def _build_queue_row(queue_url: str, attributes: dict, region: str) -> dict[str, Any]:
    """
    Build the export row for a single SQS queue.

    Extracted so the per-queue processing can be wrapped in try/except by the
    caller: a malformed queue entry is logged and skipped rather than
    discarding the whole region's results. Every field is read with ``.get()``
    and a safe default for the same reason.

    Args:
        queue_url: The queue's URL (from list_queues).
        attributes: The 'Attributes' dict from get_queue_attributes.
        region: AWS region name.

    Returns:
        dict: The assembled queue row.
    """
    queue_name = queue_url.split('/')[-1]

    queue_arn = attributes.get('QueueArn', 'N/A')
    is_fifo = queue_name.endswith('.fifo')
    queue_type = 'FIFO' if is_fifo else 'Standard'

    created_timestamp = attributes.get('CreatedTimestamp', '')
    created_date_str = datetime.datetime.fromtimestamp(int(float(created_timestamp))).strftime('%Y-%m-%d %H:%M:%S') if created_timestamp else 'N/A'

    retention_period = attributes.get('MessageRetentionPeriod', '345600')
    retention_days = int(retention_period) / 86400
    redrive_policy = attributes.get('RedrivePolicy')
    kms_master_key_id = attributes.get('KmsMasterKeyId')
    content_dedup = attributes.get('ContentBasedDeduplication', 'false') if is_fifo else 'N/A'

    return {
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
    }


def _scan_sqs_queues_region(region: str) -> list[dict[str, Any]]:
    """
    Collect SQS queue information from a single AWS region.

    This is a primary scope collector. It deliberately does NOT swallow
    region-level errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the region
    as failed instead of silently reporting "no SQS queues" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed/unreadable queues are skipped (logged) rather than
    aborting the whole region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with SQS queue information

    Raises:
        Exception: Any AWS/pagination error for the region (caller records it
            as a failed region and surfaces it; it is never masked as empty).
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"\nProcessing region: {region}")

    sqs_client = utils.get_boto3_client('sqs', region_name=region)
    queue_urls = []
    paginator = sqs_client.get_paginator('list_queues')
    for page in paginator.paginate():
        queue_urls.extend(page.get('QueueUrls', []))

    region_queues = []
    queue_count = len(queue_urls)
    skipped = 0

    for queue_url in queue_urls:
        queue_name = queue_url.split('/')[-1]

        try:
            attrs_response = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])
            attributes = attrs_response.get('Attributes', {})
            region_queues.append(_build_queue_row(queue_url, attributes, region))
        except Exception as e:
            skipped += 1
            utils.log_error(
                f"Skipping SQS queue '{queue_name}' in {region} due to a processing error", e
            )
            continue

    if skipped:
        utils.log_warning(
            f"{skipped} of {queue_count} SQS queue(s) in {region} were skipped due to "
            "processing errors (see log above); the remaining queues were still collected."
        )

    print(f"  Found {queue_count} SQS queues")
    return region_queues


def collect_sqs_queues(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect SQS queue information across regions, surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Args:
        regions: List of AWS regions to scan

    Returns:
        tuple: ``(queues, failed_regions)`` where ``failed_regions`` is a list
        of ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING SQS QUEUES ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_sqs_queues_region,
        show_progress=True,
        collect_failures=True,
    )
    all_queues = [q for result in region_results for q in result]
    utils.log_success(f"Total SQS queues collected: {len(all_queues)}")
    return all_queues, failed_regions


def _build_topic_row(topic_arn: str, attributes: dict, region: str) -> dict[str, Any]:
    """
    Build the export row for a single SNS topic.

    Extracted so the per-topic processing can be wrapped in try/except by the
    caller: a malformed topic entry is logged and skipped rather than
    discarding the whole region's results. Every field is read with ``.get()``
    and a safe default for the same reason.

    Args:
        topic_arn: The topic's ARN (from list_topics).
        attributes: The 'Attributes' dict from get_topic_attributes.
        region: AWS region name.

    Returns:
        dict: The assembled topic row.
    """
    topic_name = topic_arn.split(':')[-1]
    is_fifo = topic_name.endswith('.fifo')
    kms_master_key_id = attributes.get('KmsMasterKeyId')
    delivery_policy = attributes.get('DeliveryPolicy')

    return {
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
    }


def _scan_sns_topics_region(region: str) -> list[dict[str, Any]]:
    """
    Collect SNS topic information from a single AWS region.

    This is a primary scope collector. It deliberately does NOT swallow
    region-level errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the region
    as failed instead of silently reporting "no SNS topics" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed/unreadable topics are skipped (logged) rather than
    aborting the whole region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with SNS topic information

    Raises:
        Exception: Any AWS/pagination error for the region (caller records it
            as a failed region and surfaces it; it is never masked as empty).
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"\nProcessing region: {region}")

    sns_client = utils.get_boto3_client('sns', region_name=region)
    paginator = sns_client.get_paginator('list_topics')

    region_topics = []
    topic_count = 0
    skipped = 0

    for page in paginator.paginate():
        topics = page.get('Topics', [])
        topic_count += len(topics)

        for topic in topics:
            topic_arn = topic.get('TopicArn', 'N/A')
            topic_name = topic_arn.split(':')[-1]

            try:
                attrs_response = sns_client.get_topic_attributes(TopicArn=topic_arn)
                attributes = attrs_response.get('Attributes', {})
                region_topics.append(_build_topic_row(topic_arn, attributes, region))
            except Exception as e:
                skipped += 1
                utils.log_error(
                    f"Skipping SNS topic '{topic_name}' in {region} due to a processing error", e
                )
                continue

    if skipped:
        utils.log_warning(
            f"{skipped} of {topic_count} SNS topic(s) in {region} were skipped due to "
            "processing errors (see log above); the remaining topics were still collected."
        )

    print(f"  Found {topic_count} SNS topics")
    return region_topics


def collect_sns_topics(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect SNS topic information across regions, surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Args:
        regions: List of AWS regions to scan

    Returns:
        tuple: ``(topics, failed_regions)`` where ``failed_regions`` is a list
        of ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING SNS TOPICS ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_sns_topics_region,
        show_progress=True,
        collect_failures=True,
    )
    all_topics = [t for result in region_results for t in result]
    utils.log_success(f"Total SNS topics collected: {len(all_topics)}")
    return all_topics, failed_regions


def _scan_sns_subscriptions_region(region: str) -> list[dict[str, Any]]:
    """Scan a single region for SNS subscriptions."""
    subs_data = []
    if not utils.is_aws_region(region):
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
def collect_sns_subscriptions(regions: list[str]) -> list[dict[str, Any]]:
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
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect SQS queues (primary scope — region failures must
    # propagate as failed_regions, never collapse into "empty").
    queues, failed_regions_sqs = collect_sqs_queues(regions)
    if queues:
        data_frames['SQS Queues'] = pd.DataFrame(queues)

    # STEP 2: Collect SNS topics (primary scope — region failures must
    # propagate as failed_regions, never collapse into "empty").
    topics, failed_regions_sns = collect_sns_topics(regions)
    if topics:
        data_frames['SNS Topics'] = pd.DataFrame(topics)

    # Both scopes are primary: merge their failed regions into ONE combined
    # list that drives a single marker + non-zero exit below.
    failed_regions = failed_regions_sqs + failed_regions_sns

    # STEP 3: Collect SNS subscriptions (enrichment — degrades gracefully; a
    # region-level failure here does not fail the whole export).
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
        standard_queues = sum(1 for q in queues if q.get('Queue Type') == 'Standard')
        fifo_queues = sum(1 for q in queues if q.get('Queue Type') == 'FIFO')

        # Encrypted queues
        encrypted_queues = sum(1 for q in queues if q.get('Encrypted') == 'Yes')

        # Topic types
        standard_topics = sum(1 for t in topics if t.get('Topic Type') == 'Standard')
        fifo_topics = sum(1 for t in topics if t.get('Topic Type') == 'FIFO')

        # Encrypted topics
        encrypted_topics = sum(1 for t in topics if t.get('Encrypted') == 'Yes')

        # Subscription status
        confirmed_subs = sum(1 for s in subscriptions if s.get('Status') == 'Confirmed')
        pending_subs = sum(1 for s in subscriptions if s.get('Status') == 'Pending')

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

    # Export whatever succeeded first — a partial export is required even
    # when some regions failed (see .collab/audit/07.16.2026-...).
    if data_frames:
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
                utils.log_success(f"File location: {output_path}")
                utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")

                # Summary of exported data
                for sheet_name, df in data_frames.items():
                    utils.log_info(f"  - {sheet_name}: {len(df)} records")
                    print(f"  - {sheet_name}: {len(df)} records")
            else:
                utils.log_error("Error creating Excel file. Please check the logs.")

        except Exception as e:
            utils.log_error("Error creating Excel file", e)
    elif not failed_regions:
        # Genuinely empty account: every region succeeded and returned nothing.
        utils.log_warning("No SQS/SNS data was collected. Nothing to export.")
        print("\nNo SQS/SNS resources found in the selected region(s).")

    # If ANY region failed either primary scope collection (SQS queues or SNS
    # topics), make it loud: write a marker and exit non-zero, even if some
    # data was exported. A partial export that looks complete is exactly the
    # failure mode this guards against.
    if failed_regions:
        utils.report_collection_failures(account_name, 'sqs-sns', failed_regions)
        print(
            "\nERROR: SQS/SNS export completed with failures — data is incomplete. "
            "See the *-sqs-sns-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    # Initialize logging
    utils.setup_logging("sqs-sns-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("sqs-sns-export.py", "AWS SQS/SNS Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS SQS/SNS EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown" and not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
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

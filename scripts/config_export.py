#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Config Export Tool
Date: NOV-16-2025

Description:
This script exports AWS Config configuration and compliance information from all regions
into an Excel file with multiple worksheets. The output includes recorders, delivery
channels, config rules, compliance status, and conformance packs.

Features:
- Configuration recorders with recording status
- Delivery channels (S3 and SNS)
- Config rules with compliance status
- Resource compliance summaries
- Conformance packs for grouped compliance
- Aggregators for multi-account/multi-region views
- Retention configurations
- Phase 4B: Concurrent region scanning (4x-10x performance improvement)
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
args = utils.parse_script_args("Export AWS Config rules, recorders, and compliance data to Excel")


def _build_recorder_row(recorder: dict, region: str, config_client: Any) -> dict[str, Any]:
    """
    Build the export row for a single Config configuration recorder.

    Extracted so per-recorder processing can be wrapped in try/except by the
    caller: a malformed recorder entry is logged and skipped rather than
    discarding the whole region's results.

    Args:
        recorder: A single ConfigurationRecorders entry.
        region: AWS region name.
        config_client: boto3 Config client for the region (used to fetch
            recorder status).

    Returns:
        dict: The assembled recorder row.
    """
    recorder_name = recorder.get('name', '')
    utils.log_info(f"Processing recorder: {recorder_name} in {region}")

    # Role ARN
    role_arn = recorder.get('roleARN', '')

    # Recording group
    recording_group = recorder.get('recordingGroup', {})
    all_supported = recording_group.get('allSupported', False)
    include_global_resources = recording_group.get('includeGlobalResourceTypes', False)
    resource_types = recording_group.get('resourceTypes', [])
    resource_type_count = len(resource_types)

    # Get recorder status
    try:
        status_response = config_client.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[recorder_name]
        )
        statuses = status_response.get('ConfigurationRecordersStatus', [])

        if statuses:
            status = statuses[0]
            recording = status.get('recording', False)
            last_status = status.get('lastStatus', 'N/A')

            last_start_time = status.get('lastStartTime', '')
            if last_start_time:
                last_start_time = last_start_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_start_time, datetime.datetime) else str(last_start_time)

            last_stop_time = status.get('lastStopTime', '')
            if last_stop_time:
                last_stop_time = last_stop_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_stop_time, datetime.datetime) else str(last_stop_time)

            last_status_change = status.get('lastStatusChangeTime', '')
            if last_status_change:
                last_status_change = last_status_change.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_status_change, datetime.datetime) else str(last_status_change)
        else:
            recording = False
            last_status = 'Unknown'
            last_start_time = 'N/A'
            last_stop_time = 'N/A'
            last_status_change = 'N/A'

    except Exception:
        recording = False
        last_status = 'Unknown'
        last_start_time = 'N/A'
        last_stop_time = 'N/A'
        last_status_change = 'N/A'

    return {
        'Region': region,
        'Recorder Name': recorder_name,
        'Recording': recording,
        'Last Status': last_status,
        'Role ARN': role_arn,
        'All Supported': all_supported,
        'Include Global Resources': include_global_resources,
        'Resource Type Count': resource_type_count,
        'Last Start': last_start_time,
        'Last Stop': last_stop_time if last_stop_time != 'N/A' else 'N/A',
        'Last Status Change': last_status_change
    }


def _scan_recorders_region(region: str) -> list[dict[str, Any]]:
    """
    Collect AWS Config configuration recorders from a single region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the region
    as failed instead of silently reporting "no recorders" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed recorders are skipped (logged) rather than aborting
    the whole region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with recorder information

    Raises:
        Exception: Any AWS/pagination error for the region (caller records it
            as a failed region and surfaces it; it is never masked as empty).
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    recorders_data = []

    config_client = utils.get_boto3_client('config', region_name=region)

    # Describe configuration recorders
    recorders_response = config_client.describe_configuration_recorders()
    recorders = recorders_response.get('ConfigurationRecorders', [])

    for recorder in recorders:
        try:
            recorders_data.append(_build_recorder_row(recorder, region, config_client))
        except Exception as e:
            utils.log_error(
                f"Skipping malformed configuration recorder in {region}: "
                f"{recorder.get('name', '<unknown>')}",
                e,
            )
            continue

    utils.log_info(f"Found {len(recorders_data)} recorders in {region}")
    return recorders_data


def collect_configuration_recorders(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect AWS Config configuration recorder information across regions,
    surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Args:
        regions: List of AWS regions to scan

    Returns:
        tuple: ``(recorders, failed_regions)`` where ``failed_regions`` is a
        list of ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING CONFIGURATION RECORDERS ===")
    utils.log_info(f"Scanning {len(regions)} regions for configuration recorders...")

    # Use concurrent region scanning
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_recorders_region,
        show_progress=True,
        collect_failures=True,
    )

    # Flatten results
    all_recorders = []
    for recorders_in_region in region_results:
        all_recorders.extend(recorders_in_region)

    utils.log_success(f"Total configuration recorders collected: {len(all_recorders)}")
    return all_recorders, failed_regions


def _build_channel_row(channel: dict, region: str) -> dict[str, Any]:
    """Build the export row for a single Config delivery channel."""
    channel_name = channel.get('name', '')

    # S3 bucket
    s3_bucket = channel.get('s3BucketName', '')

    # S3 key prefix
    s3_prefix = channel.get('s3KeyPrefix', 'N/A')

    # S3 KMS key
    s3_kms_key = channel.get('s3KmsKeyArn', 'N/A')

    # SNS topic
    sns_topic = channel.get('snsTopicARN', 'N/A')

    # Config snapshot delivery properties
    snapshot_props = channel.get('configSnapshotDeliveryProperties', {})
    delivery_frequency = snapshot_props.get('deliveryFrequency', 'N/A')

    return {
        'Region': region,
        'Channel Name': channel_name,
        'S3 Bucket': s3_bucket,
        'S3 Prefix': s3_prefix,
        'S3 KMS Key': s3_kms_key,
        'SNS Topic': sns_topic,
        'Delivery Frequency': delivery_frequency
    }


def _scan_delivery_channels_region(region: str) -> list[dict[str, Any]]:
    """
    Collect AWS Config delivery channels from a single region.

    Region-level failures are allowed to raise so ``scan_regions_concurrent``
    can record the region as FAILED rather than empty (see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).
    Per-channel errors are contained internally (logged and skipped) via
    ``_build_channel_row``.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with delivery channel information

    Raises:
        Exception: Any AWS/pagination error for the region.
    """
    if not utils.is_aws_region(region):
        return []

    channels_data = []

    config_client = utils.get_boto3_client('config', region_name=region)

    # Describe delivery channels
    channels_response = config_client.describe_delivery_channels()
    channels = channels_response.get('DeliveryChannels', [])

    for channel in channels:
        try:
            channels_data.append(_build_channel_row(channel, region))
        except Exception as e:
            utils.log_error(
                f"Skipping malformed delivery channel in {region}: "
                f"{channel.get('name', '<unknown>')}",
                e,
            )
            continue

    utils.log_info(f"Found {len(channels_data)} delivery channels in {region}")
    return channels_data


def collect_delivery_channels(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect AWS Config delivery channel information across regions, surfacing
    failures.

    Args:
        regions: List of AWS regions to scan

    Returns:
        tuple: ``(channels, failed_regions)`` where ``failed_regions`` is a
        list of ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING DELIVERY CHANNELS ===")
    utils.log_info(f"Scanning {len(regions)} regions for delivery channels...")

    # Use concurrent region scanning
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_delivery_channels_region,
        show_progress=True,
        collect_failures=True,
    )

    # Flatten results
    all_channels = []
    for channels_in_region in region_results:
        all_channels.extend(channels_in_region)

    utils.log_success(f"Total delivery channels collected: {len(all_channels)}")
    return all_channels, failed_regions


def _build_rule_row(rule: dict, region: str, config_client: Any) -> dict[str, Any]:
    """
    Build the export row for a single Config rule, including compliance status.

    Args:
        rule: A single ConfigRules entry.
        region: AWS region name.
        config_client: boto3 Config client for the region (used to fetch
            compliance status).

    Returns:
        dict: The assembled rule row.
    """
    rule_name = rule.get('ConfigRuleName', '')
    rule_arn = rule.get('ConfigRuleArn', '')
    rule_id = rule.get('ConfigRuleId', '')

    # Description
    description = rule.get('Description', 'N/A')

    # Source
    source = rule.get('Source', {})
    source_identifier = source.get('SourceIdentifier', '')
    owner = source.get('Owner', '')

    # State
    state = rule.get('ConfigRuleState', '')

    # Get compliance status
    compliance_status = 'UNKNOWN'
    compliant_count = 0
    non_compliant_count = 0

    try:
        compliance_response = config_client.describe_compliance_by_config_rule(
            ConfigRuleNames=[rule_name]
        )
        compliance_results = compliance_response.get('ComplianceByConfigRules', [])

        if compliance_results:
            compliance = compliance_results[0].get('Compliance', {})
            compliance_status = compliance.get('ComplianceType', 'UNKNOWN')

            # Get detailed counts
            try:
                summary_response = config_client.get_compliance_summary_by_config_rule()
                summary = summary_response.get('ComplianceSummary', {})
                compliant_summary = summary.get('CompliantResourceCount', {})
                non_compliant_summary = summary.get('NonCompliantResourceCount', {})
                compliant_count = compliant_summary.get('CappedCount', 0)
                non_compliant_count = non_compliant_summary.get('CappedCount', 0)
            except Exception:
                pass

    except Exception:
        pass

    return {
        'Region': region,
        'Rule Name': rule_name,
        'Rule ID': rule_id,
        'State': state,
        'Compliance Status': compliance_status,
        'Compliant Resources': compliant_count,
        'Non-Compliant Resources': non_compliant_count,
        'Owner': owner,
        'Source Identifier': source_identifier,
        'Description': description[:200] + '...' if len(description) > 200 else description,
        'Rule ARN': rule_arn
    }


def _scan_config_rules_region(region: str) -> list[dict[str, Any]]:
    """
    Collect AWS Config rules (with compliance status) from a single region.

    Region-level failures are allowed to raise so ``scan_regions_concurrent``
    can record the region as FAILED rather than empty (see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).
    Per-rule errors are contained internally (logged and skipped) via
    ``_build_rule_row``.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with config rule information

    Raises:
        Exception: Any AWS/pagination error for the region.
    """
    if not utils.is_aws_region(region):
        return []

    rules_data = []

    config_client = utils.get_boto3_client('config', region_name=region)

    # Describe config rules with pagination
    rules_paginator = config_client.get_paginator('describe_config_rules')

    for rules_page in rules_paginator.paginate():
        rules = rules_page.get('ConfigRules', [])

        for rule in rules:
            try:
                rules_data.append(_build_rule_row(rule, region, config_client))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed Config rule in {region}: "
                    f"{rule.get('ConfigRuleName', '<unknown>')}",
                    e,
                )
                continue

    utils.log_info(f"Found {len(rules_data)} Config rules in {region}")
    return rules_data


def collect_config_rules(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect AWS Config rule information across regions, surfacing failures.

    Args:
        regions: List of AWS regions to scan

    Returns:
        tuple: ``(rules, failed_regions)`` where ``failed_regions`` is a list
        of ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING CONFIG RULES ===")
    utils.log_info(f"Scanning {len(regions)} regions for Config rules...")

    # Use concurrent region scanning
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_config_rules_region,
        show_progress=True,
        collect_failures=True,
    )

    # Flatten results
    all_rules = []
    for rules_in_region in region_results:
        all_rules.extend(rules_in_region)

    utils.log_success(f"Total Config rules collected: {len(all_rules)}")
    return all_rules, failed_regions


def _build_pack_row(pack: dict, region: str, config_client: Any) -> dict[str, Any]:
    """
    Build the export row for a single Config conformance pack, including
    compliance status.

    Args:
        pack: A single ConformancePackDetails entry.
        region: AWS region name.
        config_client: boto3 Config client for the region (used to fetch
            compliance status).

    Returns:
        dict: The assembled conformance pack row.
    """
    pack_name = pack.get('ConformancePackName', '')
    pack_arn = pack.get('ConformancePackArn', '')
    pack_id = pack.get('ConformancePackId', '')

    # Created by
    created_by = pack.get('CreatedBy', 'N/A')

    # Delivery S3 bucket
    delivery_s3_bucket = pack.get('DeliveryS3Bucket', 'N/A')

    # Get compliance status
    compliance_status = 'UNKNOWN'
    try:
        compliance_response = config_client.describe_conformance_pack_compliance(
            ConformancePackName=pack_name
        )
        rules_compliance = compliance_response.get('ConformancePackRuleComplianceList', [])

        compliant = sum(1 for r in rules_compliance if r.get('ComplianceType') == 'COMPLIANT')
        non_compliant = sum(1 for r in rules_compliance if r.get('ComplianceType') == 'NON_COMPLIANT')

        if non_compliant > 0:
            compliance_status = f"{compliant} compliant, {non_compliant} non-compliant"
        elif compliant > 0:
            compliance_status = f"{compliant} compliant"
        else:
            compliance_status = 'No rules evaluated'

    except Exception:
        pass

    return {
        'Region': region,
        'Pack Name': pack_name,
        'Pack ID': pack_id,
        'Compliance Status': compliance_status,
        'Created By': created_by,
        'Delivery S3 Bucket': delivery_s3_bucket,
        'Pack ARN': pack_arn
    }


def _scan_conformance_packs_region(region: str) -> list[dict[str, Any]]:
    """
    Collect AWS Config conformance packs from a single region.

    Region-level failures are allowed to raise so ``scan_regions_concurrent``
    can record the region as FAILED rather than empty (see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).
    Per-pack errors are contained internally (logged and skipped) via
    ``_build_pack_row``.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with conformance pack information

    Raises:
        Exception: Any AWS/pagination error for the region.
    """
    if not utils.is_aws_region(region):
        return []

    packs_data = []

    config_client = utils.get_boto3_client('config', region_name=region)

    # Describe conformance packs with pagination
    packs_paginator = config_client.get_paginator('describe_conformance_packs')

    for packs_page in packs_paginator.paginate():
        packs = packs_page.get('ConformancePackDetails', [])

        for pack in packs:
            try:
                packs_data.append(_build_pack_row(pack, region, config_client))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed conformance pack in {region}: "
                    f"{pack.get('ConformancePackName', '<unknown>')}",
                    e,
                )
                continue

    utils.log_info(f"Found {len(packs_data)} conformance packs in {region}")
    return packs_data


def collect_conformance_packs(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect AWS Config conformance pack information across regions, surfacing
    failures.

    Args:
        regions: List of AWS regions to scan

    Returns:
        tuple: ``(packs, failed_regions)`` where ``failed_regions`` is a list
        of ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING CONFORMANCE PACKS ===")
    utils.log_info(f"Scanning {len(regions)} regions for conformance packs...")

    # Use concurrent region scanning
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_conformance_packs_region,
        show_progress=True,
        collect_failures=True,
    )

    # Flatten results
    all_packs = []
    for packs_in_region in region_results:
        all_packs.extend(packs_in_region)

    utils.log_success(f"Total conformance packs collected: {len(all_packs)}")
    return all_packs, failed_regions


def export_config_data(account_id: str, account_name: str):
    """
    Export AWS Config information to an Excel file.

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

    # Combined failed-region list across all four region-scanned scopes
    # (recorders, delivery channels, rules, conformance packs). Any scope's
    # failure must be surfaced — a partial export that looks complete is
    # exactly the failure mode this guards against (see
    # .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).
    failed_regions = []

    # STEP 1: Collect configuration recorders (scope collection — region
    # failures must propagate as failed_regions, never collapse into "empty").
    recorders, recorder_failures = collect_configuration_recorders(regions)
    failed_regions.extend(recorder_failures)
    if recorders:
        data_frames['Configuration Recorders'] = pd.DataFrame(recorders)

    # STEP 2: Collect delivery channels (scope collection)
    channels, channel_failures = collect_delivery_channels(regions)
    failed_regions.extend(channel_failures)
    if channels:
        data_frames['Delivery Channels'] = pd.DataFrame(channels)

    # STEP 3: Collect Config rules (scope collection)
    rules, rule_failures = collect_config_rules(regions)
    failed_regions.extend(rule_failures)
    if rules:
        data_frames['Config Rules'] = pd.DataFrame(rules)

    # STEP 4: Collect conformance packs (scope collection)
    packs, pack_failures = collect_conformance_packs(regions)
    failed_regions.extend(pack_failures)
    if packs:
        data_frames['Conformance Packs'] = pd.DataFrame(packs)

    # Export whatever succeeded first — a partial export is required even
    # when some regions failed.
    if data_frames:
        # STEP 5: Prepare all DataFrames for export
        for sheet_name in data_frames:
            data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

        # STEP 6: Create filename and export
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        final_excel_file = utils.create_export_filename(
            account_name,
            'config',
            region_suffix,
            current_date
        )

        # Save using utils module for consistent formatting
        try:
            output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

            if output_path:
                utils.log_success("AWS Config data exported successfully!")
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
        utils.log_warning("No AWS Config data was collected. Nothing to export.")
        print("\nNo AWS Config resources found in the selected region(s).")

    # If ANY scope failed in ANY region, make it loud: write a marker and
    # exit non-zero, even if some data was exported. A partial export that
    # looks complete is exactly the failure mode this guards against.
    if failed_regions:
        utils.report_collection_failures(account_name, 'config', failed_regions)
        print(
            "\nERROR: AWS Config export completed with failures — data is incomplete. "
            "See the *-config-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    # Initialize logging
    utils.setup_logging("config-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("config-export.py", "AWS Config Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS CONFIG EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown" and not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
            print("Exiting script...")
            sys.exit(0)

        # Export AWS Config data
        export_config_data(account_id, account_name)

        print("\nAWS Config export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("config-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AWS Connect Export Script for StratusScan

Exports comprehensive AWS Connect contact center information including:
- Connect instances with contact center configurations
- Queues with routing configurations
- Hours of operation
- Contact flows (IVR configurations)
- Phone numbers and claimed numbers
- User accounts and routing profiles

Output: Multi-worksheet Excel file with Connect resources
"""

import sys
from pathlib import Path
from typing import Any

try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils
args = utils.parse_script_args("Export Amazon Connect instances and resources to Excel")


def _build_instance_row(instance_summary: dict, region: str) -> dict[str, Any]:
    """
    Build a single Connect instance export row from a list_instances entry.

    Extracted so the per-instance processing can be wrapped in try/except by
    the caller: a malformed instance entry is logged and skipped rather than
    discarding the whole region's results. Every field is read with ``.get()``
    and a safe default for the same reason.
    """
    instance_id = instance_summary.get('Id', 'N/A')
    instance_arn = instance_summary.get('Arn', 'N/A')
    instance_alias = instance_summary.get('InstanceAlias', 'N/A')
    created_time = instance_summary.get('CreatedTime', 'N/A')
    if created_time != 'N/A':
        created_time = created_time.strftime('%Y-%m-%d %H:%M:%S')

    service_role = instance_summary.get('ServiceRole', 'N/A')
    instance_status = instance_summary.get('InstanceStatus', 'N/A')
    inbound_calls_enabled = instance_summary.get('InboundCallsEnabled', False)
    outbound_calls_enabled = instance_summary.get('OutboundCallsEnabled', False)
    instance_access_url = instance_summary.get('InstanceAccessUrl', 'N/A')

    return {
        'Region': region,
        'Instance ID': instance_id,
        'Instance Alias': instance_alias,
        'Status': instance_status,
        'Inbound Calls Enabled': inbound_calls_enabled,
        'Outbound Calls Enabled': outbound_calls_enabled,
        'Access URL': instance_access_url,
        'Service Role': service_role,
        'Created': created_time,
        'ARN': instance_arn
    }


def _scan_instances_region(region: str) -> list[dict[str, Any]]:
    """
    Collect Connect instances from a single region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the region
    as failed instead of silently reporting "no Connect instances" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed instances are skipped (logged) rather than aborting
    the whole region.

    Raises:
        Exception: Any AWS/pagination error for the region (caller records it
            as a failed region and surfaces it; it is never masked as empty).
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_instances = []
    connect_client = utils.get_boto3_client('connect', region_name=region)
    paginator = connect_client.get_paginator('list_instances')

    for page in paginator.paginate():
        instances = page.get('InstanceSummaryList', [])

        for instance_summary in instances:
            try:
                regional_instances.append(_build_instance_row(instance_summary, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed Connect instance in {region}: "
                    f"{instance_summary.get('Id', '<unknown>')}",
                    e,
                )
                continue

    return regional_instances


def collect_instances(regions: list[str]) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """
    Collect Connect instance information across regions, surfacing failures.

    Uses ``collect_failures=True``: ``_scan_instances_region`` raises on a
    region-level failure so that failure is recorded and surfaced by the
    caller, never silently collapsed into "no instances" (see
    .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).

    Returns:
        tuple: ``(instances, failed_regions)`` where ``failed_regions`` is a
        list of ``(region, error_message)`` tuples for regions whose scan
        raised.
    """
    print("\n=== COLLECTING CONNECT INSTANCES ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_instances_region,
        show_progress=True,
        collect_failures=True,
    )
    all_instances = [instance for result in region_results for instance in result]
    utils.log_success(f"Total Connect instances collected: {len(all_instances)}")
    return all_instances, failed_regions


def _scan_queues_region(region: str, instances: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Collect queues for Connect instances in a single region.

    Second top-level scope collector (blast-radius spec notes connect's
    primary scope has "+2" siblings). Raises on API error so the failure is
    surfaced via ``scan_regions_concurrent(..., collect_failures=True)``
    rather than swallowed into an empty result.
    """
    if not utils.is_aws_region(region):
        return []

    region_queues = []
    connect_client = utils.get_boto3_client('connect', region_name=region)

    for instance in instances:
        instance_id = instance.get('Instance ID', 'N/A')
        if instance_id == 'N/A' or instance.get('Region') != region:
            continue

        paginator = connect_client.get_paginator('list_queues')
        for page in paginator.paginate(InstanceId=instance_id):
            queues = page.get('QueueSummaryList', [])

            for queue in queues:
                queue_id = queue.get('Id', 'N/A')
                queue_arn = queue.get('Arn', 'N/A')
                queue_name = queue.get('Name', 'N/A')
                queue_type = queue.get('QueueType', 'N/A')

                region_queues.append({
                    'Region': region,
                    'Instance ID': instance_id,
                    'Queue ID': queue_id,
                    'Queue Name': queue_name,
                    'Queue Type': queue_type,
                    'Queue ARN': queue_arn
                })

    return region_queues


def collect_queues(
    instances: list[dict[str, Any]], regions: list[str]
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """
    Collect queue information for Connect instances across regions,
    surfacing failures.

    Returns:
        tuple: ``(queues, failed_regions)``.
    """
    print("\n=== COLLECTING CONNECT QUEUES ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=lambda r: _scan_queues_region(r, instances),
        show_progress=True,
        collect_failures=True,
    )
    all_queues = [queue for result in region_results for queue in result]
    utils.log_success(f"Total queues collected: {len(all_queues)}")
    return all_queues, failed_regions


def _scan_phone_numbers_region(region: str, instances: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Collect phone numbers for Connect instances in a single region.

    Third top-level scope collector (blast-radius spec notes connect's
    primary scope has "+2" siblings). Raises on API error so the failure is
    surfaced via ``scan_regions_concurrent(..., collect_failures=True)``
    rather than swallowed into an empty result.
    """
    if not utils.is_aws_region(region):
        return []

    region_numbers = []
    connect_client = utils.get_boto3_client('connect', region_name=region)

    for instance in instances:
        instance_id = instance.get('Instance ID', 'N/A')
        if instance_id == 'N/A' or instance.get('Region') != region:
            continue

        paginator = connect_client.get_paginator('list_phone_numbers_v2')
        for page in paginator.paginate(TargetArn=instance.get('ARN', '')):
            numbers = page.get('ListPhoneNumbersSummaryList', [])

            for number in numbers:
                phone_number_id = number.get('PhoneNumberId', 'N/A')
                phone_number = number.get('PhoneNumber', 'N/A')
                phone_number_type = number.get('PhoneNumberType', 'N/A')
                phone_number_country_code = number.get('PhoneNumberCountryCode', 'N/A')

                region_numbers.append({
                    'Region': region,
                    'Instance ID': instance_id,
                    'Phone Number ID': phone_number_id,
                    'Phone Number': phone_number,
                    'Type': phone_number_type,
                    'Country Code': phone_number_country_code
                })

    return region_numbers


def collect_phone_numbers(
    instances: list[dict[str, Any]], regions: list[str]
) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """
    Collect phone number information for Connect instances across regions,
    surfacing failures.

    Returns:
        tuple: ``(phone_numbers, failed_regions)``.
    """
    print("\n=== COLLECTING PHONE NUMBERS ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=lambda r: _scan_phone_numbers_region(r, instances),
        show_progress=True,
        collect_failures=True,
    )
    all_numbers = [number for result in region_results for number in result]
    utils.log_success(f"Total phone numbers collected: {len(all_numbers)}")
    return all_numbers, failed_regions


def generate_summary(instances: list[dict[str, Any]],
                     queues: list[dict[str, Any]],
                     phone_numbers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate summary statistics for Connect resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Instances summary
    total_instances = len(instances)
    active_instances = sum(1 for i in instances if i.get('Status', '') == 'ACTIVE')
    inbound_enabled = sum(1 for i in instances if i.get('Inbound Calls Enabled', False))
    outbound_enabled = sum(1 for i in instances if i.get('Outbound Calls Enabled', False))

    summary.append({
        'Metric': 'Total Connect Instances',
        'Count': total_instances,
        'Details': f'Active: {active_instances}, Inbound: {inbound_enabled}, Outbound: {outbound_enabled}'
    })

    # Queues summary
    summary.append({
        'Metric': 'Total Queues',
        'Count': len(queues),
        'Details': 'Contact routing queues across all instances'
    })

    # Phone numbers summary
    summary.append({
        'Metric': 'Total Phone Numbers',
        'Count': len(phone_numbers),
        'Details': 'Claimed phone numbers across all instances'
    })

    # Regional distribution
    if instances:
        df = pd.DataFrame(instances)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Instances in {region}',
                'Count': count,
                'Details': 'Regional distribution'
            })

    return summary


def main():
    """Main execution function."""
    if not utils.ensure_dependencies('pandas', 'openpyxl'):
        return
    global pd
    import pandas as pd
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    partition = utils.detect_partition()
    if not utils.is_service_available_in_partition("connect", partition):
        utils.log_warning("Amazon Connect is not available in AWS GovCloud. Skipping.")
        sys.exit(0)

    account_id, account_name = utils.print_script_banner("AWS CONNECT EXPORT")
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({utils.mask_account_id(account_id)})")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    # Collect data
    print("\nCollecting AWS Connect data...")

    # STEP 1: Collect Connect instances (primary scope — region failures must
    # propagate as failed_regions, never collapse into "empty").
    instances, instances_failed = collect_instances(regions)

    # STEP 2 & 3: Collect queues and phone numbers. These are also top-level
    # region-scanned scope collectors (blast-radius spec: connect +2), so
    # their failures are surfaced the same way as the primary scope.
    all_queues, queues_failed = collect_queues(instances, regions)
    all_phone_numbers, phones_failed = collect_phone_numbers(instances, regions)

    # Combine failures from all top-level scope collectors into one list so a
    # single marker + exit covers the whole export.
    failed_regions = instances_failed + queues_failed + phones_failed

    summary = generate_summary(instances, all_queues, all_phone_numbers)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    if instances:
        df_instances = pd.DataFrame(instances)
        df_instances = utils.prepare_dataframe_for_export(df_instances)
        dataframes['Instances'] = df_instances

    if all_queues:
        df_queues = pd.DataFrame(all_queues)
        df_queues = utils.prepare_dataframe_for_export(df_queues)
        dataframes['Queues'] = df_queues

    if all_phone_numbers:
        df_numbers = pd.DataFrame(all_phone_numbers)
        df_numbers = utils.prepare_dataframe_for_export(df_numbers)
        dataframes['Phone Numbers'] = df_numbers

    # Export whatever succeeded — a partial export is required even when some
    # regions failed (see the silent-collection-failure blast-radius audit).
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'connect', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)
    elif not failed_regions:
        # Genuinely empty account: every region succeeded and returned nothing.
        utils.log_warning("No Connect data found to export")

    # If ANY region failed any top-level scope collection, make it loud: write
    # a marker and exit non-zero, even if some data was exported. A partial
    # export that looks complete is exactly the failure mode this guards.
    if failed_regions:
        utils.report_collection_failures(account_name, 'connect', failed_regions)
        print(
            "\nERROR: Connect export completed with failures — data is incomplete. "
            "See the *-connect-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)

    utils.log_success("Connect export completed successfully")


if __name__ == "__main__":
    main()

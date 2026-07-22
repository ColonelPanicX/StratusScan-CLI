#!/usr/bin/env python3
"""
EC2 Dedicated Hosts Export Script

Exports AWS EC2 Dedicated Hosts for compliance and licensing management:
- Dedicated Hosts (physical servers for exclusive use)
- Host resource groups and allocations
- Instance placements on hosts
- License configurations (BYOL - Bring Your Own License)
- Host capacity and availability
- Auto-placement settings

Features:
- Complete dedicated hosts inventory
- Instance-to-host mapping
- License tracking (SQL Server, Windows, RHEL, SUSE, Oracle)
- Capacity utilization tracking
- Auto-placement and affinity settings
- Multi-region support
- Comprehensive multi-worksheet export

Note: Requires ec2:DescribeHosts and ec2:DescribeHostReservations permissions
"""

import json
import sys
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
args = utils.parse_script_args("Export EC2 Dedicated Hosts to Excel")

utils.setup_logging('ec2-dedicated-hosts-export')


def _load_dedicated_host_pricing() -> dict[str, dict[str, float]]:
    """Load per-family dedicated host on-demand rates (us-east-1).

    Returns dict: {family: {'hourly': float, 'monthly': float}}
    """
    pricing_file = Path(__file__).parent.parent / 'reference' / 'dedicated-host-pricing.json'
    try:
        with open(pricing_file, encoding='utf-8') as fh:
            data = json.load(fh)
        rates = data.get('rates', {})
        return {
            family: {
                'hourly': float(v['on_demand_hourly_usd']),
                'monthly': float(v['on_demand_monthly_usd']),
            }
            for family, v in rates.items()
        }
    except Exception:
        return {}


def _build_host_row(host: dict, region: str, host_pricing: dict, is_govcloud: bool) -> dict[str, Any]:
    """Build a single dedicated-host export row from a describe_hosts entry."""
    # Extract capacity information
    available_capacity = host.get('AvailableCapacity', {})
    capacity_details = []

    for vcpu in available_capacity.get('AvailableVCpus', []):
        capacity_details.append(
            f"{vcpu.get('InstanceType', 'N/A')}: {vcpu.get('AvailableVCpus', 0)} vCPUs"
        )

    # Extract instance information
    instances = host.get('Instances', [])
    instance_ids = [inst.get('InstanceId', 'N/A') for inst in instances]
    instance_types = list({inst.get('InstanceType', 'N/A') for inst in instances})

    # Calculate utilization
    total_capacity = available_capacity.get('AvailableInstanceCapacity', [])
    total_vcpus = sum([cap.get('TotalCapacity', 0) for cap in total_capacity])
    available_vcpus = sum([cap.get('AvailableCapacity', 0) for cap in total_capacity])
    used_vcpus = total_vcpus - available_vcpus
    utilization_pct = (used_vcpus / total_vcpus * 100) if total_vcpus > 0 else 0

    # Extract properties
    properties = host.get('HostProperties', {})

    # Format tags
    tags = []
    for tag in host.get('Tags', []):
        tags.append(f"{tag.get('Key')}={tag.get('Value')}")

    # Cost estimation — per-host flat rate keyed by InstanceFamily
    state = host.get('State', 'N/A')
    instance_family = properties.get('InstanceFamily', 'N/A')
    family_pricing = host_pricing.get(instance_family)
    if state == 'released':
        monthly_cost = 0.0
        cost_note = 'Host released; no longer billed'
    elif family_pricing:
        monthly_cost = family_pricing['monthly']
        gc_note = ' (us-east-1 rates; GovCloud may differ)' if is_govcloud else ''
        cost_note = f'Estimate: flat per-host rate × 730 hr/mo{gc_note}'
    else:
        monthly_cost = 'N/A'
        cost_note = f'Family {instance_family!r} not in pricing data'

    return {
        'Region': region,
        'HostId': host.get('HostId', 'N/A'),
        'State': host.get('State', 'N/A'),
        'AvailabilityZone': host.get('AvailabilityZone', 'N/A'),
        'AvailabilityZoneId': host.get('AvailabilityZoneId', 'N/A'),
        'InstanceType': properties.get('InstanceType', 'N/A'),
        'InstanceFamily': properties.get('InstanceFamily', 'N/A'),
        'Sockets': properties.get('Sockets', 'N/A'),
        'Cores': properties.get('Cores', 'N/A'),
        'TotalVCpus': properties.get('TotalVCpus', 'N/A'),
        'UsedVCpus': used_vcpus if total_vcpus > 0 else 'N/A',
        'AvailableVCpus': available_vcpus if total_vcpus > 0 else 'N/A',
        'UtilizationPercent': f"{utilization_pct:.1f}%" if total_vcpus > 0 else 'N/A',
        'AutoPlacement': host.get('AutoPlacement', 'off'),
        'HostRecovery': host.get('HostRecovery', 'off'),
        'AllocationTime': host.get('AllocationTime', 'N/A'),
        'ReleaseTime': host.get('ReleaseTime', 'N/A'),
        'HostReservationId': host.get('HostReservationId', 'N/A'),
        'InstancesCount': len(instances),
        'InstanceIds': ', '.join(instance_ids) if instance_ids else 'N/A',
        'InstanceTypes': ', '.join(instance_types) if instance_types else 'N/A',
        'AvailableCapacity': ', '.join(capacity_details) if capacity_details else 'N/A',
        'MemberOfServiceLinkedResourceGroup': host.get('MemberOfServiceLinkedResourceGroup', False),
        'OutpostArn': host.get('OutpostArn', 'N/A'),
        'AssetId': host.get('AssetId', 'N/A'),
        'Tags': ', '.join(tags) if tags else 'N/A',
        'Monthly Cost (On-Demand)': monthly_cost,
        'Cost Note': cost_note,
    }


def _scan_dedicated_hosts_region(region: str) -> list[dict[str, Any]]:
    """
    Collect all EC2 Dedicated Hosts in a single region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the
    region as failed instead of silently reporting "no hosts" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed hosts are skipped (logged) rather than aborting the
    whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    ec2 = utils.get_boto3_client('ec2', region_name=region)
    host_pricing = _load_dedicated_host_pricing()
    is_govcloud = utils.detect_partition(region) == 'aws-us-gov'

    hosts = []
    paginator = ec2.get_paginator('describe_hosts')
    for page in paginator.paginate():
        for host in page.get('Hosts', []):
            try:
                hosts.append(_build_host_row(host, region, host_pricing, is_govcloud))
            except Exception as e:
                # One malformed host is skipped, not fatal to the region.
                utils.log_error(
                    f"Skipping malformed dedicated host in {region}: "
                    f"{host.get('HostId', '<unknown>')}",
                    e,
                )
                continue

    return hosts


def collect_dedicated_hosts(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect EC2 Dedicated Hosts across regions, surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Returns:
        tuple: ``(hosts, failed_regions)`` where ``failed_regions`` is a list
        of ``(region, error_message)`` tuples.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_dedicated_hosts_region,
        show_progress=True,
        collect_failures=True,
    )
    all_hosts = [host for result in region_results for host in result]
    return all_hosts, failed_regions


def _build_reservation_row(reservation: dict, region: str) -> dict[str, Any]:
    """Build a single host-reservation export row from a describe_host_reservations entry."""
    host_id_set = reservation.get('HostIdSet', [])

    tags = []
    for tag in reservation.get('Tags', []):
        tags.append(f"{tag.get('Key')}={tag.get('Value')}")

    return {
        'Region': region,
        'HostReservationId': reservation.get('HostReservationId', 'N/A'),
        'OfferingId': reservation.get('OfferingId', 'N/A'),
        'InstanceFamily': reservation.get('InstanceFamily', 'N/A'),
        'PaymentOption': reservation.get('PaymentOption', 'N/A'),
        'State': reservation.get('State', 'N/A'),
        'Start': reservation.get('Start', 'N/A'),
        'End': reservation.get('End', 'N/A'),
        'Duration': reservation.get('Duration', 'N/A'),
        'Count': reservation.get('Count', 0),
        'HourlyPrice': reservation.get('HourlyPrice', 'N/A'),
        'UpfrontPrice': reservation.get('UpfrontPrice', 'N/A'),
        'CurrencyCode': reservation.get('CurrencyCode', 'USD'),
        'HostIdSet': ', '.join(host_id_set) if host_id_set else 'N/A',
        'Tags': ', '.join(tags) if tags else 'N/A',
    }


def _scan_host_reservations_region(region: str) -> list[dict[str, Any]]:
    """
    Collect Dedicated Host Reservations in a single region.

    This is a second, independent scope (its own "Host Reservations" /
    "Active Reservations" inventory sheets — not derived from the dedicated
    hosts data) so it must not swallow errors: a failure here needs to
    propagate to ``scan_regions_concurrent(..., collect_failures=True)`` the
    same way the primary dedicated-hosts scope does. Individual malformed
    reservations are skipped (logged) rather than aborting the whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    ec2 = utils.get_boto3_client('ec2', region_name=region)
    reservations = []

    paginator = ec2.get_paginator('describe_host_reservations')
    for page in paginator.paginate():
        for reservation in page.get('HostReservationSet', []):
            try:
                reservations.append(_build_reservation_row(reservation, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed host reservation in {region}: "
                    f"{reservation.get('HostReservationId', '<unknown>')}",
                    e,
                )
                continue

    return reservations


def collect_host_reservations(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect Dedicated Host Reservations across regions, surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result. Callers must merge these ``failed_regions`` with the dedicated
    hosts scope's ``failed_regions`` — both are independent top-level
    inventory sheets.

    Returns:
        tuple: ``(reservations, failed_regions)`` where ``failed_regions`` is
        a list of ``(region, error_message)`` tuples.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_host_reservations_region,
        show_progress=True,
        collect_failures=True,
    )
    all_reservations = [reservation for result in region_results for reservation in result]
    return all_reservations, failed_regions


@utils.aws_error_handler("Collecting host instances", default_return=[])
def collect_host_instances(region: str, hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract instance-to-host mappings from hosts data."""
    host_instances = []

    for host in hosts:
        host_id = host.get('HostId', 'N/A')
        instance_ids_str = host.get('InstanceIds', 'N/A')

        if instance_ids_str != 'N/A':
            instance_ids = [i.strip() for i in instance_ids_str.split(',')]

            for instance_id in instance_ids:
                host_instances.append({
                    'Region': region,
                    'HostId': host_id,
                    'InstanceId': instance_id,
                    'AvailabilityZone': host.get('AvailabilityZone', 'N/A'),
                    'HostInstanceType': host.get('InstanceType', 'N/A'),
                    'HostState': host.get('State', 'N/A'),
                })

    return host_instances


def _run_export(account_id: str, account_name: str, regions: list[str]) -> None:
    """Collect EC2 Dedicated Host data and write the Excel export."""
    utils.log_info(f"Scanning {len(regions)} region(s) for EC2 Dedicated Hosts...")

    # STEP 1: Collect dedicated hosts (primary scope — region failures must
    # propagate as failed_regions, never collapse into "empty").
    all_hosts, hosts_failed_regions = collect_dedicated_hosts(regions)
    utils.log_info(f"Found {len(all_hosts)} dedicated host(s) across {len(regions)} region(s)")

    # STEP 2: Collect host reservations (second, independent top-level
    # inventory scope — same failure-surfacing contract as dedicated hosts).
    all_reservations, reservations_failed_regions = collect_host_reservations(regions)
    utils.log_info(f"Found {len(all_reservations)} host reservation(s) across {len(regions)} region(s)")

    # Merge failed regions from both scopes so a failure in either one is
    # surfaced (see .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).
    failed_regions = hosts_failed_regions + reservations_failed_regions

    # STEP 3: Extract instance-to-host mappings (enrichment derived from the
    # already-collected hosts data — no additional API calls, degrades
    # gracefully and does not contribute to failed_regions).
    all_host_instances = []
    for region in regions:
        region_hosts = [h for h in all_hosts if h.get('Region') == region]
        if region_hosts:
            all_host_instances.extend(collect_host_instances(region, region_hosts))

    if not all_hosts and not all_reservations:
        utils.log_warning("No EC2 Dedicated Hosts found in any selected region.")
        utils.log_info("Creating empty export file...")

    utils.log_info(f"Total dedicated hosts found: {len(all_hosts)}")
    utils.log_info(f"Total host reservations found: {len(all_reservations)}")
    utils.log_info(f"Total instance placements found: {len(all_host_instances)}")

    # Create DataFrames
    df_hosts = utils.prepare_dataframe_for_export(pd.DataFrame(all_hosts))
    df_reservations = utils.prepare_dataframe_for_export(pd.DataFrame(all_reservations))
    df_host_instances = utils.prepare_dataframe_for_export(pd.DataFrame(all_host_instances))

    # Create summary
    summary_data = []
    summary_data.append({'Metric': 'Total Dedicated Hosts', 'Value': len(all_hosts)})
    summary_data.append({'Metric': 'Total Host Reservations', 'Value': len(all_reservations)})
    summary_data.append({'Metric': 'Total Instance Placements', 'Value': len(all_host_instances)})
    summary_data.append({'Metric': 'Regions Scanned', 'Value': len(regions)})

    if not df_hosts.empty:
        available_hosts = len(df_hosts[df_hosts['State'] == 'available'])
        released_hosts = len(df_hosts[df_hosts['State'] == 'released'])
        under_assessment = len(df_hosts[df_hosts['State'] == 'under-assessment'])

        summary_data.append({'Metric': 'Available Hosts', 'Value': available_hosts})
        summary_data.append({'Metric': 'Released Hosts', 'Value': released_hosts})
        summary_data.append({'Metric': 'Under Assessment', 'Value': under_assessment})

        # Calculate total instances on hosts
        total_instances = df_hosts['InstancesCount'].sum() if 'InstancesCount' in df_hosts.columns else 0
        summary_data.append({'Metric': 'Total Instances on Hosts', 'Value': int(total_instances)})

        # Find underutilized hosts
        if 'UtilizationPercent' in df_hosts.columns:
            # Extract numeric value from percentage string
            df_hosts['UtilizationNumeric'] = df_hosts['UtilizationPercent'].str.rstrip('%').apply(
                lambda x: float(x) if x != 'N/A' else 0
            )
            underutilized = len(df_hosts[
                (df_hosts['State'] == 'available') &
                (df_hosts['UtilizationNumeric'] < 50) &
                (df_hosts['UtilizationNumeric'] > 0)
            ])
            summary_data.append({'Metric': 'Underutilized Hosts (<50%)', 'Value': underutilized})

    if not df_reservations.empty:
        active_reservations = len(df_reservations[df_reservations['State'] == 'active'])
        expired_reservations = len(df_reservations[df_reservations['State'] == 'expired'])

        summary_data.append({'Metric': 'Active Host Reservations', 'Value': active_reservations})
        summary_data.append({'Metric': 'Expired Host Reservations', 'Value': expired_reservations})

    df_summary = utils.prepare_dataframe_for_export(pd.DataFrame(summary_data))

    # Create filtered views
    df_available = pd.DataFrame()
    df_underutilized = pd.DataFrame()
    df_active_reservations = pd.DataFrame()

    if not df_hosts.empty:
        df_available = df_hosts[df_hosts['State'] == 'available']

        # Underutilized hosts
        if 'UtilizationNumeric' in df_hosts.columns:
            df_underutilized = df_hosts[
                (df_hosts['State'] == 'available') &
                (df_hosts['UtilizationNumeric'] < 50) &
                (df_hosts['UtilizationNumeric'] > 0)
            ][df_hosts.columns.difference(['UtilizationNumeric'])]  # Remove temp column

            # Remove temp column from main DataFrame
            df_hosts = df_hosts.drop(columns=['UtilizationNumeric'])

    if not df_reservations.empty:
        df_active_reservations = df_reservations[df_reservations['State'] == 'active']

    # Export to Excel
    filename = utils.create_export_filename(account_name, 'ec2-dedicated-hosts', 'all')

    sheets = {
        'Summary': df_summary,
        'All Hosts': df_hosts,
        'Available Hosts': df_available,
        'Underutilized Hosts': df_underutilized,
        'Host Reservations': df_reservations,
        'Active Reservations': df_active_reservations,
        'Instance Placements': df_host_instances,
    }

    utils.save_multiple_dataframes_to_excel(sheets, filename)

    utils.log_info(f"  Dedicated Hosts: {len(all_hosts)}")
    utils.log_info(f"  Host Reservations: {len(all_reservations)}")
    utils.log_info(f"  Instance Placements: {len(all_host_instances)}")

    utils.log_success("EC2 Dedicated Hosts export completed successfully!")

    # If ANY region failed either scope's collection (dedicated hosts or host
    # reservations), make it loud: write a marker and exit non-zero, even
    # though the workbook (with its always-written Summary sheet) already
    # landed. A partial export that looks complete is exactly the failure
    # mode this guards against. A genuinely empty account (every region
    # succeeded and returned nothing) stays a plain warning with exit 0 —
    # no marker.
    if failed_regions:
        utils.report_collection_failures(account_name, 'ec2-dedicated-hosts', failed_regions)
        print(
            "\nERROR: EC2 Dedicated Hosts export completed with failures — data is incomplete. "
            "See the *-ec2-dedicated-hosts-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    """Main execution function — 3-step state machine (region -> confirm -> export)."""
    try:
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return
        global pd
        import pandas as pd
        account_id, account_name = utils.print_script_banner("AWS EC2 DEDICATED HOSTS EXPORT")

        step = 1
        regions = None

        while True:
            if step == 1:
                result = utils.prompt_region_selection(service_name="EC2 Dedicated Hosts")
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                regions = result
                step = 2

            elif step == 2:
                region_str = regions[0] if len(regions) == 1 else f"{len(regions)} regions"
                msg = f"Ready to export EC2 Dedicated Hosts ({region_str})."
                result = utils.prompt_confirmation(msg)
                if result == 'back':
                    step = 1
                    continue
                if result == 'exit':
                    sys.exit(11)
                step = 3

            elif step == 3:
                _run_export(account_id, account_name, regions)
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

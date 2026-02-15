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

import sys
from pathlib import Path
from typing import List, Dict, Any
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

# Check required packages
utils.check_required_packages(['boto3', 'pandas', 'openpyxl'])

# Setup logging
logger = utils.setup_logging('ec2-dedicated-hosts-export')
utils.log_script_start('ec2-dedicated-hosts-export', 'Export EC2 Dedicated Hosts')


@utils.aws_error_handler("Collecting dedicated hosts", default_return=[])
def collect_dedicated_hosts(region: str) -> List[Dict[str, Any]]:
    """Collect all EC2 Dedicated Hosts in a region."""
    ec2 = utils.get_boto3_client('ec2', region_name=region)
    hosts = []

    paginator = ec2.get_paginator('describe_hosts')
    for page in paginator.paginate():
        for host in page.get('Hosts', []):
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
            instance_types = list(set([inst.get('InstanceType', 'N/A') for inst in instances]))

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

            hosts.append({
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
            })

    return hosts


@utils.aws_error_handler("Collecting host reservations", default_return=[])
def collect_host_reservations(region: str) -> List[Dict[str, Any]]:
    """Collect Dedicated Host Reservations in a region."""
    ec2 = utils.get_boto3_client('ec2', region_name=region)
    reservations = []

    try:
        paginator = ec2.get_paginator('describe_host_reservations')
        for page in paginator.paginate():
            for reservation in page.get('HostReservationSet', []):
                # Extract host IDs
                host_id_set = reservation.get('HostIdSet', [])

                # Format tags
                tags = []
                for tag in reservation.get('Tags', []):
                    tags.append(f"{tag.get('Key')}={tag.get('Value')}")

                reservations.append({
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
                })
    except Exception:
        # Host reservations might not be available
        pass

    return reservations


@utils.aws_error_handler("Collecting host instances", default_return=[])
def collect_host_instances(region: str, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract instance-to-host mappings from hosts data."""
    host_instances = []

    for host in hosts:
        host_id = host['HostId']
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


def main():
    """Main execution function."""
    try:
        # Get account information
        account_id, account_name = utils.get_account_info()
        utils.log_info(f"Exporting EC2 Dedicated Hosts for account: {account_name} ({account_id})")

        # Prompt for regions
        utils.log_info("EC2 Dedicated Hosts are regional resources.")
        regions = utils.prompt_region_selection(
            service_name="EC2 Dedicated Hosts",
            default_to_all=False
        )

        if not regions:
            utils.log_error("No regions selected. Exiting.")
            return

        utils.log_info(f"Scanning {len(regions)} region(s) for EC2 Dedicated Hosts...")

        # Collect all resources
        all_hosts = []
        all_reservations = []
        all_host_instances = []

        for idx, region in enumerate(regions, 1):
            utils.log_info(f"[{idx}/{len(regions)}] Processing region: {region}")

            # Collect dedicated hosts
            hosts = collect_dedicated_hosts(region)
            if hosts:
                utils.log_info(f"  Found {len(hosts)} dedicated host(s)")
                all_hosts.extend(hosts)

                # Extract instance-to-host mappings
                host_instances = collect_host_instances(region, hosts)
                all_host_instances.extend(host_instances)

            # Collect host reservations
            reservations = collect_host_reservations(region)
            if reservations:
                utils.log_info(f"  Found {len(reservations)} host reservation(s)")
                all_reservations.extend(reservations)

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

        # Log summary
        utils.log_export_summary(
            total_items=len(all_hosts) + len(all_reservations),
            item_type='EC2 Dedicated Hosts',
            filename=filename
        )

        utils.log_info(f"  Dedicated Hosts: {len(all_hosts)}")
        utils.log_info(f"  Host Reservations: {len(all_reservations)}")
        utils.log_info(f"  Instance Placements: {len(all_host_instances)}")

        utils.log_success("EC2 Dedicated Hosts export completed successfully!")

    except Exception as e:
        utils.log_error(f"Failed to export EC2 Dedicated Hosts: {str(e)}")
        raise


if __name__ == "__main__":
    main()

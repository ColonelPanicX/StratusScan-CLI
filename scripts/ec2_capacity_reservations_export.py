#!/usr/bin/env python3
"""
EC2 Capacity Reservations Export Script

Exports AWS EC2 Capacity Reservations for on-demand capacity management:
- On-Demand Capacity Reservations (ODCRs)
- Capacity Reservation Groups/Fleets
- Capacity Block Reservations (for ML workloads)
- Reservation utilization and availability
- Instance type and availability zone details
- Tenancy and EBS optimization settings

Features:
- Complete capacity reservation inventory
- Utilization tracking (used vs total capacity)
- Expiration and renewal tracking
- Cost optimization insights
- Multi-region support
- Comprehensive multi-worksheet export

Note: Requires ec2:Describe*CapacityReservation* permissions
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

utils.setup_logging('ec2-capacity-reservations-export')


@utils.aws_error_handler("Collecting capacity reservations", default_return=[])
def collect_capacity_reservations(region: str) -> List[Dict[str, Any]]:
    """Collect all EC2 Capacity Reservations in a region."""
    ec2 = utils.get_boto3_client('ec2', region_name=region)
    reservations = []

    paginator = ec2.get_paginator('describe_capacity_reservations')
    for page in paginator.paginate():
        for cr in page.get('CapacityReservations', []):
            # Calculate utilization
            total_capacity = cr.get('TotalInstanceCount', 0)
            available_capacity = cr.get('AvailableInstanceCount', 0)
            used_capacity = total_capacity - available_capacity
            utilization_pct = (used_capacity / total_capacity * 100) if total_capacity > 0 else 0

            # Format tags
            tags = []
            for tag in cr.get('Tags', []):
                tags.append(f"{tag.get('Key')}={tag.get('Value')}")

            reservations.append({
                'Region': region,
                'CapacityReservationId': cr.get('CapacityReservationId', 'N/A'),
                'CapacityReservationArn': cr.get('CapacityReservationArn', 'N/A'),
                'InstanceType': cr.get('InstanceType', 'N/A'),
                'AvailabilityZone': cr.get('AvailabilityZone', 'N/A'),
                'AvailabilityZoneId': cr.get('AvailabilityZoneId', 'N/A'),
                'State': cr.get('State', 'N/A'),
                'TotalInstanceCount': total_capacity,
                'AvailableInstanceCount': available_capacity,
                'UsedInstanceCount': used_capacity,
                'UtilizationPercent': f"{utilization_pct:.1f}%",
                'Tenancy': cr.get('Tenancy', 'default'),
                'EbsOptimized': cr.get('EbsOptimized', False),
                'EphemeralStorage': cr.get('EphemeralStorage', False),
                'InstancePlatform': cr.get('InstancePlatform', 'N/A'),
                'EndDate': cr.get('EndDate', 'N/A'),
                'EndDateType': cr.get('EndDateType', 'unlimited'),
                'InstanceMatchCriteria': cr.get('InstanceMatchCriteria', 'open'),
                'CreateDate': cr.get('CreateDate'),
                'StartDate': cr.get('StartDate', 'N/A'),
                'OwnerId': cr.get('OwnerId', 'N/A'),
                'PlacementGroupArn': cr.get('PlacementGroupArn', 'N/A'),
                'OutpostArn': cr.get('OutpostArn', 'N/A'),
                'CapacityReservationFleetId': cr.get('CapacityReservationFleetId', 'N/A'),
                'Tags': ', '.join(tags) if tags else 'N/A',
            })

    return reservations


@utils.aws_error_handler("Collecting capacity reservation fleets", default_return=[])
def collect_capacity_reservation_fleets(region: str) -> List[Dict[str, Any]]:
    """Collect Capacity Reservation Fleets in a region."""
    ec2 = utils.get_boto3_client('ec2', region_name=region)
    fleets = []

    try:
        paginator = ec2.get_paginator('describe_capacity_reservation_fleets')
        for page in paginator.paginate():
            for fleet in page.get('CapacityReservationFleets', []):
                # Format tags
                tags = []
                for tag in fleet.get('Tags', []):
                    tags.append(f"{tag.get('Key')}={tag.get('Value')}")

                fleets.append({
                    'Region': region,
                    'CapacityReservationFleetId': fleet.get('CapacityReservationFleetId', 'N/A'),
                    'CapacityReservationFleetArn': fleet.get('CapacityReservationFleetArn', 'N/A'),
                    'State': fleet.get('State', 'N/A'),
                    'TotalTargetCapacity': fleet.get('TotalTargetCapacity', 0),
                    'TotalFulfilledCapacity': fleet.get('TotalFulfilledCapacity', 0),
                    'Tenancy': fleet.get('Tenancy', 'default'),
                    'EndDate': fleet.get('EndDate', 'N/A'),
                    'InstanceMatchCriteria': fleet.get('InstanceMatchCriteria', 'open'),
                    'AllocationStrategy': fleet.get('AllocationStrategy', 'N/A'),
                    'CreateTime': fleet.get('CreateTime'),
                    'Tags': ', '.join(tags) if tags else 'N/A',
                })
    except Exception:
        # Fleets might not be available in all regions
        pass

    return fleets


@utils.aws_error_handler("Collecting capacity blocks", default_return=[])
def collect_capacity_blocks(region: str) -> List[Dict[str, Any]]:
    """Collect Capacity Block Reservations (for ML workloads)."""
    ec2 = utils.get_boto3_client('ec2', region_name=region)
    blocks = []

    try:
        # Capacity blocks are filtered capacity reservations with specific criteria
        paginator = ec2.get_paginator('describe_capacity_reservations')
        for page in paginator.paginate(
            Filters=[
                {'Name': 'instance-match-criteria', 'Values': ['targeted']}
            ]
        ):
            for cr in page.get('CapacityReservations', []):
                # Check if this looks like a capacity block (has specific attributes)
                if cr.get('EndDateType') == 'limited' and cr.get('InstanceMatchCriteria') == 'targeted':
                    blocks.append({
                        'Region': region,
                        'CapacityReservationId': cr.get('CapacityReservationId', 'N/A'),
                        'InstanceType': cr.get('InstanceType', 'N/A'),
                        'AvailabilityZone': cr.get('AvailabilityZone', 'N/A'),
                        'State': cr.get('State', 'N/A'),
                        'TotalInstanceCount': cr.get('TotalInstanceCount', 0),
                        'StartDate': cr.get('StartDate', 'N/A'),
                        'EndDate': cr.get('EndDate', 'N/A'),
                        'InstancePlatform': cr.get('InstancePlatform', 'N/A'),
                    })
    except Exception:
        pass

    return blocks


def _run_export(account_id: str, account_name: str, regions: List[str]) -> None:
    """Collect EC2 Capacity Reservation data and write the Excel export."""
    utils.log_info(f"Scanning {len(regions)} region(s) for EC2 Capacity Reservations...")

    # Collect all resources
    all_reservations = []
    all_fleets = []
    all_blocks = []

    for idx, region in enumerate(regions, 1):
        utils.log_info(f"[{idx}/{len(regions)}] Processing region: {region}")

        # Collect capacity reservations
        reservations = collect_capacity_reservations(region)
        if reservations:
            utils.log_info(f"  Found {len(reservations)} capacity reservation(s)")
            all_reservations.extend(reservations)

        # Collect fleets
        fleets = collect_capacity_reservation_fleets(region)
        if fleets:
            utils.log_info(f"  Found {len(fleets)} capacity reservation fleet(s)")
            all_fleets.extend(fleets)

        # Collect capacity blocks
        blocks = collect_capacity_blocks(region)
        if blocks:
            utils.log_info(f"  Found {len(blocks)} capacity block(s)")
            all_blocks.extend(blocks)

    if not all_reservations and not all_fleets:
        utils.log_warning("No EC2 Capacity Reservations found in any selected region.")
        utils.log_info("Creating empty export file...")

    utils.log_info(f"Total capacity reservations found: {len(all_reservations)}")
    utils.log_info(f"Total capacity fleets found: {len(all_fleets)}")
    utils.log_info(f"Total capacity blocks found: {len(all_blocks)}")

    # Create DataFrames
    df_reservations = utils.prepare_dataframe_for_export(pd.DataFrame(all_reservations))
    df_fleets = utils.prepare_dataframe_for_export(pd.DataFrame(all_fleets))
    df_blocks = utils.prepare_dataframe_for_export(pd.DataFrame(all_blocks))

    # Create summary
    summary_data = []
    summary_data.append({'Metric': 'Total Capacity Reservations', 'Value': len(all_reservations)})
    summary_data.append({'Metric': 'Total Capacity Fleets', 'Value': len(all_fleets)})
    summary_data.append({'Metric': 'Total Capacity Blocks', 'Value': len(all_blocks)})
    summary_data.append({'Metric': 'Regions Scanned', 'Value': len(regions)})

    if not df_reservations.empty:
        active_reservations = len(df_reservations[df_reservations['State'] == 'active'])
        expired_reservations = len(df_reservations[df_reservations['State'] == 'expired'])
        pending_reservations = len(df_reservations[df_reservations['State'] == 'pending'])

        summary_data.append({'Metric': 'Active Reservations', 'Value': active_reservations})
        summary_data.append({'Metric': 'Expired Reservations', 'Value': expired_reservations})
        summary_data.append({'Metric': 'Pending Reservations', 'Value': pending_reservations})

        # Calculate total capacity
        total_instances = df_reservations['TotalInstanceCount'].sum() if 'TotalInstanceCount' in df_reservations.columns else 0
        used_instances = df_reservations['UsedInstanceCount'].sum() if 'UsedInstanceCount' in df_reservations.columns else 0

        summary_data.append({'Metric': 'Total Reserved Capacity', 'Value': int(total_instances)})
        summary_data.append({'Metric': 'Total Used Capacity', 'Value': int(used_instances)})

        # Find underutilized reservations
        if 'UtilizationPercent' in df_reservations.columns:
            # Extract numeric value from percentage string
            df_reservations['UtilizationNumeric'] = df_reservations['UtilizationPercent'].str.rstrip('%').astype(float)
            underutilized = len(df_reservations[
                (df_reservations['State'] == 'active') &
                (df_reservations['UtilizationNumeric'] < 50)
            ])
            summary_data.append({'Metric': 'Underutilized Reservations (<50%)', 'Value': underutilized})

    df_summary = utils.prepare_dataframe_for_export(pd.DataFrame(summary_data))

    # Create filtered views
    df_active = pd.DataFrame()
    df_underutilized = pd.DataFrame()

    if not df_reservations.empty:
        df_active = df_reservations[df_reservations['State'] == 'active']

        # Underutilized reservations
        if 'UtilizationNumeric' in df_reservations.columns:
            df_underutilized = df_reservations[
                (df_reservations['State'] == 'active') &
                (df_reservations['UtilizationNumeric'] < 50)
            ][df_reservations.columns.difference(['UtilizationNumeric'])]  # Remove temp column

    # Remove temp column if it exists
    if 'UtilizationNumeric' in df_reservations.columns:
        df_reservations = df_reservations.drop(columns=['UtilizationNumeric'])

    # Export to Excel
    filename = utils.create_export_filename(account_name, 'ec2-capacity-reservations', 'all')

    sheets = {
        'Summary': df_summary,
        'All Reservations': df_reservations,
        'Active Reservations': df_active,
        'Underutilized': df_underutilized,
        'Capacity Fleets': df_fleets,
        'Capacity Blocks': df_blocks,
    }

    utils.save_multiple_dataframes_to_excel(sheets, filename)

    utils.log_info(f"  Capacity Reservations: {len(all_reservations)}")
    utils.log_info(f"  Capacity Fleets: {len(all_fleets)}")
    utils.log_info(f"  Capacity Blocks: {len(all_blocks)}")

    utils.log_success("EC2 Capacity Reservations export completed successfully!")


def main():
    """Main execution function — 3-step state machine (region -> confirm -> export)."""
    try:
        account_id, account_name = utils.print_script_banner("AWS EC2 CAPACITY RESERVATIONS EXPORT")

        step = 1
        regions = None

        while True:
            if step == 1:
                result = utils.prompt_region_selection(service_name="EC2 Capacity Reservations")
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                regions = result
                step = 2

            elif step == 2:
                region_str = regions[0] if len(regions) == 1 else f"{len(regions)} regions"
                msg = f"Ready to export EC2 Capacity Reservations ({region_str})."
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

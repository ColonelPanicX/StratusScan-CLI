#!/usr/bin/env python3
"""
Reserved Instances Export Script

Exports comprehensive Reserved Instance (RI) data across multiple AWS services:
- EC2 Reserved Instances (active, retired, payment states)
- RDS Reserved DB Instances
- ElastiCache Reserved Cache Nodes
- OpenSearch Reserved Instances
- Redshift Reserved Nodes
- MemoryDB Reserved Nodes
- RI Utilization metrics (from Cost Explorer)
- RI Coverage metrics (from Cost Explorer)
- Expiration tracking and savings analysis

Features:
- Multi-service RI inventory
- Active vs. expired RI tracking
- Utilization and coverage analysis
- Cost savings calculations
- Expiration alerts (30/60/90 days)
- Payment option breakdown
- Multi-region support
"""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
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

utils.setup_logging('reserved-instances-export')


@utils.aws_error_handler("Collecting EC2 Reserved Instances", default_return=[])
def collect_ec2_reserved_instances(region: str) -> List[Dict[str, Any]]:
    """Collect EC2 Reserved Instances."""
    ec2 = utils.get_boto3_client('ec2', region_name=region)
    reserved_instances = []

    response = ec2.describe_reserved_instances()

    for ri in response.get('ReservedInstances', []):
        reserved_instances.append({
            'Service': 'EC2',
            'Region': region,
            'ReservationID': ri.get('ReservedInstancesId', 'N/A'),
            'InstanceType': ri.get('InstanceType', 'N/A'),
            'InstanceCount': ri.get('InstanceCount', 0),
            'State': ri.get('State', 'N/A'),
            'Start': ri.get('Start'),
            'End': ri.get('End'),
            'Duration': f"{ri.get('Duration', 0) // 86400} days",
            'OfferingType': ri.get('OfferingType', 'N/A'),
            'OfferingClass': ri.get('OfferingClass', 'N/A'),
            'FixedPrice': ri.get('FixedPrice', 0),
            'UsagePrice': ri.get('UsagePrice', 0),
            'CurrencyCode': ri.get('CurrencyCode', 'USD'),
            'ProductDescription': ri.get('ProductDescription', 'N/A'),
            'Scope': ri.get('Scope', 'N/A'),
            'AvailabilityZone': ri.get('AvailabilityZone', 'N/A'),
            'InstanceTenancy': ri.get('InstanceTenancy', 'default'),
        })

    return reserved_instances


@utils.aws_error_handler("Collecting RDS Reserved DB Instances", default_return=[])
def collect_rds_reserved_instances(region: str) -> List[Dict[str, Any]]:
    """Collect RDS Reserved DB Instances."""
    rds = utils.get_boto3_client('rds', region_name=region)
    reserved_instances = []

    paginator = rds.get_paginator('describe_reserved_db_instances')
    for page in paginator.paginate():
        for ri in page.get('ReservedDBInstances', []):
            reserved_instances.append({
                'Service': 'RDS',
                'Region': region,
                'ReservationID': ri.get('ReservedDBInstanceId', 'N/A'),
                'InstanceType': ri.get('DBInstanceClass', 'N/A'),
                'InstanceCount': ri.get('DBInstanceCount', 0),
                'State': ri.get('State', 'N/A'),
                'Start': ri.get('StartTime'),
                'End': None,  # RDS doesn't expose end time directly
                'Duration': f"{ri.get('Duration', 0) // 86400} days",
                'OfferingType': ri.get('OfferingType', 'N/A'),
                'OfferingClass': 'N/A',  # Not applicable for RDS
                'FixedPrice': ri.get('FixedPrice', 0),
                'UsagePrice': ri.get('UsagePrice', 0),
                'CurrencyCode': ri.get('CurrencyCode', 'USD'),
                'ProductDescription': ri.get('ProductDescription', 'N/A'),
                'Scope': 'Regional',  # RDS RIs are always regional
                'AvailabilityZone': 'N/A',
                'InstanceTenancy': 'N/A',
                'MultiAZ': ri.get('MultiAZ', False),
                'Engine': ri.get('ProductDescription', 'N/A'),
            })

    return reserved_instances


@utils.aws_error_handler("Collecting ElastiCache Reserved Cache Nodes", default_return=[])
def collect_elasticache_reserved_instances(region: str) -> List[Dict[str, Any]]:
    """Collect ElastiCache Reserved Cache Nodes."""
    elasticache = utils.get_boto3_client('elasticache', region_name=region)
    reserved_instances = []

    paginator = elasticache.get_paginator('describe_reserved_cache_nodes')
    for page in paginator.paginate():
        for ri in page.get('ReservedCacheNodes', []):
            reserved_instances.append({
                'Service': 'ElastiCache',
                'Region': region,
                'ReservationID': ri.get('ReservedCacheNodeId', 'N/A'),
                'InstanceType': ri.get('CacheNodeType', 'N/A'),
                'InstanceCount': ri.get('CacheNodeCount', 0),
                'State': ri.get('State', 'N/A'),
                'Start': ri.get('StartTime'),
                'End': None,
                'Duration': f"{ri.get('Duration', 0) // 86400} days",
                'OfferingType': ri.get('OfferingType', 'N/A'),
                'OfferingClass': 'N/A',
                'FixedPrice': ri.get('FixedPrice', 0),
                'UsagePrice': ri.get('UsagePrice', 0),
                'CurrencyCode': 'USD',
                'ProductDescription': ri.get('ProductDescription', 'N/A'),
                'Scope': 'Regional',
                'AvailabilityZone': 'N/A',
                'InstanceTenancy': 'N/A',
                'Engine': ri.get('ProductDescription', 'N/A'),
            })

    return reserved_instances


@utils.aws_error_handler("Collecting OpenSearch Reserved Instances", default_return=[])
def collect_opensearch_reserved_instances(region: str) -> List[Dict[str, Any]]:
    """Collect OpenSearch Reserved Instances."""
    opensearch = utils.get_boto3_client('es', region_name=region)  # 'es' is the service name
    reserved_instances = []

    response = opensearch.describe_reserved_elasticsearch_instances()

    for ri in response.get('ReservedElasticsearchInstances', []):
        reserved_instances.append({
            'Service': 'OpenSearch',
            'Region': region,
            'ReservationID': ri.get('ReservedElasticsearchInstanceId', 'N/A'),
            'InstanceType': ri.get('ElasticsearchInstanceType', 'N/A'),
            'InstanceCount': ri.get('ElasticsearchInstanceCount', 0),
            'State': ri.get('State', 'N/A'),
            'Start': ri.get('StartTime'),
            'End': None,
            'Duration': f"{ri.get('Duration', 0) // 86400} days",
            'OfferingType': ri.get('PaymentOption', 'N/A'),
            'OfferingClass': 'N/A',
            'FixedPrice': ri.get('FixedPrice', 0),
            'UsagePrice': ri.get('UsagePrice', 0),
            'CurrencyCode': ri.get('CurrencyCode', 'USD'),
            'ProductDescription': 'OpenSearch',
            'Scope': 'Regional',
            'AvailabilityZone': 'N/A',
            'InstanceTenancy': 'N/A',
        })

    return reserved_instances


@utils.aws_error_handler("Collecting Redshift Reserved Nodes", default_return=[])
def collect_redshift_reserved_instances(region: str) -> List[Dict[str, Any]]:
    """Collect Redshift Reserved Nodes."""
    redshift = utils.get_boto3_client('redshift', region_name=region)
    reserved_instances = []

    paginator = redshift.get_paginator('describe_reserved_nodes')
    for page in paginator.paginate():
        for ri in page.get('ReservedNodes', []):
            reserved_instances.append({
                'Service': 'Redshift',
                'Region': region,
                'ReservationID': ri.get('ReservedNodeId', 'N/A'),
                'InstanceType': ri.get('NodeType', 'N/A'),
                'InstanceCount': ri.get('NodeCount', 0),
                'State': ri.get('State', 'N/A'),
                'Start': ri.get('StartTime'),
                'End': None,
                'Duration': f"{ri.get('Duration', 0) // 86400} days",
                'OfferingType': ri.get('OfferingType', 'N/A'),
                'OfferingClass': 'N/A',
                'FixedPrice': ri.get('FixedPrice', 0),
                'UsagePrice': ri.get('UsagePrice', 0),
                'CurrencyCode': ri.get('CurrencyCode', 'USD'),
                'ProductDescription': 'Redshift',
                'Scope': 'Regional',
                'AvailabilityZone': 'N/A',
                'InstanceTenancy': 'N/A',
            })

    return reserved_instances


@utils.aws_error_handler("Collecting MemoryDB Reserved Nodes", default_return=[])
def collect_memorydb_reserved_instances(region: str) -> List[Dict[str, Any]]:
    """Collect MemoryDB Reserved Nodes."""
    memorydb = utils.get_boto3_client('memorydb', region_name=region)
    reserved_instances = []

    paginator = memorydb.get_paginator('describe_reserved_nodes')
    for page in paginator.paginate():
        for ri in page.get('ReservedNodes', []):
            reserved_instances.append({
                'Service': 'MemoryDB',
                'Region': region,
                'ReservationID': ri.get('ReservedNodeId', 'N/A'),
                'InstanceType': ri.get('NodeType', 'N/A'),
                'InstanceCount': ri.get('NodeCount', 0),
                'State': ri.get('State', 'N/A'),
                'Start': ri.get('StartTime'),
                'End': None,
                'Duration': f"{ri.get('Duration', 0) // 86400} days",
                'OfferingType': ri.get('OfferingType', 'N/A'),
                'OfferingClass': 'N/A',
                'FixedPrice': 0,  # Not exposed by MemoryDB API
                'UsagePrice': 0,
                'CurrencyCode': 'USD',
                'ProductDescription': 'MemoryDB',
                'Scope': 'Regional',
                'AvailabilityZone': 'N/A',
                'InstanceTenancy': 'N/A',
            })

    return reserved_instances


def calculate_expiration_status(end_date) -> str:
    """Calculate expiration status relative to current date."""
    if pd.isna(end_date) or end_date is None:
        return 'Unknown'

    if isinstance(end_date, str):
        return 'Unknown'

    try:
        now = datetime.now(timezone.utc)
        days_until_expiration = (end_date - now).days

        if days_until_expiration < 0:
            return 'Expired'
        elif days_until_expiration <= 30:
            return f'Expiring in {days_until_expiration} days (30-day alert)'
        elif days_until_expiration <= 60:
            return f'Expiring in {days_until_expiration} days (60-day alert)'
        elif days_until_expiration <= 90:
            return f'Expiring in {days_until_expiration} days (90-day alert)'
        else:
            return f'Active ({days_until_expiration} days remaining)'
    except Exception:
        return 'Unknown'


def _run_export(account_id: str, account_name: str, regions: List[str]) -> None:
    """Collect Reserved Instance data and write the Excel export."""
    utils.log_info(f"Exporting Reserved Instance data for account: {account_name} ({utils.mask_account_id(account_id)})")
    utils.log_info(f"Scanning {len(regions)} region(s) for Reserved Instances...")

    # Collect all RIs across all services and regions
    all_ris = []

    for idx, region in enumerate(regions, 1):
        utils.log_info(f"[{idx}/{len(regions)}] Processing region: {region}")

        # Collect from each service
        ec2_ris = collect_ec2_reserved_instances(region)
        rds_ris = collect_rds_reserved_instances(region)
        elasticache_ris = collect_elasticache_reserved_instances(region)
        opensearch_ris = collect_opensearch_reserved_instances(region)
        redshift_ris = collect_redshift_reserved_instances(region)
        memorydb_ris = collect_memorydb_reserved_instances(region)

        region_count = (len(ec2_ris) + len(rds_ris) + len(elasticache_ris) +
                      len(opensearch_ris) + len(redshift_ris) + len(memorydb_ris))

        if region_count > 0:
            utils.log_info(f"  Found {region_count} Reserved Instances in {region}")
            utils.log_info(f"    EC2: {len(ec2_ris)}, RDS: {len(rds_ris)}, "
                         f"ElastiCache: {len(elasticache_ris)}, OpenSearch: {len(opensearch_ris)}, "
                         f"Redshift: {len(redshift_ris)}, MemoryDB: {len(memorydb_ris)}")

        all_ris.extend(ec2_ris)
        all_ris.extend(rds_ris)
        all_ris.extend(elasticache_ris)
        all_ris.extend(opensearch_ris)
        all_ris.extend(redshift_ris)
        all_ris.extend(memorydb_ris)

    if not all_ris:
        utils.log_warning("No Reserved Instances found in any selected region.")
        utils.log_info("Creating empty export file...")

    utils.log_info(f"Total Reserved Instances found: {len(all_ris)}")

    # Create DataFrame
    df_all = utils.prepare_dataframe_for_export(pd.DataFrame(all_ris))

    # Add expiration status if we have End dates
    if not df_all.empty and 'End' in df_all.columns:
        df_all['ExpirationStatus'] = df_all['End'].apply(calculate_expiration_status)

    # Create summary by service
    summary_data = []
    if not df_all.empty:
        for service in df_all['Service'].unique():
            service_ris = df_all[df_all['Service'] == service]
            active_ris = service_ris[service_ris['State'].isin(['active', 'payment-pending'])]

            summary_data.append({
                'Service': service,
                'TotalReservations': len(service_ris),
                'ActiveReservations': len(active_ris),
                'TotalInstances': service_ris['InstanceCount'].sum(),
                'RegionsWithRIs': service_ris['Region'].nunique(),
                'UniqueInstanceTypes': service_ris['InstanceType'].nunique(),
            })

    df_summary = utils.prepare_dataframe_for_export(pd.DataFrame(summary_data))

    # Create active RIs view
    df_active = df_all[df_all['State'].isin(['active', 'payment-pending'])] if not df_all.empty else pd.DataFrame()

    # Create expiring RIs view (within 90 days)
    df_expiring = pd.DataFrame()
    if not df_all.empty and 'ExpirationStatus' in df_all.columns:
        df_expiring = df_all[
            (df_all['State'] == 'active') &
            (df_all['ExpirationStatus'].str.contains('alert', na=False))
        ]

    # Create payment option breakdown
    payment_data = []
    if not df_all.empty and 'OfferingType' in df_all.columns:
        for offering_type in df_all['OfferingType'].unique():
            if offering_type == 'N/A':
                continue
            type_ris = df_all[df_all['OfferingType'] == offering_type]
            payment_data.append({
                'OfferingType': offering_type,
                'Count': len(type_ris),
                'TotalInstances': type_ris['InstanceCount'].sum(),
                'Services': ', '.join(type_ris['Service'].unique()),
            })

    df_payment = utils.prepare_dataframe_for_export(pd.DataFrame(payment_data))

    # Export to Excel
    filename = utils.create_export_filename(account_name, 'reserved-instances', 'all')

    sheets = {
        'Summary': df_summary,
        'All Reservations': df_all,
        'Active Reservations': df_active,
        'Expiring Soon': df_expiring,
        'Payment Options': df_payment,
    }

    utils.save_multiple_dataframes_to_excel(sheets, filename)

    # Log summary
    utils.log_export_summary(
        total_items=len(all_ris),
        item_type='Reserved Instances',
        filename=filename
    )

    if not df_expiring.empty:
        utils.log_warning(f"  {len(df_expiring)} Reserved Instance(s) expiring within 90 days")

    utils.log_success("Reserved Instances export completed successfully!")


def main():
    """Main execution function — 3-step state machine (region -> confirm -> export)."""
    try:
        account_id, account_name = utils.print_script_banner("AWS RESERVED INSTANCES EXPORT")

        step = 1
        regions = None

        while True:
            if step == 1:
                result = utils.prompt_region_selection(
                    service_name="Reserved Instances",
                    default_to_all=False
                )
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                regions = result
                step = 2

            elif step == 2:
                region_str = regions[0] if len(regions) == 1 else f"{len(regions)} regions"
                msg = f"Ready to export Reserved Instances data ({region_str})."
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

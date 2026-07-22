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
from datetime import datetime, timezone
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
args = utils.parse_script_args("Export EC2 Reserved Instances to Excel")

utils.setup_logging('reserved-instances-export')


def _build_ec2_ri_row(ri: dict, region: str) -> dict[str, Any]:
    """Build a single EC2 Reserved Instance export row."""
    return {
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
    }


def _scan_ec2_ri_region(region: str) -> list[dict[str, Any]]:
    """
    Collect EC2 Reserved Instances from a single region.

    This is a primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the
    region as failed instead of silently reporting "no Reserved Instances"
    (the silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed RIs are skipped (logged) rather than aborting the
    whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    ec2 = utils.get_boto3_client('ec2', region_name=region)
    reserved_instances = []

    response = ec2.describe_reserved_instances()

    for ri in response.get('ReservedInstances', []):
        try:
            reserved_instances.append(_build_ec2_ri_row(ri, region))
        except Exception as e:
            utils.log_error(
                f"Skipping malformed EC2 Reserved Instance in {region}: "
                f"{ri.get('ReservedInstancesId', '<unknown>')}",
                e,
            )
            continue

    return reserved_instances


def collect_ec2_reserved_instances(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect EC2 Reserved Instances across regions, surfacing failures.

    Returns:
        tuple: ``(reserved_instances, failed_regions)`` where ``failed_regions``
        is a list of ``(region, error_message)`` tuples.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_ec2_ri_region,
        show_progress=True,
        collect_failures=True,
    )
    all_ris = [ri for result in region_results for ri in result]
    failed_regions = [(region, f"EC2 RI: {error}") for region, error in failed_regions]
    return all_ris, failed_regions


def _build_rds_ri_row(ri: dict, region: str) -> dict[str, Any]:
    """Build a single RDS Reserved DB Instance export row."""
    return {
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
    }


def _scan_rds_ri_region(region: str) -> list[dict[str, Any]]:
    """Collect RDS Reserved DB Instances from a single region. Raises on failure — see _scan_ec2_ri_region."""
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    rds = utils.get_boto3_client('rds', region_name=region)
    reserved_instances = []

    paginator = rds.get_paginator('describe_reserved_db_instances')
    for page in paginator.paginate():
        for ri in page.get('ReservedDBInstances', []):
            try:
                reserved_instances.append(_build_rds_ri_row(ri, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed RDS Reserved Instance in {region}: "
                    f"{ri.get('ReservedDBInstanceId', '<unknown>')}",
                    e,
                )
                continue

    return reserved_instances


def collect_rds_reserved_instances(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """Collect RDS Reserved DB Instances across regions, surfacing failures."""
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_rds_ri_region,
        show_progress=True,
        collect_failures=True,
    )
    all_ris = [ri for result in region_results for ri in result]
    failed_regions = [(region, f"RDS RI: {error}") for region, error in failed_regions]
    return all_ris, failed_regions


def _build_elasticache_ri_row(ri: dict, region: str) -> dict[str, Any]:
    """Build a single ElastiCache Reserved Cache Node export row."""
    return {
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
    }


def _scan_elasticache_ri_region(region: str) -> list[dict[str, Any]]:
    """Collect ElastiCache Reserved Cache Nodes from a single region. Raises on failure — see _scan_ec2_ri_region."""
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    elasticache = utils.get_boto3_client('elasticache', region_name=region)
    reserved_instances = []

    paginator = elasticache.get_paginator('describe_reserved_cache_nodes')
    for page in paginator.paginate():
        for ri in page.get('ReservedCacheNodes', []):
            try:
                reserved_instances.append(_build_elasticache_ri_row(ri, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed ElastiCache Reserved Cache Node in {region}: "
                    f"{ri.get('ReservedCacheNodeId', '<unknown>')}",
                    e,
                )
                continue

    return reserved_instances


def collect_elasticache_reserved_instances(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """Collect ElastiCache Reserved Cache Nodes across regions, surfacing failures."""
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_elasticache_ri_region,
        show_progress=True,
        collect_failures=True,
    )
    all_ris = [ri for result in region_results for ri in result]
    failed_regions = [(region, f"ElastiCache RI: {error}") for region, error in failed_regions]
    return all_ris, failed_regions


def _build_opensearch_ri_row(ri: dict, region: str) -> dict[str, Any]:
    """Build a single OpenSearch Reserved Instance export row."""
    return {
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
    }


def _scan_opensearch_ri_region(region: str) -> list[dict[str, Any]]:
    """Collect OpenSearch Reserved Instances from a single region. Raises on failure — see _scan_ec2_ri_region."""
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    opensearch = utils.get_boto3_client('es', region_name=region)  # 'es' is the service name
    reserved_instances = []

    response = opensearch.describe_reserved_elasticsearch_instances()

    for ri in response.get('ReservedElasticsearchInstances', []):
        try:
            reserved_instances.append(_build_opensearch_ri_row(ri, region))
        except Exception as e:
            utils.log_error(
                f"Skipping malformed OpenSearch Reserved Instance in {region}: "
                f"{ri.get('ReservedElasticsearchInstanceId', '<unknown>')}",
                e,
            )
            continue

    return reserved_instances


def collect_opensearch_reserved_instances(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """Collect OpenSearch Reserved Instances across regions, surfacing failures."""
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_opensearch_ri_region,
        show_progress=True,
        collect_failures=True,
    )
    all_ris = [ri for result in region_results for ri in result]
    failed_regions = [(region, f"OpenSearch RI: {error}") for region, error in failed_regions]
    return all_ris, failed_regions


def _build_redshift_ri_row(ri: dict, region: str) -> dict[str, Any]:
    """Build a single Redshift Reserved Node export row."""
    return {
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
    }


def _scan_redshift_ri_region(region: str) -> list[dict[str, Any]]:
    """Collect Redshift Reserved Nodes from a single region. Raises on failure — see _scan_ec2_ri_region."""
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    redshift = utils.get_boto3_client('redshift', region_name=region)
    reserved_instances = []

    paginator = redshift.get_paginator('describe_reserved_nodes')
    for page in paginator.paginate():
        for ri in page.get('ReservedNodes', []):
            try:
                reserved_instances.append(_build_redshift_ri_row(ri, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed Redshift Reserved Node in {region}: "
                    f"{ri.get('ReservedNodeId', '<unknown>')}",
                    e,
                )
                continue

    return reserved_instances


def collect_redshift_reserved_instances(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """Collect Redshift Reserved Nodes across regions, surfacing failures."""
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_redshift_ri_region,
        show_progress=True,
        collect_failures=True,
    )
    all_ris = [ri for result in region_results for ri in result]
    failed_regions = [(region, f"Redshift RI: {error}") for region, error in failed_regions]
    return all_ris, failed_regions


def _build_memorydb_ri_row(ri: dict, region: str) -> dict[str, Any]:
    """Build a single MemoryDB Reserved Node export row."""
    return {
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
    }


def _scan_memorydb_ri_region(region: str) -> list[dict[str, Any]]:
    """Collect MemoryDB Reserved Nodes from a single region. Raises on failure — see _scan_ec2_ri_region."""
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    memorydb = utils.get_boto3_client('memorydb', region_name=region)
    reserved_instances = []

    paginator = memorydb.get_paginator('describe_reserved_nodes')
    for page in paginator.paginate():
        for ri in page.get('ReservedNodes', []):
            try:
                reserved_instances.append(_build_memorydb_ri_row(ri, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed MemoryDB Reserved Node in {region}: "
                    f"{ri.get('ReservedNodeId', '<unknown>')}",
                    e,
                )
                continue

    return reserved_instances


def collect_memorydb_reserved_instances(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """Collect MemoryDB Reserved Nodes across regions, surfacing failures."""
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_memorydb_ri_region,
        show_progress=True,
        collect_failures=True,
    )
    all_ris = [ri for result in region_results for ri in result]
    failed_regions = [(region, f"MemoryDB RI: {error}") for region, error in failed_regions]
    return all_ris, failed_regions


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


def _run_export(account_id: str, account_name: str, regions: list[str]) -> None:
    """Collect Reserved Instance data and write the Excel export."""
    utils.log_info(f"Exporting Reserved Instance data for account: {account_name} ({utils.mask_account_id(account_id)})")
    utils.log_info(f"Scanning {len(regions)} region(s) for Reserved Instances...")

    # Collect each RI scope (EC2, RDS, ElastiCache, OpenSearch, Redshift,
    # MemoryDB). Each scope wrapper uses scan_regions_concurrent(...,
    # collect_failures=True) so a region-level API failure is surfaced as a
    # failed region rather than silently collapsed into "no RIs" (the
    # silent-collection-loss bug — see
    # .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).
    ec2_ris, ec2_failed = collect_ec2_reserved_instances(regions)
    rds_ris, rds_failed = collect_rds_reserved_instances(regions)
    elasticache_ris, elasticache_failed = collect_elasticache_reserved_instances(regions)
    opensearch_ris, opensearch_failed = collect_opensearch_reserved_instances(regions)
    redshift_ris, redshift_failed = collect_redshift_reserved_instances(regions)
    memorydb_ris, memorydb_failed = collect_memorydb_reserved_instances(regions)

    utils.log_info(f"  EC2: {len(ec2_ris)}, RDS: {len(rds_ris)}, "
                 f"ElastiCache: {len(elasticache_ris)}, OpenSearch: {len(opensearch_ris)}, "
                 f"Redshift: {len(redshift_ris)}, MemoryDB: {len(memorydb_ris)}")

    all_ris = []
    all_ris.extend(ec2_ris)
    all_ris.extend(rds_ris)
    all_ris.extend(elasticache_ris)
    all_ris.extend(opensearch_ris)
    all_ris.extend(redshift_ris)
    all_ris.extend(memorydb_ris)

    # Merge every scope's failed regions into ONE combined list, so a single
    # failure marker + non-zero exit covers all RI services.
    failed_regions = (
        ec2_failed + rds_failed + elasticache_failed +
        opensearch_failed + redshift_failed + memorydb_failed
    )

    if not all_ris and not failed_regions:
        # Genuinely empty account: every scope/region succeeded and returned nothing.
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
    if not df_expiring.empty:
        utils.log_warning(f"  {len(df_expiring)} Reserved Instance(s) expiring within 90 days")

    utils.log_success("Reserved Instances export completed successfully!")

    # If ANY RI scope failed for ANY region, make it loud: write a marker and
    # exit non-zero, even though the always-written Summary sheet above means
    # a workbook still lands (Tier-3 PARTIAL). A zero-row-looking sheet that
    # is actually a failed scope is exactly the silent-loss failure mode this
    # guards against.
    if failed_regions:
        utils.report_collection_failures(account_name, 'reserved-instances', failed_regions)
        print(
            "\nERROR: Reserved Instances export completed with failures — data is incomplete. "
            "See the *-reserved-instances-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    """Main execution function — 3-step state machine (region -> confirm -> export)."""
    try:
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return
        global pd
        import pandas as pd
        account_id, account_name = utils.print_script_banner("AWS RESERVED INSTANCES EXPORT")

        step = 1
        regions = None

        while True:
            if step == 1:
                result = utils.prompt_region_selection(
                    service_name="Reserved Instances"
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

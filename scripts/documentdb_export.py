#!/usr/bin/env python3
"""
DocumentDB Export Script for StratusScan

Exports comprehensive AWS DocumentDB (MongoDB-compatible) cluster and instance information
including cluster details, instances, snapshots, subnet groups, and parameter groups.

Features:
- DocumentDB Clusters: Configuration, encryption, backup retention
- DocumentDB Instances: Instance details, status, endpoint information
- Cluster Snapshots: Backup information and restore points
- Subnet Groups: VPC and subnet associations
- Summary: Resource counts and key metrics

Output: Excel file with 5 worksheets
"""

import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

try:
    import pandas as pd
except ImportError:
    utils.log_error("pandas library is required but not installed")
    utils.log_error("Install with: pip install pandas")
    sys.exit(1)


def _scan_documentdb_clusters_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for DocumentDB clusters."""
    clusters_data = []

    try:
        docdb_client = utils.get_boto3_client('docdb', region_name=region)

        paginator = docdb_client.get_paginator('describe_db_clusters')
        for page in paginator.paginate():
            db_clusters = page.get('DBClusters', [])

            for cluster in db_clusters:
                cluster_id = cluster.get('DBClusterIdentifier', 'N/A')

                # Basic cluster information
                engine = cluster.get('Engine', 'N/A')
                engine_version = cluster.get('EngineVersion', 'N/A')
                status = cluster.get('Status', 'unknown')

                # Endpoint information
                endpoint = cluster.get('Endpoint', 'N/A')
                reader_endpoint = cluster.get('ReaderEndpoint', 'N/A')
                port = cluster.get('Port', 0)

                # Member instances
                cluster_members = cluster.get('DBClusterMembers', [])
                member_count = len(cluster_members)

                # Primary instance identifier
                primary_instance = 'N/A'
                for member in cluster_members:
                    if member.get('IsClusterWriter', False):
                        primary_instance = member.get('DBInstanceIdentifier', 'N/A')
                        break

                # Multi-AZ and availability zones
                multi_az = cluster.get('MultiAZ', False)
                availability_zones = cluster.get('AvailabilityZones', [])
                az_list = ', '.join(availability_zones) if availability_zones else 'N/A'

                # Backup configuration
                backup_retention_period = cluster.get('BackupRetentionPeriod', 0)
                preferred_backup_window = cluster.get('PreferredBackupWindow', 'N/A')
                preferred_maintenance_window = cluster.get('PreferredMaintenanceWindow', 'N/A')

                # Encryption
                storage_encrypted = cluster.get('StorageEncrypted', False)
                kms_key_id = cluster.get('KmsKeyId', 'N/A')
                if kms_key_id != 'N/A' and '/' in kms_key_id:
                    kms_key_id = kms_key_id.split('/')[-1]  # Extract key ID from ARN

                # Deletion protection
                deletion_protection = cluster.get('DeletionProtection', False)

                # Cluster creation time
                cluster_create_time = cluster.get('ClusterCreateTime')
                if cluster_create_time:
                    cluster_create_time_str = cluster_create_time.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    cluster_create_time_str = 'N/A'

                # VPC security groups
                vpc_security_groups = cluster.get('VpcSecurityGroups', [])
                security_group_ids = [sg.get('VpcSecurityGroupId', '') for sg in vpc_security_groups]
                security_groups_str = ', '.join(security_group_ids) if security_group_ids else 'N/A'

                # DB subnet group
                db_subnet_group = cluster.get('DBSubnetGroup', 'N/A')
                if isinstance(db_subnet_group, dict):
                    db_subnet_group = db_subnet_group.get('DBSubnetGroupName', 'N/A')

                # Cluster parameter group
                db_cluster_parameter_group = cluster.get('DBClusterParameterGroup', 'N/A')

                # Enabled CloudWatch logs exports
                enabled_cloudwatch_logs_exports = cluster.get('EnabledCloudwatchLogsExports', [])
                logs_exports_str = ', '.join(enabled_cloudwatch_logs_exports) if enabled_cloudwatch_logs_exports else 'None'

                clusters_data.append({
                    'Region': region,
                    'Cluster ID': cluster_id,
                    'Engine': engine,
                    'Engine Version': engine_version,
                    'Status': status,
                    'Endpoint': endpoint,
                    'Reader Endpoint': reader_endpoint,
                    'Port': port,
                    'Member Instances': member_count,
                    'Primary Instance': primary_instance,
                    'Multi-AZ': 'Yes' if multi_az else 'No',
                    'Availability Zones': az_list,
                    'Backup Retention (Days)': backup_retention_period,
                    'Backup Window': preferred_backup_window,
                    'Maintenance Window': preferred_maintenance_window,
                    'Storage Encrypted': 'Yes' if storage_encrypted else 'No',
                    'KMS Key ID': kms_key_id if storage_encrypted else 'N/A',
                    'Deletion Protection': 'Yes' if deletion_protection else 'No',
                    'Created': cluster_create_time_str,
                    'Security Groups': security_groups_str,
                    'Subnet Group': db_subnet_group,
                    'Parameter Group': db_cluster_parameter_group,
                    'CloudWatch Logs': logs_exports_str,
                })

    except Exception as e:
        utils.log_error(f"Error collecting DocumentDB clusters in {region}", e)

    return clusters_data


@utils.aws_error_handler("Collecting DocumentDB clusters", default_return=[])
def collect_documentdb_clusters(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect DocumentDB cluster information from AWS regions."""
    results = utils.scan_regions_concurrent(regions, _scan_documentdb_clusters_region)
    all_clusters = [cluster for result in results for cluster in result]
    utils.log_success(f"Collected {len(all_clusters)} DocumentDB clusters")
    return all_clusters


def _scan_documentdb_instances_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for DocumentDB instances."""
    instances_data = []

    try:
        docdb_client = utils.get_boto3_client('docdb', region_name=region)

        paginator = docdb_client.get_paginator('describe_db_instances')
        # Filter for DocumentDB instances only (engine = docdb)
        for page in paginator.paginate(Filters=[{'Name': 'engine', 'Values': ['docdb']}]):
            db_instances = page.get('DBInstances', [])

            for instance in db_instances:
                instance_id = instance.get('DBInstanceIdentifier', 'N/A')

                # Basic instance information
                instance_class = instance.get('DBInstanceClass', 'N/A')
                engine = instance.get('Engine', 'N/A')
                engine_version = instance.get('EngineVersion', 'N/A')
                status = instance.get('DBInstanceStatus', 'unknown')

                # Cluster membership
                cluster_id = instance.get('DBClusterIdentifier', 'N/A')

                # Endpoint information
                endpoint = instance.get('Endpoint', {})
                endpoint_address = endpoint.get('Address', 'N/A') if endpoint else 'N/A'
                endpoint_port = endpoint.get('Port', 0) if endpoint else 0

                # Availability zone
                availability_zone = instance.get('AvailabilityZone', 'N/A')

                # Instance role (writer or reader)
                promotion_tier = instance.get('PromotionTier', 'N/A')

                # Auto minor version upgrade
                auto_minor_version_upgrade = instance.get('AutoMinorVersionUpgrade', False)

                # Preferred maintenance window
                preferred_maintenance_window = instance.get('PreferredMaintenanceWindow', 'N/A')

                # Instance creation time
                instance_create_time = instance.get('InstanceCreateTime')
                if instance_create_time:
                    instance_create_time_str = instance_create_time.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    instance_create_time_str = 'N/A'

                # CA certificate identifier
                ca_certificate_identifier = instance.get('CACertificateIdentifier', 'N/A')

                # Enabled CloudWatch logs exports
                enabled_cloudwatch_logs_exports = instance.get('EnabledCloudwatchLogsExports', [])
                logs_exports_str = ', '.join(enabled_cloudwatch_logs_exports) if enabled_cloudwatch_logs_exports else 'None'

                instances_data.append({
                    'Region': region,
                    'Instance ID': instance_id,
                    'Cluster ID': cluster_id,
                    'Instance Class': instance_class,
                    'Engine': engine,
                    'Engine Version': engine_version,
                    'Status': status,
                    'Endpoint': endpoint_address,
                    'Port': endpoint_port,
                    'Availability Zone': availability_zone,
                    'Promotion Tier': promotion_tier,
                    'Auto Minor Version Upgrade': 'Yes' if auto_minor_version_upgrade else 'No',
                    'Maintenance Window': preferred_maintenance_window,
                    'Created': instance_create_time_str,
                    'CA Certificate': ca_certificate_identifier,
                    'CloudWatch Logs': logs_exports_str,
                })

    except Exception as e:
        utils.log_error(f"Error collecting DocumentDB instances in {region}", e)

    return instances_data


@utils.aws_error_handler("Collecting DocumentDB instances", default_return=[])
def collect_documentdb_instances(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect DocumentDB instance information from AWS regions."""
    results = utils.scan_regions_concurrent(regions, _scan_documentdb_instances_region)
    all_instances = [instance for result in results for instance in result]
    utils.log_success(f"Collected {len(all_instances)} DocumentDB instances")
    return all_instances


def _scan_documentdb_snapshots_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for DocumentDB cluster snapshots."""
    snapshots_data = []

    try:
        docdb_client = utils.get_boto3_client('docdb', region_name=region)

        paginator = docdb_client.get_paginator('describe_db_cluster_snapshots')
        for page in paginator.paginate():
            db_snapshots = page.get('DBClusterSnapshots', [])

            for snapshot in db_snapshots:
                snapshot_id = snapshot.get('DBClusterSnapshotIdentifier', 'N/A')

                # Basic snapshot information
                cluster_id = snapshot.get('DBClusterIdentifier', 'N/A')
                snapshot_type = snapshot.get('SnapshotType', 'N/A')  # manual or automated
                status = snapshot.get('Status', 'unknown')

                # Snapshot creation time
                snapshot_create_time = snapshot.get('SnapshotCreateTime')
                if snapshot_create_time:
                    snapshot_create_time_str = snapshot_create_time.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    snapshot_create_time_str = 'N/A'

                # Engine information
                engine = snapshot.get('Engine', 'N/A')
                engine_version = snapshot.get('EngineVersion', 'N/A')

                # Storage information
                allocated_storage = snapshot.get('AllocatedStorage', 0)
                storage_encrypted = snapshot.get('StorageEncrypted', False)
                kms_key_id = snapshot.get('KmsKeyId', 'N/A')
                if kms_key_id != 'N/A' and '/' in kms_key_id:
                    kms_key_id = kms_key_id.split('/')[-1]  # Extract key ID from ARN

                # Availability zones
                availability_zones = snapshot.get('AvailabilityZones', [])
                az_list = ', '.join(availability_zones) if availability_zones else 'N/A'

                # VPC ID
                vpc_id = snapshot.get('VpcId', 'N/A')

                # Percent progress
                percent_progress = snapshot.get('PercentProgress', 0)

                # Cluster snapshot ARN
                snapshot_arn = snapshot.get('DBClusterSnapshotArn', 'N/A')

                snapshots_data.append({
                    'Region': region,
                    'Snapshot ID': snapshot_id,
                    'Cluster ID': cluster_id,
                    'Snapshot Type': snapshot_type.upper(),
                    'Status': status,
                    'Created': snapshot_create_time_str,
                    'Engine': engine,
                    'Engine Version': engine_version,
                    'Allocated Storage (GB)': allocated_storage,
                    'Storage Encrypted': 'Yes' if storage_encrypted else 'No',
                    'KMS Key ID': kms_key_id if storage_encrypted else 'N/A',
                    'Availability Zones': az_list,
                    'VPC ID': vpc_id,
                    'Progress (%)': percent_progress,
                    'Snapshot ARN': snapshot_arn,
                })

    except Exception as e:
        utils.log_error(f"Error collecting DocumentDB snapshots in {region}", e)

    return snapshots_data


@utils.aws_error_handler("Collecting DocumentDB snapshots", default_return=[])
def collect_documentdb_snapshots(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect DocumentDB cluster snapshot information from AWS regions."""
    results = utils.scan_regions_concurrent(regions, _scan_documentdb_snapshots_region)
    all_snapshots = [snapshot for result in results for snapshot in result]
    utils.log_success(f"Collected {len(all_snapshots)} DocumentDB snapshots")
    return all_snapshots


def _scan_documentdb_subnet_groups_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for DocumentDB subnet groups."""
    subnet_groups_data = []

    try:
        docdb_client = utils.get_boto3_client('docdb', region_name=region)

        paginator = docdb_client.get_paginator('describe_db_subnet_groups')
        for page in paginator.paginate():
            db_subnet_groups = page.get('DBSubnetGroups', [])

            for sg in db_subnet_groups:
                subnet_group_name = sg.get('DBSubnetGroupName', 'N/A')

                # Description
                description = sg.get('DBSubnetGroupDescription', 'N/A')

                # VPC ID
                vpc_id = sg.get('VpcId', 'N/A')

                # Subnet information
                subnets = sg.get('Subnets', [])
                subnet_count = len(subnets)

                # Extract subnet IDs and availability zones
                subnet_ids = [s.get('SubnetIdentifier', '') for s in subnets]
                subnet_ids_str = ', '.join(subnet_ids) if subnet_ids else 'N/A'

                azs = set([s.get('SubnetAvailabilityZone', {}).get('Name', '')
                          for s in subnets if s.get('SubnetAvailabilityZone')])
                az_list = ', '.join(sorted(azs)) if azs else 'N/A'

                # Subnet group status
                subnet_group_status = sg.get('SubnetGroupStatus', 'unknown')

                # ARN
                subnet_group_arn = sg.get('DBSubnetGroupArn', 'N/A')

                subnet_groups_data.append({
                    'Region': region,
                    'Subnet Group Name': subnet_group_name,
                    'Description': description,
                    'VPC ID': vpc_id,
                    'Subnet Count': subnet_count,
                    'Subnet IDs': subnet_ids_str,
                    'Availability Zones': az_list,
                    'Status': subnet_group_status,
                    'Subnet Group ARN': subnet_group_arn,
                })

    except Exception as e:
        utils.log_error(f"Error collecting DocumentDB subnet groups in {region}", e)

    return subnet_groups_data


@utils.aws_error_handler("Collecting DocumentDB subnet groups", default_return=[])
def collect_documentdb_subnet_groups(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect DocumentDB subnet group information from AWS regions."""
    results = utils.scan_regions_concurrent(regions, _scan_documentdb_subnet_groups_region)
    all_subnet_groups = [sg for result in results for sg in result]
    utils.log_success(f"Collected {len(all_subnet_groups)} DocumentDB subnet groups")
    return all_subnet_groups


def generate_summary(clusters: List[Dict[str, Any]],
                     instances: List[Dict[str, Any]],
                     snapshots: List[Dict[str, Any]],
                     subnet_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for DocumentDB resources."""
    summary = []

    # Overall counts
    summary.append({
        'Metric': 'Total DocumentDB Clusters',
        'Count': len(clusters),
        'Details': f"{len([c for c in clusters if c['Status'] == 'available'])} available"
    })

    summary.append({
        'Metric': 'Total DocumentDB Instances',
        'Count': len(instances),
        'Details': f"{len([i for i in instances if i['Status'] == 'available'])} available"
    })

    summary.append({
        'Metric': 'Total Cluster Snapshots',
        'Count': len(snapshots),
        'Details': f"{len([s for s in snapshots if s['Snapshot Type'] == 'MANUAL'])} manual, {len([s for s in snapshots if s['Snapshot Type'] == 'AUTOMATED'])} automated"
    })

    summary.append({
        'Metric': 'Total Subnet Groups',
        'Count': len(subnet_groups),
        'Details': f"{sum(sg['Subnet Count'] for sg in subnet_groups)} total subnets"
    })

    # Encryption statistics for clusters
    encrypted_clusters = len([c for c in clusters if c['Storage Encrypted'] == 'Yes'])
    summary.append({
        'Metric': 'Encrypted Clusters',
        'Count': encrypted_clusters,
        'Details': f"{encrypted_clusters}/{len(clusters)} clusters encrypted" if clusters else "N/A"
    })

    # Deletion protection statistics
    protected_clusters = len([c for c in clusters if c['Deletion Protection'] == 'Yes'])
    summary.append({
        'Metric': 'Deletion Protected Clusters',
        'Count': protected_clusters,
        'Details': f"{protected_clusters}/{len(clusters)} clusters protected" if clusters else "N/A"
    })

    # Multi-AZ statistics
    multi_az_clusters = len([c for c in clusters if c['Multi-AZ'] == 'Yes'])
    summary.append({
        'Metric': 'Multi-AZ Clusters',
        'Count': multi_az_clusters,
        'Details': f"{multi_az_clusters}/{len(clusters)} clusters multi-AZ" if clusters else "N/A"
    })

    # Backup retention statistics
    if clusters:
        avg_retention = sum(c['Backup Retention (Days)'] for c in clusters) / len(clusters)
        summary.append({
            'Metric': 'Average Backup Retention',
            'Count': round(avg_retention, 1),
            'Details': f"{round(avg_retention, 1)} days average"
        })

    # Clusters by region
    if clusters:
        regions = {}
        for cluster in clusters:
            region = cluster['Region']
            regions[region] = regions.get(region, 0) + 1

        region_details = ', '.join([f"{region}: {count}" for region, count in sorted(regions.items())])
        summary.append({
            'Metric': 'Clusters by Region',
            'Count': len(regions),
            'Details': region_details
        })

    # Instance classes distribution
    if instances:
        instance_classes = {}
        for instance in instances:
            instance_class = instance['Instance Class']
            instance_classes[instance_class] = instance_classes.get(instance_class, 0) + 1

        top_classes = sorted(instance_classes.items(), key=lambda x: x[1], reverse=True)[:3]
        class_details = ', '.join([f"{cls}: {count}" for cls, count in top_classes])
        summary.append({
            'Metric': 'Top Instance Classes',
            'Count': len(instance_classes),
            'Details': class_details
        })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    # Check dependencies
    if not utils.check_dependencies(['pandas', 'openpyxl', 'boto3']):
        utils.log_error("Required dependencies not installed")
        return

    # Get account information
    account_id, account_name = utils.get_account_info()
    utils.log_info(f"Account: {account_name} ({utils.mask_account_id(account_id)})")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Collect data
    print("\n=== Collecting DocumentDB Data ===")
    clusters = collect_documentdb_clusters(regions)
    instances = collect_documentdb_instances(regions)
    snapshots = collect_documentdb_snapshots(regions)
    subnet_groups = collect_documentdb_subnet_groups(regions)

    # Generate summary
    summary = generate_summary(clusters, instances, snapshots, subnet_groups)

    # Convert to DataFrames
    clusters_df = pd.DataFrame(clusters) if clusters else pd.DataFrame()
    instances_df = pd.DataFrame(instances) if instances else pd.DataFrame()
    snapshots_df = pd.DataFrame(snapshots) if snapshots else pd.DataFrame()
    subnet_groups_df = pd.DataFrame(subnet_groups) if subnet_groups else pd.DataFrame()
    summary_df = pd.DataFrame(summary)

    # Prepare DataFrames for export
    if not clusters_df.empty:
        clusters_df = utils.prepare_dataframe_for_export(clusters_df)
    if not instances_df.empty:
        instances_df = utils.prepare_dataframe_for_export(instances_df)
    if not snapshots_df.empty:
        snapshots_df = utils.prepare_dataframe_for_export(snapshots_df)
    if not subnet_groups_df.empty:
        subnet_groups_df = utils.prepare_dataframe_for_export(subnet_groups_df)
    if not summary_df.empty:
        summary_df = utils.prepare_dataframe_for_export(summary_df)

    # Create export filename (region_suffix already set earlier)
    filename = utils.create_export_filename(account_name, 'documentdb', region_suffix)

    # Save to Excel with multiple sheets
    print("\n=== Exporting to Excel ===")
    dataframes = {
        'DocumentDB Clusters': clusters_df,
        'DocumentDB Instances': instances_df,
        'Cluster Snapshots': snapshots_df,
        'Subnet Groups': subnet_groups_df,
        'Summary': summary_df
    }

    if utils.save_multiple_dataframes_to_excel(dataframes, filename):
        utils.log_export_summary(
            filename=filename,
            total_items=len(clusters) + len(instances) + len(snapshots) + len(subnet_groups),
            details={
                'Clusters': len(clusters),
                'Instances': len(instances),
                'Snapshots': len(snapshots),
                'Subnet Groups': len(subnet_groups)
            }
        )

    utils.log_script_end(script_name)


if __name__ == "__main__":
    main()

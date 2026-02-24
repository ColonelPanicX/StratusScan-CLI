#!/usr/bin/env python3
"""
Neptune Export Script for StratusScan

Exports comprehensive AWS Neptune (Graph Database) cluster and instance information
including cluster details, instances, snapshots, endpoints, and parameter groups.

Features:
- Neptune Clusters: Configuration, encryption, backup retention
- Neptune Instances: Instance details, status, endpoint information
- Cluster Snapshots: Backup information and restore points
- Cluster Endpoints: Custom endpoints for workload routing
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


@utils.aws_error_handler("Collecting Neptune clusters", default_return=[])
def collect_neptune_clusters(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Neptune cluster information from AWS regions."""
    all_clusters = []

    for region in regions:
        utils.log_info(f"Scanning Neptune clusters in {region}...")
        neptune_client = utils.get_boto3_client('neptune', region_name=region)

        paginator = neptune_client.get_paginator('describe_db_clusters')
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

                # IAM database authentication
                iam_database_authentication_enabled = cluster.get('IAMDatabaseAuthenticationEnabled', False)

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

                # Cluster parameter group
                db_cluster_parameter_group = cluster.get('DBClusterParameterGroup', 'N/A')

                # Enabled CloudWatch logs exports
                enabled_cloudwatch_logs_exports = cluster.get('EnabledCloudwatchLogsExports', [])
                logs_exports_str = ', '.join(enabled_cloudwatch_logs_exports) if enabled_cloudwatch_logs_exports else 'None'

                # Serverless v2 scaling configuration
                serverless_v2_scaling = cluster.get('ServerlessV2ScalingConfiguration', {})
                if serverless_v2_scaling:
                    min_capacity = serverless_v2_scaling.get('MinCapacity', 'N/A')
                    max_capacity = serverless_v2_scaling.get('MaxCapacity', 'N/A')
                    serverless_config = f"Min: {min_capacity}, Max: {max_capacity}"
                else:
                    serverless_config = 'N/A'

                all_clusters.append({
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
                    'IAM Auth Enabled': 'Yes' if iam_database_authentication_enabled else 'No',
                    'Deletion Protection': 'Yes' if deletion_protection else 'No',
                    'Serverless v2 Config': serverless_config,
                    'Created': cluster_create_time_str,
                    'Security Groups': security_groups_str,
                    'Subnet Group': db_subnet_group,
                    'Parameter Group': db_cluster_parameter_group,
                    'CloudWatch Logs': logs_exports_str,
                })

        utils.log_success(f"Collected {len([c for c in all_clusters if c['Region'] == region])} Neptune clusters from {region}")

    return all_clusters


@utils.aws_error_handler("Collecting Neptune instances", default_return=[])
def collect_neptune_instances(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Neptune instance information from AWS regions."""
    all_instances = []

    for region in regions:
        utils.log_info(f"Scanning Neptune instances in {region}...")
        neptune_client = utils.get_boto3_client('neptune', region_name=region)

        paginator = neptune_client.get_paginator('describe_db_instances')
        # Filter for Neptune instances only (engine = neptune)
        for page in paginator.paginate(Filters=[{'Name': 'engine', 'Values': ['neptune']}]):
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

                # Storage type
                storage_type = instance.get('StorageType', 'N/A')

                # Performance Insights
                performance_insights_enabled = instance.get('PerformanceInsightsEnabled', False)

                # Enabled CloudWatch logs exports
                enabled_cloudwatch_logs_exports = instance.get('EnabledCloudwatchLogsExports', [])
                logs_exports_str = ', '.join(enabled_cloudwatch_logs_exports) if enabled_cloudwatch_logs_exports else 'None'

                all_instances.append({
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
                    'Storage Type': storage_type,
                    'Auto Minor Version Upgrade': 'Yes' if auto_minor_version_upgrade else 'No',
                    'Performance Insights': 'Enabled' if performance_insights_enabled else 'Disabled',
                    'Maintenance Window': preferred_maintenance_window,
                    'Created': instance_create_time_str,
                    'CA Certificate': ca_certificate_identifier,
                    'CloudWatch Logs': logs_exports_str,
                })

        utils.log_success(f"Collected {len([i for i in all_instances if i['Region'] == region])} Neptune instances from {region}")

    return all_instances


@utils.aws_error_handler("Collecting Neptune snapshots", default_return=[])
def collect_neptune_snapshots(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Neptune cluster snapshot information from AWS regions."""
    all_snapshots = []

    for region in regions:
        utils.log_info(f"Scanning Neptune snapshots in {region}...")
        neptune_client = utils.get_boto3_client('neptune', region_name=region)

        paginator = neptune_client.get_paginator('describe_db_cluster_snapshots')
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

                # IAM database authentication
                iam_database_authentication_enabled = snapshot.get('IAMDatabaseAuthenticationEnabled', False)

                # Cluster snapshot ARN
                snapshot_arn = snapshot.get('DBClusterSnapshotArn', 'N/A')

                all_snapshots.append({
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
                    'IAM Auth Enabled': 'Yes' if iam_database_authentication_enabled else 'No',
                    'Availability Zones': az_list,
                    'VPC ID': vpc_id,
                    'Progress (%)': percent_progress,
                    'Snapshot ARN': snapshot_arn,
                })

        utils.log_success(f"Collected {len([s for s in all_snapshots if s['Region'] == region])} Neptune snapshots from {region}")

    return all_snapshots


@utils.aws_error_handler("Collecting Neptune cluster endpoints", default_return=[])
def collect_neptune_endpoints(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Neptune cluster custom endpoint information from AWS regions."""
    all_endpoints = []

    for region in regions:
        utils.log_info(f"Scanning Neptune cluster endpoints in {region}...")
        neptune_client = utils.get_boto3_client('neptune', region_name=region)

        # First, get all clusters to retrieve their endpoints
        paginator = neptune_client.get_paginator('describe_db_clusters')
        for page in paginator.paginate():
            db_clusters = page.get('DBClusters', [])

            for cluster in db_clusters:
                cluster_id = cluster.get('DBClusterIdentifier', 'N/A')

                # Try to describe custom endpoints for this cluster
                try:
                    endpoint_paginator = neptune_client.get_paginator('describe_db_cluster_endpoints')
                    for endpoint_page in endpoint_paginator.paginate(
                        DBClusterIdentifier=cluster_id
                    ):
                        db_cluster_endpoints = endpoint_page.get('DBClusterEndpoints', [])

                        for endpoint in db_cluster_endpoints:
                            endpoint_id = endpoint.get('DBClusterEndpointIdentifier', 'N/A')
                            endpoint_type = endpoint.get('EndpointType', 'N/A')
                            custom_endpoint_type = endpoint.get('CustomEndpointType', 'N/A')
                            endpoint_address = endpoint.get('Endpoint', 'N/A')
                            status = endpoint.get('Status', 'unknown')

                            # Static members (instances included in endpoint)
                            static_members = endpoint.get('StaticMembers', [])
                            static_members_str = ', '.join(static_members) if static_members else 'N/A'

                            # Excluded members (instances excluded from endpoint)
                            excluded_members = endpoint.get('ExcludedMembers', [])
                            excluded_members_str = ', '.join(excluded_members) if excluded_members else 'N/A'

                            all_endpoints.append({
                                'Region': region,
                                'Cluster ID': cluster_id,
                                'Endpoint ID': endpoint_id,
                                'Endpoint Type': endpoint_type,
                                'Custom Endpoint Type': custom_endpoint_type,
                                'Endpoint Address': endpoint_address,
                                'Status': status,
                                'Static Members': static_members_str,
                                'Excluded Members': excluded_members_str,
                            })

                except Exception as e:
                    # Some clusters may not have custom endpoints, which is fine
                    utils.log_warning(f"Could not retrieve endpoints for cluster {cluster_id}: {str(e)}")
                    continue

        utils.log_success(f"Collected {len([e for e in all_endpoints if e['Region'] == region])} Neptune cluster endpoints from {region}")

    return all_endpoints


def generate_summary(clusters: List[Dict[str, Any]],
                     instances: List[Dict[str, Any]],
                     snapshots: List[Dict[str, Any]],
                     endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Neptune resources."""
    summary = []

    # Overall counts
    summary.append({
        'Metric': 'Total Neptune Clusters',
        'Count': len(clusters),
        'Details': f"{len([c for c in clusters if c['Status'] == 'available'])} available"
    })

    summary.append({
        'Metric': 'Total Neptune Instances',
        'Count': len(instances),
        'Details': f"{len([i for i in instances if i['Status'] == 'available'])} available"
    })

    summary.append({
        'Metric': 'Total Cluster Snapshots',
        'Count': len(snapshots),
        'Details': f"{len([s for s in snapshots if s['Snapshot Type'] == 'MANUAL'])} manual, {len([s for s in snapshots if s['Snapshot Type'] == 'AUTOMATED'])} automated"
    })

    summary.append({
        'Metric': 'Total Custom Endpoints',
        'Count': len(endpoints),
        'Details': f"{len([e for e in endpoints if e['Status'] == 'available'])} available"
    })

    # Encryption statistics for clusters
    encrypted_clusters = len([c for c in clusters if c['Storage Encrypted'] == 'Yes'])
    summary.append({
        'Metric': 'Encrypted Clusters',
        'Count': encrypted_clusters,
        'Details': f"{encrypted_clusters}/{len(clusters)} clusters encrypted" if clusters else "N/A"
    })

    # IAM database authentication
    iam_auth_clusters = len([c for c in clusters if c['IAM Auth Enabled'] == 'Yes'])
    summary.append({
        'Metric': 'IAM Auth Enabled Clusters',
        'Count': iam_auth_clusters,
        'Details': f"{iam_auth_clusters}/{len(clusters)} clusters with IAM auth" if clusters else "N/A"
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

    # Serverless v2 clusters
    serverless_clusters = len([c for c in clusters if c['Serverless v2 Config'] != 'N/A'])
    summary.append({
        'Metric': 'Serverless v2 Clusters',
        'Count': serverless_clusters,
        'Details': f"{serverless_clusters}/{len(clusters)} using Serverless v2" if clusters else "N/A"
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

    # Performance Insights usage
    if instances:
        pi_enabled = len([i for i in instances if i['Performance Insights'] == 'Enabled'])
        summary.append({
            'Metric': 'Performance Insights Enabled',
            'Count': pi_enabled,
            'Details': f"{pi_enabled}/{len(instances)} instances with Performance Insights"
        })

    return summary


def _run_export(account_id: str, account_name: str, regions: List[str]) -> None:
    """Collect Neptune data and write the Excel export."""
    print("\n=== Collecting Neptune Data ===")
    clusters = collect_neptune_clusters(regions)
    instances = collect_neptune_instances(regions)
    snapshots = collect_neptune_snapshots(regions)
    endpoints = collect_neptune_endpoints(regions)

    # Generate summary
    summary = generate_summary(clusters, instances, snapshots, endpoints)

    # Convert to DataFrames
    clusters_df = pd.DataFrame(clusters) if clusters else pd.DataFrame()
    instances_df = pd.DataFrame(instances) if instances else pd.DataFrame()
    snapshots_df = pd.DataFrame(snapshots) if snapshots else pd.DataFrame()
    endpoints_df = pd.DataFrame(endpoints) if endpoints else pd.DataFrame()
    summary_df = pd.DataFrame(summary)

    # Prepare DataFrames for export
    if not clusters_df.empty:
        clusters_df = utils.prepare_dataframe_for_export(clusters_df)
    if not instances_df.empty:
        instances_df = utils.prepare_dataframe_for_export(instances_df)
    if not snapshots_df.empty:
        snapshots_df = utils.prepare_dataframe_for_export(snapshots_df)
    if not endpoints_df.empty:
        endpoints_df = utils.prepare_dataframe_for_export(endpoints_df)
    if not summary_df.empty:
        summary_df = utils.prepare_dataframe_for_export(summary_df)

    # Create export filename
    region_suffix = regions[0] if len(regions) == 1 else 'all-regions'
    filename = utils.create_export_filename(account_name, 'neptune', region_suffix)

    # Save to Excel with multiple sheets
    print("\n=== Exporting to Excel ===")
    dataframes = {
        'Neptune Clusters': clusters_df,
        'Neptune Instances': instances_df,
        'Cluster Snapshots': snapshots_df,
        'Cluster Endpoints': endpoints_df,
        'Summary': summary_df
    }

    if utils.save_multiple_dataframes_to_excel(dataframes, filename):
        utils.log_export_summary(
            resource_type='Neptune',
            count=len(clusters) + len(instances) + len(snapshots) + len(endpoints),
            output_file=filename
        )


def main():
    """Main execution function — 3-step state machine (region -> confirm -> export)."""
    try:
        utils.setup_logging('neptune-export')
        account_id, account_name = utils.print_script_banner("AWS NEPTUNE EXPORT")

        utils.log_info(f"Account: {account_name} ({utils.mask_account_id(account_id)})")

        step = 1
        regions = None

        while True:
            if step == 1:
                result = utils.prompt_region_selection(service_name="Neptune")
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                regions = result
                step = 2

            elif step == 2:
                region_str = regions[0] if len(regions) == 1 else f"{len(regions)} regions"
                msg = f"Ready to export Neptune data ({region_str})."
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

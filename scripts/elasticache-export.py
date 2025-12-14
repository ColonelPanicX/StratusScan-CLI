#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS ElastiCache Export Tool
Version: v1.0.0
Date: NOV-09-2025

Description:
This script exports AWS ElastiCache information into an Excel file with multiple
worksheets. The output includes Redis and Memcached clusters, replication groups,
cache nodes, parameter groups, and subnet groups.

Features:
- Redis replication groups with automatic failover
- Memcached clusters with cache nodes
- Cache node details (instance type, status, AZ)
- Parameter groups and subnet groups
- Snapshot retention and backup windows
- Encryption at-rest and in-transit
"""

import sys
import datetime
from pathlib import Path
from typing import List, Dict, Any

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

# Initialize logging
SCRIPT_START_TIME = datetime.datetime.now()
utils.setup_logging("elasticache-export")
utils.log_script_start("elasticache-export.py", "AWS ElastiCache Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("               AWS ELASTICACHE EXPORT TOOL")
    print("====================================================================")
    print("Version: v1.0.0                        Date: NOV-09-2025")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")

    # Get the current AWS account ID
    try:
        sts_client = utils.get_boto3_client('sts')
        account_id = sts_client.get_caller_identity().get('Account')
        account_name = utils.get_account_name(account_id, default=account_id)

        print(f"Account ID: {account_id}")
        print(f"Account Name: {account_name}")
    except Exception as e:
        print("Could not determine account information.")
        utils.log_error("Error getting account information", e)
        account_id = "unknown"
        account_name = "unknown"

    print("====================================================================")
    return account_id, account_name


def get_aws_regions():
    """Get list of all available AWS regions for the current partition."""
    try:
        # Detect partition and get ALL regions for that partition
        partition = utils.detect_partition()
        regions = utils.get_partition_regions(partition, all_regions=True)
        utils.log_info(f"Retrieved {len(regions)} regions for partition {partition}")
        return regions
    except Exception as e:
        utils.log_error("Error getting AWS regions", e)
        # Fallback to default regions for the partition
        partition = utils.detect_partition()
        return utils.get_partition_regions(partition, all_regions=False)


def scan_replication_groups_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan ElastiCache replication groups (Redis) in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with replication group information from this region
    """
    regional_replication_groups = []

    try:
        elasticache_client = utils.get_boto3_client('elasticache', region_name=region)

        paginator = elasticache_client.get_paginator('describe_replication_groups')
        for page in paginator.paginate():
            replication_groups = page.get('ReplicationGroups', [])

            for rg in replication_groups:
                rg_id = rg.get('ReplicationGroupId', 'N/A')

                print(f"  Processing replication group: {rg_id}")

                # Basic info
                description = rg.get('Description', 'N/A')
                status = rg.get('Status', 'UNKNOWN')

                # Cluster mode
                cluster_enabled = rg.get('ClusterEnabled', False)

                # Member clusters
                member_clusters = rg.get('MemberClusters', [])
                member_count = len(member_clusters)

                # Node type
                cache_node_type = rg.get('CacheNodeType', 'N/A')

                # Engine
                engine = 'redis'  # Replication groups are always Redis
                engine_version = rg.get('EngineVersion', 'N/A')

                # Automatic failover
                automatic_failover = rg.get('AutomaticFailover', 'disabled')

                # Multi-AZ
                multi_az = rg.get('MultiAZ', 'disabled')

                # Snapshot retention
                snapshot_retention_limit = rg.get('SnapshotRetentionLimit', 0)
                snapshot_window = rg.get('SnapshotWindow', 'N/A')

                # Encryption
                at_rest_encryption = rg.get('AtRestEncryptionEnabled', False)
                transit_encryption = rg.get('TransitEncryptionEnabled', False)
                auth_token_enabled = rg.get('AuthTokenEnabled', False)

                # Parameter group
                cache_param_group_name = rg.get('CacheParameterGroup', {}).get('CacheParameterGroupName', 'N/A')

                # Subnet group
                cache_subnet_group = 'N/A'
                node_groups = rg.get('NodeGroups', [])
                if node_groups:
                    for node_group in node_groups:
                        primary_endpoint = node_group.get('PrimaryEndpoint', {})
                        reader_endpoint = node_group.get('ReaderEndpoint', {})

                        # Get subnet group from first node group
                        if not cache_subnet_group or cache_subnet_group == 'N/A':
                            cache_subnet_group = 'default'  # Will be populated from member clusters if available

                # ARN
                arn = rg.get('ARN', 'N/A')

                regional_replication_groups.append({
                    'Region': region,
                    'Replication Group ID': rg_id,
                    'Description': description,
                    'Status': status,
                    'Engine': engine,
                    'Engine Version': engine_version,
                    'Node Type': cache_node_type,
                    'Cluster Mode': 'Enabled' if cluster_enabled else 'Disabled',
                    'Member Clusters': member_count,
                    'Automatic Failover': automatic_failover.upper(),
                    'Multi-AZ': multi_az.upper(),
                    'Snapshot Retention (days)': snapshot_retention_limit,
                    'Snapshot Window': snapshot_window,
                    'Encryption at Rest': 'Yes' if at_rest_encryption else 'No',
                    'Encryption in Transit': 'Yes' if transit_encryption else 'No',
                    'Auth Token Enabled': 'Yes' if auth_token_enabled else 'No',
                    'Parameter Group': cache_param_group_name,
                    'ARN': arn
                })

        utils.log_info(f"Found {len(regional_replication_groups)} ElastiCache replication groups in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting replication groups in region {region}", e)

    return regional_replication_groups


@utils.aws_error_handler("Collecting ElastiCache replication groups", default_return=[])
def collect_replication_groups(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect ElastiCache replication group (Redis) information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with replication group information
    """
    print("\n=== COLLECTING ELASTICACHE REPLICATION GROUPS (Redis) ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_replication_groups = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_replication_groups_in_region,
        resource_type="ElastiCache replication groups"
    )

    utils.log_success(f"Total ElastiCache replication groups collected: {len(all_replication_groups)}")
    return all_replication_groups


def scan_cache_clusters_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan ElastiCache cache clusters in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with cache cluster information from this region
    """
    regional_clusters = []

    try:
        elasticache_client = utils.get_boto3_client('elasticache', region_name=region)

        paginator = elasticache_client.get_paginator('describe_cache_clusters')
        for page in paginator.paginate(ShowCacheNodeInfo=True):
            cache_clusters = page.get('CacheClusters', [])

            for cluster in cache_clusters:
                cluster_id = cluster.get('CacheClusterId', 'N/A')

                print(f"  Processing cache cluster: {cluster_id}")

                # Basic info
                engine = cluster.get('Engine', 'N/A')
                engine_version = cluster.get('EngineVersion', 'N/A')
                status = cluster.get('CacheClusterStatus', 'UNKNOWN')

                # Node info
                cache_node_type = cluster.get('CacheNodeType', 'N/A')
                num_cache_nodes = cluster.get('NumCacheNodes', 0)

                # Preferred AZ
                preferred_az = cluster.get('PreferredAvailabilityZone', 'N/A')

                # Creation time
                creation_time = cluster.get('CacheClusterCreateTime', '')
                if creation_time:
                    creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_time, datetime.datetime) else str(creation_time)

                # Parameter group
                param_group = cluster.get('CacheParameterGroup', {}).get('CacheParameterGroupName', 'N/A')

                # Subnet group
                subnet_group = cluster.get('CacheSubnetGroupName', 'N/A')

                # Security groups
                security_groups = cluster.get('SecurityGroups', [])
                sg_ids = ', '.join([sg.get('SecurityGroupId', '') for sg in security_groups]) if security_groups else 'None'

                # Replication group membership
                replication_group_id = cluster.get('ReplicationGroupId', 'None')

                # Endpoint
                endpoint = cluster.get('ConfigurationEndpoint', cluster.get('CacheNodes', [{}])[0].get('Endpoint', {}))
                endpoint_address = endpoint.get('Address', 'N/A') if endpoint else 'N/A'
                endpoint_port = endpoint.get('Port', 'N/A') if endpoint else 'N/A'

                # ARN
                arn = cluster.get('ARN', 'N/A')

                regional_clusters.append({
                    'Region': region,
                    'Cluster ID': cluster_id,
                    'Engine': engine,
                    'Engine Version': engine_version,
                    'Status': status,
                    'Node Type': cache_node_type,
                    'Number of Nodes': num_cache_nodes,
                    'Availability Zone': preferred_az,
                    'Replication Group': replication_group_id,
                    'Parameter Group': param_group,
                    'Subnet Group': subnet_group,
                    'Security Groups': sg_ids,
                    'Endpoint Address': endpoint_address,
                    'Endpoint Port': endpoint_port,
                    'Created Date': creation_time if creation_time else 'N/A',
                    'ARN': arn
                })

        utils.log_info(f"Found {len(regional_clusters)} ElastiCache cache clusters in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting cache clusters in region {region}", e)

    return regional_clusters


@utils.aws_error_handler("Collecting ElastiCache clusters", default_return=[])
def collect_cache_clusters(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect ElastiCache cache cluster information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with cache cluster information
    """
    print("\n=== COLLECTING ELASTICACHE CACHE CLUSTERS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_clusters = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_cache_clusters_in_region,
        resource_type="ElastiCache cache clusters"
    )

    utils.log_success(f"Total ElastiCache cache clusters collected: {len(all_clusters)}")
    return all_clusters


def scan_cache_subnet_groups_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan ElastiCache cache subnet groups in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with subnet group information from this region
    """
    regional_subnet_groups = []

    try:
        elasticache_client = utils.get_boto3_client('elasticache', region_name=region)

        paginator = elasticache_client.get_paginator('describe_cache_subnet_groups')
        for page in paginator.paginate():
            subnet_groups = page.get('CacheSubnetGroups', [])

            for sg in subnet_groups:
                sg_name = sg.get('CacheSubnetGroupName', 'N/A')

                print(f"  Processing subnet group: {sg_name}")

                # Description
                description = sg.get('CacheSubnetGroupDescription', 'N/A')

                # VPC ID
                vpc_id = sg.get('VpcId', 'N/A')

                # Subnets
                subnets = sg.get('Subnets', [])
                subnet_count = len(subnets)
                subnet_ids = ', '.join([s.get('SubnetIdentifier', '') for s in subnets])

                # Availability zones
                azs = set([s.get('SubnetAvailabilityZone', {}).get('Name', '') for s in subnets if s.get('SubnetAvailabilityZone')])
                az_list = ', '.join(sorted(azs)) if azs else 'N/A'

                # ARN
                arn = sg.get('ARN', 'N/A')

                regional_subnet_groups.append({
                    'Region': region,
                    'Subnet Group Name': sg_name,
                    'Description': description,
                    'VPC ID': vpc_id,
                    'Subnet Count': subnet_count,
                    'Subnet IDs': subnet_ids,
                    'Availability Zones': az_list,
                    'ARN': arn
                })

        utils.log_info(f"Found {len(regional_subnet_groups)} ElastiCache subnet groups in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting subnet groups in region {region}", e)

    return regional_subnet_groups


@utils.aws_error_handler("Collecting ElastiCache subnet groups", default_return=[])
def collect_cache_subnet_groups(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect ElastiCache cache subnet group information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with subnet group information
    """
    print("\n=== COLLECTING ELASTICACHE SUBNET GROUPS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_subnet_groups = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_cache_subnet_groups_in_region,
        resource_type="ElastiCache subnet groups"
    )

    utils.log_success(f"Total ElastiCache subnet groups collected: {len(all_subnet_groups)}")
    return all_subnet_groups


def export_elasticache_data(account_id: str, account_name: str):
    """
    Export ElastiCache information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition for region examples
    partition = utils.detect_partition()
    if partition == 'aws-us-gov':
        example_regions = "us-gov-west-1, us-gov-east-1"
    else:
        example_regions = "us-east-1, us-west-1, us-west-2, eu-west-1"

    # Display standardized region selection menu
    print("\n" + "=" * 68)
    print("REGION SELECTION")
    print("=" * 68)
    print()
    print("Please select which AWS regions to scan:")
    print()
    print("1. Default Regions (recommended for most use cases)")
    print(f"   └─ {example_regions}")
    print()
    print("2. All Available Regions")
    print("   └─ Scans all regions (slower, more comprehensive)")
    print()
    print("3. Specific Region")
    print("   └─ Choose a single region to scan")
    print()

    # Get user selection with validation
    while True:
        try:
            selection = input("Enter your selection (1-3): ").strip()
            selection_int = int(selection)
            if 1 <= selection_int <= 3:
                break
            else:
                print("Please enter a number between 1 and 3.")
        except ValueError:
            print("Please enter a valid number (1-3).")

    # Get regions based on selection
    all_available_regions = get_aws_regions()
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        regions = default_regions
        region_text = f"default AWS regions ({len(regions)} regions)"
        region_suffix = ""
    elif selection_int == 2:
        regions = all_available_regions
        region_text = f"all AWS regions ({len(regions)} regions)"
        region_suffix = ""
    else:  # selection_int == 3
        # Display numbered list of regions
        print("\n" + "=" * 68)
        print("AVAILABLE AWS REGIONS")
        print("=" * 68)
        print()
        for idx, region in enumerate(all_available_regions, 1):
            print(f"{idx:2}. {region}")
        print()

        # Get region selection with validation
        while True:
            try:
                region_num = input(f"Enter region number (1-{len(all_available_regions)}): ").strip()
                region_idx = int(region_num) - 1
                if 0 <= region_idx < len(all_available_regions):
                    selected_region = all_available_regions[region_idx]
                    regions = [selected_region]
                    region_text = f"AWS region \"{selected_region}\""
                    region_suffix = f"-{selected_region}"
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print(f"Please enter a valid number (1-{len(all_available_regions)}).")

    print(f"\nStarting ElastiCache export process for {region_text}...")
    print("=" * 68)
    print("This may take some time depending on the number of regions and clusters...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect replication groups (Redis)
    replication_groups = collect_replication_groups(regions)
    if replication_groups:
        data_frames['Redis Replication Groups'] = pd.DataFrame(replication_groups)

    # STEP 2: Collect cache clusters
    cache_clusters = collect_cache_clusters(regions)
    if cache_clusters:
        data_frames['Cache Clusters'] = pd.DataFrame(cache_clusters)

    # STEP 3: Collect subnet groups
    subnet_groups = collect_cache_subnet_groups(regions)
    if subnet_groups:
        data_frames['Subnet Groups'] = pd.DataFrame(subnet_groups)

    # STEP 4: Create summary
    if replication_groups or cache_clusters or subnet_groups:
        summary_data = []

        total_rgs = len(replication_groups)
        total_clusters = len(cache_clusters)
        total_subnet_groups = len(subnet_groups)

        # Redis vs Memcached
        redis_clusters = sum(1 for c in cache_clusters if c['Engine'] == 'redis')
        memcached_clusters = sum(1 for c in cache_clusters if c['Engine'] == 'memcached')

        # Encryption
        encrypted_at_rest = sum(1 for rg in replication_groups if rg['Encryption at Rest'] == 'Yes')
        encrypted_in_transit = sum(1 for rg in replication_groups if rg['Encryption in Transit'] == 'Yes')

        # Cluster mode
        cluster_mode_enabled = sum(1 for rg in replication_groups if rg['Cluster Mode'] == 'Enabled')

        summary_data.append({'Metric': 'Total Replication Groups', 'Value': total_rgs})
        summary_data.append({'Metric': 'Total Cache Clusters', 'Value': total_clusters})
        summary_data.append({'Metric': 'Redis Clusters', 'Value': redis_clusters})
        summary_data.append({'Metric': 'Memcached Clusters', 'Value': memcached_clusters})
        summary_data.append({'Metric': 'Cluster Mode Enabled', 'Value': cluster_mode_enabled})
        summary_data.append({'Metric': 'Encrypted at Rest', 'Value': encrypted_at_rest})
        summary_data.append({'Metric': 'Encrypted in Transit', 'Value': encrypted_in_transit})
        summary_data.append({'Metric': 'Total Subnet Groups', 'Value': total_subnet_groups})

        data_frames['Summary'] = pd.DataFrame(summary_data)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No ElastiCache data was collected. Nothing to export.")
        print("\nNo ElastiCache resources found in the selected region(s).")
        return

    # STEP 5: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 6: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'elasticache',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("ElastiCache data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")

            # Summary of exported data
            for sheet_name, df in data_frames.items():
                utils.log_info(f"  - {sheet_name}: {len(df)} records")
                print(f"  - {sheet_name}: {len(df)} records")
        else:
            utils.log_error("Error creating Excel file. Please check the logs.")

    except Exception as e:
        utils.log_error("Error creating Excel file", e)


def main():
    """Main function to execute the script."""
    try:
        # Print title and get account information
        account_id, account_name = print_title()

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            proceed = input("Unable to determine account name. Proceed anyway? (y/n): ").lower()
            if proceed != 'y':
                print("Exiting script...")
                sys.exit(0)

        # Export ElastiCache data
        export_elasticache_data(account_id, account_name)

        print("\nElastiCache export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("elasticache-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

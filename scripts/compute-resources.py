#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Compute Resources All-in-One Export Script
Date: OCT-08-2025

Description:
This script performs a comprehensive export of all compute resources from AWS
environments including EC2 instances, RDS databases, and EKS clusters. All data
collection is performed directly within this script (no external script execution).
Each resource type is exported to a separate Excel file, and all files are
automatically archived into a single zip file for easy distribution and storage.

Collected information includes:
- EC2 instances with detailed configuration, security groups, storage, and pricing
- RDS instances with engine details, security, backup, monitoring, and pricing
- EKS clusters with node groups, add-ons, and comprehensive cluster settings
- Automatic archiving of all exports into a single zip file
"""

import os
import sys
import datetime
import time
import json
import zipfile
import csv
import re
import botocore.exceptions
from pathlib import Path
from botocore.exceptions import ClientError, NoCredentialsError
from io import StringIO

# Add path to import utils module
try:
    # Try to import directly (if utils.py is in Python path)
    import utils
except ImportError:
    # If import fails, try to find the module relative to this script
    script_dir = Path(__file__).parent.absolute()

    # Check if we're in the scripts directory
    if script_dir.name.lower() == 'scripts':
        # Add the parent directory (StratusScan root) to the path
        sys.path.append(str(script_dir.parent))
    else:
        # Add the current directory to the path
        sys.path.append(str(script_dir))

    # Try import again
    try:
        import utils
    except ImportError:
        print("ERROR: Could not import the utils module. Make sure utils.py is in the StratusScan directory.")
        sys.exit(1)

# Setup logging
logger = utils.setup_logging('compute-resources')

# ============================================================================
# DEPENDENCY CHECKING AND INITIALIZATION
# ============================================================================
@utils.aws_error_handler("Getting account information", default_return=("Unknown", "Unknown-AWS-Account"))
def get_account_info():
    """
    Get the current AWS account ID and name with AWS validation.

    Returns:
        tuple: (account_id, account_name)
    """
    sts = utils.get_boto3_client('sts')
    account_id = sts.get_caller_identity()['Account']
    account_name = utils.get_account_name(account_id, default=f"AWS-ACCOUNT-{account_id}")
    return account_id, account_name


def print_title():
    """
    Print the script title and account information.

    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS COMPUTE RESOURCES ALL-IN-ONE COLLECTION")
    print("====================================================================")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")

    # Get account information
    account_id, account_name = get_account_info()
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")

    return account_id, account_name


def get_region_selection():
    """
    Get region selection from user for compute resources scanning.

    Returns:
        list: List of selected regions to scan
    """
    # Detect partition for region examples
    regions = utils.prompt_region_selection()
# ============================================================================
# EC2 DATA COLLECTION FUNCTIONS
# ============================================================================

def get_os_info_from_ssm(instance_id, region):
    """
    Retrieve detailed operating system information using SSM with timeout safeguards
    Returns the full OS version string or 'Unknown OS' if unavailable
    """
    try:
        ssm = utils.get_boto3_client('ssm', region_name=region)

        response = ssm.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
        )

        if not response['InstanceInformationList']:
            return "Unknown OS"

        instance_info = response['InstanceInformationList'][0]
        platform_type = instance_info.get('PlatformType', '')
        platform_name = instance_info.get('PlatformName', '')
        platform_version = instance_info.get('PlatformVersion', '')

        if platform_name and platform_version:
            return f"{platform_name} {platform_version}"
        elif platform_name:
            return platform_name

        if platform_type == 'Windows':
            return "Windows (Use AMI Name for details)"

        return "Linux (Use AMI Name for details)"

    except Exception as e:
        utils.log_warning(f"SSM error for instance {instance_id} in region {region}: {e}")
        return "Unknown OS"


def get_instance_memory(ec2_client, instance_type):
    """Get RAM information for a given instance type using EC2 API"""
    try:
        response = ec2_client.describe_instance_types(InstanceTypes=[instance_type])
        if response['InstanceTypes']:
            return response['InstanceTypes'][0]['MemoryInfo']['SizeInMiB']
        return 'N/A'
    except Exception as e:
        utils.log_warning(f"Could not get memory info for instance type {instance_type}: {e}")
        return 'N/A'


def get_instance_stop_date(ec2_client, instance_id, state):
    """Get the date when an instance was stopped"""
    if state != 'stopped':
        return 'N/A'

    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])

        if response['Reservations']:
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if instance['InstanceId'] == instance_id and instance.get('State', {}).get('Name') == 'stopped':
                        state_reason = instance.get('StateTransitionReason', '')

                        if 'User initiated' in state_reason and '(' in state_reason and ')' in state_reason:
                            date_start = state_reason.find('(') + 1
                            date_end = state_reason.find(')')
                            if date_start > 0 and date_end > date_start:
                                return state_reason[date_start:date_end]
                        elif state_reason:
                            return f"System initiated ({state_reason})"

        return 'Stopped (Date Unknown)'

    except Exception as e:
        utils.log_warning(f"Could not determine stop date for instance {instance_id}: {e}")
        return 'Stopped (Date Unknown)'


def get_os_info_from_ami(ec2_client, image_id, platform_details, platform):
    """Get detailed OS information from AMI metadata"""
    try:
        response = ec2_client.describe_images(ImageIds=[image_id])

        if response['Images']:
            image = response['Images'][0]

            if platform == 'windows':
                description = image.get('Description', '')
                if description:
                    return description
                name = image.get('Name', '')
                if name and 'Windows' in name:
                    return name
                return platform_details

            name = image.get('Name', '')
            description = image.get('Description', '')

            if 'amzn' in name.lower() or 'amazon linux' in name.lower():
                return name if name else "Amazon Linux"

            if any(distro in name.lower() or distro in description.lower() for distro in
                   ['rhel', 'red hat', 'ubuntu', 'debian', 'suse', 'centos']):
                return name if name else description

            if name:
                return name

            if description:
                return description

        return platform_details

    except Exception as e:
        utils.log_warning(f"Could not get detailed OS info for AMI {image_id}: {e}")
        return platform_details


def format_tags(tags):
    """Format EC2 instance tags in the format 'Key1:Value1, Key2:Value2'"""
    if not tags:
        return 'N/A'

    formatted_tags = []
    for tag in tags:
        if 'Key' in tag and 'Value' in tag:
            formatted_tags.append(f"{tag['Key']}:{tag['Value']}")

    if formatted_tags:
        return ', '.join(formatted_tags)
    else:
        return 'N/A'


def load_ec2_pricing_data():
    """Load EC2 pricing data from the reference CSV file"""
    pricing_data = {}
    try:
        script_dir = Path(__file__).parent.absolute()
        pricing_file = script_dir.parent / 'reference' / 'ec2-pricing.csv'

        if not pricing_file.exists():
            utils.log_warning(f"Pricing file not found at {pricing_file}")
            return pricing_data

        with open(pricing_file, 'r', encoding='utf-8-sig') as file:
            reader = csv.DictReader(file)
            for row in reader:
                instance_type = row.get('API Name', '').strip()
                if instance_type:
                    linux_price_str = row.get(' On Demand (Monthly) ', '').strip()
                    linux_price = parse_price(linux_price_str)

                    windows_price_str = row.get(' Windows On Demand cost (Monthly) ', '').strip()
                    windows_price = parse_price(windows_price_str)

                    pricing_data[instance_type] = {
                        'linux': linux_price,
                        'windows': windows_price
                    }

        utils.log_info(f"Loaded EC2 pricing data for {len(pricing_data)} instance types")
        return pricing_data

    except Exception as e:
        utils.log_warning(f"Error loading EC2 pricing data: {e}")
        return pricing_data


def load_storage_pricing_data():
    """Load EBS volume pricing data from the reference CSV file"""
    storage_pricing = {}
    try:
        script_dir = Path(__file__).parent.absolute()
        pricing_file = script_dir.parent / 'reference' / 'ebsvol-pricing.csv'

        if not pricing_file.exists():
            utils.log_warning(f"Storage pricing file not found at {pricing_file}")
            return storage_pricing

        with open(pricing_file, 'r', encoding='utf-8-sig') as file:
            reader = csv.DictReader(file)
            for row in reader:
                volume_type = row.get('Type', '').strip()
                price_str = row.get(' Cost per GB/month ', '').strip()

                if volume_type and price_str:
                    price = parse_price(price_str)
                    if price is not None:
                        storage_pricing[volume_type] = price

        utils.log_info(f"Loaded storage pricing data for {len(storage_pricing)} volume types")
        return storage_pricing

    except Exception as e:
        utils.log_warning(f"Error loading storage pricing data: {e}")
        return storage_pricing


def parse_price(price_str):
    """Parse price string and return float value"""
    if not price_str or price_str.lower() in ['unavailable', 'n/a', '']:
        return None

    cleaned = re.sub(r'[$,\s]', '', price_str)

    try:
        return float(cleaned)
    except ValueError:
        return None


def calculate_monthly_cost(instance_type, platform, state, pricing_data):
    """Calculate monthly cost for an EC2 instance"""
    if state != 'running':
        return 0.00

    if instance_type not in pricing_data:
        return 'N/A'

    is_windows = platform and platform.lower() == 'windows'
    price_key = 'windows' if is_windows else 'linux'

    price = pricing_data[instance_type].get(price_key)

    if price is None:
        return 'N/A'

    return price


def get_attached_volumes(ec2_client, instance):
    """Get all attached volumes for an instance, excluding the root volume"""
    attached_volumes = []
    volume_info = {}
    root_device_name = instance.get('RootDeviceName')

    try:
        for device in instance.get('BlockDeviceMappings', []):
            device_name = device.get('DeviceName')
            volume_id = device.get('Ebs', {}).get('VolumeId')

            if device_name == root_device_name:
                continue

            if volume_id:
                attached_volumes.append(volume_id)

                try:
                    volumes = ec2_client.describe_volumes(VolumeIds=[volume_id])
                    if volumes and 'Volumes' in volumes and len(volumes['Volumes']) > 0:
                        vol = volumes['Volumes'][0]
                        volume_info[volume_id] = {
                            'size': vol.get('Size', 0),
                            'type': vol.get('VolumeType', 'standard')
                        }
                except Exception as e:
                    utils.log_warning(f"Error getting volume info for {volume_id}: {e}")
                    volume_info[volume_id] = {'size': 0, 'type': 'standard'}

    except Exception as e:
        utils.log_warning(f"Error getting attached volumes: {e}")

    return attached_volumes, volume_info


def calculate_storage_cost(root_size, root_type, attached_volume_info, storage_pricing):
    """Calculate total monthly storage cost for all volumes"""
    try:
        total_cost = 0.0

        if root_size != 'N/A' and root_type != 'N/A':
            root_price = storage_pricing.get(root_type, storage_pricing.get('gp3', 0.08))
            total_cost += float(root_size) * root_price

        for vol_id, vol_info in attached_volume_info.items():
            vol_size = vol_info.get('size', 0)
            vol_type = vol_info.get('type', 'gp3')
            vol_price = storage_pricing.get(vol_type, storage_pricing.get('gp3', 0.08))
            total_cost += float(vol_size) * vol_price

        return round(total_cost, 2)

    except Exception as e:
        utils.log_warning(f"Error calculating storage cost: {e}")
        return 'N/A'


def collect_ec2_data(region):
    """
    Collect EC2 instance data for a specific AWS region

    Args:
        region (str): AWS region name

    Returns:
        list: List of EC2 instance dictionaries
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Invalid AWS region: {region}")
        return []

    ec2 = utils.get_boto3_client('ec2', region_name=region)
    instances = []

    pricing_data = load_ec2_pricing_data()
    storage_pricing = load_storage_pricing_data()

    try:
        paginator = ec2.get_paginator('describe_instances')
        all_reservations = []
        for page in paginator.paginate():
            all_reservations.extend(page['Reservations'])

        total_instances = 0
        for reservation in all_reservations:
            total_instances += len(reservation['Instances'])

        if total_instances > 0:
            utils.log_info(f"Found {total_instances} EC2 instances in {region} to process")

        processed = 0
        for reservation in all_reservations:
            for instance in reservation['Instances']:
                processed += 1
                instance_id = instance.get('InstanceId', 'Unknown')
                progress = (processed / total_instances) * 100 if total_instances > 0 else 0

                utils.log_info(f"[{progress:.1f}%] Processing EC2 instance {processed}/{total_instances}: {instance_id}")

                root_device = next((device for device in instance.get('BlockDeviceMappings', [])
                                  if device['DeviceName'] == instance.get('RootDeviceName')), None)

                os_info = get_os_info_from_ssm(instance.get('InstanceId', ''), region)

                ami_name = get_os_info_from_ami(
                    ec2,
                    instance.get('ImageId', ''),
                    instance.get('PlatformDetails', 'N/A'),
                    instance.get('Platform', '')
                )

                instance_type = instance.get('InstanceType', 'N/A')
                ram_mib = get_instance_memory(ec2, instance_type)

                root_device_size = 'N/A'
                root_volume_id = 'N/A'
                root_volume_type = 'N/A'

                if root_device:
                    root_volume_id = root_device.get('Ebs', {}).get('VolumeId', 'N/A')
                    if root_volume_id != 'N/A':
                        try:
                            volumes = ec2.describe_volumes(VolumeIds=[root_volume_id])
                            if volumes and 'Volumes' in volumes and len(volumes['Volumes']) > 0:
                                root_device_size = volumes['Volumes'][0].get('Size', 'N/A')
                                root_volume_type = volumes['Volumes'][0].get('VolumeType', 'N/A')
                        except Exception as e:
                            utils.log_warning(f"Error getting volume info for {root_volume_id}: {e}")
                    else:
                        root_device_size = root_device.get('Ebs', {}).get('VolumeSize', 'N/A')

                attached_vols, attached_vol_info = get_attached_volumes(ec2, instance)
                attached_volumes_str = ', '.join(attached_vols) if attached_vols else 'N/A'

                instance_state = instance.get('State', {}).get('Name', 'N/A')
                stop_date = get_instance_stop_date(ec2, instance.get('InstanceId', ''), instance_state)

                instance_tags = format_tags(instance.get('Tags', []))

                monthly_cost = calculate_monthly_cost(
                    instance.get('InstanceType', 'N/A'),
                    instance.get('Platform', 'Linux/UNIX'),
                    instance_state,
                    pricing_data
                )

                storage_cost = calculate_storage_cost(
                    root_device_size,
                    root_volume_type,
                    attached_vol_info,
                    storage_pricing
                )

                total_monthly_cost = 'N/A'
                if monthly_cost != 'N/A' and storage_cost != 'N/A':
                    total_monthly_cost = round(float(monthly_cost) + float(storage_cost), 2)
                elif monthly_cost != 'N/A':
                    total_monthly_cost = float(monthly_cost)
                elif storage_cost != 'N/A':
                    total_monthly_cost = float(storage_cost)

                instance_data = {
                    'Computer Name': next((tag['Value'] for tag in instance.get('Tags', [])
                                        if tag['Key'] == 'Name'), 'N/A'),
                    'Instance ID': instance.get('InstanceId', 'N/A'),
                    'State': instance_state,
                    'Stopped Date': stop_date,
                    'Instance Type': instance.get('InstanceType', 'N/A'),
                    'Platform': instance.get('Platform', 'Linux/UNIX'),
                    'Monthly Cost (On-Demand)': monthly_cost,
                    'Monthly Storage Cost': storage_cost,
                    'Total Monthly Cost': total_monthly_cost,
                    'Operating System': os_info,
                    'AMI Name': ami_name,
                    'Private IPv4': instance.get('PrivateIpAddress', 'N/A'),
                    'Public IPv4': instance.get('PublicIpAddress', 'N/A'),
                    'IPv6': next((
                        next((addr.get('Ipv6Address', 'N/A')
                             for addr in interface.get('Ipv6Addresses', [])), 'N/A')
                        for interface in instance.get('NetworkInterfaces', [])
                    ), 'N/A'),
                    'VPC ID': instance.get('VpcId', 'N/A'),
                    'Subnet ID': instance.get('SubnetId', 'N/A'),
                    'Availability Zone': instance.get('Placement', {}).get('AvailabilityZone', 'N/A'),
                    'AMI ID': instance.get('ImageId', 'N/A'),
                    'Launch Time': instance.get('LaunchTime', 'N/A'),
                    'Key Pair': instance.get('KeyName', 'N/A'),
                    'Region': region,
                    'Owner ID': utils.get_account_name_formatted(instance.get('OwnerId', 'N/A')),
                    'vCPU': instance.get('CpuOptions', {}).get('CoreCount', 'N/A'),
                    'RAM (MiB)': ram_mib,
                    'Root Device Volume ID': root_volume_id,
                    'Root Device Size (GiB)': root_device_size,
                    'Attached Volumes': attached_volumes_str,
                    'Tags': instance_tags
                }
                instances.append(instance_data)

    except Exception as e:
        utils.log_error(f"Error getting EC2 instances in region {region}", e)

    return instances


# ============================================================================
# RDS DATA COLLECTION FUNCTIONS
# ============================================================================

def get_security_group_info(rds_client, sg_ids):
    """Get security group names and IDs from a list of security group IDs"""
    if not sg_ids:
        return ""

    try:
        region = rds_client.meta.region_name
        ec2_client = utils.get_boto3_client('ec2', region_name=region)

        response = ec2_client.describe_security_groups(GroupIds=sg_ids)
        sg_info = [f"{sg['GroupName']} ({sg['GroupId']})" for sg in response['SecurityGroups']]
        return ", ".join(sg_info)
    except Exception as e:
        utils.log_warning(f"Could not get security group names for {sg_ids}: {e}")
        return ", ".join(sg_ids)


def get_vpc_info(rds_client, vpc_id):
    """Get VPC name and ID information from a VPC ID"""
    if not vpc_id:
        return "N/A"

    try:
        region = rds_client.meta.region_name
        ec2_client = utils.get_boto3_client('ec2', region_name=region)

        response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        if response['Vpcs']:
            vpc = response['Vpcs'][0]
            vpc_name = "Unnamed"
            for tag in vpc.get('Tags', []):
                if tag['Key'] == 'Name':
                    vpc_name = tag['Value']
                    break
            return f"{vpc_name} ({vpc_id})"
        return vpc_id
    except Exception as e:
        utils.log_warning(f"Could not get VPC info for {vpc_id}: {e}")
        return vpc_id


def get_subnet_ids(subnet_group):
    """Extract subnet IDs from a DB subnet group"""
    if not subnet_group or 'Subnets' not in subnet_group:
        return "N/A"

    try:
        subnet_ids = [subnet['SubnetIdentifier'] for subnet in subnet_group['Subnets']]
        return ", ".join(subnet_ids)
    except Exception:
        return "N/A"


def load_rds_pricing_data():
    """Load RDS pricing data from the reference CSV file"""
    pricing_data = {}
    try:
        script_dir = Path(__file__).parent.absolute()
        pricing_file = script_dir.parent / 'reference' / 'rds-pricing.csv'

        if not pricing_file.exists():
            utils.log_warning(f"RDS pricing file not found at {pricing_file}")
            return pricing_data

        with open(pricing_file, 'r', encoding='utf-8-sig') as file:
            reader = csv.DictReader(file)
            for row in reader:
                instance_type = row.get('API Name', '').strip()
                if instance_type:
                    pricing_data[instance_type] = row

        utils.log_info(f"Loaded RDS pricing data for {len(pricing_data)} instance types")
        return pricing_data

    except Exception as e:
        utils.log_warning(f"Error loading RDS pricing data: {e}")
        return pricing_data


def calculate_rds_monthly_cost(instance_type, engine, pricing_data):
    """Calculate monthly cost for an RDS instance based on instance type and engine"""
    if instance_type not in pricing_data:
        return 'N/A'

    instance_pricing = pricing_data[instance_type]

    engine_lower = engine.lower()
    pricing_column = None

    if 'postgres' in engine_lower and 'aurora' not in engine_lower:
        pricing_column = 'PostgreSQL (Monthly)'
    elif 'mysql' in engine_lower and 'aurora' not in engine_lower:
        pricing_column = 'MySQL On Demand Cost (Monthly)'
    elif 'mariadb' in engine_lower:
        pricing_column = 'MariaDB On Demand Cost (Monthly)'
    elif 'aurora-postgresql' in engine_lower or 'aurora-mysql' in engine_lower:
        pricing_column = 'Aurora Postgres & MySQL On Demand Cost (Monthly)'
    elif 'sqlserver-ex' in engine_lower:
        pricing_column = 'SQL Server Expresss On Demand Cost (Monthly)'
    elif 'sqlserver-web' in engine_lower:
        pricing_column = 'SQL Server Web On Demand Cost (Monthly)'
    elif 'sqlserver-se' in engine_lower:
        pricing_column = 'SQL Server Standard On Demand Cost (Monthly)'
    elif 'sqlserver-ee' in engine_lower:
        pricing_column = 'SQL Server Enterprise On Demand Cost (Monthly)'
    elif 'oracle' in engine_lower:
        pricing_column = 'Oracle Enterprise On Demand Cost (Monthly)'
    else:
        return 'N/A'

    price_str = instance_pricing.get(pricing_column, '').strip()
    price = parse_price(price_str)

    return price if price is not None else 'N/A'


def calculate_rds_storage_cost(storage_size, storage_type, storage_pricing):
    """Calculate monthly storage cost for an RDS instance"""
    try:
        if storage_size == 'N/A' or storage_type == 'N/A':
            return 'N/A'

        price_per_gb = storage_pricing.get(storage_type, storage_pricing.get('gp3', 0.08))

        if price_per_gb is None:
            return 'N/A'

        total_cost = float(storage_size) * price_per_gb
        return round(total_cost, 2)

    except Exception as e:
        utils.log_warning(f"Error calculating storage cost: {e}")
        return 'N/A'


def collect_rds_data(region):
    """
    Collect RDS instance data for a specific AWS region

    Args:
        region (str): AWS region name

    Returns:
        list: List of RDS instance dictionaries
    """
    if not utils.validate_aws_region(region):
        utils.log_error(f"Invalid AWS region: {region}")
        return []

    rds_instances = []

    pricing_data = load_rds_pricing_data()
    storage_pricing = load_storage_pricing_data()

    try:
        rds_client = utils.get_boto3_client('rds', region_name=region)

        paginator = rds_client.get_paginator('describe_db_instances')
        page_iterator = paginator.paginate()

        total_instances = 0
        for page in paginator.paginate():
            total_instances += len(page['DBInstances'])

        if total_instances > 0:
            utils.log_info(f"Found {total_instances} RDS instances in {region} to process")

        paginator = rds_client.get_paginator('describe_db_instances')
        page_iterator = paginator.paginate()

        processed = 0
        for page in page_iterator:
            for instance in page['DBInstances']:
                processed += 1
                instance_id = instance.get('DBInstanceIdentifier', 'Unknown')
                progress = (processed / total_instances) * 100 if total_instances > 0 else 0

                utils.log_info(f"[{progress:.1f}%] Processing RDS instance {processed}/{total_instances}: {instance_id}")

                sg_ids = [sg['VpcSecurityGroupId'] for sg in instance.get('VpcSecurityGroups', [])]
                sg_info = get_security_group_info(rds_client, sg_ids)

                vpc_id = instance.get('DBSubnetGroup', {}).get('VpcId', 'N/A')
                vpc_info = get_vpc_info(rds_client, vpc_id) if vpc_id != 'N/A' else 'N/A'

                subnet_ids = get_subnet_ids(instance.get('DBSubnetGroup', {}))

                port = instance.get('Endpoint', {}).get('Port', 'N/A') if 'Endpoint' in instance else 'N/A'

                endpoint_address = instance.get('Endpoint', {}).get('Address', 'N/A') if 'Endpoint' in instance else 'N/A'

                master_username = instance.get('MasterUsername', 'N/A')

                db_cluster_id = instance.get('DBClusterIdentifier', 'N/A')
                role = 'Standalone'
                if db_cluster_id != 'N/A':
                    try:
                        cluster_info = rds_client.describe_db_clusters(
                            DBClusterIdentifier=db_cluster_id
                        )
                        if cluster_info and 'DBClusters' in cluster_info and cluster_info['DBClusters']:
                            cluster = cluster_info['DBClusters'][0]
                            if 'DBClusterMembers' in cluster:
                                for member in cluster['DBClusterMembers']:
                                    if member.get('DBInstanceIdentifier') == instance['DBInstanceIdentifier']:
                                        role = 'Primary' if member.get('IsClusterWriter', False) else 'Replica'
                    except Exception as e:
                        utils.log_warning(f"Could not determine cluster role for {instance['DBInstanceIdentifier']}: {e}")

                extended_support = 'No'
                try:
                    if 'StatusInfos' in instance:
                        for status_info in instance['StatusInfos']:
                            if status_info.get('Status') == 'extended-support':
                                extended_support = 'Yes'
                except Exception as e:
                    utils.log_warning(f"Could not determine extended support for {instance.get('DBInstanceIdentifier', '?')}: {e}")

                cert_expiry = 'N/A'
                try:
                    if 'CertificateDetails' in instance and 'ValidTill' in instance['CertificateDetails']:
                        valid_till = instance['CertificateDetails']['ValidTill']
                        if isinstance(valid_till, datetime.datetime):
                            cert_expiry = valid_till.replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S')
                except Exception as e:
                    utils.log_warning(f"Could not parse cert expiry for {instance.get('DBInstanceIdentifier', '?')}: {e}")

                created_time = 'N/A'
                try:
                    if 'InstanceCreateTime' in instance:
                        create_time = instance['InstanceCreateTime']
                        if isinstance(create_time, datetime.datetime):
                            created_time = create_time.replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S')
                except Exception as e:
                    utils.log_warning(f"Could not parse create time for {instance.get('DBInstanceIdentifier', '?')}: {e}")

                monthly_cost = calculate_rds_monthly_cost(
                    instance['DBInstanceClass'],
                    instance['Engine'],
                    pricing_data
                )

                storage_cost = calculate_rds_storage_cost(
                    instance['AllocatedStorage'],
                    instance['StorageType'],
                    storage_pricing
                )

                total_monthly_cost = 'N/A'
                if monthly_cost != 'N/A' and storage_cost != 'N/A':
                    total_monthly_cost = round(float(monthly_cost) + float(storage_cost), 2)
                elif monthly_cost != 'N/A':
                    total_monthly_cost = float(monthly_cost)
                elif storage_cost != 'N/A':
                    total_monthly_cost = float(storage_cost)

                instance_data = {
                    'DB Identifier': instance['DBInstanceIdentifier'],
                    'DB Cluster Identifier': db_cluster_id,
                    'Role': role,
                    'Engine': instance['Engine'],
                    'Engine Version': instance['EngineVersion'],
                    'RDS Extended Support': extended_support,
                    'Region': region,
                    'Size': instance['DBInstanceClass'],
                    'Monthly Cost (On-Demand)': monthly_cost,
                    'Monthly Storage Cost': storage_cost,
                    'Total Monthly Cost': total_monthly_cost,
                    'Storage Type': instance['StorageType'],
                    'Storage (GB)': instance['AllocatedStorage'],
                    'Provisioned IOPS': instance.get('Iops', 'N/A'),
                    'Port': port,
                    'Endpoint': endpoint_address,
                    'Master Username': master_username,
                    'VPC': vpc_info,
                    'Subnet IDs': subnet_ids,
                    'Security Groups': sg_info,
                    'DB Subnet Group Name': instance.get('DBSubnetGroup', {}).get('DBSubnetGroupName', 'N/A'),
                    'DB Certificate Expiry': cert_expiry,
                    'Created Time': created_time,
                    'Encryption': 'Yes' if instance.get('StorageEncrypted', False) else 'No',
                    'Owner ID': utils.get_account_name_formatted(instance.get('OwnerId', 'N/A'))
                }

                rds_instances.append(instance_data)

        return rds_instances
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            utils.log_warning(f"Access denied in AWS region {region}. Skipping...")
        elif e.response['Error']['Code'] == 'AuthFailure':
            utils.log_warning(f"Authentication failure in AWS region {region}. Skipping...")
        else:
            utils.log_error(f"Error in AWS region {region}", e)
        return []
    except Exception as e:
        utils.log_error(f"Error accessing AWS region {region}", e)
        return []


# ============================================================================
# EKS DATA COLLECTION FUNCTIONS
# ============================================================================

def format_timestamp(timestamp):
    """Format datetime timestamp for display"""
    if timestamp is None:
        return 'N/A'

    try:
        if hasattr(timestamp, 'strftime'):
            return timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            return str(timestamp)
    except Exception:
        return 'N/A'


def collect_cluster_details(client, cluster_name, region):
    """Collect detailed information about an EKS cluster"""
    try:
        response = client.describe_cluster(name=cluster_name)
        cluster = response['cluster']

        vpc_config = cluster.get('resourcesVpcConfig', {})

        logging_config = cluster.get('logging', {})
        log_types = logging_config.get('clusterLogging', [])

        log_status = {
            'api': 'Disabled',
            'audit': 'Disabled',
            'authenticator': 'Disabled',
            'controllerManager': 'Disabled',
            'scheduler': 'Disabled'
        }

        for log_setup in log_types:
            if log_setup.get('enabled', False):
                for log_type in log_setup.get('types', []):
                    log_status[log_type] = 'Enabled'

        encryption_config = cluster.get('encryptionConfig', [])
        kms_key_arn = 'Not Configured'
        if encryption_config:
            kms_key_arn = encryption_config[0].get('provider', {}).get('keyArn', 'Not Configured')

        identity = cluster.get('identity', {})
        oidc_issuer = identity.get('oidc', {}).get('issuer', 'Not Available')

        tags = cluster.get('tags', {})
        tag_string = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'No Tags'

        cluster_info = {
            'Region': region,
            'Cluster Name': cluster.get('name', 'N/A'),
            'Cluster ARN': cluster.get('arn', 'N/A'),
            'Status': cluster.get('status', 'N/A'),
            'Kubernetes Version': cluster.get('version', 'N/A'),
            'Platform Version': cluster.get('platformVersion', 'N/A'),
            'Created At': format_timestamp(cluster.get('createdAt')),
            'Endpoint URL': cluster.get('endpoint', 'N/A'),
            'Certificate Authority': 'Available' if cluster.get('certificateAuthority', {}).get('data') else 'Not Available',
            'Cluster Role ARN': cluster.get('roleArn', 'N/A'),
            'VPC ID': vpc_config.get('vpcId', 'N/A'),
            'Subnet IDs': ', '.join(vpc_config.get('subnetIds', [])) or 'None',
            'Security Group IDs': ', '.join(vpc_config.get('securityGroupIds', [])) or 'None',
            'Cluster Security Group': vpc_config.get('clusterSecurityGroupId', 'N/A'),
            'Public Access': 'Yes' if vpc_config.get('endpointConfigPublicAccess', False) else 'No',
            'Private Access': 'Yes' if vpc_config.get('endpointConfigPrivateAccess', False) else 'No',
            'Public Access CIDRs': ', '.join(vpc_config.get('publicAccessCidrs', [])) or 'None',
            'Service IPv4 CIDR': cluster.get('kubernetesNetworkConfig', {}).get('serviceIpv4Cidr', 'N/A'),
            'Service IPv6 CIDR': cluster.get('kubernetesNetworkConfig', {}).get('serviceIpv6Cidr', 'N/A'),
            'API Server Logging': log_status.get('api', 'N/A'),
            'Audit Logging': log_status.get('audit', 'N/A'),
            'Authenticator Logging': log_status.get('authenticator', 'N/A'),
            'Controller Manager Logging': log_status.get('controllerManager', 'N/A'),
            'Scheduler Logging': log_status.get('scheduler', 'N/A'),
            'Encryption KMS Key ARN': kms_key_arn,
            'OIDC Issuer URL': oidc_issuer,
            'Tags': tag_string[:500]
        }

        return cluster_info

    except Exception as e:
        utils.log_error(f"Error collecting details for cluster {cluster_name}", e)
        return None


def collect_node_groups(client, cluster_name, region):
    """Collect information about all node groups for a cluster"""
    node_groups_data = []

    try:
        response = client.list_nodegroups(clusterName=cluster_name)
        nodegroup_names = response.get('nodegroups', [])

        if not nodegroup_names:
            utils.log_info(f"No node groups found for cluster {cluster_name}")
            return []

        utils.log_info(f"Found {len(nodegroup_names)} node groups for cluster {cluster_name}")

        for nodegroup_name in nodegroup_names:
            try:
                ng_response = client.describe_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=nodegroup_name
                )
                nodegroup = ng_response['nodegroup']

                scaling_config = nodegroup.get('scalingConfig', {})

                instance_types = nodegroup.get('instanceTypes', [])
                instance_types_str = ', '.join(instance_types) if instance_types else 'N/A'

                launch_template = nodegroup.get('launchTemplate', {})
                lt_info = 'Not Used'
                if launch_template:
                    lt_name = launch_template.get('name', 'N/A')
                    lt_version = launch_template.get('version', 'N/A')
                    lt_id = launch_template.get('id', 'N/A')
                    lt_info = f"Name: {lt_name}, Version: {lt_version}, ID: {lt_id}"

                remote_access = nodegroup.get('remoteAccess', {})
                remote_access_info = 'Not Configured'
                if remote_access:
                    ec2_key = remote_access.get('ec2SshKey', 'N/A')
                    source_sgs = remote_access.get('sourceSecurityGroups', [])
                    remote_access_info = f"Key: {ec2_key}, Security Groups: {', '.join(source_sgs) if source_sgs else 'None'}"

                update_config = nodegroup.get('updateConfig', {})
                update_strategy = 'N/A'
                if update_config:
                    max_unavailable = update_config.get('maxUnavailable', 'N/A')
                    max_unavailable_percentage = update_config.get('maxUnavailablePercentage', 'N/A')
                    update_strategy = f"Max Unavailable: {max_unavailable}, Max Unavailable %: {max_unavailable_percentage}"

                tags = nodegroup.get('tags', {})
                tag_string = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'No Tags'

                nodegroup_info = {
                    'Region': region,
                    'Cluster Name': cluster_name,
                    'Node Group Name': nodegroup.get('nodegroupName', 'N/A'),
                    'Node Group ARN': nodegroup.get('nodegroupArn', 'N/A'),
                    'Status': nodegroup.get('status', 'N/A'),
                    'Capacity Type': nodegroup.get('capacityType', 'N/A'),
                    'AMI Type': nodegroup.get('amiType', 'N/A'),
                    'Release Version': nodegroup.get('releaseVersion', 'N/A'),
                    'Kubernetes Version': nodegroup.get('version', 'N/A'),
                    'Instance Types': instance_types_str,
                    'Desired Size': scaling_config.get('desiredSize', 'N/A'),
                    'Min Size': scaling_config.get('minSize', 'N/A'),
                    'Max Size': scaling_config.get('maxSize', 'N/A'),
                    'Disk Size (GB)': nodegroup.get('diskSize', 'N/A'),
                    'Node Role ARN': nodegroup.get('nodeRole', 'N/A'),
                    'Subnets': ', '.join(nodegroup.get('subnets', [])) or 'None',
                    'Launch Template': lt_info[:300],
                    'Remote Access': remote_access_info[:300],
                    'Update Strategy': update_strategy[:200],
                    'Created At': format_timestamp(nodegroup.get('createdAt')),
                    'Modified At': format_timestamp(nodegroup.get('modifiedAt')),
                    'Tags': tag_string[:500]
                }

                node_groups_data.append(nodegroup_info)

            except Exception as e:
                utils.log_warning(f"Error collecting details for node group {nodegroup_name}: {e}")
                continue

    except Exception as e:
        utils.log_error(f"Error collecting node groups for cluster {cluster_name}", e)

    return node_groups_data


def collect_cluster_addons(client, cluster_name, region):
    """Collect information about EKS add-ons for a cluster"""
    addons_data = []

    try:
        response = client.list_addons(clusterName=cluster_name)
        addon_names = response.get('addons', [])

        if not addon_names:
            utils.log_info(f"No add-ons found for cluster {cluster_name}")
            return []

        utils.log_info(f"Found {len(addon_names)} add-ons for cluster {cluster_name}")

        for addon_name in addon_names:
            try:
                addon_response = client.describe_addon(
                    clusterName=cluster_name,
                    addonName=addon_name
                )
                addon = addon_response['addon']

                config_values = addon.get('configurationValues', 'Default Configuration')

                tags = addon.get('tags', {})
                tag_string = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'No Tags'

                addon_info = {
                    'Region': region,
                    'Cluster Name': cluster_name,
                    'Add-on Name': addon.get('addonName', 'N/A'),
                    'Add-on ARN': addon.get('addonArn', 'N/A'),
                    'Status': addon.get('status', 'N/A'),
                    'Version': addon.get('addonVersion', 'N/A'),
                    'Service Account Role ARN': addon.get('serviceAccountRoleArn', 'Not Configured'),
                    'Configuration Values': str(config_values)[:300] if config_values != 'Default Configuration' else config_values,
                    'Resolve Conflicts': addon.get('resolveConflicts', 'N/A'),
                    'Health Issues': len(addon.get('health', {}).get('issues', [])),
                    'Created At': format_timestamp(addon.get('createdAt')),
                    'Modified At': format_timestamp(addon.get('modifiedAt')),
                    'Tags': tag_string[:300]
                }

                addons_data.append(addon_info)

            except Exception as e:
                utils.log_warning(f"Error collecting details for add-on {addon_name}: {e}")
                continue

    except Exception as e:
        utils.log_error(f"Error collecting add-ons for cluster {cluster_name}", e)

    return addons_data


def collect_eks_data(region):
    """
    Collect EKS cluster information from a specific region

    Args:
        region: AWS region to collect clusters from

    Returns:
        tuple: (clusters_data, node_groups_data, addons_data)
    """
    clusters_data = []
    node_groups_data = []
    addons_data = []

    try:
        client = utils.get_boto3_client('eks', region_name=region)

        response = client.list_clusters()
        cluster_names = response.get('clusters', [])

        if not cluster_names:
            utils.log_info(f"No EKS clusters found in {region}")
            return clusters_data, node_groups_data, addons_data

        utils.log_info(f"Found {len(cluster_names)} EKS clusters in {region} to process")

        for i, cluster_name in enumerate(cluster_names, 1):
            progress = (i / len(cluster_names)) * 100
            utils.log_info(f"[{progress:.1f}%] Processing EKS cluster {i}/{len(cluster_names)}: {cluster_name}")

            cluster_info = collect_cluster_details(client, cluster_name, region)
            if cluster_info:
                clusters_data.append(cluster_info)

            cluster_node_groups = collect_node_groups(client, cluster_name, region)
            node_groups_data.extend(cluster_node_groups)

            cluster_addons = collect_cluster_addons(client, cluster_name, region)
            addons_data.extend(cluster_addons)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            utils.log_warning(f"Access denied to EKS in {region}. Check permissions.")
        else:
            utils.log_error(f"Error accessing EKS in {region}: {e}")
    except Exception as e:
        utils.log_error(f"Error collecting EKS clusters from {region}", e)

    return clusters_data, node_groups_data, addons_data


# ============================================================================
# EXPORT FUNCTIONS
# ============================================================================

def export_ec2_data(ec2_data, account_name, current_date):
    """
    Export EC2 data to Excel file

    Args:
        ec2_data: List of EC2 instance dictionaries
        account_name: AWS account name
        current_date: Current date string (MM.DD.YYYY)

    Returns:
        str: Path to exported file or None if failed
    """
    if not ec2_data:
        utils.log_warning("No EC2 data to export")
        return None

    try:
        import pandas as pd

        df = pd.DataFrame(ec2_data)
        df['Launch Time'] = pd.to_datetime(df['Launch Time']).dt.tz_localize(None)

        filename = f"ec2-export-{current_date}.xlsx"

        output_path = utils.save_dataframe_to_excel(df, filename)

        if output_path:
            utils.log_success(f"EC2 data exported successfully to {filename}")
            return output_path
        else:
            utils.log_error("Error exporting EC2 data")
            return None

    except Exception as e:
        utils.log_error("Error exporting EC2 data", e)
        return None


def export_rds_data(rds_data, account_name, current_date):
    """
    Export RDS data to Excel file

    Args:
        rds_data: List of RDS instance dictionaries
        account_name: AWS account name
        current_date: Current date string (MM.DD.YYYY)

    Returns:
        str: Path to exported file or None if failed
    """
    if not rds_data:
        utils.log_warning("No RDS data to export")
        return None

    try:
        import pandas as pd

        processed_data = []
        for item in rds_data:
            processed_item = {}
            for key, value in item.items():
                if isinstance(value, datetime.datetime) and value.tzinfo is not None:
                    processed_item[key] = value.replace(tzinfo=None)
                else:
                    processed_item[key] = value
            processed_data.append(processed_item)

        df = pd.DataFrame(processed_data)

        filename = f"rds-export-{current_date}.xlsx"

        output_path = utils.save_dataframe_to_excel(df, filename, sheet_name='RDS Instances')

        if output_path:
            utils.log_success(f"RDS data exported successfully to {filename}")
            return output_path
        else:
            utils.log_error("Error exporting RDS data")
            return None

    except Exception as e:
        utils.log_error("Error exporting RDS data", e)
        return None


def export_eks_data(clusters_data, node_groups_data, addons_data, account_name, current_date):
    """
    Export EKS data to Excel file with multiple sheets

    Args:
        clusters_data: List of cluster dictionaries
        node_groups_data: List of node group dictionaries
        addons_data: List of add-on dictionaries
        account_name: AWS account name
        current_date: Current date string (MM.DD.YYYY)

    Returns:
        str: Path to exported file or None if failed
    """
    if not clusters_data and not node_groups_data and not addons_data:
        utils.log_warning("No EKS data to export")
        return None

    try:
        import pandas as pd

        data_frames = {}

        if clusters_data:
            clusters_df = pd.DataFrame(clusters_data)
            data_frames['EKS Clusters'] = clusters_df

        if node_groups_data:
            node_groups_df = pd.DataFrame(node_groups_data)
            data_frames['Node Groups'] = node_groups_df

        if addons_data:
            addons_df = pd.DataFrame(addons_data)
            data_frames['Cluster Add-ons'] = addons_df

        filename = f"eks-export-{current_date}.xlsx"

        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success(f"EKS data exported successfully to {filename}")
            return output_path
        else:
            utils.log_error("Error exporting EKS data")
            return None

    except Exception as e:
        utils.log_error("Error exporting EKS data", e)
        return None


def create_compute_archive(output_files, current_date):
    """
    Create a zip archive containing all compute resource exports

    Args:
        output_files: List of output file paths
        current_date: Current date string (MM.DD.YYYY)

    Returns:
        str: Path to created archive or None if failed
    """
    try:
        valid_files = [f for f in output_files if f and Path(f).exists()]

        if not valid_files:
            utils.log_error("No valid output files to archive")
            return None

        archive_filename = f"compute-resources-{current_date}.zip"
        archive_path = utils.get_output_filepath(archive_filename)

        utils.log_info(f"Creating archive: {archive_filename}")

        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in valid_files:
                file_path_obj = Path(file_path)
                if file_path_obj.exists():
                    zipf.write(file_path_obj, file_path_obj.name)
                    utils.log_info(f"Added to archive: {file_path_obj.name}")

        if archive_path.exists():
            archive_size = archive_path.stat().st_size / (1024 * 1024)
            utils.log_success(f"Archive created successfully: {archive_filename}")
            utils.log_info(f"Archive size: {archive_size:.2f} MB")
            utils.log_info(f"Files included: {len(valid_files)}")
            return str(archive_path)
        else:
            utils.log_error("Archive creation failed")
            return None

    except Exception as e:
        utils.log_error("Error creating archive", e)
        return None


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """
    Main function to orchestrate the all-in-one compute resources collection
    """
    try:
        # Check dependencies first
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return

        # Import pandas after dependency check
        import pandas as pd

        # Print title and get account info
        account_id, account_name = print_title()

        # Validate AWS credentials
        try:
            sts = utils.get_boto3_client('sts')
            sts.get_caller_identity()
            utils.log_success("AWS credentials validated")

        except NoCredentialsError:
            utils.log_error("AWS credentials not found. Please configure your credentials using:")
            print("  - AWS CLI: aws configure")
            print("  - Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
            print("  - IAM role (if running on EC2)")
            return
        except Exception as e:
            utils.log_error("Error validating AWS credentials", e)
            return

        # Get region selection
        selected_regions = get_region_selection()

        utils.log_info(f"Starting comprehensive compute resources collection from AWS...")
        utils.log_info(f"Selected regions: {', '.join(selected_regions)}")

        current_date = datetime.datetime.now().strftime("%m.%d.%Y")

        print(f"\n{'='*70}")
        print(f"COMPUTE RESOURCES ALL-IN-ONE EXPORT")
        print(f"Regions: {', '.join(selected_regions)}")
        print(f"{'='*70}\n")

        # Track execution times
        start_time = datetime.datetime.now()

        # ====================================================================
        # COLLECT EC2 DATA
        # ====================================================================
        print(f"\n{'='*70}")
        print(f"COLLECTING EC2 INSTANCES")
        print(f"{'='*70}")

        ec2_start = datetime.datetime.now()
        all_ec2_data = []

        for region in selected_regions:
            utils.log_info(f"Collecting EC2 data from {region}...")
            ec2_data = collect_ec2_data(region)
            all_ec2_data.extend(ec2_data)
            utils.log_info(f"Found {len(ec2_data)} EC2 instances in {region}")

        ec2_duration = (datetime.datetime.now() - ec2_start).total_seconds()
        utils.log_success(f"EC2 collection completed in {ec2_duration:.1f} seconds")
        utils.log_info(f"Total EC2 instances: {len(all_ec2_data)}")

        # ====================================================================
        # COLLECT RDS DATA
        # ====================================================================
        print(f"\n{'='*70}")
        print(f"COLLECTING RDS INSTANCES")
        print(f"{'='*70}")

        rds_start = datetime.datetime.now()
        all_rds_data = []

        for region in selected_regions:
            utils.log_info(f"Collecting RDS data from {region}...")
            rds_data = collect_rds_data(region)
            all_rds_data.extend(rds_data)
            utils.log_info(f"Found {len(rds_data)} RDS instances in {region}")

        rds_duration = (datetime.datetime.now() - rds_start).total_seconds()
        utils.log_success(f"RDS collection completed in {rds_duration:.1f} seconds")
        utils.log_info(f"Total RDS instances: {len(all_rds_data)}")

        # ====================================================================
        # COLLECT EKS DATA
        # ====================================================================
        print(f"\n{'='*70}")
        print(f"COLLECTING EKS CLUSTERS")
        print(f"{'='*70}")

        eks_start = datetime.datetime.now()
        all_clusters_data = []
        all_node_groups_data = []
        all_addons_data = []

        for region in selected_regions:
            utils.log_info(f"Collecting EKS data from {region}...")
            clusters_data, node_groups_data, addons_data = collect_eks_data(region)
            all_clusters_data.extend(clusters_data)
            all_node_groups_data.extend(node_groups_data)
            all_addons_data.extend(addons_data)
            utils.log_info(f"Found {len(clusters_data)} EKS clusters in {region}")

        eks_duration = (datetime.datetime.now() - eks_start).total_seconds()
        utils.log_success(f"EKS collection completed in {eks_duration:.1f} seconds")
        utils.log_info(f"Total EKS clusters: {len(all_clusters_data)}")

        # ====================================================================
        # EXPORT DATA
        # ====================================================================
        print(f"\n{'='*70}")
        print(f"EXPORTING DATA TO EXCEL FILES")
        print(f"{'='*70}")

        output_files = []

        # Export EC2 data
        ec2_file = export_ec2_data(all_ec2_data, account_name, current_date)
        if ec2_file:
            output_files.append(ec2_file)

        # Export RDS data
        rds_file = export_rds_data(all_rds_data, account_name, current_date)
        if rds_file:
            output_files.append(rds_file)

        # Export EKS data
        eks_file = export_eks_data(all_clusters_data, all_node_groups_data, all_addons_data, account_name, current_date)
        if eks_file:
            output_files.append(eks_file)

        # ====================================================================
        # CREATE ARCHIVE
        # ====================================================================
        if output_files:
            print(f"\n{'='*70}")
            print(f"CREATING ARCHIVE")
            print(f"{'='*70}")

            archive_path = create_compute_archive(output_files, current_date)

            if archive_path:
                total_duration = (datetime.datetime.now() - start_time).total_seconds()

                print(f"\n{'='*70}")
                print(f"COMPUTE RESOURCES EXPORT COMPLETED SUCCESSFULLY")
                print(f"{'='*70}")

                utils.log_success(f"Archive location: {archive_path}")
                utils.log_info(f"Total execution time: {total_duration:.1f} seconds")

                print(f"\nSummary:")
                print(f"  EC2 Instances: {len(all_ec2_data)}")
                print(f"  RDS Instances: {len(all_rds_data)}")
                print(f"  EKS Clusters: {len(all_clusters_data)}")
                print(f"  Regions: {', '.join(selected_regions)}")
                print(f"  Archive: {Path(archive_path).name}")
            else:
                utils.log_error("Failed to create archive")
        else:
            utils.log_error("No data was exported successfully")

        print(f"\nScript execution completed.")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

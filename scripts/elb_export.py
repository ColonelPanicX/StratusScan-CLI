#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Elastic Load Balancer Data Export
Date: NOV-15-2025

Description:
This script queries for Load Balancers across available AWS regions or a specific
AWS region and exports the list to a single Excel spreadsheet.

Phase 4B Update:
- Concurrent region scanning (4x-10x performance improvement)
- Automatic fallback to sequential on errors
"""

import pandas as pd
import datetime
import os
import sys
from pathlib import Path

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

def is_valid_aws_region(region_name):
    """
    Check if a region name is a valid AWS region

    Args:
        region_name (str): The region name to check

    Returns:
        bool: True if valid, False otherwise
    """
    return utils.is_aws_region(region_name)

@utils.aws_error_handler("Fetching security group names", default_return={})
def get_security_group_names(security_group_ids, region):
    """
    Get security group names for the given IDs

    Args:
        security_group_ids (list): List of security group IDs
        region (str): AWS region

    Returns:
        dict: Mapping of security group IDs to names
    """
    if not security_group_ids:
        return {}

    # Validate region is AWS
    if not utils.is_aws_region(region):
        utils.log_error(f"Invalid AWS region: {region}")
        return {}

    ec2 = utils.get_boto3_client('ec2', region_name=region)
    sg_mapping = {}

    # Fetch security group information
    response = ec2.describe_security_groups(GroupIds=security_group_ids)

    # Create a mapping of security group IDs to names
    for sg in response['SecurityGroups']:
        sg_mapping[sg['GroupId']] = sg['GroupName']

    return sg_mapping

@utils.aws_error_handler("Collecting Classic Load Balancers", default_return=[])
def get_classic_load_balancers(region):
    """
    Get information about Classic Load Balancers in the specified AWS region

    Args:
        region (str): AWS region

    Returns:
        list: List of dictionaries containing Classic Load Balancer information
    """
    # Validate region is AWS
    if not utils.is_aws_region(region):
        utils.log_error(f"Invalid AWS region: {region}")
        return []

    elb_data = []

    # Create an ELB client for the specified region
    elb = utils.get_boto3_client('elb', region_name=region)

    # Describe all Classic Load Balancers
    paginator = elb.get_paginator('describe_load_balancers')
    all_lbs = []
    for page in paginator.paginate():
        all_lbs.extend(page.get('LoadBalancerDescriptions', []))

    for lb in all_lbs:
        # Get security group names for the security group IDs
        sg_ids = lb.get('SecurityGroups', [])
        sg_mapping = get_security_group_names(sg_ids, region)

        # Format security groups as "sg-name (sg-id), ..."
        security_groups = []
        for sg_id in sg_ids:
            sg_name = sg_mapping.get(sg_id, "Unknown")
            security_groups.append(f"{sg_name} ({sg_id})")

        # Format availability zones as "subnet-id (az), ..."
        availability_zones = []
        for az in lb.get('AvailabilityZones', []):
            availability_zones.append(f"{az}")

        # Add subnets if available (VPC Classic ELB)
        for subnet_id in lb.get('Subnets', []):
            # For VPC Classic ELBs, we need to get the AZ for each subnet
            try:
                ec2 = utils.get_boto3_client('ec2', region_name=region)
                subnet_response = ec2.describe_subnets(SubnetIds=[subnet_id])
                subnet_az = subnet_response['Subnets'][0]['AvailabilityZone']
                availability_zones.append(f"{subnet_id} ({subnet_az})")
            except Exception as e:
                utils.log_warning(f"Could not get AZ for subnet {subnet_id}: {e}")
                availability_zones.append(f"{subnet_id} (Unknown AZ)")

        # Get creation time
        created_time = lb.get('CreatedTime', datetime.datetime.now())

        # Get owner information
        owner_id = lb.get('OwnerId', 'N/A')
        owner_name = utils.get_account_name_formatted(owner_id)

        # Add load balancer data to the list
        elb_data.append({
            'Region': region,
            'Name': lb.get('LoadBalancerName', ''),
            'DNS Name': lb.get('DNSName', ''),
            'VPC ID': lb.get('VPCId', 'N/A'),
            'Availability Zones': ', '.join(availability_zones),
            'Type': 'Classic',
            'Date Created': created_time.strftime('%Y-%m-%d'),
            'Security Groups': ', '.join(security_groups) if security_groups else 'N/A',
            'Owner': owner_name
        })

    return elb_data

@utils.aws_error_handler("Collecting Application and Network Load Balancers", default_return=[])
def get_application_network_load_balancers(region):
    """
    Get information about Application and Network Load Balancers in the specified AWS region

    Args:
        region (str): AWS region

    Returns:
        list: List of dictionaries containing ALB/NLB information
    """
    # Validate region is AWS
    if not utils.is_aws_region(region):
        utils.log_error(f"Invalid AWS region: {region}")
        return []

    elb_data = []

    # Create an ELBv2 client for the specified region
    elbv2 = utils.get_boto3_client('elbv2', region_name=region)

    # Describe all ALBs and NLBs
    paginator = elbv2.get_paginator('describe_load_balancers')
    all_lbs = []
    for page in paginator.paginate():
        all_lbs.extend(page.get('LoadBalancers', []))

    for lb in all_lbs:
        # Get load balancer type
        lb_type = lb.get('Type', 'Unknown')

        # Get security group names for ALBs (NLBs don't have security groups)
        sg_ids = lb.get('SecurityGroups', [])
        security_groups = []

        if sg_ids:
            sg_mapping = get_security_group_names(sg_ids, region)
            for sg_id in sg_ids:
                sg_name = sg_mapping.get(sg_id, "Unknown")
                security_groups.append(f"{sg_name} ({sg_id})")

        # Get subnet information
        availability_zones = []
        for az_info in lb.get('AvailabilityZones', []):
            subnet_id = az_info.get('SubnetId', '')
            zone_name = az_info.get('ZoneName', '')
            availability_zones.append(f"{subnet_id} ({zone_name})")

        # Get creation time
        created_time = lb.get('CreatedTime', datetime.datetime.now())

        # Get owner information from the ARN
        lb_arn = lb.get('LoadBalancerArn', '')
        if lb_arn:
            # Parse owner from ARN
            try:
                arn_parts = lb_arn.split(':')
                if len(arn_parts) >= 5:
                    owner_id = arn_parts[4]
                    owner_name = utils.get_account_name_formatted(owner_id)
                else:
                    owner_name = 'N/A'
            except Exception:
                owner_name = 'N/A'
        else:
            owner_name = 'N/A'

        # Add load balancer data to the list
        elb_data.append({
            'Region': region,
            'Name': lb.get('LoadBalancerName', ''),
            'DNS Name': lb.get('DNSName', ''),
            'VPC ID': lb.get('VpcId', 'N/A'),
            'Availability Zones': ', '.join(availability_zones),
            'Type': lb_type,
            'Date Created': created_time.strftime('%Y-%m-%d'),
            'Security Groups': ', '.join(security_groups) if security_groups else 'N/A',
            'Owner': owner_name
        })

    return elb_data

def main():
    """
    Main function to run the script
    """
    # Print the title screen and get the account name
    utils.setup_logging("elb-export")
    account_id, account_name = utils.print_script_banner("AWS ELB INVENTORY EXPORT")
    
    # Check for required dependencies
    if not utils.ensure_dependencies('pandas', 'openpyxl'):
        sys.exit(1)
    
    regions = utils.prompt_region_selection()
    region_suffix = 'all'

    # Collect ELB data from all regions (Phase 4B: concurrent)
    utils.log_info("Collecting ELB data from all regions...")

    # Define region scan function
    def scan_region_elbs(region):
        utils.log_info(f"Processing AWS region: {region}")
        region_elbs = []

        # Get Classic Load Balancers
        utils.log_info(f"  Fetching Classic Load Balancers...")
        classic_elbs = get_classic_load_balancers(region)
        classic_count = len(classic_elbs)
        utils.log_info(f"  Found {classic_count} Classic Load Balancers.")
        region_elbs.extend(classic_elbs)

        # Get Application and Network Load Balancers
        utils.log_info(f"  Fetching Application and Network Load Balancers...")
        elbv2s = get_application_network_load_balancers(region)
        elbv2_count = len(elbv2s)
        utils.log_info(f"  Found {elbv2_count} Application and Network Load Balancers.")
        region_elbs.extend(elbv2s)

        return region_elbs

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_region_elbs,
        show_progress=True
    )

    # Flatten results and count totals
    all_elb_data = []
    total_classic_elbs = 0
    total_elbv2s = 0

    for region_elbs in region_results:
        for elb in region_elbs:
            if elb.get('Type') == 'Classic':
                total_classic_elbs += 1
            else:
                total_elbv2s += 1
        all_elb_data.extend(region_elbs)
    
    # If no ELBs found, exit
    if not all_elb_data:
        utils.log_warning("No Elastic Load Balancers found in any AWS region.")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(all_elb_data)
    
    # Sort by Region, Type, and Name
    df = df.sort_values(by=['Region', 'Type', 'Name'])
    
    # Generate filename with current date
    current_date = datetime.datetime.now().strftime('%m.%d.%Y')
    
    # Use utils to create filename
    filename = utils.create_export_filename(
        account_name,
        "elb",
        region_suffix,
        current_date
    )
    
    # Export to Excel using utils
    output_path = utils.save_dataframe_to_excel(df, filename)
    
    if output_path:
        utils.log_success("AWS ELB data exported successfully!")
        utils.log_info(f"File location: {output_path}")
        utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")
        utils.log_info(f"Total Classic ELBs: {total_classic_elbs}")
        utils.log_info(f"Total ALB/NLB: {total_elbv2s}")
        utils.log_info(f"Total Load Balancers: {len(all_elb_data)}")
        print("\nScript execution completed.")
    else:
        utils.log_error("Failed to save the Excel file.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
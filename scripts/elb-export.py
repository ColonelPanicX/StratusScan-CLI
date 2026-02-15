#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Elastic Load Balancer Data Export
Version: v2.1.0
Date: NOV-15-2025

Description:
This script queries for Load Balancers across available AWS regions or a specific
AWS region and exports the list to a single Excel spreadsheet.

Phase 4B Update:
- Concurrent region scanning (4x-10x performance improvement)
- Automatic fallback to sequential on errors
"""

import boto3
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

def print_title_screen():
    """
    Prints a formatted title screen with script information

    Returns:
        str: The account name
    """
    # Get the AWS account ID using STS
    try:
        sts_client = utils.get_boto3_client('sts')
        account_id = sts_client.get_caller_identity()['Account']

        # Get the corresponding account name from utils module
        account_name = utils.get_account_name(account_id, default="UNKNOWN-ACCOUNT")
    except Exception as e:
        utils.log_error("Unable to determine AWS account ID", e)
        account_id = "UNKNOWN"
        account_name = "UNKNOWN-ACCOUNT"

    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"

    # Print the title screen with account information
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS ELB INVENTORY EXPORT SCRIPT")
    print("====================================================================")
    print("Version: v2.0.0                             Date: AUG-19-2025")
    print(f"Environment: {partition_name}")
    print("====================================================================")
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")

    return account_name

def check_dependencies():
    """
    Checks if required dependencies are installed and offers to install them
    
    Returns:
        bool: True if all dependencies are installed or successfully installed,
              False otherwise
    """
    required_packages = ['pandas', 'openpyxl', 'boto3']
    missing_packages = []
    
    # Check which required packages are missing
    for package in required_packages:
        try:
            __import__(package)
            utils.log_info(f"[OK] {package} is already installed")
        except ImportError:
            missing_packages.append(package)
    
    # If there are missing packages, prompt the user to install them
    if missing_packages:
        utils.log_warning(f"Missing dependencies: {', '.join(missing_packages)}")
        install_choice = input("Do you want to install the missing dependencies? (y/n): ").lower().strip()
        
        if install_choice == 'y':
            import subprocess
            for package in missing_packages:
                utils.log_info(f"Installing {package}...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    utils.log_success(f"{package} installed successfully.")
                except Exception as e:
                    utils.log_error(f"Error installing {package}", e)
                    print("Please install it manually with: pip install " + package)
                    return False
            return True
        else:
            print("Script cannot continue without required dependencies. Exiting.")
            return False
    
    return True

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

def is_valid_aws_region(region_name):
    """
    Check if a region name is a valid AWS region

    Args:
        region_name (str): The region name to check

    Returns:
        bool: True if valid, False otherwise
    """
    return utils.validate_aws_region(region_name)

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
    if not utils.validate_aws_region(region):
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
    if not utils.validate_aws_region(region):
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
    if not utils.validate_aws_region(region):
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
    account_name = print_title_screen()
    
    # Check for required dependencies
    if not check_dependencies():
        sys.exit(1)
    
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
        region_suffix = ""
        utils.log_info(f"Scanning {len(regions)} default AWS regions")
    elif selection_int == 2:
        regions = all_available_regions
        region_suffix = ""
        utils.log_info(f"Scanning all {len(regions)} AWS regions")
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
                    region_suffix = f"-{selected_region}"
                    utils.log_info(f"Scanning region: {selected_region}")
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print(f"Please enter a valid number (1-{len(all_available_regions)}).")
    
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
#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Network ACL (NACL) Data Export
Date: NOV-15-2025

Description:
This script exports Network ACL (NACL) information from AWS regions, including NACL ID,
VPC ID, inbound/outbound rules, subnet associations, and tags. The data is exported to an Excel
file for analysis and compliance purposes.

Phase 4B Update:
- Concurrent region scanning (4x-10x performance improvement)
- Automatic fallback to sequential on errors
"""

import sys
import datetime
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

def print_title():
    """
    Print the script title banner and get account info.
    
    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS NETWORK ACL (NACL) DATA EXPORT TOOL")
    print("====================================================================")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")
    
    # Get account information using utils
    account_id, account_name = utils.get_account_info()

    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    
    print("====================================================================")
    return account_id, account_name
def is_valid_aws_region(region_name):
    """
    Check if a region name is a valid AWS region.

    Args:
        region_name (str): The region name to validate

    Returns:
        bool: True if valid, False otherwise
    """
    return utils.validate_aws_region(region_name)

def get_tag_value(tags, key='Name'):
    """
    Get a tag value from a list of tags.
    
    Args:
        tags: List of tag dictionaries
        key: The tag key to look for
        
    Returns:
        str: The tag value or "N/A" if not found
    """
    if not tags:
        return "N/A"
    
    for tag in tags:
        if tag['Key'] == key:
            return tag['Value']
    
    return "N/A"

def format_rule(rule):
    """
    Format a NACL rule into a readable string.
    
    Args:
        rule: The NACL rule dictionary
        
    Returns:
        str: A formatted string representation of the rule
    """
    rule_number = rule.get('RuleNumber', 'N/A')
    protocol = rule.get('Protocol', 'N/A')
    
    # Convert protocol number to name if possible
    if protocol == '-1':
        protocol = 'All'
    elif protocol == '6':
        protocol = 'TCP'
    elif protocol == '17':
        protocol = 'UDP'
    elif protocol == '1':
        protocol = 'ICMP'
    
    # Get port range
    port_range = f"{rule.get('PortRange', {}).get('From', 'All')}-{rule.get('PortRange', {}).get('To', 'All')}"
    if port_range == "All-All":
        port_range = "All"
    
    cidr = rule.get('CidrBlock', rule.get('Ipv6CidrBlock', 'N/A'))
    action = rule.get('RuleAction', 'N/A')
    
    return f"{rule_number}: {action.upper()} {protocol}:{port_range} from {cidr}"

@utils.aws_error_handler("Collecting Network ACL data", default_return=[])
def get_nacl_data(region):
    """
    Get Network ACL information for a specific AWS region.

    Args:
        region: AWS region name

    Returns:
        list: List of dictionaries with NACL information
    """
    # Validate region is AWS
    if not utils.validate_aws_region(region):
        utils.log_error(f"Invalid AWS region: {region}")
        return []

    nacl_data = []

    # Create EC2 client for the specified AWS region
    ec2_client = utils.get_boto3_client('ec2', region_name=region)

    # Get all NACLs in the region
    paginator = ec2_client.get_paginator('describe_network_acls')
    all_nacls = []
    for page in paginator.paginate():
        all_nacls.extend(page.get('NetworkAcls', []))

    for nacl in all_nacls:
        nacl_id = nacl.get('NetworkAclId', 'N/A')
        vpc_id = nacl.get('VpcId', 'N/A')
        is_default = nacl.get('IsDefault', False)

        # Get NACL name from tags
        nacl_name = get_tag_value(nacl.get('Tags', []))

        # Format tags as a string
        tags_str = '; '.join([f"{tag['Key']}={tag['Value']}" for tag in nacl.get('Tags', [])])
        if not tags_str:
            tags_str = "N/A"

        # Get inbound and outbound rules
        inbound_rules = [rule for rule in nacl.get('Entries', []) if not rule.get('Egress', False)]
        outbound_rules = [rule for rule in nacl.get('Entries', []) if rule.get('Egress', False)]

        # Format rules as strings
        inbound_rules_str = '; '.join([format_rule(rule) for rule in sorted(inbound_rules, key=lambda x: x.get('RuleNumber', 0))])
        outbound_rules_str = '; '.join([format_rule(rule) for rule in sorted(outbound_rules, key=lambda x: x.get('RuleNumber', 0))])

        if not inbound_rules_str:
            inbound_rules_str = "N/A"
        if not outbound_rules_str:
            outbound_rules_str = "N/A"

        # Get subnet associations
        subnet_associations = []
        for assoc in nacl.get('Associations', []):
            subnet_id = assoc.get('SubnetId', 'N/A')
            if subnet_id != 'N/A':
                subnet_associations.append(subnet_id)

        subnet_associations_str = '; '.join(subnet_associations) if subnet_associations else "N/A"

        # Get owner information
        owner_id = nacl.get('OwnerId', 'N/A')
        owner_formatted = utils.get_account_name_formatted(owner_id)

        # Add NACL data
        nacl_entry = {
            'Region': region,
            'NACL ID': nacl_id,
            'NACL Name': nacl_name,
            'VPC ID': vpc_id,
            'Is Default': 'Yes' if is_default else 'No',
            'Inbound Rules': inbound_rules_str,
            'Outbound Rules': outbound_rules_str,
            'Subnet Associations': subnet_associations_str,
            'Owner ID': owner_formatted,
            'Tags': tags_str
        }

        nacl_data.append(nacl_entry)

    return nacl_data

def main():
    """
    Main function to execute the script.
    """
    try:
        # Print title and get account information
        account_id, account_name = print_title()
        
        # Check for required dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)
            
        # Now import pandas after ensuring it's installed
        import pandas as pd
        
        if account_name == "UNKNOWN-ACCOUNT":
            proceed = utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False)
            if not proceed:
                utils.log_info("Exiting script...")
                sys.exit(0)
        
        regions = utils.prompt_region_selection()
        region_suffix = 'all'

        # Collect NACL data from all specified AWS regions (Phase 4B: concurrent)
        utils.log_info("Collecting Network ACL data from AWS regions...")

        # Define region scan function
        def scan_region_nacls(region):
            utils.log_info(f"Processing AWS region: {region}")
            region_data = get_nacl_data(region)
            utils.log_info(f"Found {len(region_data)} NACLs in {region}")
            return region_data

        # Use concurrent region scanning
        region_results = utils.scan_regions_concurrent(
            regions=regions,
            scan_function=scan_region_nacls,
            show_progress=True
        )

        # Flatten results
        all_nacl_data = []
        for data in region_results:
            all_nacl_data.extend(data)

        # Create DataFrame from collected data
        df = pd.DataFrame(all_nacl_data)

        # Prepare and sanitize DataFrame (NACLs may have sensitive tags)
        df = utils.sanitize_for_export(
            utils.prepare_dataframe_for_export(df)
        )

        # Get current date for filename
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")

        # Use utils module to generate filename and save data
        filename = utils.create_export_filename(
            account_name,
            "nacl",
            region_suffix,
            current_date
        )

        # Save data using the utility function
        output_path = utils.save_dataframe_to_excel(df, filename)
        
        if output_path:
            utils.log_success("AWS Network ACL data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")
            utils.log_info(f"Total Network ACLs exported: {len(all_nacl_data)}")
            print("\nScript execution completed.")
        else:
            utils.log_error("Error exporting data. Please check the logs.")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
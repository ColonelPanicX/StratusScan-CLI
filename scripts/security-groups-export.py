#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Security Groups Export Script
Version: v2.1.0
Date: NOV-15-2025

Description:
This script exports security group information from AWS regions including group name, ID,
VPC, inbound rules, outbound rules, and associated resources. Each security group rule is listed
on its own line for better analysis and filtering. The data is exported to an Excel file with
AWS-specific naming convention and compliance markers.

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
    Print the script title and account information.
    
    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS SECURITY GROUPS EXPORT")
    print("====================================================================")
    print("Version: v2.0.0                       Date: AUG-26-2025")
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
    Check if a region name is a valid AWS region.
    
    Args:
        region_name (str): The region name to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    return utils.validate_aws_region(region_name)

def get_vpc_name(ec2_client, vpc_id):
    """
    Get the name of a VPC from its ID.
    
    Args:
        ec2_client: The boto3 EC2 client
        vpc_id: The VPC ID
        
    Returns:
        str: The VPC name and ID or default value
    """
    if not vpc_id:
        return "No VPC (EC2-Classic)"
    
    try:
        response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        
        if not response['Vpcs']:
            return vpc_id  # Return the ID if no VPC found
        
        # Look for the Name tag
        for tag in response['Vpcs'][0].get('Tags', []):
            if tag['Key'] == 'Name':
                return f"{tag['Value']} ({vpc_id})"
        
        # If no Name tag, just return the ID
        return vpc_id
    except Exception as e:
        return vpc_id  # Return the ID on error

def format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=True):
    """
    Format IP range rule details.
    
    Args:
        ip_range: The IP range dictionary
        protocol: The protocol
        from_port: The from port
        to_port: The to port
        is_inbound: Whether this is an inbound rule
        
    Returns:
        str: Formatted rule string
    """
    if protocol == '-1':
        protocol = 'All'
    
    # Format port range
    port_range = ''
    if from_port is not None and to_port is not None:
        if from_port == to_port:
            port_range = str(from_port)
        else:
            port_range = f"{from_port}-{to_port}"
    else:
        port_range = 'All'
    
    # Format CIDR
    cidr = ip_range.get('CidrIp', ip_range.get('CidrIpv6', 'Unknown'))
    
    if is_inbound:
        return f"{cidr} → {protocol}:{port_range}"
    else:
        return f"{protocol}:{port_range} → {cidr}"

def format_security_group_reference(sg_ref, protocol, from_port, to_port, is_inbound=True):
    """
    Format security group reference rule details.
    
    Args:
        sg_ref: The security group reference dictionary
        protocol: The protocol
        from_port: The from port
        to_port: The to port
        is_inbound: Whether this is an inbound rule
        
    Returns:
        str: Formatted rule string
    """
    if protocol == '-1':
        protocol = 'All'
    
    # Format port range
    port_range = ''
    if from_port is not None and to_port is not None:
        if from_port == to_port:
            port_range = str(from_port)
        else:
            port_range = f"{from_port}-{to_port}"
    else:
        port_range = 'All'
    
    # Format security group reference
    sg_identifier = ""
    if 'GroupId' in sg_ref:
        sg_identifier = f"sg:{sg_ref['GroupId']}"
    elif 'GroupName' in sg_ref:
        sg_identifier = f"sg:{sg_ref['GroupName']}"
    else:
        sg_identifier = "sg:Unknown"
    
    if is_inbound:
        return f"{sg_identifier} → {protocol}:{port_range}"
    else:
        return f"{protocol}:{port_range} → {sg_identifier}"

def get_security_group_resources(ec2_client, sg_id):
    """
    Find EC2 instances, RDS instances, and other resources using this security group.
    
    Args:
        ec2_client: The boto3 EC2 client
        sg_id: The security group ID
        
    Returns:
        list: List of resources using this security group
    """
    resources = []
    
    # Check EC2 instances
    try:
        response = ec2_client.describe_instances(
            Filters=[{'Name': 'instance.group-id', 'Values': [sg_id]}]
        )
        
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                # Get instance name from tags
                instance_name = 'Unnamed'
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
                
                resources.append(f"EC2:{instance_name} ({instance['InstanceId']})")
    except Exception as e:
        utils.log_warning(f"Could not fetch EC2 instances for SG {sg_id}: {e}")

    # Try to check RDS instances
    try:
        rds_client = utils.get_boto3_client('rds', region_name=ec2_client.meta.region_name)
        rds_paginator = rds_client.get_paginator('describe_db_instances')
        rds_instances = []
        for page in rds_paginator.paginate():
            rds_instances.extend(page.get('DBInstances', []))

        for instance in rds_instances:
            for sg in instance.get('VpcSecurityGroups', []):
                if sg.get('VpcSecurityGroupId') == sg_id:
                    resources.append(f"RDS:{instance['DBInstanceIdentifier']}")
                    break
    except Exception as e:
        utils.log_warning(f"Could not fetch RDS instances for SG {sg_id}: {e}")

    # Try to check ELBs (Classic Load Balancers)
    try:
        elb_client = utils.get_boto3_client('elb', region_name=ec2_client.meta.region_name)
        elb_paginator = elb_client.get_paginator('describe_load_balancers')
        elb_lbs = []
        for page in elb_paginator.paginate():
            elb_lbs.extend(page.get('LoadBalancerDescriptions', []))

        for lb in elb_lbs:
            if sg_id in lb.get('SecurityGroups', []):
                resources.append(f"ELB:{lb['LoadBalancerName']}")
    except Exception as e:
        utils.log_warning(f"Could not fetch ELBs for SG {sg_id}: {e}")

    # Try to check ELBv2 (Application and Network Load Balancers)
    try:
        elbv2_client = utils.get_boto3_client('elbv2', region_name=ec2_client.meta.region_name)
        elbv2_paginator = elbv2_client.get_paginator('describe_load_balancers')
        elbv2_lbs = []
        for page in elbv2_paginator.paginate():
            elbv2_lbs.extend(page.get('LoadBalancers', []))

        for lb in elbv2_lbs:
            if sg_id in lb.get('SecurityGroups', []):
                resources.append(f"ALB/NLB:{lb['LoadBalancerName']}")
    except Exception as e:
        utils.log_warning(f"Could not fetch ALBs/NLBs for SG {sg_id}: {e}")

    # Try to check Lambda functions
    try:
        lambda_client = utils.get_boto3_client('lambda', region_name=ec2_client.meta.region_name)
        lambda_paginator = lambda_client.get_paginator('list_functions')
        lambda_funcs = []
        for page in lambda_paginator.paginate():
            lambda_funcs.extend(page.get('Functions', []))

        for function in lambda_funcs:
            if 'VpcConfig' in function and sg_id in function['VpcConfig'].get('SecurityGroupIds', []):
                resources.append(f"Lambda:{function['FunctionName']}")
    except Exception as e:
        utils.log_warning(f"Could not fetch Lambda functions for SG {sg_id}: {e}")
    
    return resources

@utils.aws_error_handler("Collecting security group rules", default_return=[])
def get_security_group_rules(region):
    """
    Get all security groups and their rules from a specific AWS region.

    Args:
        region: AWS region name

    Returns:
        list: List of dictionaries with security group rule information
    """
    # Validate region is AWS
    if not utils.validate_aws_region(region):
        utils.log_error(f"Invalid AWS region: {region}")
        return []

    security_group_rules = []

    # Create EC2 client for this AWS region
    ec2_client = utils.get_boto3_client('ec2', region_name=region)

    # Get all security groups using paginator
    sg_paginator = ec2_client.get_paginator('describe_security_groups')
    security_groups_all = []
    for page in sg_paginator.paginate():
        security_groups_all.extend(page.get('SecurityGroups', []))

    # Get all security group rules using paginator
    rules_paginator = ec2_client.get_paginator('describe_security_group_rules')
    all_rules = []
    for page in rules_paginator.paginate():
        all_rules.extend(page.get('SecurityGroupRules', []))

    # Create a map of security group rules for faster lookup
    rules_map = {}
    for rule in all_rules:
        sg_id = rule.get('GroupId', '')
        if sg_id not in rules_map:
            rules_map[sg_id] = []
        rules_map[sg_id].append(rule)

    security_groups = security_groups_all
    total_sgs = len(security_groups)

    if total_sgs > 0:
        utils.log_info(f"Found {total_sgs} security groups in {region} to process")

    for sg_index, sg in enumerate(security_groups, 1):
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', 'Unnamed')
        progress = (sg_index / total_sgs) * 100 if total_sgs > 0 else 0

        utils.log_info(f"[{progress:.1f}%] Processing security group {sg_index}/{total_sgs}: {sg_id} ({sg_name})")

        # Get VPC name if available
        vpc_id = sg.get('VpcId', '')
        vpc_name = get_vpc_name(ec2_client, vpc_id) if vpc_id else "No VPC (EC2-Classic)"

        # Get resources using this security group
        resources = get_security_group_resources(ec2_client, sg_id)
        resources_str = '; '.join(resources) if resources else 'None'

        # Get description
        description = sg.get('Description', '')

        # Get owner information
        owner_id = sg.get('OwnerId', 'N/A')
        owner_formatted = utils.get_account_name_formatted(owner_id)

        # Process inbound rules (IpPermissions)
        for permission in sg.get('IpPermissions', []):
            protocol = permission.get('IpProtocol', 'All')
            from_port = permission.get('FromPort', None)
            to_port = permission.get('ToPort', None)

            # Process IPv4 ranges
            for ip_range in permission.get('IpRanges', []):
                # Find matching rule in the rules map
                rule_id = sg_id  # Default to using the security group ID
                if sg_id in rules_map:
                    for rule in rules_map[sg_id]:
                        if (rule.get('IpProtocol') == protocol and
                            rule.get('FromPort', None) == from_port and
                            rule.get('ToPort', None) == to_port and
                            rule.get('CidrIpv4', '') == ip_range.get('CidrIp', '') and
                            not rule.get('IsEgress', True)):
                            rule_id = rule.get('SecurityGroupRuleId', sg_id)
                            break

                rule_desc = ip_range.get('Description', '')
                rule_text = format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=True)

                security_group_rules.append({
                    'Rule ID': rule_id,
                    'SG Name': sg_name,
                    'SG ID': sg_id,
                    'VPC': vpc_name,
                    'SG Description': description,
                    'Direction': 'Inbound',
                    'Rule': rule_text,
                    'Rule Description': rule_desc,
                    'Protocol': protocol if protocol != '-1' else 'All',
                    'From Port': from_port if from_port is not None else 'All',
                    'To Port': to_port if to_port is not None else 'All',
                    'CIDR': ip_range.get('CidrIp', ''),
                    'Owner ID': owner_formatted,
                    'Used By': resources_str,
                    'Region': region
                })

            # Process IPv6 ranges
            for ip_range in permission.get('Ipv6Ranges', []):
                # Find matching rule in the rules map
                rule_id = sg_id  # Default to using the security group ID
                if sg_id in rules_map:
                    for rule in rules_map[sg_id]:
                        if (rule.get('IpProtocol') == protocol and
                            rule.get('FromPort', None) == from_port and
                            rule.get('ToPort', None) == to_port and
                            rule.get('CidrIpv6', '') == ip_range.get('CidrIpv6', '') and
                            not rule.get('IsEgress', True)):
                            rule_id = rule.get('SecurityGroupRuleId', sg_id)
                            break

                rule_desc = ip_range.get('Description', '')
                rule_text = format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=True)

                security_group_rules.append({
                    'Rule ID': rule_id,
                    'SG Name': sg_name,
                    'SG ID': sg_id,
                    'VPC': vpc_name,
                    'SG Description': description,
                    'Direction': 'Inbound',
                    'Rule': rule_text,
                    'Rule Description': rule_desc,
                    'Protocol': protocol if protocol != '-1' else 'All',
                    'From Port': from_port if from_port is not None else 'All',
                    'To Port': to_port if to_port is not None else 'All',
                    'CIDR': ip_range.get('CidrIpv6', ''),
                    'Owner ID': owner_formatted,
                    'Used By': resources_str,
                    'Region': region
                })

            # Process security group references
            for sg_ref in permission.get('UserIdGroupPairs', []):
                # Find matching rule in the rules map
                rule_id = sg_id  # Default to using the security group ID
                ref_group_id = sg_ref.get('GroupId', '')
                if sg_id in rules_map:
                    for rule in rules_map[sg_id]:
                        referenced_group = rule.get('ReferencedGroupInfo', {}).get('GroupId', '')
                        if (rule.get('IpProtocol') == protocol and
                            rule.get('FromPort', None) == from_port and
                            rule.get('ToPort', None) == to_port and
                            referenced_group == ref_group_id and
                            not rule.get('IsEgress', True)):
                            rule_id = rule.get('SecurityGroupRuleId', sg_id)
                            break

                rule_desc = sg_ref.get('Description', '')
                rule_text = format_security_group_reference(sg_ref, protocol, from_port, to_port, is_inbound=True)

                security_group_rules.append({
                    'Rule ID': rule_id,
                    'SG Name': sg_name,
                    'SG ID': sg_id,
                    'VPC': vpc_name,
                    'SG Description': description,
                    'Direction': 'Inbound',
                    'Rule': rule_text,
                    'Rule Description': rule_desc,
                    'Protocol': protocol if protocol != '-1' else 'All',
                    'From Port': from_port if from_port is not None else 'All',
                    'To Port': to_port if to_port is not None else 'All',
                    'Referenced SG': sg_ref.get('GroupId', ''),
                    'Owner ID': owner_formatted,
                    'Used By': resources_str,
                    'Region': region
                })

        # Process outbound rules (IpPermissionsEgress)
        for permission in sg.get('IpPermissionsEgress', []):
            protocol = permission.get('IpProtocol', 'All')
            from_port = permission.get('FromPort', None)
            to_port = permission.get('ToPort', None)

            # Process IPv4 ranges
            for ip_range in permission.get('IpRanges', []):
                # Find matching rule in the rules map
                rule_id = sg_id  # Default to using the security group ID
                if sg_id in rules_map:
                    for rule in rules_map[sg_id]:
                        if (rule.get('IpProtocol') == protocol and
                            rule.get('FromPort', None) == from_port and
                            rule.get('ToPort', None) == to_port and
                            rule.get('CidrIpv4', '') == ip_range.get('CidrIp', '') and
                            rule.get('IsEgress', False)):
                            rule_id = rule.get('SecurityGroupRuleId', sg_id)
                            break

                rule_desc = ip_range.get('Description', '')
                rule_text = format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=False)

                security_group_rules.append({
                    'Rule ID': rule_id,
                    'SG Name': sg_name,
                    'SG ID': sg_id,
                    'VPC': vpc_name,
                    'SG Description': description,
                    'Direction': 'Outbound',
                    'Rule': rule_text,
                    'Rule Description': rule_desc,
                    'Protocol': protocol if protocol != '-1' else 'All',
                    'From Port': from_port if from_port is not None else 'All',
                    'To Port': to_port if to_port is not None else 'All',
                    'CIDR': ip_range.get('CidrIp', ''),
                    'Owner ID': owner_formatted,
                    'Used By': resources_str,
                    'Region': region
                })

            # Process IPv6 ranges
            for ip_range in permission.get('Ipv6Ranges', []):
                # Find matching rule in the rules map
                rule_id = sg_id  # Default to using the security group ID
                if sg_id in rules_map:
                    for rule in rules_map[sg_id]:
                        if (rule.get('IpProtocol') == protocol and
                            rule.get('FromPort', None) == from_port and
                            rule.get('ToPort', None) == to_port and
                            rule.get('CidrIpv6', '') == ip_range.get('CidrIpv6', '') and
                            rule.get('IsEgress', False)):
                            rule_id = rule.get('SecurityGroupRuleId', sg_id)
                            break

                rule_desc = ip_range.get('Description', '')
                rule_text = format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=False)

                security_group_rules.append({
                    'Rule ID': rule_id,
                    'SG Name': sg_name,
                    'SG ID': sg_id,
                    'VPC': vpc_name,
                    'SG Description': description,
                    'Direction': 'Outbound',
                    'Rule': rule_text,
                    'Rule Description': rule_desc,
                    'Protocol': protocol if protocol != '-1' else 'All',
                    'From Port': from_port if from_port is not None else 'All',
                    'To Port': to_port if to_port is not None else 'All',
                    'CIDR': ip_range.get('CidrIpv6', ''),
                    'Owner ID': owner_formatted,
                    'Used By': resources_str,
                    'Region': region
                })

            # Process security group references
            for sg_ref in permission.get('UserIdGroupPairs', []):
                # Find matching rule in the rules map
                rule_id = sg_id  # Default to using the security group ID
                ref_group_id = sg_ref.get('GroupId', '')
                if sg_id in rules_map:
                    for rule in rules_map[sg_id]:
                        referenced_group = rule.get('ReferencedGroupInfo', {}).get('GroupId', '')
                        if (rule.get('IpProtocol') == protocol and
                            rule.get('FromPort', None) == from_port and
                            rule.get('ToPort', None) == to_port and
                            referenced_group == ref_group_id and
                            rule.get('IsEgress', False)):
                            rule_id = rule.get('SecurityGroupRuleId', sg_id)
                            break

                rule_desc = sg_ref.get('Description', '')
                rule_text = format_security_group_reference(sg_ref, protocol, from_port, to_port, is_inbound=False)

                security_group_rules.append({
                    'Rule ID': rule_id,
                    'SG Name': sg_name,
                    'SG ID': sg_id,
                    'VPC': vpc_name,
                    'SG Description': description,
                    'Direction': 'Outbound',
                    'Rule': rule_text,
                    'Rule Description': rule_desc,
                    'Protocol': protocol if protocol != '-1' else 'All',
                    'From Port': from_port if from_port is not None else 'All',
                    'To Port': to_port if to_port is not None else 'All',
                    'Referenced SG': sg_ref.get('GroupId', ''),
                    'Owner ID': owner_formatted,
                    'Used By': resources_str,
                    'Region': region
                })

        # If no rules found, add a placeholder entry
        if not sg.get('IpPermissions', []) and not sg.get('IpPermissionsEgress', []):
            security_group_rules.append({
                'Rule ID': sg_id,
                'SG Name': sg_name,
                'SG ID': sg_id,
                'VPC': vpc_name,
                'SG Description': description,
                'Direction': 'N/A',
                'Rule': 'No rules defined',
                'Rule Description': '',
                'Protocol': 'N/A',
                'From Port': 'N/A',
                'To Port': 'N/A',
                'CIDR': '',
                'Owner ID': owner_formatted,
                'Used By': resources_str,
                'Region': region
            })

    return security_group_rules

def export_to_excel(security_group_rules, account_name, region_suffix=""):
    """
    Export security group rules data to Excel with AWS identifier.
    
    Args:
        security_group_rules: List of security group rules
        account_name: AWS account name
        region_suffix: Region suffix for filename
        
    Returns:
        str: Path to the exported file or None if failed
    """
    import pandas as pd
    
    if not security_group_rules:
        utils.log_warning("No security group rules found to export.")
        return None
    
    # Create a DataFrame
    df = pd.DataFrame(security_group_rules)

    # Prepare and sanitize DataFrame for export (security groups may have sensitive descriptions/tags)
    df = utils.sanitize_for_export(
        utils.prepare_dataframe_for_export(df)
    )

    # Get current date for filename
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")

    # Use utils to create output filename with AWS identifier
    filename = utils.create_export_filename(
        account_name,
        "sg-rules",
        region_suffix,
        current_date
    )

    # Save using utils function
    output_path = utils.save_dataframe_to_excel(df, filename, sheet_name='Security Group Rules')
    
    if output_path:
        utils.log_success("AWS Security Group data exported successfully!")
        utils.log_info(f"File location: {output_path}")
        return output_path
    else:
        utils.log_error("Error exporting data. Please check the logs.")
        return None

def main():
    """
    Main function to run the script.
    """
    try:
        # Print title and get account information
        account_id, account_name = print_title()
        
        # Check dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)
        
        # Import pandas after dependency check
        import pandas as pd
        
        if account_name.startswith("UNKNOWN"):
            proceed = utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False)
            if not proceed:
                utils.log_info("Exiting script...")
                sys.exit(0)
        
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
            utils.log_info(f"Scanning default regions: {len(regions)} regions")
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
                        region_suffix = selected_region
                        utils.log_info(f"Scanning region: {selected_region}")
                        break
                    else:
                        print(f"Please enter a number between 1 and {len(all_available_regions)}.")
                except ValueError:
                    print(f"Please enter a valid number (1-{len(all_available_regions)}).")
                region_suffix = ""
        
        # Collect security group rules from selected AWS regions (Phase 4B: concurrent)
        utils.log_info("This may take some time depending on the number of regions and security groups.")

        # Define region scan function
        def scan_region_security_groups(region):
            utils.log_info(f"Processing AWS region: {region}")
            region_rules = get_security_group_rules(region)
            utils.log_info(f"Found {len(region_rules)} security group rules in {region}")
            return region_rules

        # Use concurrent region scanning
        region_results = utils.scan_regions_concurrent(
            regions=regions,
            scan_function=scan_region_security_groups,
            show_progress=True
        )

        # Flatten results
        all_security_group_rules = []
        for rules in region_results:
            all_security_group_rules.extend(rules)
        
        # Print summary
        total_rules = len(all_security_group_rules)
        utils.log_success(f"Total security group rules found across all AWS regions: {total_rules}")
        
        if total_rules > 0:
            # Export to Excel
            utils.log_info("Exporting security group rules to Excel format...")
            output_file = export_to_excel(all_security_group_rules, account_name, region_suffix)
            
            if output_file:
                utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")
                utils.log_info(f"Total security group rules exported: {total_rules}")
                print("\nScript execution completed.")
            else:
                utils.log_error("Failed to export data. Please check the logs.")
                sys.exit(1)
        else:
            utils.log_warning("No security group rules found. Nothing to export.")
    
    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
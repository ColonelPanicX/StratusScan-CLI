#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS VPC, Subnet, NAT Gateway, Peering Connection, and Elastic IP Export Tool
Date: NOV-15-2025

Description:
This script exports VPC, subnet, NAT Gateway, VPC Peering Connection, and Elastic IP information
from AWS regions into an Excel file with separate worksheets. The output filename
includes the AWS account name based on the account ID mapping in the configuration and includes
AWS identifiers for compliance and audit purposes.

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

@utils.aws_error_handler("Collecting VPC data for region", default_return=[])
def collect_vpc_data_for_region(region):
    """
    Collect comprehensive VPC information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with VPC information
    """
    vpc_data = []

    # Validate region is AWS
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"\nCollecting VPC details in AWS region: {region}")

    # Create EC2 client for this region
    ec2_client = utils.get_boto3_client('ec2', region_name=region)

    # Get all VPCs in the region
    paginator = ec2_client.get_paginator('describe_vpcs')
    vpcs = []
    for page in paginator.paginate():
        vpcs.extend(page.get('Vpcs', []))

    print(f"Found {len(vpcs)} VPCs in AWS region {region}")

    # Process each VPC
    for vpc in vpcs:
        vpc_id = vpc['VpcId']

        # Extract VPC name from tags
        vpc_name = None
        vpc_tags = {}
        if 'Tags' in vpc:
            for tag in vpc['Tags']:
                if tag['Key'] == 'Name':
                    vpc_name = tag['Value']
                vpc_tags[tag['Key']] = tag['Value']

        # Get primary IPv4 CIDR
        ipv4_cidr = vpc.get('CidrBlock', 'N/A')

        # Get all IPv4 CIDR blocks (including secondary)
        ipv4_cidrs = [ipv4_cidr]
        if 'CidrBlockAssociationSet' in vpc:
            for assoc in vpc['CidrBlockAssociationSet']:
                cidr = assoc.get('CidrBlock')
                if cidr and cidr not in ipv4_cidrs:
                    ipv4_cidrs.append(cidr)
        ipv4_cidr_combined = ', '.join(ipv4_cidrs)

        # Get IPv6 CIDR if available
        ipv6_cidr = 'N/A'
        ipv6_cidrs = []
        if 'Ipv6CidrBlockAssociationSet' in vpc:
            for ipv6_assoc in vpc['Ipv6CidrBlockAssociationSet']:
                if ipv6_assoc.get('Ipv6CidrBlockState', {}).get('State') == 'associated':
                    cidr = ipv6_assoc.get('Ipv6CidrBlock', 'N/A')
                    if cidr != 'N/A':
                        ipv6_cidrs.append(cidr)
        if ipv6_cidrs:
            ipv6_cidr = ', '.join(ipv6_cidrs)

        # Get DHCP Options Set
        dhcp_options_id = vpc.get('DhcpOptionsId', 'N/A')

        # Check if default VPC
        is_default = vpc.get('IsDefault', False)
        default_vpc = 'Yes' if is_default else 'No'

        # Get Main Route Table
        main_route_table = 'N/A'
        try:
            rt_response = ec2_client.describe_route_tables(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'association.main', 'Values': ['true']}
                ]
            )
            route_tables = rt_response.get('RouteTables', [])
            if route_tables:
                main_route_table = route_tables[0]['RouteTableId']
        except Exception as e:
            utils.log_warning(f"Error getting main route table for VPC {vpc_id}: {e}")

        # Get Main NACL
        main_nacl = 'N/A'
        try:
            nacl_response = ec2_client.describe_network_acls(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'default', 'Values': ['true']}
                ]
            )
            nacls = nacl_response.get('NetworkAcls', [])
            if nacls:
                main_nacl = nacls[0]['NetworkAclId']
        except Exception as e:
            utils.log_warning(f"Error getting main NACL for VPC {vpc_id}: {e}")

        # Get Block Public Access settings (VPC-level BPA for IPv4)
        # Note: This is a newer feature and might not be available in all regions/accounts
        block_public_access = 'Off'  # Default to 'Off' to match AWS console behavior
        try:
            bpa_response = ec2_client.describe_vpc_block_public_access_options(
                VpcIds=[vpc_id]
            )
            if 'VpcBlockPublicAccessOptions' in bpa_response and bpa_response['VpcBlockPublicAccessOptions']:
                bpa_option = bpa_response['VpcBlockPublicAccessOptions'][0]
                internet_gateway_block_mode = bpa_option.get('InternetGatewayBlockMode', 'off')
                # Capitalize first letter to match AWS console display
                block_public_access = internet_gateway_block_mode.capitalize() if internet_gateway_block_mode else 'Off'
        except Exception as e:
            # If API call fails entirely (feature not available in region), show 'Off'
            # This matches AWS console behavior where the feature just shows as disabled
            block_public_access = 'Off'

        # Format tags as string for better readability
        tags_str = ', '.join([f"{k}={v}" for k, v in vpc_tags.items()]) if vpc_tags else 'N/A'

        # Append VPC data
        vpc_data.append({
            'Region': region,
            'VPC Name': vpc_name if vpc_name else 'N/A',
            'VPC ID': vpc_id,
            'Block Public Access': block_public_access,
            'IPv4 CIDR': ipv4_cidr_combined,
            'IPv6 CIDR': ipv6_cidr,
            'DHCP Option Set': dhcp_options_id,
            'Main Route Table': main_route_table,
            'Main NACL': main_nacl,
            'Default VPC': default_vpc,
            'Tags': tags_str
        })

    return vpc_data

def collect_vpc_data(regions):
    """
    Collect VPC information from AWS regions (Phase 4B: concurrent).

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with VPC information
    """
    print("\n=== COLLECTING VPC INFORMATION ===")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_vpc_data_for_region,
        show_progress=True
    )

    # Flatten results
    all_vpc_data = []
    for vpcs in region_results:
        all_vpc_data.extend(vpcs)

    utils.log_success(f"Total VPCs collected: {len(all_vpc_data)}")
    return all_vpc_data

def is_subnet_public(ec2_client, subnet_id, vpc_id):
    """
    Determine if a subnet is public by checking if it has a route to an Internet Gateway.
    
    Args:
        ec2_client: The boto3 EC2 client
        subnet_id: The ID of the subnet to check
        vpc_id: The ID of the VPC the subnet belongs to
        
    Returns:
        bool: True if the subnet is public, False otherwise
    """
    try:
        # Get the route tables associated with the subnet
        response = ec2_client.describe_route_tables(
            Filters=[
                {
                    'Name': 'association.subnet-id',
                    'Values': [subnet_id]
                }
            ]
        )
        
        # If there are explicit route table associations for this subnet
        route_tables = response.get('RouteTables', [])
        
        # If no explicit route table associated, get the main route table for the VPC
        if not route_tables:
            response = ec2_client.describe_route_tables(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    },
                    {
                        'Name': 'association.main',
                        'Values': ['true']
                    }
                ]
            )
            route_tables = response.get('RouteTables', [])
        
        # Check if any route table has a route to an IGW
        for rt in route_tables:
            for route in rt.get('Routes', []):
                # Check for a default route (0.0.0.0/0) pointing to an IGW
                if route.get('DestinationCidrBlock') == '0.0.0.0/0' and 'GatewayId' in route and route['GatewayId'].startswith('igw-'):
                    return True
        
        # If we get here, no route to IGW was found
        return False
    except Exception as e:
        utils.log_warning(f"Error checking if subnet {subnet_id} is public: {e}")
        return "Unknown"

@utils.aws_error_handler("Collecting VPC and subnet data for region", default_return=[])
def collect_vpc_subnet_data_for_region(region):
    """
    Collect VPC and subnet information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with subnet information
    """
    subnet_data = []

    # Validate region is AWS
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"\nProcessing AWS region: {region}")

    # Create EC2 client for this region
    ec2_client = utils.get_boto3_client('ec2', region_name=region)

    # Get all VPCs in the region
    paginator = ec2_client.get_paginator('describe_vpcs')
    vpcs = []
    for page in paginator.paginate():
        vpcs.extend(page.get('Vpcs', []))

    print(f"Found {len(vpcs)} VPCs in AWS region {region}")

    # Process each VPC
    for vpc_index, vpc in enumerate(vpcs, 1):
        vpc_id = vpc['VpcId']
        vpc_progress = (vpc_index / len(vpcs)) * 100 if len(vpcs) > 0 else 0
        print(f"  [{vpc_progress:.1f}%] Processing VPC {vpc_index}/{len(vpcs)}: {vpc_id}")

        # Extract VPC name from tags
        vpc_name = None
        if 'Tags' in vpc:
            for tag in vpc['Tags']:
                if tag['Key'] == 'Name':
                    vpc_name = tag['Value']
                    break

        # Get VPC CIDR Block
        vpc_cidr = vpc.get('CidrBlock', 'N/A')

        # Get all subnets for this VPC
        subnet_response = ec2_client.describe_subnets(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                }
            ]
        )
        subnets = subnet_response.get('Subnets', [])

        print(f"    Found {len(subnets)} subnets")

        # Process each subnet
        for subnet_index, subnet in enumerate(subnets, 1):
            subnet_id = subnet['SubnetId']
            subnet_progress = (subnet_index / len(subnets)) * 100 if len(subnets) > 0 else 0
            if len(subnets) > 1:  # Only show subnet progress if there are multiple subnets
                print(f"      [{subnet_progress:.1f}%] Processing subnet {subnet_index}/{len(subnets)}: {subnet_id}")

            # Extract subnet name and all tags
            subnet_name = None
            subnet_tags = {}
            if 'Tags' in subnet:
                for tag in subnet['Tags']:
                    if tag['Key'] == 'Name':
                        subnet_name = tag['Value']
                    subnet_tags[tag['Key']] = tag['Value']

            availability_zone = subnet['AvailabilityZone']
            ipv4_cidr = subnet['CidrBlock']
            ipv4_address_count = subnet.get('AvailableIpAddressCount', 'N/A')

            # Get IPv6 CIDR if available
            ipv6_cidr = 'N/A'
            if 'Ipv6CidrBlockAssociationSet' in subnet and subnet['Ipv6CidrBlockAssociationSet']:
                for ipv6_assoc in subnet['Ipv6CidrBlockAssociationSet']:
                    if ipv6_assoc.get('Ipv6CidrBlockState', {}).get('State') == 'associated':
                        ipv6_cidr = ipv6_assoc.get('Ipv6CidrBlock', 'N/A')
                        break

            # Determine if subnet is public or private
            public_status = is_subnet_public(ec2_client, subnet_id, vpc_id)
            public_private = "Public" if public_status else "Private"

            # Format tags as string for better readability
            tags_str = ', '.join([f"{k}={v}" for k, v in subnet_tags.items()]) if subnet_tags else 'N/A'

            # Append subnet data to the list
            subnet_data.append({
                'Region': region,
                'VPC Name': vpc_name if vpc_name else 'N/A',
                'VPC ID': vpc_id,
                'VPC CIDR Block': vpc_cidr,
                'Subnet ID': subnet_id,
                'Subnet Name': subnet_name if subnet_name else 'N/A',
                'Availability Zone': availability_zone,
                'IPv4 CIDR Block': ipv4_cidr,
                'IPv4 Address Count': ipv4_address_count,
                'IPv6 CIDR Block': ipv6_cidr,
                'Public/Private': public_private,
                'Subnet Tags': tags_str
            })

    return subnet_data

def collect_vpc_subnet_data(regions):
    """
    Collect VPC and subnet information from AWS regions (Phase 4B: concurrent).

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with subnet information
    """
    print("\n=== COLLECTING VPC AND SUBNET INFORMATION ===")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_vpc_subnet_data_for_region,
        show_progress=True
    )

    # Flatten results
    all_subnet_data = []
    for subnets in region_results:
        all_subnet_data.extend(subnets)

    utils.log_success(f"Total subnets collected: {len(all_subnet_data)}")
    return all_subnet_data

@utils.aws_error_handler("Collecting NAT Gateway data for region", default_return=[])
def collect_nat_gateway_data_for_region(region):
    """
    Collect NAT Gateway information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with NAT Gateway information
    """
    nat_gateways = []

    # Validate region is AWS
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"\nSearching for NAT Gateways in AWS region: {region}")

    # Create EC2 client for this region
    ec2_client = utils.get_boto3_client('ec2', region_name=region)

    # Get NAT Gateways in the region
    nat_gw_response = ec2_client.describe_nat_gateways()
    nat_gws = nat_gw_response.get('NatGateways', [])
    print(f"  Found {len(nat_gws)} NAT Gateways")

    # Process each NAT Gateway
    for nat_gw in nat_gws:
        nat_gw_id = nat_gw.get('NatGatewayId', '')
        print(f"    Processing NAT Gateway: {nat_gw_id}")

        state = nat_gw.get('State', '')
        connectivity = nat_gw.get('ConnectivityType', '')
        vpc_id = nat_gw.get('VpcId', '')
        subnet_id = nat_gw.get('SubnetId', '')

        # Get creation timestamp and format it
        creation_timestamp = nat_gw.get('CreateTime', '')
        if creation_timestamp:
            # Convert to datetime object and then to string format
            creation_date = creation_timestamp.strftime('%Y-%m-%d') if isinstance(creation_timestamp, datetime.datetime) else str(creation_timestamp)
        else:
            creation_date = ""

        # Extract name from tags
        name = None
        if 'Tags' in nat_gw:
            for tag in nat_gw['Tags']:
                if tag['Key'] == 'Name':
                    name = tag['Value']
                    break

        # Get primary network interface details
        primary_public_ip = ""
        primary_private_ip = ""
        primary_eni_id = ""

        nat_addresses = nat_gw.get('NatGatewayAddresses', [])
        if nat_addresses:
            primary_nat_address = nat_addresses[0]
            primary_public_ip = primary_nat_address.get('PublicIp', '')
            primary_private_ip = primary_nat_address.get('PrivateIp', '')
            primary_eni_id = primary_nat_address.get('NetworkInterfaceId', '')

        # Add to results
        nat_gateways.append({
            'Region': region,
            'Name': name if name else 'N/A',
            'NAT Gateway ID': nat_gw_id,
            'State': state,
            'Connectivity': connectivity,
            'Primary Public IPv4': primary_public_ip,
            'Primary Private IPv4': primary_private_ip,
            'Primary Network Interface ID': primary_eni_id,
            'VPC': vpc_id,
            'Subnet': subnet_id,
            'Creation Date': creation_date
        })

    return nat_gateways

def collect_nat_gateway_data(regions):
    """
    Collect NAT Gateway information from AWS regions (Phase 4B: concurrent).

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with NAT Gateway information
    """
    print("\n=== COLLECTING NAT GATEWAY INFORMATION ===")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_nat_gateway_data_for_region,
        show_progress=True
    )

    # Flatten results
    all_nat_gateways = []
    for nat_gws in region_results:
        all_nat_gateways.extend(nat_gws)

    utils.log_success(f"Total NAT Gateways collected: {len(all_nat_gateways)}")
    return all_nat_gateways

@utils.aws_error_handler("Collecting VPC Peering data for region", default_return=[])
def collect_vpc_peering_data_for_region(region):
    """
    Collect VPC Peering Connection information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with VPC Peering information
    """
    vpc_peerings = []

    # Validate region is AWS
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"\nSearching for VPC Peering Connections in AWS region: {region}")

    # Create EC2 client for this region
    ec2_client = utils.get_boto3_client('ec2', region_name=region)

    # Get VPC Peering Connections in the region
    peering_response = ec2_client.describe_vpc_peering_connections()
    peerings = peering_response.get('VpcPeeringConnections', [])
    print(f"  Found {len(peerings)} VPC Peering Connections")

    # Process each VPC Peering Connection
    for peering in peerings:
        peering_id = peering.get('VpcPeeringConnectionId', '')
        print(f"    Processing VPC Peering Connection: {peering_id}")

        # Get peering status
        status = peering.get('Status', {}).get('Code', '')

        # Get requester VPC information
        requester_info = peering.get('RequesterVpcInfo', {})
        requester_vpc = requester_info.get('VpcId', '')
        requester_cidr = requester_info.get('CidrBlock', '')
        requester_owner = requester_info.get('OwnerId', '')
        requester_region = requester_info.get('Region', '')

        # Get accepter VPC information
        accepter_info = peering.get('AccepterVpcInfo', {})
        accepter_vpc = accepter_info.get('VpcId', '')
        accepter_cidr = accepter_info.get('CidrBlock', '')
        accepter_owner = accepter_info.get('OwnerId', '')
        accepter_region = accepter_info.get('Region', '')

        # Format account owner IDs with names if available
        requester_owner_formatted = utils.get_account_name_formatted(requester_owner)
        accepter_owner_formatted = utils.get_account_name_formatted(accepter_owner)

        # Extract name from tags
        name = None
        if 'Tags' in peering:
            for tag in peering['Tags']:
                if tag['Key'] == 'Name':
                    name = tag['Value']
                    break

        # Add to results
        vpc_peerings.append({
            'Name': name if name else 'N/A',
            'Peering Connection ID': peering_id,
            'Status': status,
            'Requester VPC': requester_vpc,
            'Accepter VPC': accepter_vpc,
            'Requester CIDR': requester_cidr,
            'Accepter CIDR': accepter_cidr,
            'Requester Owner ID': requester_owner_formatted,
            'Accepter Owner ID': accepter_owner_formatted,
            'Requester Region': requester_region,
            'Accepter Region': accepter_region
        })

    return vpc_peerings

def collect_vpc_peering_data(regions):
    """
    Collect VPC Peering Connection information from AWS regions (Phase 4B: concurrent).

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with VPC Peering information
    """
    print("\n=== COLLECTING VPC PEERING CONNECTION INFORMATION ===")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_vpc_peering_data_for_region,
        show_progress=True
    )

    # Flatten results
    all_vpc_peerings = []
    for peerings in region_results:
        all_vpc_peerings.extend(peerings)

    utils.log_success(f"Total VPC Peering Connections collected: {len(all_vpc_peerings)}")
    return all_vpc_peerings

@utils.aws_error_handler("Collecting Elastic IP data for region", default_return=[])
def collect_elastic_ip_data_for_region(region):
    """
    Collect Elastic IP information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with Elastic IP information
    """
    elastic_ips = []

    # Validate region is AWS
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    print(f"\nSearching for Elastic IPs in AWS region: {region}")

    # Create EC2 client for this region
    ec2_client = utils.get_boto3_client('ec2', region_name=region)

    # Get Elastic IPs in the region
    eip_response = ec2_client.describe_addresses()
    eips = eip_response.get('Addresses', [])
    print(f"  Found {len(eips)} Elastic IPs")

    # Process each Elastic IP
    for eip in eips:
        allocated_ip = eip.get('PublicIp', '')
        print(f"    Processing Elastic IP: {allocated_ip}")

        # Get EIP attributes
        allocation_id = eip.get('AllocationId', '')
        domain_type = eip.get('Domain', '')  # 'vpc' or 'standard'

        # Get associated information if available
        instance_id = eip.get('InstanceId', '')
        private_ip = eip.get('PrivateIpAddress', '')
        association_id = eip.get('AssociationId', '')
        network_interface_id = eip.get('NetworkInterfaceId', '')
        network_interface_owner_id = eip.get('NetworkInterfaceOwnerId', '')
        network_border_group = eip.get('NetworkBorderGroup', '')

        # Get Public DNS (Reverse DNS record)
        public_dns = eip.get('PublicDnsName', '')

        # Extract name from tags
        name = None
        if 'Tags' in eip:
            for tag in eip['Tags']:
                if tag['Key'] == 'Name':
                    name = tag['Value']
                    break

        # Add to results
        elastic_ips.append({
            'Region': region,
            'Name': name if name else 'N/A',
            'Allocated IPv4': allocated_ip,
            'Type': domain_type,
            'Allocation ID': allocation_id,
            'Reverse DNS Record': public_dns,
            'Associated Instance ID': instance_id,
            'Private IPv4': private_ip,
            'Association ID': association_id,
            'Network Interface Owner ID': network_interface_owner_id,
            'Network Border Group': network_border_group
        })

    return elastic_ips

def collect_elastic_ip_data(regions):
    """
    Collect Elastic IP information from AWS regions (Phase 4B: concurrent).

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with Elastic IP information
    """
    print("\n=== COLLECTING ELASTIC IP INFORMATION ===")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_elastic_ip_data_for_region,
        show_progress=True
    )

    # Flatten results
    all_elastic_ips = []
    for eips in region_results:
        all_elastic_ips.extend(eips)

    utils.log_success(f"Total Elastic IPs collected: {len(all_elastic_ips)}")
    return all_elastic_ips

def export_vpc_subnet_natgw_peering_info(account_id, account_name):
    """
    Export VPC, subnet, NAT Gateway, VPC Peering, and Elastic IP information to an Excel file.
    Uses AWS regions and includes AWS identifiers in filenames.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition and set partition-appropriate region examples
    partition = utils.detect_partition()
    if partition == 'aws-us-gov':
        example_regions = "us-gov-west-1, us-gov-east-1"
    else:
        example_regions = "us-east-1, us-west-1, us-west-2, eu-west-1"

    # Display menu for user selection
    if utils.is_auto_run():
        choice = 5  # All of the Above
    else:
        print("\n" + "=" * 60)
        print("What would you like to export?")
        print("1. VPC and Subnet")
        print("2. NAT Gateways")
        print("3. VPC Peering Connections")
        print("4. Elastic IP")
        print("5. All of the Above")
        print("=" * 60)

        while True:
            try:
                choice = input("Enter your choice (1-5): ")
                choice = int(choice)
                if 1 <= choice <= 5:
                    break
                else:
                    print("Please enter a number between 1 and 5.")
            except ValueError:
                print("Please enter a valid number.")

    # Determine what to export based on user choice
    export_vpc_subnet = choice in [1, 5]
    export_nat_gateways = choice in [2, 5]
    export_vpc_peering = choice in [3, 5]
    export_elastic_ip = choice in [4, 5]

    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Get current date for file naming
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")

    # Determine resource type based on choice
    if choice == 1:
        resource_type = "vpc-subnet"
    elif choice == 2:
        resource_type = "ngw"
    elif choice == 3:
        resource_type = "vpc-peering"
    elif choice == 4:
        resource_type = "elastic-ip"
    else:  # choice == 5
        resource_type = "vpc-all"
    
    # Create filename using utils with AWS identifier
    final_excel_file = utils.create_export_filename(
        account_name, 
        resource_type, 
        region_suffix, 
        current_date
    )
    
    print(f"\nStarting AWS export process for {', '.join(regions)}...")
    print("This may take some time depending on the number of regions and resources...")
    
    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")
    
    # Import pandas for DataFrame handling (after dependency check)
    import pandas as pd
    
    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect VPC information (if VPC/Subnet selected)
    if export_vpc_subnet:
        all_vpc_data = collect_vpc_data(regions)
        if all_vpc_data:
            data_frames['VPCs'] = pd.DataFrame(all_vpc_data)

    # STEP 2: Collect VPC and Subnet information (if selected)
    if export_vpc_subnet:
        all_subnet_data = collect_vpc_subnet_data(regions)
        if all_subnet_data:
            data_frames['VPCs and Subnets'] = pd.DataFrame(all_subnet_data)
    
    # STEP 3: Collect NAT Gateway information (if selected)
    if export_nat_gateways:
        all_nat_gateway_data = collect_nat_gateway_data(regions)
        if all_nat_gateway_data:
            data_frames['NAT Gateways'] = pd.DataFrame(all_nat_gateway_data)

    # STEP 4: Collect VPC Peering information (if selected)
    if export_vpc_peering:
        all_vpc_peering_data = collect_vpc_peering_data(regions)
        if all_vpc_peering_data:
            data_frames['VPC Peering Connections'] = pd.DataFrame(all_vpc_peering_data)

    # STEP 5: Collect Elastic IP information (if selected)
    if export_elastic_ip:
        all_elastic_ip_data = collect_elastic_ip_data(regions)
        if all_elastic_ip_data:
            data_frames['Elastic IPs'] = pd.DataFrame(all_elastic_ip_data)

    # STEP 6: Prepare and sanitize all DataFrames
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.sanitize_for_export(
            utils.prepare_dataframe_for_export(data_frames[sheet_name])
        )

    # STEP 7: Save the Excel file using utils module
    if not data_frames:
        utils.log_warning("No data was collected. Nothing to export.")
        return

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)
        
        if output_path:
            utils.log_success("AWS VPC data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")
            
            # Summary of exported data
            for sheet_name, df in data_frames.items():
                utils.log_info(f"  - {sheet_name}: {len(df)} records")
        else:
            utils.log_error("Error creating Excel file. Please check the logs.")
        
    except Exception as e:
        utils.log_error(f"Error creating Excel file", e)

def main():
    """Main function to execute the script."""
    try:
        # Print title and get account information
        utils.setup_logging("vpc-data-export")
        account_id, account_name = utils.print_script_banner("AWS VPC, SUBNET, NAT GATEWAY, PEERING, AND ELASTIC IP EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)
        
        # Check if account name is unknown
        if account_name == "unknown":
            if not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
                print("Exiting script...")
                sys.exit(0)
        
        # Export VPC, subnet, NAT Gateway, VPC Peering, and Elastic IP information
        export_vpc_subnet_natgw_peering_info(account_id, account_name)
        
        print("\nAWS VPC data export script execution completed.")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
        
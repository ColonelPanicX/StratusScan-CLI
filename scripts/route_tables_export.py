#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Route Tables Export
Date: NOV-15-2025

Description:
This script exports AWS route table information across all regions or a specific region
into an Excel spreadsheet. It captures route table ID, VPC ID, route destinations, targets,
states, types, propagation status, subnet associations, edge associations, and tags.

Phase 4B Update:
- Concurrent region scanning (4x-10x performance improvement)
- Automatic fallback to sequential on errors
"""

import os
import sys
import datetime
from botocore.exceptions import ClientError
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
def get_all_regions():
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

def is_valid_region(region_name):
    """
    Check if a region name is valid.
    
    Args:
        region_name (str): AWS region name
        
    Returns:
        bool: True if valid region, False otherwise
    """
    all_regions = get_all_regions()
    return region_name in all_regions

def get_vpc_tags(ec2_client, vpc_id):
    """
    Get tags for a VPC.
    
    Args:
        ec2_client: The boto3 EC2 client
        vpc_id (str): The VPC ID
        
    Returns:
        dict: Dictionary of tags
    """
    if not vpc_id:
        return {}
    
    try:
        response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        if response and 'Vpcs' in response and response['Vpcs']:
            return {tag['Key']: tag['Value'] for tag in response['Vpcs'][0].get('Tags', [])}
    except Exception:
        pass
    
    return {}

def format_tags(tags_list):
    """
    Format tags into a string.
    
    Args:
        tags_list (list): List of tag dictionaries
        
    Returns:
        str: Formatted tags string
    """
    if not tags_list:
        return "N/A"
    
    tags = []
    for tag in tags_list:
        tags.append(f"{tag.get('Key', '')}={tag.get('Value', '')}")
    
    return "; ".join(tags)

def get_route_type(route):
    """
    Determine the type of route based on its target.
    
    Args:
        route (dict): The route information
        
    Returns:
        str: The route type
    """
    if 'GatewayId' in route and route['GatewayId'].startswith('igw-'):
        return "Internet Gateway"
    elif 'GatewayId' in route and route['GatewayId'].startswith('vgw-'):
        return "Virtual Private Gateway"
    elif 'GatewayId' in route and route['GatewayId'].startswith('nat-'):
        return "NAT Gateway"
    elif 'GatewayId' in route and route['GatewayId'].startswith('tgw-'):
        return "Transit Gateway"
    elif 'NatGatewayId' in route:
        return "NAT Gateway"
    elif 'VpcPeeringConnectionId' in route:
        return "VPC Peering"
    elif 'InstanceId' in route:
        return "EC2 Instance"
    elif 'NetworkInterfaceId' in route:
        return "Network Interface"
    elif 'TransitGatewayId' in route:
        return "Transit Gateway"
    elif 'LocalGatewayId' in route:
        return "Local Gateway"
    elif 'CarrierGatewayId' in route:
        return "Carrier Gateway"
    elif 'GatewayId' in route and route['GatewayId'] == 'local':
        return "Local"
    else:
        return "Unknown"

def get_route_target(route):
    """
    Get the target identifier for a route.
    
    Args:
        route (dict): The route information
        
    Returns:
        str: The target identifier
    """
    if 'GatewayId' in route:
        return route['GatewayId']
    elif 'NatGatewayId' in route:
        return route['NatGatewayId']
    elif 'VpcPeeringConnectionId' in route:
        return route['VpcPeeringConnectionId']
    elif 'InstanceId' in route:
        return route['InstanceId']
    elif 'NetworkInterfaceId' in route:
        return route['NetworkInterfaceId']
    elif 'TransitGatewayId' in route:
        return route['TransitGatewayId']
    elif 'LocalGatewayId' in route:
        return route['LocalGatewayId']
    elif 'CarrierGatewayId' in route:
        return route['CarrierGatewayId']
    else:
        return "N/A"

def get_route_destination(route):
    """
    Get the destination for a route.
    
    Args:
        route (dict): The route information
        
    Returns:
        str: The route destination
    """
    if 'DestinationCidrBlock' in route:
        return route['DestinationCidrBlock']
    elif 'DestinationIpv6CidrBlock' in route:
        return route['DestinationIpv6CidrBlock']
    elif 'DestinationPrefixListId' in route:
        return route['DestinationPrefixListId']
    else:
        return "N/A"

def get_route_tables(region):
    """
    Get all route tables in a specific region.
    
    Args:
        region (str): AWS region name
        
    Returns:
        list: List of dictionaries with route table information
    """
    route_table_data = []
    
    try:
        # Create EC2 client for the region
        ec2_client = utils.get_boto3_client('ec2', region_name=region)

        # Get all route tables in the region
        paginator = ec2_client.get_paginator('describe_route_tables')
        for page in paginator.paginate():
            for route_table in page['RouteTables']:
                rt_id = route_table['RouteTableId']
                vpc_id = route_table.get('VpcId', 'N/A')
                
                # Get routes
                routes = route_table.get('Routes', [])
                
                # Get subnet associations
                subnet_associations = []
                for association in route_table.get('Associations', []):
                    if 'SubnetId' in association:
                        subnet_associations.append(association['SubnetId'])
                
                # Get edge associations (like gateways)
                edge_associations = []
                for association in route_table.get('Associations', []):
                    if 'GatewayId' in association:
                        edge_associations.append(association['GatewayId'])
                
                # Get tags
                tags = format_tags(route_table.get('Tags', []))
                
                # For each route, create a separate entry
                if routes:
                    for route in routes:
                        route_destination = get_route_destination(route)
                        route_target = get_route_target(route)
                        route_state = route.get('State', 'N/A')
                        route_type = get_route_type(route)
                        propagated = route.get('Origin', '') == 'EnableVgwRoutePropagation'
                        
                        # Create entry for this route
                        route_entry = {
                            'Region': region,
                            'Route Table ID': rt_id,
                            'VPC ID': vpc_id,
                            'Route Destination': route_destination,
                            'Target': route_target,
                            'Route State': route_state,
                            'Route Type': route_type,
                            'Propagated': 'Yes' if propagated else 'No',
                            'Subnet Association': '; '.join(subnet_associations) if subnet_associations else 'N/A',
                            'Edge Association': '; '.join(edge_associations) if edge_associations else 'N/A',
                            'Tags': tags
                        }
                        
                        route_table_data.append(route_entry)
                else:
                    # Create an entry for the route table with no routes
                    route_entry = {
                        'Region': region,
                        'Route Table ID': rt_id,
                        'VPC ID': vpc_id,
                        'Route Destination': 'N/A',
                        'Target': 'N/A',
                        'Route State': 'N/A',
                        'Route Type': 'N/A',
                        'Propagated': 'N/A',
                        'Subnet Association': '; '.join(subnet_associations) if subnet_associations else 'N/A',
                        'Edge Association': '; '.join(edge_associations) if edge_associations else 'N/A',
                        'Tags': tags
                    }
                    
                    route_table_data.append(route_entry)
    
    except Exception as e:
        print(f"Error getting route tables in region {region}: {e}")
    
    return route_table_data

def export_route_tables(account_name, regions, region_suffix=""):
    """
    Export route table information to an Excel file.

    Args:
        account_name (str): AWS account name
        regions (list): List of AWS regions to export from
        region_suffix (str): Suffix to add to filename (e.g., "-us-east-1")

    Returns:
        str: Path to the exported file
    """
    import pandas as pd

    print("\nCollecting route table information...")

    # Determine which regions to process
    regions_to_process = regions
    if len(regions) == 1:
        print(f"Processing region: {regions[0]}")
    else:
        print(f"Processing {len(regions)} AWS regions")
    
    # Collect route table data from all regions (Phase 4B: concurrent)
    all_route_tables = []

    # Define region scan function
    def scan_region_route_tables(region):
        print(f"  Collecting route tables from {region}...")
        region_route_tables = get_route_tables(region)
        print(f"  Found {len(region_route_tables)} route entries in {region}")
        return region_route_tables

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions_to_process,
        scan_function=scan_region_route_tables,
        show_progress=True
    )

    # Flatten results
    for route_tables in region_results:
        all_route_tables.extend(route_tables)
    
    # Check if we found any route tables
    if not all_route_tables:
        print("No route tables found.")
        return None
    
    # Create DataFrame
    df = pd.DataFrame(all_route_tables)
    
    # Generate file name
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    filename = utils.create_export_filename(account_name, "route-tables", region_suffix, current_date)
    
    # Export to Excel
    output_path = utils.save_dataframe_to_excel(df, filename)
    
    if output_path:
        return output_path
    return None

def main():
    """
    Main function to run the script.
    """
    try:
        # Print script header and get account info
        utils.setup_logging("route-tables-export")
        account_id, account_name = utils.print_script_banner("AWS ROUTE TABLES EXPORT")
        
        # Check for required dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)
        
        # Import pandas now that we've checked dependencies
        import pandas as pd
        
        # Detect partition and set partition-aware example regions
        regions = utils.prompt_region_selection()

        output_file = export_route_tables(account_name, regions)

        # Report results
        if output_file:
            print("\nExport completed successfully!")
            print(f"Output file: {output_file}")
        else:
            print("\nExport failed or no data was found.")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    main()

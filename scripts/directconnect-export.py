#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Direct Connect Export Tool
Version: v0.1.0
Date: NOV-11-2025

Description:
This script exports AWS Direct Connect information from all regions into an Excel file with
multiple worksheets. The output includes Direct Connect connections, virtual interfaces,
Link Aggregation Groups (LAGs), Direct Connect gateways, and gateway associations.

Features:
- Physical connections with state, location, and bandwidth
- Virtual interfaces (private, public, transit) with BGP configurations
- Link Aggregation Groups (LAGs) with member connections
- Direct Connect gateways with ASN configurations
- Virtual private gateway associations
- Transit gateway associations
- Summary statistics

Cost Awareness:
- Direct Connect is a premium service with port-hour charges and data transfer fees
- Connections incur charges even when idle ($0.30/hour for 1Gbps, $2.25/hour for 10Gbps in us-east-1)
- Additional charges apply for data transfer out to the internet
- LAGs provide redundancy but each member connection is billed separately
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
utils.setup_logging("directconnect-export")
utils.log_script_start("directconnect-export.py", "AWS Direct Connect Export Tool")


def _scan_connections_region(region: str) -> List[Dict[str, Any]]:
    """Scan Direct Connect connections in a single region."""
    regional_connections = []

    try:
        dx = utils.get_boto3_client('directconnect', region_name=region)

        # Get Direct Connect connections
        response = dx.describe_connections()
        connections = response.get('connections', [])

        for conn in connections:
            connection_id = conn.get('connectionId', 'N/A')

            # Extract connection details
            connection_name = conn.get('connectionName', 'N/A')
            connection_state = conn.get('connectionState', 'N/A')
            location = conn.get('location', 'N/A')
            bandwidth = conn.get('bandwidth', 'N/A')
            vlan = conn.get('vlan', 'N/A')
            partner_name = conn.get('partnerName', 'N/A')
            lag_id = conn.get('lagId', 'N/A')
            aws_device = conn.get('awsDevice', 'N/A')
            aws_device_v2 = conn.get('awsDeviceV2', 'N/A')
            provider_name = conn.get('providerName', 'N/A')
            owner_account = conn.get('ownerAccount', 'N/A')
            has_logical_redundancy = conn.get('hasLogicalRedundancy', 'unknown')
            jumbo_frame_capable = conn.get('jumboFrameCapable', False)
            aws_logical_device_id = conn.get('awsLogicalDeviceId', 'N/A')

            # Get tags
            tags = conn.get('tags', [])
            tag_string = ', '.join([f"{tag['key']}={tag['value']}" for tag in tags]) if tags else 'N/A'

            regional_connections.append({
                'Region': region,
                'Connection ID': connection_id,
                'Connection Name': connection_name,
                'State': connection_state,
                'Location': location,
                'Bandwidth': bandwidth,
                'VLAN': vlan,
                'Partner Name': partner_name,
                'Provider Name': provider_name,
                'LAG ID': lag_id,
                'AWS Device': aws_device_v2 if aws_device_v2 != 'N/A' else aws_device,
                'AWS Logical Device ID': aws_logical_device_id,
                'Owner Account': owner_account,
                'Has Logical Redundancy': has_logical_redundancy,
                'Jumbo Frame Capable': jumbo_frame_capable,
                'Tags': tag_string
            })

    except Exception as e:
        utils.log_error(f"Error collecting Direct Connect connections in {region}", e)

    return regional_connections


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("              AWS DIRECT CONNECT EXPORT TOOL")
    print("====================================================================")
    print("Version: v0.1.0                        Date: NOV-11-2025")
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


@utils.aws_error_handler("Collecting Direct Connect connections", default_return=[])
def collect_connections(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Direct Connect connection information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with connection information
    """
    print("\n=== COLLECTING DIRECT CONNECT CONNECTIONS ===")
    results = utils.scan_regions_concurrent(regions, _scan_connections_region)
    all_connections = [conn for result in results for conn in result]
    utils.log_success(f"Total Direct Connect connections collected: {len(all_connections)}")
    return all_connections


def _scan_virtual_interfaces_region(region: str) -> List[Dict[str, Any]]:
    """Scan Direct Connect virtual interfaces in a single region."""
    regional_vifs = []

    try:
        dx = utils.get_boto3_client('directconnect', region_name=region)

        # Get Virtual Interfaces
        response = dx.describe_virtual_interfaces()
        vifs = response.get('virtualInterfaces', [])

        for vif in vifs:
            vif_id = vif.get('virtualInterfaceId', 'N/A')

            # Extract VIF details
            vif_name = vif.get('virtualInterfaceName', 'N/A')
            vif_type = vif.get('virtualInterfaceType', 'N/A')
            vif_state = vif.get('virtualInterfaceState', 'N/A')
            connection_id = vif.get('connectionId', 'N/A')
            vlan = vif.get('vlan', 'N/A')
            asn = vif.get('asn', 'N/A')
            amazon_side_asn = vif.get('amazonSideAsn', 'N/A')
            bgp_peers = vif.get('bgpPeers', [])
            amazon_address = vif.get('amazonAddress', 'N/A')
            customer_address = vif.get('customerAddress', 'N/A')
            virtual_gateway_id = vif.get('virtualGatewayId', 'N/A')
            directconnect_gateway_id = vif.get('directConnectGatewayId', 'N/A')
            location = vif.get('location', 'N/A')
            mtu = vif.get('mtu', 'N/A')
            jumbo_frame_capable = vif.get('jumboFrameCapable', False)
            owner_account = vif.get('ownerAccount', 'N/A')

            # BGP Peer details (extract first peer if multiple)
            bgp_peer_state = 'N/A'
            bgp_status = 'N/A'
            if bgp_peers:
                bgp_peer_state = bgp_peers[0].get('bgpPeerState', 'N/A')
                bgp_status = bgp_peers[0].get('bgpStatus', 'N/A')

            # Get tags
            tags = vif.get('tags', [])
            tag_string = ', '.join([f"{tag['key']}={tag['value']}" for tag in tags]) if tags else 'N/A'

            regional_vifs.append({
                'Region': region,
                'Virtual Interface ID': vif_id,
                'Virtual Interface Name': vif_name,
                'Type': vif_type,
                'State': vif_state,
                'Connection ID': connection_id,
                'VLAN': vlan,
                'BGP ASN': asn,
                'Amazon Side ASN': amazon_side_asn,
                'Amazon Address': amazon_address,
                'Customer Address': customer_address,
                'Virtual Gateway ID': virtual_gateway_id,
                'Direct Connect Gateway ID': directconnect_gateway_id,
                'BGP Peer State': bgp_peer_state,
                'BGP Status': bgp_status,
                'Location': location,
                'MTU Size': mtu,
                'Jumbo Frame Capable': jumbo_frame_capable,
                'Owner Account': owner_account,
                'Tags': tag_string
            })

    except Exception as e:
        utils.log_error(f"Error collecting Virtual Interfaces in {region}", e)

    return regional_vifs


@utils.aws_error_handler("Collecting Virtual Interfaces", default_return=[])
def collect_virtual_interfaces(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Direct Connect virtual interface information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with virtual interface information
    """
    print("\n=== COLLECTING VIRTUAL INTERFACES ===")
    results = utils.scan_regions_concurrent(regions, _scan_virtual_interfaces_region)
    all_vifs = [vif for result in results for vif in result]
    utils.log_success(f"Total virtual interfaces collected: {len(all_vifs)}")
    return all_vifs


def _scan_lags_region(region: str) -> List[Dict[str, Any]]:
    """Scan Direct Connect LAGs in a single region."""
    regional_lags = []

    try:
        dx = utils.get_boto3_client('directconnect', region_name=region)

        # Get LAGs
        response = dx.describe_lags()
        lags = response.get('lags', [])

        for lag in lags:
            lag_id = lag.get('lagId', 'N/A')

            # Extract LAG details
            lag_name = lag.get('lagName', 'N/A')
            lag_state = lag.get('lagState', 'N/A')
            location = lag.get('location', 'N/A')
            connections = lag.get('connections', [])
            connections_bandwidth = lag.get('connectionsBandwidth', 'N/A')
            number_of_connections = lag.get('numberOfConnections', 0)
            minimum_links = lag.get('minimumLinks', 0)
            allow_auto_negotiation = lag.get('allowsHostedConnections', False)
            jumbo_frame_capable = lag.get('jumboFrameCapable', False)
            has_logical_redundancy = lag.get('hasLogicalRedundancy', 'unknown')
            owner_account = lag.get('ownerAccount', 'N/A')
            aws_device = lag.get('awsDevice', 'N/A')
            aws_device_v2 = lag.get('awsDeviceV2', 'N/A')
            aws_logical_device_id = lag.get('awsLogicalDeviceId', 'N/A')

            # Count connections by state
            connection_states = {}
            for conn in connections:
                state = conn.get('connectionState', 'unknown')
                connection_states[state] = connection_states.get(state, 0) + 1

            connection_state_summary = ', '.join([f"{state}: {count}" for state, count in connection_states.items()]) if connection_states else 'No connections'

            # Get tags
            tags = lag.get('tags', [])
            tag_string = ', '.join([f"{tag['key']}={tag['value']}" for tag in tags]) if tags else 'N/A'

            regional_lags.append({
                'Region': region,
                'LAG ID': lag_id,
                'LAG Name': lag_name,
                'State': lag_state,
                'Location': location,
                'Bandwidth': connections_bandwidth,
                'Number of Connections': number_of_connections,
                'Minimum Links': minimum_links,
                'Connection States': connection_state_summary,
                'AWS Device': aws_device_v2 if aws_device_v2 != 'N/A' else aws_device,
                'AWS Logical Device ID': aws_logical_device_id,
                'Allows Hosted Connections': allow_auto_negotiation,
                'Has Logical Redundancy': has_logical_redundancy,
                'Jumbo Frame Capable': jumbo_frame_capable,
                'Owner Account': owner_account,
                'Tags': tag_string
            })

    except Exception as e:
        utils.log_error(f"Error collecting LAGs in {region}", e)

    return regional_lags


@utils.aws_error_handler("Collecting LAGs", default_return=[])
def collect_lags(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Direct Connect Link Aggregation Group (LAG) information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with LAG information
    """
    print("\n=== COLLECTING LINK AGGREGATION GROUPS (LAGs) ===")
    results = utils.scan_regions_concurrent(regions, _scan_lags_region)
    all_lags = [lag for result in results for lag in result]
    utils.log_success(f"Total LAGs collected: {len(all_lags)}")
    return all_lags


@utils.aws_error_handler("Collecting Direct Connect Gateways", default_return=[])
def collect_directconnect_gateways(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Direct Connect Gateway information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with Direct Connect Gateway information
    """
    print("\n=== COLLECTING DIRECT CONNECT GATEWAYS ===")
    all_gateways = []

    # Direct Connect Gateways are global but accessed via a specific region
    # We only need to query from one region to get all gateways
    primary_region = regions[0] if regions else 'us-east-1'

    print(f"\nQuerying Direct Connect Gateways (global resources via {primary_region})")

    try:
        dx = utils.get_boto3_client('directconnect', region_name=primary_region)

        # Get Direct Connect Gateways
        response = dx.describe_direct_connect_gateways()
        gateways = response.get('directConnectGateways', [])

        print(f"  Found {len(gateways)} Direct Connect Gateways")

        for gw in gateways:
            gw_id = gw.get('directConnectGatewayId', 'N/A')
            print(f"  Processing Gateway: {gw_id}")

            # Extract gateway details
            gw_name = gw.get('directConnectGatewayName', 'N/A')
            gw_state = gw.get('directConnectGatewayState', 'N/A')
            amazon_side_asn = gw.get('amazonSideAsn', 'N/A')
            owner_account = gw.get('ownerAccount', 'N/A')
            state_change_error = gw.get('stateChangeError', 'N/A')

            all_gateways.append({
                'Gateway ID': gw_id,
                'Gateway Name': gw_name,
                'State': gw_state,
                'Amazon Side ASN': amazon_side_asn,
                'Owner Account': owner_account,
                'State Change Error': state_change_error
            })

    except Exception as e:
        utils.log_error(f"Error collecting Direct Connect Gateways from {primary_region}", e)

    utils.log_success(f"Total Direct Connect Gateways collected: {len(all_gateways)}")
    return all_gateways


@utils.aws_error_handler("Collecting Virtual Gateway Associations", default_return=[])
def collect_virtual_gateway_associations(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Direct Connect Gateway virtual private gateway associations.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with VGW association information
    """
    print("\n=== COLLECTING VIRTUAL GATEWAY ASSOCIATIONS ===")
    all_associations = []

    # Query from primary region (associations are global)
    primary_region = regions[0] if regions else 'us-east-1'

    print(f"\nQuerying VGW associations (global resources via {primary_region})")

    try:
        dx = utils.get_boto3_client('directconnect', region_name=primary_region)

        # First get all Direct Connect Gateways
        response = dx.describe_direct_connect_gateways()
        gateways = response.get('directConnectGateways', [])

        for gw in gateways:
            gw_id = gw.get('directConnectGatewayId', 'N/A')

            try:
                # Get associations for this gateway
                assoc_response = dx.describe_direct_connect_gateway_associations(
                    directConnectGatewayId=gw_id
                )

                associations = assoc_response.get('directConnectGatewayAssociations', [])

                for assoc in associations:
                    # Filter for VGW associations (not TGW)
                    if assoc.get('associatedGateway', {}).get('type') == 'virtualPrivateGateway':
                        assoc_id = assoc.get('associationId', 'N/A')
                        assoc_state = assoc.get('associationState', 'N/A')
                        vgw_id = assoc.get('associatedGateway', {}).get('id', 'N/A')
                        vgw_owner_account = assoc.get('associatedGateway', {}).get('ownerAccount', 'N/A')
                        vgw_region = assoc.get('associatedGateway', {}).get('region', 'N/A')

                        # Get allowed prefixes
                        allowed_prefixes = assoc.get('allowedPrefixesToDirectConnectGateway', [])
                        prefix_list = ', '.join([prefix.get('cidr', '') for prefix in allowed_prefixes]) if allowed_prefixes else 'N/A'

                        all_associations.append({
                            'Association ID': assoc_id,
                            'Direct Connect Gateway ID': gw_id,
                            'Virtual Private Gateway ID': vgw_id,
                            'State': assoc_state,
                            'VGW Region': vgw_region,
                            'VGW Owner Account': vgw_owner_account,
                            'Allowed Prefixes': prefix_list
                        })

            except Exception as e:
                utils.log_error(f"Error getting associations for gateway {gw_id}", e)

    except Exception as e:
        utils.log_error(f"Error collecting virtual gateway associations from {primary_region}", e)

    utils.log_success(f"Total VGW associations collected: {len(all_associations)}")
    return all_associations


@utils.aws_error_handler("Collecting Transit Gateway Associations", default_return=[])
def collect_transit_gateway_associations(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Direct Connect Gateway transit gateway associations.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with TGW association information
    """
    print("\n=== COLLECTING TRANSIT GATEWAY ASSOCIATIONS ===")
    all_associations = []

    # Query from primary region (associations are global)
    primary_region = regions[0] if regions else 'us-east-1'

    print(f"\nQuerying TGW associations (global resources via {primary_region})")

    try:
        dx = utils.get_boto3_client('directconnect', region_name=primary_region)

        # First get all Direct Connect Gateways
        response = dx.describe_direct_connect_gateways()
        gateways = response.get('directConnectGateways', [])

        for gw in gateways:
            gw_id = gw.get('directConnectGatewayId', 'N/A')

            try:
                # Get associations for this gateway
                assoc_response = dx.describe_direct_connect_gateway_associations(
                    directConnectGatewayId=gw_id
                )

                associations = assoc_response.get('directConnectGatewayAssociations', [])

                for assoc in associations:
                    # Filter for TGW associations
                    if assoc.get('associatedGateway', {}).get('type') == 'transitGateway':
                        assoc_id = assoc.get('associationId', 'N/A')
                        assoc_state = assoc.get('associationState', 'N/A')
                        tgw_id = assoc.get('associatedGateway', {}).get('id', 'N/A')
                        tgw_owner_account = assoc.get('associatedGateway', {}).get('ownerAccount', 'N/A')
                        tgw_region = assoc.get('associatedGateway', {}).get('region', 'N/A')

                        # Get allowed prefixes
                        allowed_prefixes = assoc.get('allowedPrefixesToDirectConnectGateway', [])
                        prefix_list = ', '.join([prefix.get('cidr', '') for prefix in allowed_prefixes]) if allowed_prefixes else 'N/A'

                        all_associations.append({
                            'Association ID': assoc_id,
                            'Direct Connect Gateway ID': gw_id,
                            'Transit Gateway ID': tgw_id,
                            'State': assoc_state,
                            'TGW Region': tgw_region,
                            'TGW Owner Account': tgw_owner_account,
                            'Allowed Prefixes': prefix_list
                        })

            except Exception as e:
                utils.log_error(f"Error getting associations for gateway {gw_id}", e)

    except Exception as e:
        utils.log_error(f"Error collecting transit gateway associations from {primary_region}", e)

    utils.log_success(f"Total TGW associations collected: {len(all_associations)}")
    return all_associations


def create_summary(data_frames: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Create summary statistics for Direct Connect resources.

    Args:
        data_frames: Dictionary of DataFrames with collected data

    Returns:
        list: List of summary dictionaries
    """
    summary = []

    # Connection summary
    if 'Connections' in data_frames:
        df_connections = data_frames['Connections']
        total_connections = len(df_connections)

        if total_connections > 0:
            # Count by state
            state_counts = df_connections['State'].value_counts().to_dict()
            for state, count in state_counts.items():
                summary.append({
                    'Category': 'Connections',
                    'Metric': f'State: {state}',
                    'Count': count
                })

            # Count by bandwidth
            bandwidth_counts = df_connections['Bandwidth'].value_counts().to_dict()
            for bandwidth, count in bandwidth_counts.items():
                summary.append({
                    'Category': 'Connections',
                    'Metric': f'Bandwidth: {bandwidth}',
                    'Count': count
                })

    # Virtual Interface summary
    if 'Virtual Interfaces' in data_frames:
        df_vifs = data_frames['Virtual Interfaces']
        total_vifs = len(df_vifs)

        if total_vifs > 0:
            # Count by type
            type_counts = df_vifs['Type'].value_counts().to_dict()
            for vif_type, count in type_counts.items():
                summary.append({
                    'Category': 'Virtual Interfaces',
                    'Metric': f'Type: {vif_type}',
                    'Count': count
                })

            # Count by state
            state_counts = df_vifs['State'].value_counts().to_dict()
            for state, count in state_counts.items():
                summary.append({
                    'Category': 'Virtual Interfaces',
                    'Metric': f'State: {state}',
                    'Count': count
                })

    # LAG summary
    if 'LAGs' in data_frames:
        df_lags = data_frames['LAGs']
        total_lags = len(df_lags)
        summary.append({
            'Category': 'LAGs',
            'Metric': 'Total LAGs',
            'Count': total_lags
        })

    # Gateway summary
    if 'Direct Connect Gateways' in data_frames:
        df_gateways = data_frames['Direct Connect Gateways']
        total_gateways = len(df_gateways)
        summary.append({
            'Category': 'Direct Connect Gateways',
            'Metric': 'Total Gateways',
            'Count': total_gateways
        })

    # Association summaries
    if 'VGW Associations' in data_frames:
        df_vgw_assoc = data_frames['VGW Associations']
        total_vgw_assoc = len(df_vgw_assoc)
        summary.append({
            'Category': 'Associations',
            'Metric': 'Virtual Private Gateway Associations',
            'Count': total_vgw_assoc
        })

    if 'TGW Associations' in data_frames:
        df_tgw_assoc = data_frames['TGW Associations']
        total_tgw_assoc = len(df_tgw_assoc)
        summary.append({
            'Category': 'Associations',
            'Metric': 'Transit Gateway Associations',
            'Count': total_tgw_assoc
        })

    return summary


def export_directconnect_data(account_id: str, account_name: str):
    """
    Export Direct Connect information to an Excel file.

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
    print("\nDirect Connect is a regional service.")
    print("\nNOTE: Direct Connect resources are often deployed in specific")
    print("      locations. Consider using 'All Available Regions' to ensure")
    print("      complete coverage across regions.")
    print("\nPlease select an option for region selection:")
    print("\n  1. Default Regions")
    print(f"     ({example_regions})")
    print("\n  2. All Available Regions")
    print("     (Scan all regions where Direct Connect is available)")
    print("\n  3. Specific Region")
    print("     (Enter a specific AWS region code)")
    print("\n" + "-" * 68)

    # Get and validate region choice
    regions = []
    while not regions:
        try:
            region_choice = input("\nEnter your choice (1, 2, or 3): ").strip()

            if region_choice == '1':
                regions = utils.get_partition_default_regions()
                print(f"\nUsing default regions: {', '.join(regions)}")
                region_suffix = ""
            elif region_choice == '2':
                regions = utils.get_partition_regions(partition, all_regions=True)
                print(f"\nScanning all {len(regions)} available regions")
                region_suffix = ""
            elif region_choice == '3':
                available_regions = utils.get_partition_regions(partition, all_regions=True)
                print("\n" + "=" * 68)
                print("AVAILABLE REGIONS")
                print("=" * 68)
                for idx, region in enumerate(available_regions, 1):
                    print(f"  {idx:2d}. {region}")
                print("=" * 68)

                region_input = input("\nEnter region number or region code: ").strip()

                if region_input.isdigit():
                    region_idx = int(region_input)
                    if 1 <= region_idx <= len(available_regions):
                        regions = [available_regions[region_idx - 1]]
                        print(f"\nUsing region: {regions[0]}")
                        region_suffix = f"-{regions[0]}"
                    else:
                        print(f"\nInvalid region number. Please enter a number between 1 and {len(available_regions)}.")
                else:
                    if region_input in available_regions:
                        regions = [region_input]
                        print(f"\nUsing region: {regions[0]}")
                        region_suffix = f"-{regions[0]}"
                    else:
                        print(f"\nInvalid region code: {region_input}")
                        print("Please enter a valid region code from the list above.")
            else:
                print("\nInvalid choice. Please enter 1, 2, or 3.")
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            sys.exit(0)
        except Exception as e:
            utils.log_error(f"Error getting region selection: {str(e)}")
            print("Please try again.")

    if not regions:
        utils.log_error("No regions selected. Exiting.")
        return

    print(f"\nStarting Direct Connect export process for {len(regions)} region(s)...")
    print("This may take some time depending on the number of resources...")
    print("\nNOTE: If you don't have Direct Connect configured, all sheets will be empty.")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect Connections
    connections = collect_connections(regions)
    if connections:
        data_frames['Connections'] = pd.DataFrame(connections)

    # STEP 2: Collect Virtual Interfaces
    vifs = collect_virtual_interfaces(regions)
    if vifs:
        data_frames['Virtual Interfaces'] = pd.DataFrame(vifs)

    # STEP 3: Collect LAGs
    lags = collect_lags(regions)
    if lags:
        data_frames['LAGs'] = pd.DataFrame(lags)

    # STEP 4: Collect Direct Connect Gateways
    gateways = collect_directconnect_gateways(regions)
    if gateways:
        data_frames['Direct Connect Gateways'] = pd.DataFrame(gateways)

    # STEP 5: Collect VGW Associations
    vgw_associations = collect_virtual_gateway_associations(regions)
    if vgw_associations:
        data_frames['VGW Associations'] = pd.DataFrame(vgw_associations)

    # STEP 6: Collect TGW Associations
    tgw_associations = collect_transit_gateway_associations(regions)
    if tgw_associations:
        data_frames['TGW Associations'] = pd.DataFrame(tgw_associations)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No Direct Connect data was collected. Nothing to export.")
        print("\nNo Direct Connect resources found in the selected region(s).")
        print("This is normal if Direct Connect is not configured in this account.")
        return

    # STEP 7: Create Summary
    summary_data = create_summary(data_frames)
    if summary_data:
        data_frames['Summary'] = pd.DataFrame(summary_data)

    # STEP 8: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 9: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'directconnect',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("Direct Connect data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")

            # Summary of exported data
            print("\n=== EXPORT SUMMARY ===")
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

        # Export Direct Connect data
        export_directconnect_data(account_id, account_name)

        print("\nDirect Connect export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("directconnect-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS VPN Connectivity Export Tool
Date: NOV-11-2025

Description:
This script exports comprehensive AWS VPN connectivity information into an Excel file with
multiple worksheets. The output includes Site-to-Site VPN connections, VPN tunnels, customer
gateways, virtual private gateways, Client VPN endpoints, and authorization rules.

Features:
- Site-to-Site VPN connections with tunnel details
- VPN tunnel status and configuration
- Customer gateways with BGP ASN
- Virtual private gateways and VPC attachments
- Client VPN endpoints and configurations
- Client VPN authorization rules
- Comprehensive summary sheet

Notes:
- VPN services are regional and require multi-region scanning
- Supports both Site-to-Site VPN and Client VPN
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


def scan_vpn_connections_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan Site-to-Site VPN connections in a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of VPN connection dictionaries for this region
    """
    vpn_connections = []

    try:
        ec2 = utils.get_boto3_client('ec2', region_name=region)

        # Describe VPN connections
        response = ec2.describe_vpn_connections()
        vpn_list = response.get('VpnConnections', [])

        for vpn in vpn_list:
            vpn_id = vpn.get('VpnConnectionId', '')
            state = vpn.get('State', '')
            vpn_type = vpn.get('Type', '')

            print(f"    Processing VPN connection: {vpn_id} ({state})")

            # Gateway IDs
            customer_gateway_id = vpn.get('CustomerGatewayId', 'N/A')
            vpn_gateway_id = vpn.get('VpnGatewayId', 'N/A')
            transit_gateway_id = vpn.get('TransitGatewayId', 'N/A')

            # Routing
            static_routes_only = vpn.get('Options', {}).get('StaticRoutesOnly', False)
            routing_type = 'Static' if static_routes_only else 'Dynamic (BGP)'

            # BGP ASN
            customer_gateway_config = vpn.get('CustomerGatewayConfiguration', '')
            bgp_asn = vpn.get('Options', {}).get('RemoteIpv4NetworkCidr', 'N/A')

            # Static routes
            static_routes = vpn.get('Routes', [])
            route_list = [f"{r.get('DestinationCidrBlock', '')} ({r.get('State', '')})" for r in static_routes]
            routes = ', '.join(route_list) if route_list else 'N/A'

            # Tunnel details (count)
            vgw_telemetry = vpn.get('VgwTelemetry', [])
            tunnel_count = len(vgw_telemetry)

            # Check tunnel status
            tunnels_up = sum(1 for t in vgw_telemetry if t.get('Status', '') == 'UP')
            tunnel_status = f"{tunnels_up}/{tunnel_count} UP"

            # Tags
            tags = vpn.get('Tags', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            name = tag_dict.get('Name', 'N/A')
            tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

            vpn_connections.append({
                'Region': region,
                'VPN Connection ID': vpn_id,
                'Name': name,
                'State': state,
                'Type': vpn_type,
                'Routing Type': routing_type,
                'Customer Gateway ID': customer_gateway_id,
                'Virtual Private Gateway ID': vpn_gateway_id,
                'Transit Gateway ID': transit_gateway_id,
                'Tunnel Status': tunnel_status,
                'Tunnel Count': tunnel_count,
                'Static Routes': routes,
                'Tags': tags_str
            })

    except Exception as e:
        utils.log_error(f"Error collecting VPN connections in {region}", e)

    utils.log_info(f"Found {len(vpn_connections)} VPN connections in {region}")
    return vpn_connections


@utils.aws_error_handler("Collecting Site-to-Site VPN connections", default_return=[])
def collect_vpn_connections(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Site-to-Site VPN connection information across regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with VPN connection details
    """
    print("\n=== COLLECTING SITE-TO-SITE VPN CONNECTIONS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    vpn_connections = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_vpn_connections_in_region,
    )

    utils.log_success(f"Total Site-to-Site VPN connections collected: {len(vpn_connections)}")
    return vpn_connections


def scan_vpn_tunnels_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan VPN tunnels in a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of VPN tunnel dictionaries for this region
    """
    tunnels = []

    try:
        ec2 = utils.get_boto3_client('ec2', region_name=region)

        # Describe VPN connections
        response = ec2.describe_vpn_connections()
        vpn_list = response.get('VpnConnections', [])

        for vpn in vpn_list:
            vpn_id = vpn.get('VpnConnectionId', '')

            # Get tunnel telemetry
            vgw_telemetry = vpn.get('VgwTelemetry', [])

            for idx, tunnel in enumerate(vgw_telemetry, 1):
                tunnel_outside_ip = tunnel.get('OutsideIpAddress', 'N/A')
                status = tunnel.get('Status', 'N/A')
                status_message = tunnel.get('StatusMessage', 'N/A')

                # Last status change
                last_status_change = tunnel.get('LastStatusChange', '')
                if last_status_change:
                    if isinstance(last_status_change, datetime.datetime):
                        last_status_change = last_status_change.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        last_status_change = str(last_status_change)
                else:
                    last_status_change = 'N/A'

                # Accepted route count
                accepted_route_count = tunnel.get('AcceptedRouteCount', 0)

                # Get tunnel options from VPN connection options
                tunnel_options = vpn.get('Options', {}).get('TunnelOptions', [])
                if idx <= len(tunnel_options):
                    tunnel_option = tunnel_options[idx - 1]

                    # DPD timeout
                    dpd_timeout = tunnel_option.get('DpdTimeoutSeconds', 'N/A')

                    # IKE versions
                    ike_versions = tunnel_option.get('IkeVersions', [])
                    ike_versions_str = ', '.join([v.get('Value', '') for v in ike_versions]) if ike_versions else 'N/A'

                    # Phase 1 encryption algorithms
                    phase1_encryption = tunnel_option.get('Phase1EncryptionAlgorithms', [])
                    phase1_enc_str = ', '.join([a.get('Value', '') for a in phase1_encryption]) if phase1_encryption else 'N/A'

                    # Phase 2 encryption algorithms
                    phase2_encryption = tunnel_option.get('Phase2EncryptionAlgorithms', [])
                    phase2_enc_str = ', '.join([a.get('Value', '') for a in phase2_encryption]) if phase2_encryption else 'N/A'

                    # Inside CIDR
                    tunnel_inside_cidr = tunnel_option.get('TunnelInsideCidr', 'N/A')

                    # Pre-shared key (masked for security)
                    preshared_key = 'CONFIGURED' if tunnel_option.get('PreSharedKey') else 'N/A'
                else:
                    dpd_timeout = 'N/A'
                    ike_versions_str = 'N/A'
                    phase1_enc_str = 'N/A'
                    phase2_enc_str = 'N/A'
                    tunnel_inside_cidr = 'N/A'
                    preshared_key = 'N/A'

                tunnels.append({
                    'Region': region,
                    'VPN Connection ID': vpn_id,
                    'Tunnel Index': idx,
                    'Outside IP Address': tunnel_outside_ip,
                    'Status': status,
                    'Status Message': status_message,
                    'Last Status Change': last_status_change,
                    'Accepted Routes': accepted_route_count,
                    'Tunnel Inside CIDR': tunnel_inside_cidr,
                    'DPD Timeout (s)': dpd_timeout,
                    'IKE Versions': ike_versions_str,
                    'Phase 1 Encryption': phase1_enc_str,
                    'Phase 2 Encryption': phase2_enc_str,
                    'Pre-Shared Key': preshared_key
                })

    except Exception as e:
        utils.log_error(f"Error collecting VPN tunnels in {region}", e)

    utils.log_info(f"Found {len(tunnels)} VPN tunnels in {region}")
    return tunnels


@utils.aws_error_handler("Collecting VPN tunnel details", default_return=[])
def collect_vpn_tunnels(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect VPN tunnel information across regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with VPN tunnel details
    """
    print("\n=== COLLECTING VPN TUNNEL DETAILS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    tunnels = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_vpn_tunnels_in_region,
    )

    utils.log_success(f"Total VPN tunnels collected: {len(tunnels)}")
    return tunnels


def scan_customer_gateways_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan customer gateways in a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of customer gateway dictionaries for this region
    """
    gateways = []

    try:
        ec2 = utils.get_boto3_client('ec2', region_name=region)

        # Describe customer gateways
        response = ec2.describe_customer_gateways()
        cgw_list = response.get('CustomerGateways', [])

        for cgw in cgw_list:
            cgw_id = cgw.get('CustomerGatewayId', '')
            state = cgw.get('State', '')

            print(f"    Processing customer gateway: {cgw_id} ({state})")

            # Gateway details
            bgp_asn = cgw.get('BgpAsn', 'N/A')
            ip_address = cgw.get('IpAddress', 'N/A')
            cgw_type = cgw.get('Type', 'N/A')

            # Device name (optional)
            device_name = cgw.get('DeviceName', 'N/A')

            # Tags
            tags = cgw.get('Tags', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            name = tag_dict.get('Name', 'N/A')
            tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

            gateways.append({
                'Region': region,
                'Customer Gateway ID': cgw_id,
                'Name': name,
                'State': state,
                'Type': cgw_type,
                'BGP ASN': bgp_asn,
                'IP Address': ip_address,
                'Device Name': device_name,
                'Tags': tags_str
            })

    except Exception as e:
        utils.log_error(f"Error collecting customer gateways in {region}", e)

    utils.log_info(f"Found {len(gateways)} customer gateways in {region}")
    return gateways


@utils.aws_error_handler("Collecting customer gateways", default_return=[])
def collect_customer_gateways(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect customer gateway information across regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with customer gateway details
    """
    print("\n=== COLLECTING CUSTOMER GATEWAYS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    gateways = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_customer_gateways_in_region,
    )

    utils.log_success(f"Total customer gateways collected: {len(gateways)}")
    return gateways


def scan_virtual_private_gateways_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan virtual private gateways in a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of virtual private gateway dictionaries for this region
    """
    vgws = []

    try:
        ec2 = utils.get_boto3_client('ec2', region_name=region)

        # Describe virtual private gateways
        response = ec2.describe_vpn_gateways()
        vgw_list = response.get('VpnGateways', [])

        for vgw in vgw_list:
            vgw_id = vgw.get('VpnGatewayId', '')
            state = vgw.get('State', '')

            print(f"    Processing virtual private gateway: {vgw_id} ({state})")

            # Gateway details
            vgw_type = vgw.get('Type', 'N/A')
            amazon_side_asn = vgw.get('AmazonSideAsn', 'N/A')

            # VPC attachments
            vpc_attachments = vgw.get('VpcAttachments', [])
            vpc_list = []
            for attachment in vpc_attachments:
                vpc_id = attachment.get('VpcId', '')
                attach_state = attachment.get('State', '')
                vpc_list.append(f"{vpc_id} ({attach_state})")
            vpcs = ', '.join(vpc_list) if vpc_list else 'N/A'

            # Availability zone
            availability_zone = vgw.get('AvailabilityZone', 'N/A')

            # Tags
            tags = vgw.get('Tags', [])
            tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            name = tag_dict.get('Name', 'N/A')
            tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

            vgws.append({
                'Region': region,
                'Virtual Private Gateway ID': vgw_id,
                'Name': name,
                'State': state,
                'Type': vgw_type,
                'Amazon Side ASN': amazon_side_asn,
                'VPC Attachments': vpcs,
                'Availability Zone': availability_zone,
                'Tags': tags_str
            })

    except Exception as e:
        utils.log_error(f"Error collecting virtual private gateways in {region}", e)

    utils.log_info(f"Found {len(vgws)} virtual private gateways in {region}")
    return vgws


@utils.aws_error_handler("Collecting virtual private gateways", default_return=[])
def collect_virtual_private_gateways(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect virtual private gateway information across regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with virtual private gateway details
    """
    print("\n=== COLLECTING VIRTUAL PRIVATE GATEWAYS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    vgws = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_virtual_private_gateways_in_region,
    )

    utils.log_success(f"Total virtual private gateways collected: {len(vgws)}")
    return vgws


@utils.aws_error_handler("Collecting Client VPN endpoints", default_return=[])
def collect_client_vpn_endpoints(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Client VPN endpoint information across regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with Client VPN endpoint details
    """
    print("\n=== COLLECTING CLIENT VPN ENDPOINTS ===")

    endpoints = []

    for region in regions:
        print(f"\n  Scanning region: {region}")

        try:
            ec2 = utils.get_boto3_client('ec2', region_name=region)

            # Describe Client VPN endpoints
            response = ec2.describe_client_vpn_endpoints()
            endpoint_list = response.get('ClientVpnEndpoints', [])

            for endpoint in endpoint_list:
                endpoint_id = endpoint.get('ClientVpnEndpointId', '')
                status = endpoint.get('Status', {}).get('Code', 'N/A')

                print(f"    Processing Client VPN endpoint: {endpoint_id} ({status})")

                # Endpoint details
                dns_name = endpoint.get('DnsName', 'N/A')
                client_cidr_block = endpoint.get('ClientCidrBlock', 'N/A')
                server_certificate_arn = endpoint.get('ServerCertificateArn', 'N/A')

                # VPC and security groups
                vpc_id = endpoint.get('VpcId', 'N/A')
                security_group_ids = endpoint.get('SecurityGroupIds', [])
                security_groups = ', '.join(security_group_ids) if security_group_ids else 'N/A'

                # Split tunnel
                split_tunnel = endpoint.get('SplitTunnel', False)

                # Transport protocol
                transport_protocol = endpoint.get('TransportProtocol', 'N/A')

                # VPN protocol
                vpn_protocol = endpoint.get('VpnProtocol', 'N/A')

                # Authentication options
                auth_options = endpoint.get('AuthenticationOptions', [])
                auth_list = []
                for auth in auth_options:
                    auth_type = auth.get('Type', '')
                    if auth_type == 'certificate-authentication':
                        auth_list.append('Certificate')
                    elif auth_type == 'directory-service-authentication':
                        directory_id = auth.get('ActiveDirectory', {}).get('DirectoryId', '')
                        auth_list.append(f'Active Directory ({directory_id})')
                    elif auth_type == 'federated-authentication':
                        saml_provider_arn = auth.get('FederatedAuthentication', {}).get('SamlProviderArn', '')
                        auth_list.append(f'SAML ({saml_provider_arn})')
                    else:
                        auth_list.append(auth_type)
                authentication = ', '.join(auth_list) if auth_list else 'N/A'

                # Connection logging
                connection_log_options = endpoint.get('ConnectionLogOptions', {})
                logging_enabled = connection_log_options.get('Enabled', False)
                log_group = connection_log_options.get('CloudwatchLogGroup', 'N/A') if logging_enabled else 'Disabled'

                # Tags
                tags = endpoint.get('Tags', [])
                tag_dict = {tag['Key']: tag['Value'] for tag in tags}
                name = tag_dict.get('Name', 'N/A')
                tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

                endpoints.append({
                    'Region': region,
                    'Client VPN Endpoint ID': endpoint_id,
                    'Name': name,
                    'Status': status,
                    'DNS Name': dns_name,
                    'Client CIDR Block': client_cidr_block,
                    'VPC ID': vpc_id,
                    'Security Group IDs': security_groups,
                    'Transport Protocol': transport_protocol,
                    'VPN Protocol': vpn_protocol,
                    'Split Tunnel': split_tunnel,
                    'Authentication': authentication,
                    'Server Certificate ARN': server_certificate_arn,
                    'Connection Logging': log_group,
                    'Tags': tags_str
                })

        except Exception as e:
            utils.log_error(f"Error collecting Client VPN endpoints in {region}", e)

    utils.log_success(f"Total Client VPN endpoints collected: {len(endpoints)}")
    return endpoints


def scan_client_vpn_authorization_rules_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan Client VPN authorization rules in a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of authorization rule dictionaries for this region
    """
    rules = []

    try:
        ec2 = utils.get_boto3_client('ec2', region_name=region)

        # First get all Client VPN endpoints
        endpoints_response = ec2.describe_client_vpn_endpoints()
        endpoint_list = endpoints_response.get('ClientVpnEndpoints', [])

        for endpoint in endpoint_list:
            endpoint_id = endpoint.get('ClientVpnEndpointId', '')

            # Get authorization rules for this endpoint
            try:
                rules_response = ec2.describe_client_vpn_authorization_rules(
                    ClientVpnEndpointId=endpoint_id
                )
                rule_list = rules_response.get('AuthorizationRules', [])

                for rule in rule_list:
                    target_network_cidr = rule.get('DestinationCidr', '')
                    access_group_id = rule.get('GroupId', 'N/A')
                    authorize_all_groups = rule.get('AccessAll', False)
                    status = rule.get('Status', {}).get('Code', 'N/A')
                    description = rule.get('Description', 'N/A')

                    rules.append({
                        'Region': region,
                        'Client VPN Endpoint ID': endpoint_id,
                        'Target Network CIDR': target_network_cidr,
                        'Access Group ID': access_group_id,
                        'Authorize All Groups': authorize_all_groups,
                        'Status': status,
                        'Description': description
                    })

            except Exception as e:
                utils.log_error(f"Error collecting authorization rules for endpoint {endpoint_id}", e)

    except Exception as e:
        utils.log_error(f"Error collecting Client VPN authorization rules in {region}", e)

    utils.log_info(f"Found {len(rules)} Client VPN authorization rules in {region}")
    return rules


@utils.aws_error_handler("Collecting Client VPN authorization rules", default_return=[])
def collect_client_vpn_authorization_rules(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Client VPN authorization rule information across regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with authorization rule details
    """
    print("\n=== COLLECTING CLIENT VPN AUTHORIZATION RULES ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    rules = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_client_vpn_authorization_rules_in_region,
    )

    utils.log_success(f"Total Client VPN authorization rules collected: {len(rules)}")
    return rules


def generate_summary(vpn_connections: List[Dict], tunnels: List[Dict], customer_gateways: List[Dict],
                     vgws: List[Dict], client_vpn_endpoints: List[Dict], auth_rules: List[Dict]) -> List[Dict[str, Any]]:
    """
    Generate summary statistics for VPN resources.

    Args:
        vpn_connections: List of Site-to-Site VPN connections
        tunnels: List of VPN tunnels
        customer_gateways: List of customer gateways
        vgws: List of virtual private gateways
        client_vpn_endpoints: List of Client VPN endpoints
        auth_rules: List of authorization rules

    Returns:
        list: List of dictionaries with summary data
    """
    print("\n=== GENERATING SUMMARY ===")

    summary = []

    # Site-to-Site VPN connections by state
    if vpn_connections:
        import pandas as pd
        vpn_df = pd.DataFrame(vpn_connections)
        vpn_states = vpn_df['State'].value_counts().to_dict()

        for state, count in sorted(vpn_states.items()):
            summary.append({
                'Category': 'Site-to-Site VPN',
                'Subcategory': f'{state} Connections',
                'Count': count
            })

        summary.append({
            'Category': 'Site-to-Site VPN',
            'Subcategory': 'Total Connections',
            'Count': len(vpn_connections)
        })

    # VPN tunnels
    if tunnels:
        import pandas as pd
        tunnel_df = pd.DataFrame(tunnels)
        tunnel_statuses = tunnel_df['Status'].value_counts().to_dict()

        for status, count in sorted(tunnel_statuses.items()):
            summary.append({
                'Category': 'VPN Tunnels',
                'Subcategory': f'{status} Tunnels',
                'Count': count
            })

        summary.append({
            'Category': 'VPN Tunnels',
            'Subcategory': 'Total Tunnels',
            'Count': len(tunnels)
        })

    # Customer gateways
    summary.append({
        'Category': 'Gateways',
        'Subcategory': 'Customer Gateways',
        'Count': len(customer_gateways)
    })

    # Virtual private gateways
    summary.append({
        'Category': 'Gateways',
        'Subcategory': 'Virtual Private Gateways',
        'Count': len(vgws)
    })

    # Client VPN endpoints by status
    if client_vpn_endpoints:
        import pandas as pd
        client_vpn_df = pd.DataFrame(client_vpn_endpoints)
        endpoint_statuses = client_vpn_df['Status'].value_counts().to_dict()

        for status, count in sorted(endpoint_statuses.items()):
            summary.append({
                'Category': 'Client VPN',
                'Subcategory': f'{status} Endpoints',
                'Count': count
            })

        summary.append({
            'Category': 'Client VPN',
            'Subcategory': 'Total Endpoints',
            'Count': len(client_vpn_endpoints)
        })

    # Authorization rules
    summary.append({
        'Category': 'Client VPN',
        'Subcategory': 'Authorization Rules',
        'Count': len(auth_rules)
    })

    utils.log_success("Summary generated successfully")
    return summary


def export_vpn_data(account_id: str, account_name: str, regions: List[str]):
    """
    Export VPN connectivity information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
        regions: List of AWS regions to scan
    """
    print("\n" + "=" * 60)
    print("Starting VPN export process...")
    print("=" * 60)

    utils.log_info("Beginning VPN data collection")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect Site-to-Site VPN connections
    vpn_connections = collect_vpn_connections(regions)
    if vpn_connections:
        data_frames['S2S VPN Connections'] = pd.DataFrame(vpn_connections)

    # STEP 2: Collect VPN tunnels
    tunnels = collect_vpn_tunnels(regions)
    if tunnels:
        data_frames['VPN Tunnels'] = pd.DataFrame(tunnels)

    # STEP 3: Collect customer gateways
    customer_gateways = collect_customer_gateways(regions)
    if customer_gateways:
        data_frames['Customer Gateways'] = pd.DataFrame(customer_gateways)

    # STEP 4: Collect virtual private gateways
    vgws = collect_virtual_private_gateways(regions)
    if vgws:
        data_frames['Virtual Private Gateways'] = pd.DataFrame(vgws)

    # STEP 5: Collect Client VPN endpoints
    client_vpn_endpoints = collect_client_vpn_endpoints(regions)
    if client_vpn_endpoints:
        data_frames['Client VPN Endpoints'] = pd.DataFrame(client_vpn_endpoints)

    # STEP 6: Collect Client VPN authorization rules
    auth_rules = collect_client_vpn_authorization_rules(regions)
    if auth_rules:
        data_frames['Client VPN Auth Rules'] = pd.DataFrame(auth_rules)

    # STEP 7: Generate summary
    summary = generate_summary(vpn_connections, tunnels, customer_gateways, vgws, client_vpn_endpoints, auth_rules)
    if summary:
        data_frames['Summary'] = pd.DataFrame(summary)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No VPN data was collected. Nothing to export.")
        print("\nNo VPN resources found in the selected regions.")
        return

    # STEP 8: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 9: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    region_suffix = 'multi-region' if len(regions) > 1 else regions[0]
    final_excel_file = utils.create_export_filename(
        account_name,
        'vpn',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("VPN data exported successfully!")
            utils.log_info(f"File location: {output_path}")

            # Summary of exported data
            print("\n" + "=" * 60)
            print("EXPORT SUMMARY")
            print("=" * 60)
            for sheet_name, df in data_frames.items():
                utils.log_info(f"  - {sheet_name}: {len(df)} records")
                print(f"  - {sheet_name}: {len(df)} records")
        else:
            utils.log_error("Error creating Excel file. Please check the logs.")

    except Exception as e:
        utils.log_error("Error creating Excel file", e)


def main():
    # Initialize logging
    utils.setup_logging("vpn-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("vpn-export.py", "AWS VPN Connectivity Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS VPN CONNECTIVITY EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            if not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
                print("Exiting script...")
                sys.exit(0)

        # Detect partition for region examples
        regions = utils.prompt_region_selection()
        # Export VPN data
        export_vpn_data(account_id, account_name, regions)

        print("\nVPN export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("vpn-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

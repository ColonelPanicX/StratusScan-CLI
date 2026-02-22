#!/usr/bin/env python3
"""
AWS Network Manager Export Script

Exports AWS Network Manager resources for SD-WAN and global networking:
- Global Networks and network metadata
- Transit Gateway Network Manager registrations
- Sites (physical locations)
- Links (connection between sites)
- Devices (routers, SD-WAN appliances)
- Connections (device-to-link associations)
- Customer Gateway Associations
- Link Associations and Transit Gateway Connect Peer Associations

Features:
- Complete Network Manager global network inventory
- Site and device topology tracking
- Link bandwidth and latency configurations
- Transit Gateway integrations
- Customer gateway associations
- Multi-region global network support
- Comprehensive multi-worksheet export

Note: Requires networkmanager:* permissions
Note: Network Manager is a global service accessed through us-west-2
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
import pandas as pd

# Standard utils import pattern
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

utils.setup_logging('network-manager-export')

# Module-level home_region — set once in main() before any collect_* calls.
# Network Manager is a global service; the region is partition-specific.
home_region: str = 'us-west-2'


@utils.aws_error_handler("Collecting global networks", default_return=[])
def collect_global_networks() -> List[Dict[str, Any]]:
    """Collect all Network Manager global networks."""
    # Network Manager is a global service, use us-west-2
    # Networkmanager is a global service - use partition-aware home region
    nm = utils.get_boto3_client('networkmanager', region_name=home_region)
    networks = []

    try:
        paginator = nm.get_paginator('describe_global_networks')
        for page in paginator.paginate():
            for network in page.get('GlobalNetworks', []):
                # Format tags
                tags = []
                for tag in network.get('Tags', []):
                    tags.append(f"{tag.get('Key')}={tag.get('Value')}")

                networks.append({
                    'GlobalNetworkId': network.get('GlobalNetworkId', 'N/A'),
                    'GlobalNetworkArn': network.get('GlobalNetworkArn', 'N/A'),
                    'Description': network.get('Description', 'N/A'),
                    'State': network.get('State', 'N/A'),
                    'CreatedAt': network.get('CreatedAt'),
                    'Tags': ', '.join(tags) if tags else 'N/A',
                })
    except Exception as e:
        utils.log_warning(f"Error collecting Network Manager global networks: {e}")

    return networks


@utils.aws_error_handler("Collecting sites", default_return=[])
def collect_sites(global_network_id: str) -> List[Dict[str, Any]]:
    """Collect sites for a global network."""
    nm = utils.get_boto3_client('networkmanager', region_name=home_region)
    sites = []

    try:
        paginator = nm.get_paginator('get_sites')
        for page in paginator.paginate(GlobalNetworkId=global_network_id):
            for site in page.get('Sites', []):
                location = site.get('Location', {})

                # Format tags
                tags = []
                for tag in site.get('Tags', []):
                    tags.append(f"{tag.get('Key')}={tag.get('Value')}")

                sites.append({
                    'GlobalNetworkId': global_network_id,
                    'SiteId': site.get('SiteId', 'N/A'),
                    'SiteArn': site.get('SiteArn', 'N/A'),
                    'Description': site.get('Description', 'N/A'),
                    'State': site.get('State', 'N/A'),
                    'Address': location.get('Address', 'N/A'),
                    'Latitude': location.get('Latitude', 'N/A'),
                    'Longitude': location.get('Longitude', 'N/A'),
                    'CreatedAt': site.get('CreatedAt'),
                    'Tags': ', '.join(tags) if tags else 'N/A',
                })
    except Exception:
        pass

    return sites


@utils.aws_error_handler("Collecting links", default_return=[])
def collect_links(global_network_id: str) -> List[Dict[str, Any]]:
    """Collect links for a global network."""
    nm = utils.get_boto3_client('networkmanager', region_name=home_region)
    links = []

    try:
        paginator = nm.get_paginator('get_links')
        for page in paginator.paginate(GlobalNetworkId=global_network_id):
            for link in page.get('Links', []):
                bandwidth = link.get('Bandwidth', {})

                # Format tags
                tags = []
                for tag in link.get('Tags', []):
                    tags.append(f"{tag.get('Key')}={tag.get('Value')}")

                links.append({
                    'GlobalNetworkId': global_network_id,
                    'LinkId': link.get('LinkId', 'N/A'),
                    'LinkArn': link.get('LinkArn', 'N/A'),
                    'Description': link.get('Description', 'N/A'),
                    'State': link.get('State', 'N/A'),
                    'Type': link.get('Type', 'N/A'),
                    'Provider': link.get('Provider', 'N/A'),
                    'SiteId': link.get('SiteId', 'N/A'),
                    'UploadSpeed': bandwidth.get('UploadSpeed', 'N/A'),
                    'DownloadSpeed': bandwidth.get('DownloadSpeed', 'N/A'),
                    'CreatedAt': link.get('CreatedAt'),
                    'Tags': ', '.join(tags) if tags else 'N/A',
                })
    except Exception:
        pass

    return links


@utils.aws_error_handler("Collecting devices", default_return=[])
def collect_devices(global_network_id: str) -> List[Dict[str, Any]]:
    """Collect devices for a global network."""
    nm = utils.get_boto3_client('networkmanager', region_name=home_region)
    devices = []

    try:
        paginator = nm.get_paginator('get_devices')
        for page in paginator.paginate(GlobalNetworkId=global_network_id):
            for device in page.get('Devices', []):
                location = device.get('Location', {})
                aws_location = device.get('AWSLocation', {})

                # Format tags
                tags = []
                for tag in device.get('Tags', []):
                    tags.append(f"{tag.get('Key')}={tag.get('Value')}")

                devices.append({
                    'GlobalNetworkId': global_network_id,
                    'DeviceId': device.get('DeviceId', 'N/A'),
                    'DeviceArn': device.get('DeviceArn', 'N/A'),
                    'Description': device.get('Description', 'N/A'),
                    'State': device.get('State', 'N/A'),
                    'Type': device.get('Type', 'N/A'),
                    'Vendor': device.get('Vendor', 'N/A'),
                    'Model': device.get('Model', 'N/A'),
                    'SerialNumber': device.get('SerialNumber', 'N/A'),
                    'SiteId': device.get('SiteId', 'N/A'),
                    'Address': location.get('Address', 'N/A'),
                    'Latitude': location.get('Latitude', 'N/A'),
                    'Longitude': location.get('Longitude', 'N/A'),
                    'AWSZone': aws_location.get('Zone', 'N/A'),
                    'AWSSubnetArn': aws_location.get('SubnetArn', 'N/A'),
                    'CreatedAt': device.get('CreatedAt'),
                    'Tags': ', '.join(tags) if tags else 'N/A',
                })
    except Exception:
        pass

    return devices


@utils.aws_error_handler("Collecting connections", default_return=[])
def collect_connections(global_network_id: str) -> List[Dict[str, Any]]:
    """Collect connections for a global network."""
    nm = utils.get_boto3_client('networkmanager', region_name=home_region)
    connections = []

    try:
        paginator = nm.get_paginator('get_connections')
        for page in paginator.paginate(GlobalNetworkId=global_network_id):
            for connection in page.get('Connections', []):
                # Format tags
                tags = []
                for tag in connection.get('Tags', []):
                    tags.append(f"{tag.get('Key')}={tag.get('Value')}")

                connections.append({
                    'GlobalNetworkId': global_network_id,
                    'ConnectionId': connection.get('ConnectionId', 'N/A'),
                    'ConnectionArn': connection.get('ConnectionArn', 'N/A'),
                    'Description': connection.get('Description', 'N/A'),
                    'State': connection.get('State', 'N/A'),
                    'DeviceId': connection.get('DeviceId', 'N/A'),
                    'ConnectedDeviceId': connection.get('ConnectedDeviceId', 'N/A'),
                    'LinkId': connection.get('LinkId', 'N/A'),
                    'ConnectedLinkId': connection.get('ConnectedLinkId', 'N/A'),
                    'CreatedAt': connection.get('CreatedAt'),
                    'Tags': ', '.join(tags) if tags else 'N/A',
                })
    except Exception:
        pass

    return connections


@utils.aws_error_handler("Collecting transit gateway registrations", default_return=[])
def collect_tgw_registrations(global_network_id: str) -> List[Dict[str, Any]]:
    """Collect Transit Gateway registrations for a global network."""
    nm = utils.get_boto3_client('networkmanager', region_name=home_region)
    registrations = []

    try:
        paginator = nm.get_paginator('get_transit_gateway_registrations')
        for page in paginator.paginate(GlobalNetworkId=global_network_id):
            for registration in page.get('TransitGatewayRegistrations', []):
                state = registration.get('State', {})

                registrations.append({
                    'GlobalNetworkId': global_network_id,
                    'TransitGatewayArn': registration.get('TransitGatewayArn', 'N/A'),
                    'State': state.get('Code', 'N/A'),
                    'StateMessage': state.get('Message', 'N/A'),
                })
    except Exception:
        pass

    return registrations


@utils.aws_error_handler("Collecting customer gateway associations", default_return=[])
def collect_cgw_associations(global_network_id: str) -> List[Dict[str, Any]]:
    """Collect Customer Gateway Associations for a global network."""
    nm = utils.get_boto3_client('networkmanager', region_name=home_region)
    associations = []

    try:
        paginator = nm.get_paginator('get_customer_gateway_associations')
        for page in paginator.paginate(GlobalNetworkId=global_network_id):
            for assoc in page.get('CustomerGatewayAssociations', []):
                state = assoc.get('State', 'N/A')

                associations.append({
                    'GlobalNetworkId': global_network_id,
                    'CustomerGatewayArn': assoc.get('CustomerGatewayArn', 'N/A'),
                    'DeviceId': assoc.get('DeviceId', 'N/A'),
                    'LinkId': assoc.get('LinkId', 'N/A'),
                    'State': state,
                })
    except Exception:
        pass

    return associations


def _run_export(account_id: str, account_name: str) -> None:
    """Collect Network Manager data and write the Excel export."""
    utils.log_info("Network Manager is a global service accessed through us-west-2.")
    utils.log_info("Scanning for global networks and SD-WAN topology...")

    # Collect global networks
    global_networks = collect_global_networks()

    if not global_networks:
        utils.log_warning("No Network Manager global networks found.")
        utils.log_info("Creating empty export file...")
    else:
        utils.log_info(f"Found {len(global_networks)} global network(s)")

    # Collect resources for each global network
    all_sites = []
    all_links = []
    all_devices = []
    all_connections = []
    all_tgw_registrations = []
    all_cgw_associations = []

    for idx, network in enumerate(global_networks, 1):
        global_network_id = network['GlobalNetworkId']
        utils.log_info(f"[{idx}/{len(global_networks)}] Processing global network: {global_network_id}")

        # Collect sites
        sites = collect_sites(global_network_id)
        if sites:
            utils.log_info(f"  Found {len(sites)} site(s)")
            all_sites.extend(sites)

        # Collect links
        links = collect_links(global_network_id)
        if links:
            utils.log_info(f"  Found {len(links)} link(s)")
            all_links.extend(links)

        # Collect devices
        devices = collect_devices(global_network_id)
        if devices:
            utils.log_info(f"  Found {len(devices)} device(s)")
            all_devices.extend(devices)

        # Collect connections
        connections = collect_connections(global_network_id)
        if connections:
            utils.log_info(f"  Found {len(connections)} connection(s)")
            all_connections.extend(connections)

        # Collect TGW registrations
        tgw_registrations = collect_tgw_registrations(global_network_id)
        if tgw_registrations:
            utils.log_info(f"  Found {len(tgw_registrations)} Transit Gateway registration(s)")
            all_tgw_registrations.extend(tgw_registrations)

        # Collect CGW associations
        cgw_associations = collect_cgw_associations(global_network_id)
        if cgw_associations:
            utils.log_info(f"  Found {len(cgw_associations)} Customer Gateway association(s)")
            all_cgw_associations.extend(cgw_associations)

    utils.log_info(f"Total global networks found: {len(global_networks)}")
    utils.log_info(f"Total sites found: {len(all_sites)}")
    utils.log_info(f"Total links found: {len(all_links)}")
    utils.log_info(f"Total devices found: {len(all_devices)}")
    utils.log_info(f"Total connections found: {len(all_connections)}")
    utils.log_info(f"Total TGW registrations found: {len(all_tgw_registrations)}")
    utils.log_info(f"Total CGW associations found: {len(all_cgw_associations)}")

    # Create DataFrames
    df_networks = utils.prepare_dataframe_for_export(pd.DataFrame(global_networks))
    df_sites = utils.prepare_dataframe_for_export(pd.DataFrame(all_sites))
    df_links = utils.prepare_dataframe_for_export(pd.DataFrame(all_links))
    df_devices = utils.prepare_dataframe_for_export(pd.DataFrame(all_devices))
    df_connections = utils.prepare_dataframe_for_export(pd.DataFrame(all_connections))
    df_tgw_registrations = utils.prepare_dataframe_for_export(pd.DataFrame(all_tgw_registrations))
    df_cgw_associations = utils.prepare_dataframe_for_export(pd.DataFrame(all_cgw_associations))

    # Create summary
    summary_data = []
    summary_data.append({'Metric': 'Total Global Networks', 'Value': len(global_networks)})
    summary_data.append({'Metric': 'Total Sites', 'Value': len(all_sites)})
    summary_data.append({'Metric': 'Total Links', 'Value': len(all_links)})
    summary_data.append({'Metric': 'Total Devices', 'Value': len(all_devices)})
    summary_data.append({'Metric': 'Total Connections', 'Value': len(all_connections)})
    summary_data.append({'Metric': 'Total TGW Registrations', 'Value': len(all_tgw_registrations)})
    summary_data.append({'Metric': 'Total CGW Associations', 'Value': len(all_cgw_associations)})

    if not df_networks.empty:
        available_networks = len(df_networks[df_networks['State'] == 'AVAILABLE'])
        summary_data.append({'Metric': 'Available Global Networks', 'Value': available_networks})

    if not df_devices.empty:
        available_devices = len(df_devices[df_devices['State'] == 'AVAILABLE'])
        summary_data.append({'Metric': 'Available Devices', 'Value': available_devices})

    df_summary = utils.prepare_dataframe_for_export(pd.DataFrame(summary_data))

    # Create filtered views
    df_available_networks = pd.DataFrame()
    df_available_devices = pd.DataFrame()

    if not df_networks.empty:
        df_available_networks = df_networks[df_networks['State'] == 'AVAILABLE']

    if not df_devices.empty:
        df_available_devices = df_devices[df_devices['State'] == 'AVAILABLE']

    # Export to Excel
    filename = utils.create_export_filename(account_name, 'network-manager', 'global')

    sheets = {
        'Summary': df_summary,
        'Global Networks': df_networks,
        'Available Networks': df_available_networks,
        'Sites': df_sites,
        'Links': df_links,
        'Devices': df_devices,
        'Available Devices': df_available_devices,
        'Connections': df_connections,
        'TGW Registrations': df_tgw_registrations,
        'CGW Associations': df_cgw_associations,
    }

    utils.save_multiple_dataframes_to_excel(sheets, filename)

    # Log summary
    total_resources = (len(global_networks) + len(all_sites) + len(all_links) +
                      len(all_devices) + len(all_connections) +
                      len(all_tgw_registrations) + len(all_cgw_associations))

    utils.log_info(f"  Global Networks: {len(global_networks)}")
    utils.log_info(f"  Sites: {len(all_sites)}")
    utils.log_info(f"  Links: {len(all_links)}")
    utils.log_info(f"  Devices: {len(all_devices)}")
    utils.log_info(f"  Connections: {len(all_connections)}")
    utils.log_info(f"  TGW Registrations: {len(all_tgw_registrations)}")
    utils.log_info(f"  CGW Associations: {len(all_cgw_associations)}")

    utils.log_success("Network Manager export completed successfully!")


def main():
    """Main execution function — 3-step state machine (region -> confirm -> export).

    Network Manager is a global service; region selection sets the API endpoint
    partition (us-west-2 for Commercial, us-gov-west-1 for GovCloud). A single
    region is selected and stored in the module-level home_region variable used
    by all collector functions.
    """
    global home_region

    try:
        account_id, account_name = utils.print_script_banner("AWS NETWORK MANAGER EXPORT")

        utils.log_info(f"Exporting Network Manager resources for account: {account_name} ({utils.mask_account_id(account_id)})")
        utils.log_info("Network Manager is a global service accessed through us-west-2.")

        step = 1
        regions = None

        while True:
            if step == 1:
                result = utils.prompt_region_selection(service_name="Network Manager")
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                regions = result
                # Network Manager is global — use the first selected region as the API endpoint
                home_region = regions[0]
                step = 2

            elif step == 2:
                msg = f"Ready to export Network Manager data (global service, endpoint: {home_region})."
                result = utils.prompt_confirmation(msg)
                if result == 'back':
                    step = 1
                    continue
                if result == 'exit':
                    sys.exit(11)
                step = 3

            elif step == 3:
                _run_export(account_id, account_name)
                break

    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        utils.log_error(f"Failed to export Network Manager resources: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

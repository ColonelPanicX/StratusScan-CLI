#!/usr/bin/env python3
"""
AWS Network Manager Export Script for StratusScan

Exports comprehensive AWS Network Manager information including:
- Global networks (SD-WAN and transit gateway management)
- Devices (physical or virtual network appliances)
- Links (internet connections from devices)
- Sites (physical locations)
- Transit gateway registrations
- Connect peer associations

Output: Multi-worksheet Excel file with Network Manager resources
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

try:
    import pandas as pd
except ImportError:
    print("Error: pandas is not installed. Please install it using 'pip install pandas'")
    sys.exit(1)


def check_dependencies():
    """Check if required dependencies are installed."""
    utils.log_info("Checking dependencies...")

    missing = []

    try:
        import pandas
        utils.log_info("✓ pandas is installed")
    except ImportError:
        missing.append("pandas")

    try:
        import openpyxl
        utils.log_info("✓ openpyxl is installed")
    except ImportError:
        missing.append("openpyxl")

    try:
        import boto3
        utils.log_info("✓ boto3 is installed")
    except ImportError:
        missing.append("boto3")

    if missing:
        utils.log_error(f"Missing dependencies: {', '.join(missing)}")
        utils.log_error("Please install using: pip install " + " ".join(missing))
        sys.exit(1)

    utils.log_success("All dependencies are installed")


@utils.aws_error_handler("Collecting global networks", default_return=[])
def collect_global_networks() -> List[Dict[str, Any]]:
    """Collect Network Manager global network information (global service)."""
    print("\n=== COLLECTING GLOBAL NETWORKS ===")
    all_networks = []
    # Network Manager is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    nm_client = utils.get_boto3_client('networkmanager', region_name=home_region)

    try:
        paginator = nm_client.get_paginator('describe_global_networks')
        for page in paginator.paginate():
            networks = page.get('GlobalNetworks', [])

            for network in networks:
                global_network_id = network.get('GlobalNetworkId', 'N/A')
                global_network_arn = network.get('GlobalNetworkArn', 'N/A')
                description = network.get('Description', 'N/A')
                created_at = network.get('CreatedAt', 'N/A')
                if created_at != 'N/A':
                    created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')

                state = network.get('State', 'N/A')

                # Get tags
                tags = network.get('Tags', [])
                tags_str = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags]) if tags else 'None'

                all_networks.append({
                    'Global Network ID': global_network_id,
                    'Description': description,
                    'State': state,
                    'Created': created_at,
                    'Tags': tags_str,
                    'ARN': global_network_arn
                })

    except Exception as e:
        utils.log_warning(f"Error listing global networks: {str(e)}")

    utils.log_success(f"Total global networks collected: {len(all_networks)}")
    return all_networks


@utils.aws_error_handler("Collecting devices", default_return=[])
def collect_devices(global_networks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collect device information for all global networks."""
    print("\n=== COLLECTING NETWORK DEVICES ===")
    all_devices = []
    home_region = utils.get_partition_default_region()
    nm_client = utils.get_boto3_client('networkmanager', region_name=home_region)

    for network in global_networks:
        global_network_id = network.get('Global Network ID', 'N/A')
        if global_network_id == 'N/A':
            continue

        try:
            paginator = nm_client.get_paginator('get_devices')
            for page in paginator.paginate(GlobalNetworkId=global_network_id):
                devices = page.get('Devices', [])

                for device in devices:
                    device_id = device.get('DeviceId', 'N/A')
                    device_arn = device.get('DeviceArn', 'N/A')
                    description = device.get('Description', 'N/A')
                    device_type = device.get('Type', 'N/A')
                    vendor = device.get('Vendor', 'N/A')
                    model = device.get('Model', 'N/A')
                    serial_number = device.get('SerialNumber', 'N/A')
                    site_id = device.get('SiteId', 'N/A')
                    created_at = device.get('CreatedAt', 'N/A')
                    if created_at != 'N/A':
                        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')

                    state = device.get('State', 'N/A')

                    # Location
                    location = device.get('Location', {})
                    address = location.get('Address', 'N/A')
                    latitude = location.get('Latitude', 'N/A')
                    longitude = location.get('Longitude', 'N/A')

                    all_devices.append({
                        'Global Network ID': global_network_id,
                        'Device ID': device_id,
                        'Description': description,
                        'Type': device_type,
                        'Vendor': vendor,
                        'Model': model,
                        'Serial Number': serial_number,
                        'Site ID': site_id,
                        'State': state,
                        'Address': address,
                        'Latitude': latitude,
                        'Longitude': longitude,
                        'Created': created_at,
                        'ARN': device_arn
                    })

        except Exception as e:
            utils.log_warning(f"Error listing devices for network {global_network_id}: {str(e)}")
            continue

    utils.log_success(f"Total devices collected: {len(all_devices)}")
    return all_devices


@utils.aws_error_handler("Collecting sites", default_return=[])
def collect_sites(global_networks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collect site information for all global networks."""
    print("\n=== COLLECTING SITES ===")
    all_sites = []
    home_region = utils.get_partition_default_region()
    nm_client = utils.get_boto3_client('networkmanager', region_name=home_region)

    for network in global_networks:
        global_network_id = network.get('Global Network ID', 'N/A')
        if global_network_id == 'N/A':
            continue

        try:
            paginator = nm_client.get_paginator('get_sites')
            for page in paginator.paginate(GlobalNetworkId=global_network_id):
                sites = page.get('Sites', [])

                for site in sites:
                    site_id = site.get('SiteId', 'N/A')
                    site_arn = site.get('SiteArn', 'N/A')
                    description = site.get('Description', 'N/A')
                    created_at = site.get('CreatedAt', 'N/A')
                    if created_at != 'N/A':
                        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')

                    state = site.get('State', 'N/A')

                    # Location
                    location = site.get('Location', {})
                    address = location.get('Address', 'N/A')
                    latitude = location.get('Latitude', 'N/A')
                    longitude = location.get('Longitude', 'N/A')

                    all_sites.append({
                        'Global Network ID': global_network_id,
                        'Site ID': site_id,
                        'Description': description,
                        'State': state,
                        'Address': address,
                        'Latitude': latitude,
                        'Longitude': longitude,
                        'Created': created_at,
                        'ARN': site_arn
                    })

        except Exception as e:
            utils.log_warning(f"Error listing sites for network {global_network_id}: {str(e)}")
            continue

    utils.log_success(f"Total sites collected: {len(all_sites)}")
    return all_sites


@utils.aws_error_handler("Collecting links", default_return=[])
def collect_links(global_networks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collect link information for all global networks."""
    print("\n=== COLLECTING LINKS ===")
    all_links = []
    home_region = utils.get_partition_default_region()
    nm_client = utils.get_boto3_client('networkmanager', region_name=home_region)

    for network in global_networks:
        global_network_id = network.get('Global Network ID', 'N/A')
        if global_network_id == 'N/A':
            continue

        try:
            paginator = nm_client.get_paginator('get_links')
            for page in paginator.paginate(GlobalNetworkId=global_network_id):
                links = page.get('Links', [])

                for link in links:
                    link_id = link.get('LinkId', 'N/A')
                    link_arn = link.get('LinkArn', 'N/A')
                    description = link.get('Description', 'N/A')
                    link_type = link.get('Type', 'N/A')
                    site_id = link.get('SiteId', 'N/A')
                    provider = link.get('Provider', 'N/A')
                    created_at = link.get('CreatedAt', 'N/A')
                    if created_at != 'N/A':
                        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')

                    state = link.get('State', 'N/A')

                    # Bandwidth
                    bandwidth = link.get('Bandwidth', {})
                    upload_speed = bandwidth.get('UploadSpeed', 'N/A')
                    download_speed = bandwidth.get('DownloadSpeed', 'N/A')

                    all_links.append({
                        'Global Network ID': global_network_id,
                        'Link ID': link_id,
                        'Description': description,
                        'Type': link_type,
                        'Site ID': site_id,
                        'Provider': provider,
                        'Upload Speed (Mbps)': upload_speed,
                        'Download Speed (Mbps)': download_speed,
                        'State': state,
                        'Created': created_at,
                        'ARN': link_arn
                    })

        except Exception as e:
            utils.log_warning(f"Error listing links for network {global_network_id}: {str(e)}")
            continue

    utils.log_success(f"Total links collected: {len(all_links)}")
    return all_links


def generate_summary(global_networks: List[Dict[str, Any]],
                     devices: List[Dict[str, Any]],
                     sites: List[Dict[str, Any]],
                     links: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Network Manager resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Global networks summary
    total_networks = len(global_networks)
    available_networks = sum(1 for n in global_networks if n.get('State', '') == 'AVAILABLE')

    summary.append({
        'Metric': 'Total Global Networks',
        'Count': total_networks,
        'Details': f'Available: {available_networks}'
    })

    # Devices summary
    summary.append({
        'Metric': 'Total Devices',
        'Count': len(devices),
        'Details': 'Network devices (physical or virtual appliances)'
    })

    # Sites summary
    summary.append({
        'Metric': 'Total Sites',
        'Count': len(sites),
        'Details': 'Physical network locations'
    })

    # Links summary
    summary.append({
        'Metric': 'Total Links',
        'Count': len(links),
        'Details': 'Internet connections from devices'
    })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    print("\n" + "="*60)
    print("AWS Network Manager Export Tool")
    print("="*60)

    # Check dependencies
    check_dependencies()

    # Get AWS account information
    account_id, account_name = utils.get_account_info()
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({account_id})")

    # Note: Network Manager is a global service
    print("\nNote: Network Manager is a global service (not region-specific)")
    print("Data will be collected from all global networks in your account.")

    # Collect data
    print("\nCollecting Network Manager data...")

    global_networks = collect_global_networks()
    devices = collect_devices(global_networks)
    sites = collect_sites(global_networks)
    links = collect_links(global_networks)
    summary = generate_summary(global_networks, devices, sites, links)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    if global_networks:
        df_networks = pd.DataFrame(global_networks)
        df_networks = utils.prepare_dataframe_for_export(df_networks)
        dataframes['Global Networks'] = df_networks

    if sites:
        df_sites = pd.DataFrame(sites)
        df_sites = utils.prepare_dataframe_for_export(df_sites)
        dataframes['Sites'] = df_sites

    if devices:
        df_devices = pd.DataFrame(devices)
        df_devices = utils.prepare_dataframe_for_export(df_devices)
        dataframes['Devices'] = df_devices

    if links:
        df_links = pd.DataFrame(links)
        df_links = utils.prepare_dataframe_for_export(df_links)
        dataframes['Links'] = df_links

    # Export to Excel
    if dataframes:
        filename = utils.create_export_filename(account_name, 'networkmanager', 'global')

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Global Networks': len(global_networks),
            'Sites': len(sites),
            'Devices': len(devices),
            'Links': len(links)
        })
    else:
        utils.log_warning("No Network Manager data found to export")

    utils.log_success("Network Manager export completed successfully")


if __name__ == "__main__":
    main()

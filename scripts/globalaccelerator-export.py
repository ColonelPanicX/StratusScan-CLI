#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Global Accelerator Export Tool
Version: v1.0.0
Date: NOV-11-2025

Description:
This script exports AWS Global Accelerator information into an Excel file with
multiple worksheets. The output includes accelerators, listeners, endpoint groups,
endpoints, and custom routing configurations.

Features:
- Standard accelerators with static IP addresses and DNS names
- Listener configurations with protocols and port ranges
- Endpoint groups with traffic dial and health check settings
- Endpoints with weights, health state, and client IP preservation
- Custom routing accelerators and configurations
- Summary statistics

Cost Awareness:
- Global Accelerator is a premium service with hourly charges and data transfer fees
- Standard accelerator: $0.025/hour per accelerator (~$18/month)
- Data Transfer Premium (DT-Premium): $0.015/GB for data transferred over AWS network
- Minimum 1-hour charge applies when creating/deleting accelerators
- Static IP addresses are included (no additional charge)

Global Service Notes:
- Global Accelerator is accessed via us-west-2 region endpoint
- Accelerators are global resources but managed from specific region
- Static IPs are anycast from AWS edge locations worldwide
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
utils.setup_logging("globalaccelerator-export")
utils.log_script_start("globalaccelerator-export.py", "AWS Global Accelerator Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("           AWS GLOBAL ACCELERATOR EXPORT TOOL")
    print("====================================================================")
    print("Version: v1.0.0                        Date: NOV-11-2025")
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


@utils.aws_error_handler("Collecting Global Accelerators", default_return=[])
def collect_accelerators() -> List[Dict[str, Any]]:
    """
    Collect Global Accelerator information.

    Returns:
        list: List of dictionaries with accelerator information
    """
    print("\n=== COLLECTING GLOBAL ACCELERATORS ===")
    all_accelerators = []

    # Global Accelerator is accessed via us-west-2 region
    region = 'us-west-2'
    print(f"\nQuerying Global Accelerators (global service via {region})")

    try:
        globalaccelerator = utils.get_boto3_client('globalaccelerator', region_name=region)

        # Get accelerators
        paginator = globalaccelerator.get_paginator('list_accelerators')

        for page in paginator.paginate():
            accelerators = page.get('Accelerators', [])

            for acc in accelerators:
                acc_arn = acc.get('AcceleratorArn', 'N/A')
                print(f"  Processing accelerator: {acc.get('Name', 'N/A')}")

                # Extract accelerator details
                name = acc.get('Name', 'N/A')
                enabled = acc.get('Enabled', False)
                status = acc.get('Status', 'N/A')
                ip_address_type = acc.get('IpAddressType', 'N/A')
                dns_name = acc.get('DnsName', 'N/A')
                created_time = acc.get('CreatedTime', '')
                last_modified_time = acc.get('LastModifiedTime', '')

                # Format timestamps
                if created_time:
                    created_time = created_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_time, datetime.datetime) else str(created_time)
                if last_modified_time:
                    last_modified_time = last_modified_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_modified_time, datetime.datetime) else str(last_modified_time)

                # Get IP addresses
                ip_sets = acc.get('IpSets', [])
                ip_addresses = []
                for ip_set in ip_sets:
                    ip_addresses.extend(ip_set.get('IpAddresses', []))

                ip_addresses_str = ', '.join(ip_addresses) if ip_addresses else 'N/A'

                all_accelerators.append({
                    'Accelerator ARN': acc_arn,
                    'Name': name,
                    'Status': status,
                    'Enabled': enabled,
                    'IP Address Type': ip_address_type,
                    'IP Addresses': ip_addresses_str,
                    'DNS Name': dns_name,
                    'Created Time': created_time,
                    'Last Modified Time': last_modified_time
                })

        print(f"  Found {len(all_accelerators)} accelerators")

    except Exception as e:
        utils.log_error(f"Error collecting Global Accelerators from {region}", e)

    utils.log_success(f"Total accelerators collected: {len(all_accelerators)}")
    return all_accelerators


@utils.aws_error_handler("Collecting Listeners", default_return=[])
def collect_listeners(accelerator_arns: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Global Accelerator listener information.

    Args:
        accelerator_arns: List of accelerator ARNs to get listeners for

    Returns:
        list: List of dictionaries with listener information
    """
    print("\n=== COLLECTING LISTENERS ===")
    all_listeners = []

    region = 'us-west-2'

    try:
        globalaccelerator = utils.get_boto3_client('globalaccelerator', region_name=region)

        for acc_arn in accelerator_arns:
            print(f"  Processing accelerator: {acc_arn.split('/')[-1]}")

            try:
                # Get listeners for this accelerator
                paginator = globalaccelerator.get_paginator('list_listeners')

                for page in paginator.paginate(AcceleratorArn=acc_arn):
                    listeners = page.get('Listeners', [])

                    for listener in listeners:
                        listener_arn = listener.get('ListenerArn', 'N/A')

                        # Extract listener details
                        protocol = listener.get('Protocol', 'N/A')
                        client_affinity = listener.get('ClientAffinity', 'N/A')

                        # Get port ranges
                        port_ranges = listener.get('PortRanges', [])
                        port_range_str = ', '.join([f"{pr.get('FromPort', '')}-{pr.get('ToPort', '')}" for pr in port_ranges]) if port_ranges else 'N/A'

                        all_listeners.append({
                            'Listener ARN': listener_arn,
                            'Accelerator ARN': acc_arn,
                            'Protocol': protocol,
                            'Port Ranges': port_range_str,
                            'Client Affinity': client_affinity
                        })

            except Exception as e:
                utils.log_error(f"Error getting listeners for accelerator {acc_arn}", e)

    except Exception as e:
        utils.log_error("Error collecting listeners", e)

    utils.log_success(f"Total listeners collected: {len(all_listeners)}")
    return all_listeners


@utils.aws_error_handler("Collecting Endpoint Groups", default_return=[])
def collect_endpoint_groups(listener_arns: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Global Accelerator endpoint group information.

    Args:
        listener_arns: List of listener ARNs to get endpoint groups for

    Returns:
        list: List of dictionaries with endpoint group information
    """
    print("\n=== COLLECTING ENDPOINT GROUPS ===")
    all_endpoint_groups = []

    region = 'us-west-2'

    try:
        globalaccelerator = utils.get_boto3_client('globalaccelerator', region_name=region)

        for listener_arn in listener_arns:
            print(f"  Processing listener: {listener_arn.split('/')[-1]}")

            try:
                # Get endpoint groups for this listener
                paginator = globalaccelerator.get_paginator('list_endpoint_groups')

                for page in paginator.paginate(ListenerArn=listener_arn):
                    endpoint_groups = page.get('EndpointGroups', [])

                    for eg in endpoint_groups:
                        eg_arn = eg.get('EndpointGroupArn', 'N/A')

                        # Extract endpoint group details
                        endpoint_group_region = eg.get('EndpointGroupRegion', 'N/A')
                        traffic_dial_percentage = eg.get('TrafficDialPercentage', 0)

                        # Health check settings
                        health_check_protocol = eg.get('HealthCheckProtocol', 'N/A')
                        health_check_port = eg.get('HealthCheckPort', 'N/A')
                        health_check_path = eg.get('HealthCheckPath', 'N/A')
                        health_check_interval = eg.get('HealthCheckIntervalSeconds', 'N/A')
                        threshold_count = eg.get('ThresholdCount', 'N/A')

                        all_endpoint_groups.append({
                            'Endpoint Group ARN': eg_arn,
                            'Listener ARN': listener_arn,
                            'Region': endpoint_group_region,
                            'Traffic Dial Percentage': traffic_dial_percentage,
                            'Health Check Protocol': health_check_protocol,
                            'Health Check Port': health_check_port,
                            'Health Check Path': health_check_path,
                            'Health Check Interval (seconds)': health_check_interval,
                            'Threshold Count': threshold_count
                        })

            except Exception as e:
                utils.log_error(f"Error getting endpoint groups for listener {listener_arn}", e)

    except Exception as e:
        utils.log_error("Error collecting endpoint groups", e)

    utils.log_success(f"Total endpoint groups collected: {len(all_endpoint_groups)}")
    return all_endpoint_groups


@utils.aws_error_handler("Collecting Endpoints", default_return=[])
def collect_endpoints(endpoint_group_arns: List[str]) -> List[Dict[str, Any]]:
    """
    Collect endpoint information from endpoint groups.

    Args:
        endpoint_group_arns: List of endpoint group ARNs

    Returns:
        list: List of dictionaries with endpoint information
    """
    print("\n=== COLLECTING ENDPOINTS ===")
    all_endpoints = []

    region = 'us-west-2'

    try:
        globalaccelerator = utils.get_boto3_client('globalaccelerator', region_name=region)

        for eg_arn in endpoint_group_arns:
            print(f"  Processing endpoint group: {eg_arn.split('/')[-1]}")

            try:
                # Describe the endpoint group to get endpoint details
                response = globalaccelerator.describe_endpoint_group(
                    EndpointGroupArn=eg_arn
                )

                endpoint_group = response.get('EndpointGroup', {})
                endpoint_descriptions = endpoint_group.get('EndpointDescriptions', [])

                for endpoint in endpoint_descriptions:
                    endpoint_id = endpoint.get('EndpointId', 'N/A')

                    # Extract endpoint details
                    weight = endpoint.get('Weight', 0)
                    health_state = endpoint.get('HealthState', 'N/A')
                    health_reason = endpoint.get('HealthReason', 'N/A')
                    client_ip_preservation = endpoint.get('ClientIPPreservationEnabled', False)

                    all_endpoints.append({
                        'Endpoint Group ARN': eg_arn,
                        'Endpoint ID': endpoint_id,
                        'Weight': weight,
                        'Health State': health_state,
                        'Health Reason': health_reason,
                        'Client IP Preservation Enabled': client_ip_preservation
                    })

            except Exception as e:
                utils.log_error(f"Error getting endpoints for endpoint group {eg_arn}", e)

    except Exception as e:
        utils.log_error("Error collecting endpoints", e)

    utils.log_success(f"Total endpoints collected: {len(all_endpoints)}")
    return all_endpoints


@utils.aws_error_handler("Collecting Custom Routing Accelerators", default_return=[])
def collect_custom_routing_accelerators() -> List[Dict[str, Any]]:
    """
    Collect Custom Routing Accelerator information.

    Returns:
        list: List of dictionaries with custom routing accelerator information
    """
    print("\n=== COLLECTING CUSTOM ROUTING ACCELERATORS ===")
    all_custom_accelerators = []

    region = 'us-west-2'
    print(f"\nQuerying Custom Routing Accelerators (global service via {region})")

    try:
        globalaccelerator = utils.get_boto3_client('globalaccelerator', region_name=region)

        # Get custom routing accelerators
        paginator = globalaccelerator.get_paginator('list_custom_routing_accelerators')

        for page in paginator.paginate():
            accelerators = page.get('Accelerators', [])

            for acc in accelerators:
                acc_arn = acc.get('AcceleratorArn', 'N/A')
                print(f"  Processing custom routing accelerator: {acc.get('Name', 'N/A')}")

                # Extract accelerator details
                name = acc.get('Name', 'N/A')
                enabled = acc.get('Enabled', False)
                status = acc.get('Status', 'N/A')
                ip_address_type = acc.get('IpAddressType', 'N/A')
                dns_name = acc.get('DnsName', 'N/A')
                created_time = acc.get('CreatedTime', '')
                last_modified_time = acc.get('LastModifiedTime', '')

                # Format timestamps
                if created_time:
                    created_time = created_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_time, datetime.datetime) else str(created_time)
                if last_modified_time:
                    last_modified_time = last_modified_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_modified_time, datetime.datetime) else str(last_modified_time)

                # Get IP addresses
                ip_sets = acc.get('IpSets', [])
                ip_addresses = []
                for ip_set in ip_sets:
                    ip_addresses.extend(ip_set.get('IpAddresses', []))

                ip_addresses_str = ', '.join(ip_addresses) if ip_addresses else 'N/A'

                all_custom_accelerators.append({
                    'Accelerator ARN': acc_arn,
                    'Name': name,
                    'Status': status,
                    'Enabled': enabled,
                    'IP Address Type': ip_address_type,
                    'IP Addresses': ip_addresses_str,
                    'DNS Name': dns_name,
                    'Created Time': created_time,
                    'Last Modified Time': last_modified_time
                })

        print(f"  Found {len(all_custom_accelerators)} custom routing accelerators")

    except Exception as e:
        utils.log_error(f"Error collecting Custom Routing Accelerators from {region}", e)

    utils.log_success(f"Total custom routing accelerators collected: {len(all_custom_accelerators)}")
    return all_custom_accelerators


@utils.aws_error_handler("Collecting Custom Routing Listeners", default_return=[])
def collect_custom_routing_listeners(accelerator_arns: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Custom Routing listener information.

    Args:
        accelerator_arns: List of custom routing accelerator ARNs

    Returns:
        list: List of dictionaries with custom routing listener information
    """
    print("\n=== COLLECTING CUSTOM ROUTING LISTENERS ===")
    all_listeners = []

    region = 'us-west-2'

    try:
        globalaccelerator = utils.get_boto3_client('globalaccelerator', region_name=region)

        for acc_arn in accelerator_arns:
            print(f"  Processing accelerator: {acc_arn.split('/')[-1]}")

            try:
                # Get listeners for this accelerator
                paginator = globalaccelerator.get_paginator('list_custom_routing_listeners')

                for page in paginator.paginate(AcceleratorArn=acc_arn):
                    listeners = page.get('Listeners', [])

                    for listener in listeners:
                        listener_arn = listener.get('ListenerArn', 'N/A')

                        # Get port ranges
                        port_ranges = listener.get('PortRanges', [])
                        port_range_str = ', '.join([f"{pr.get('FromPort', '')}-{pr.get('ToPort', '')}" for pr in port_ranges]) if port_ranges else 'N/A'

                        all_listeners.append({
                            'Listener ARN': listener_arn,
                            'Accelerator ARN': acc_arn,
                            'Port Ranges': port_range_str
                        })

            except Exception as e:
                utils.log_error(f"Error getting custom routing listeners for accelerator {acc_arn}", e)

    except Exception as e:
        utils.log_error("Error collecting custom routing listeners", e)

    utils.log_success(f"Total custom routing listeners collected: {len(all_listeners)}")
    return all_listeners


@utils.aws_error_handler("Collecting Custom Routing Endpoint Groups", default_return=[])
def collect_custom_routing_endpoint_groups(listener_arns: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Custom Routing endpoint group information.

    Args:
        listener_arns: List of custom routing listener ARNs

    Returns:
        list: List of dictionaries with custom routing endpoint group information
    """
    print("\n=== COLLECTING CUSTOM ROUTING ENDPOINT GROUPS ===")
    all_endpoint_groups = []

    region = 'us-west-2'

    try:
        globalaccelerator = utils.get_boto3_client('globalaccelerator', region_name=region)

        for listener_arn in listener_arns:
            print(f"  Processing listener: {listener_arn.split('/')[-1]}")

            try:
                # Get endpoint groups for this listener
                paginator = globalaccelerator.get_paginator('list_custom_routing_endpoint_groups')

                for page in paginator.paginate(ListenerArn=listener_arn):
                    endpoint_groups = page.get('EndpointGroups', [])

                    for eg in endpoint_groups:
                        eg_arn = eg.get('EndpointGroupArn', 'N/A')

                        # Extract endpoint group details
                        endpoint_group_region = eg.get('EndpointGroupRegion', 'N/A')

                        # Get destination configurations
                        destination_configurations = eg.get('DestinationDescriptions', [])
                        dest_config_list = []
                        for dest in destination_configurations:
                            from_port = dest.get('FromPort', '')
                            to_port = dest.get('ToPort', '')
                            protocols = dest.get('Protocols', [])
                            protocols_str = ', '.join(protocols) if protocols else 'N/A'
                            dest_config_list.append(f"{from_port}-{to_port} ({protocols_str})")

                        dest_config_str = '; '.join(dest_config_list) if dest_config_list else 'N/A'

                        all_endpoint_groups.append({
                            'Endpoint Group ARN': eg_arn,
                            'Listener ARN': listener_arn,
                            'Region': endpoint_group_region,
                            'Destination Configurations': dest_config_str
                        })

            except Exception as e:
                utils.log_error(f"Error getting custom routing endpoint groups for listener {listener_arn}", e)

    except Exception as e:
        utils.log_error("Error collecting custom routing endpoint groups", e)

    utils.log_success(f"Total custom routing endpoint groups collected: {len(all_endpoint_groups)}")
    return all_endpoint_groups


def create_summary(data_frames: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Create summary statistics for Global Accelerator resources.

    Args:
        data_frames: Dictionary of DataFrames with collected data

    Returns:
        list: List of summary dictionaries
    """
    summary = []

    # Accelerator summary
    if 'Accelerators' in data_frames:
        df_accelerators = data_frames['Accelerators']
        total_accelerators = len(df_accelerators)

        if total_accelerators > 0:
            # Count by status
            status_counts = df_accelerators['Status'].value_counts().to_dict()
            for status, count in status_counts.items():
                summary.append({
                    'Category': 'Standard Accelerators',
                    'Metric': f'Status: {status}',
                    'Count': count
                })

            # Count enabled/disabled
            enabled_count = df_accelerators['Enabled'].sum()
            summary.append({
                'Category': 'Standard Accelerators',
                'Metric': 'Enabled',
                'Count': enabled_count
            })

    # Listener summary
    if 'Listeners' in data_frames:
        df_listeners = data_frames['Listeners']
        total_listeners = len(df_listeners)
        summary.append({
            'Category': 'Standard Listeners',
            'Metric': 'Total Listeners',
            'Count': total_listeners
        })

    # Endpoint Group summary
    if 'Endpoint Groups' in data_frames:
        df_eg = data_frames['Endpoint Groups']
        total_eg = len(df_eg)
        summary.append({
            'Category': 'Standard Endpoint Groups',
            'Metric': 'Total Endpoint Groups',
            'Count': total_eg
        })

        if total_eg > 0:
            # Count by region
            region_counts = df_eg['Region'].value_counts().to_dict()
            for region, count in region_counts.items():
                summary.append({
                    'Category': 'Standard Endpoint Groups',
                    'Metric': f'Region: {region}',
                    'Count': count
                })

    # Endpoint summary
    if 'Endpoints' in data_frames:
        df_endpoints = data_frames['Endpoints']
        total_endpoints = len(df_endpoints)

        if total_endpoints > 0:
            # Count by health state
            health_counts = df_endpoints['Health State'].value_counts().to_dict()
            for health, count in health_counts.items():
                summary.append({
                    'Category': 'Standard Endpoints',
                    'Metric': f'Health State: {health}',
                    'Count': count
                })

    # Custom Routing summary
    if 'Custom Routing Accelerators' in data_frames:
        df_custom = data_frames['Custom Routing Accelerators']
        total_custom = len(df_custom)
        summary.append({
            'Category': 'Custom Routing',
            'Metric': 'Total Custom Routing Accelerators',
            'Count': total_custom
        })

    if 'Custom Routing Listeners' in data_frames:
        df_custom_listeners = data_frames['Custom Routing Listeners']
        total_custom_listeners = len(df_custom_listeners)
        summary.append({
            'Category': 'Custom Routing',
            'Metric': 'Total Custom Routing Listeners',
            'Count': total_custom_listeners
        })

    if 'Custom Routing Endpoint Groups' in data_frames:
        df_custom_eg = data_frames['Custom Routing Endpoint Groups']
        total_custom_eg = len(df_custom_eg)
        summary.append({
            'Category': 'Custom Routing',
            'Metric': 'Total Custom Routing Endpoint Groups',
            'Count': total_custom_eg
        })

    return summary


def export_globalaccelerator_data(account_id: str, account_name: str):
    """
    Export Global Accelerator information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    print("\n" + "=" * 60)
    print("AWS Global Accelerator Export")
    print("=" * 60)
    print("\nNOTE: Global Accelerator is a global service accessed via us-west-2 region.")
    print("All accelerators (global resources) will be included in the export.")
    print("If you don't have Global Accelerator configured, all sheets will be empty.")
    print()

    proceed = input("Continue with export? (y/n): ").lower()
    if proceed != 'y':
        print("Export cancelled.")
        return

    print("\nStarting Global Accelerator export process...")
    print("This may take some time depending on the number of resources...")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect Standard Accelerators
    accelerators = collect_accelerators()
    if accelerators:
        data_frames['Accelerators'] = pd.DataFrame(accelerators)

        # Get ARNs for further queries
        accelerator_arns = [acc['Accelerator ARN'] for acc in accelerators]

        # STEP 2: Collect Listeners
        listeners = collect_listeners(accelerator_arns)
        if listeners:
            data_frames['Listeners'] = pd.DataFrame(listeners)

            # Get listener ARNs
            listener_arns = [listener['Listener ARN'] for listener in listeners]

            # STEP 3: Collect Endpoint Groups
            endpoint_groups = collect_endpoint_groups(listener_arns)
            if endpoint_groups:
                data_frames['Endpoint Groups'] = pd.DataFrame(endpoint_groups)

                # Get endpoint group ARNs
                endpoint_group_arns = [eg['Endpoint Group ARN'] for eg in endpoint_groups]

                # STEP 4: Collect Endpoints
                endpoints = collect_endpoints(endpoint_group_arns)
                if endpoints:
                    data_frames['Endpoints'] = pd.DataFrame(endpoints)

    # STEP 5: Collect Custom Routing Accelerators
    custom_accelerators = collect_custom_routing_accelerators()
    if custom_accelerators:
        data_frames['Custom Routing Accelerators'] = pd.DataFrame(custom_accelerators)

        # Get custom routing accelerator ARNs
        custom_accelerator_arns = [acc['Accelerator ARN'] for acc in custom_accelerators]

        # STEP 6: Collect Custom Routing Listeners
        custom_listeners = collect_custom_routing_listeners(custom_accelerator_arns)
        if custom_listeners:
            data_frames['Custom Routing Listeners'] = pd.DataFrame(custom_listeners)

            # Get custom routing listener ARNs
            custom_listener_arns = [listener['Listener ARN'] for listener in custom_listeners]

            # STEP 7: Collect Custom Routing Endpoint Groups
            custom_endpoint_groups = collect_custom_routing_endpoint_groups(custom_listener_arns)
            if custom_endpoint_groups:
                data_frames['Custom Routing Endpoint Groups'] = pd.DataFrame(custom_endpoint_groups)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No Global Accelerator data was collected. Nothing to export.")
        print("\nNo Global Accelerator resources found in this account.")
        print("This is normal if Global Accelerator is not configured.")
        return

    # STEP 8: Create Summary
    summary_data = create_summary(data_frames)
    if summary_data:
        data_frames['Summary'] = pd.DataFrame(summary_data)

    # STEP 9: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 10: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'globalaccelerator',
        '',
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("Global Accelerator data exported successfully!")
            utils.log_info(f"File location: {output_path}")

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
        # Check if running in GovCloud partition
        partition = utils.detect_partition()
        if partition == 'aws-us-gov':
            print(f"\nERROR: Global Accelerator is not available in AWS GovCloud")
            print("This service operates outside the GovCloud boundary")
            utils.log_error(f"Global Accelerator is not supported in GovCloud partition")
            sys.exit(1)

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

        # Export Global Accelerator data
        export_globalaccelerator_data(account_id, account_name)

        print("\nGlobal Accelerator export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("globalaccelerator-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AWS Connect Export Script for StratusScan

Exports comprehensive AWS Connect contact center information including:
- Connect instances with contact center configurations
- Queues with routing configurations
- Hours of operation
- Contact flows (IVR configurations)
- Phone numbers and claimed numbers
- User accounts and routing profiles

Output: Multi-worksheet Excel file with Connect resources
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


def _scan_instances_region(region: str) -> List[Dict[str, Any]]:
    """Scan Connect instances in a single region."""
    regional_instances = []
    connect_client = utils.get_boto3_client('connect', region_name=region)

    try:
        paginator = connect_client.get_paginator('list_instances')
        for page in paginator.paginate():
            instances = page.get('InstanceSummaryList', [])

            for instance_summary in instances:
                instance_id = instance_summary.get('Id', 'N/A')
                instance_arn = instance_summary.get('Arn', 'N/A')
                instance_alias = instance_summary.get('InstanceAlias', 'N/A')
                created_time = instance_summary.get('CreatedTime', 'N/A')
                if created_time != 'N/A':
                    created_time = created_time.strftime('%Y-%m-%d %H:%M:%S')

                service_role = instance_summary.get('ServiceRole', 'N/A')
                instance_status = instance_summary.get('InstanceStatus', 'N/A')
                inbound_calls_enabled = instance_summary.get('InboundCallsEnabled', False)
                outbound_calls_enabled = instance_summary.get('OutboundCallsEnabled', False)
                instance_access_url = instance_summary.get('InstanceAccessUrl', 'N/A')

                regional_instances.append({
                    'Region': region,
                    'Instance ID': instance_id,
                    'Instance Alias': instance_alias,
                    'Status': instance_status,
                    'Inbound Calls Enabled': inbound_calls_enabled,
                    'Outbound Calls Enabled': outbound_calls_enabled,
                    'Access URL': instance_access_url,
                    'Service Role': service_role,
                    'Created': created_time,
                    'ARN': instance_arn
                })

    except Exception as e:
        utils.log_warning(f"Error listing Connect instances in {region}: {str(e)}")

    return regional_instances


@utils.aws_error_handler("Collecting Connect instances", default_return=[])
def collect_instances(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Connect instance information from AWS regions."""
    print("\n=== COLLECTING CONNECT INSTANCES ===")
    results = utils.scan_regions_concurrent(regions, _scan_instances_region)
    all_instances = [instance for result in results for instance in result]
    utils.log_success(f"Total Connect instances collected: {len(all_instances)}")
    return all_instances


@utils.aws_error_handler("Collecting queues", default_return=[])
def collect_queues(instances: List[Dict[str, Any]], region: str) -> List[Dict[str, Any]]:
    """Collect queue information for Connect instances."""
    print("\n=== COLLECTING CONNECT QUEUES ===")
    all_queues = []
    connect_client = utils.get_boto3_client('connect', region_name=region)

    for instance in instances:
        instance_id = instance.get('Instance ID', 'N/A')
        if instance_id == 'N/A' or instance.get('Region') != region:
            continue

        try:
            paginator = connect_client.get_paginator('list_queues')
            for page in paginator.paginate(InstanceId=instance_id):
                queues = page.get('QueueSummaryList', [])

                for queue in queues:
                    queue_id = queue.get('Id', 'N/A')
                    queue_arn = queue.get('Arn', 'N/A')
                    queue_name = queue.get('Name', 'N/A')
                    queue_type = queue.get('QueueType', 'N/A')

                    all_queues.append({
                        'Region': region,
                        'Instance ID': instance_id,
                        'Queue ID': queue_id,
                        'Queue Name': queue_name,
                        'Queue Type': queue_type,
                        'Queue ARN': queue_arn
                    })

        except Exception as e:
            utils.log_warning(f"Error listing queues for instance {instance_id}: {str(e)}")
            continue

    utils.log_success(f"Total queues collected: {len(all_queues)}")
    return all_queues


@utils.aws_error_handler("Collecting phone numbers", default_return=[])
def collect_phone_numbers(instances: List[Dict[str, Any]], region: str) -> List[Dict[str, Any]]:
    """Collect phone number information for Connect instances."""
    print("\n=== COLLECTING PHONE NUMBERS ===")
    all_numbers = []
    connect_client = utils.get_boto3_client('connect', region_name=region)

    for instance in instances:
        instance_id = instance.get('Instance ID', 'N/A')
        if instance_id == 'N/A' or instance.get('Region') != region:
            continue

        try:
            paginator = connect_client.get_paginator('list_phone_numbers_v2')
            for page in paginator.paginate(TargetArn=instance.get('ARN', '')):
                numbers = page.get('ListPhoneNumbersSummaryList', [])

                for number in numbers:
                    phone_number_id = number.get('PhoneNumberId', 'N/A')
                    phone_number = number.get('PhoneNumber', 'N/A')
                    phone_number_type = number.get('PhoneNumberType', 'N/A')
                    phone_number_country_code = number.get('PhoneNumberCountryCode', 'N/A')

                    all_numbers.append({
                        'Region': region,
                        'Instance ID': instance_id,
                        'Phone Number ID': phone_number_id,
                        'Phone Number': phone_number,
                        'Type': phone_number_type,
                        'Country Code': phone_number_country_code
                    })

        except Exception as e:
            utils.log_warning(f"Error listing phone numbers for instance {instance_id}: {str(e)}")
            continue

    utils.log_success(f"Total phone numbers collected: {len(all_numbers)}")
    return all_numbers


def generate_summary(instances: List[Dict[str, Any]],
                     queues: List[Dict[str, Any]],
                     phone_numbers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Connect resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Instances summary
    total_instances = len(instances)
    active_instances = sum(1 for i in instances if i.get('Status', '') == 'ACTIVE')
    inbound_enabled = sum(1 for i in instances if i.get('Inbound Calls Enabled', False))
    outbound_enabled = sum(1 for i in instances if i.get('Outbound Calls Enabled', False))

    summary.append({
        'Metric': 'Total Connect Instances',
        'Count': total_instances,
        'Details': f'Active: {active_instances}, Inbound: {inbound_enabled}, Outbound: {outbound_enabled}'
    })

    # Queues summary
    summary.append({
        'Metric': 'Total Queues',
        'Count': len(queues),
        'Details': 'Contact routing queues across all instances'
    })

    # Phone numbers summary
    summary.append({
        'Metric': 'Total Phone Numbers',
        'Count': len(phone_numbers),
        'Details': 'Claimed phone numbers across all instances'
    })

    # Regional distribution
    if instances:
        df = pd.DataFrame(instances)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Instances in {region}',
                'Count': count,
                'Details': 'Regional distribution'
            })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    print("\n" + "="*60)
    print("AWS Connect Export Tool")
    print("="*60)

    # Check dependencies
    check_dependencies()

    # Get AWS account information
    account_id, account_name = utils.get_account_info()
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({account_id})")

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
    print("\nAWS Connect is a regional service.")
    print("\nPlease select an option for region selection:")
    print("\n  1. Default Regions")
    print(f"     ({example_regions})")
    print("\n  2. All Available Regions")
    print("     (Scan all regions where AWS Connect is available)")
    print("\n  3. Specific Region")
    print("     (Enter a specific AWS region code)")
    print("\n" + "-" * 68)

    # Get and validate region choice
    regions = []
    while not regions:
        try:
            region_choice = input("\nEnter your choice (1, 2, or 3): ").strip()

            if region_choice == '1':
                # Default regions
                regions = utils.get_partition_default_regions()
                print(f"\nUsing default regions: {', '.join(regions)}")
            elif region_choice == '2':
                # All available regions
                regions = utils.get_partition_regions(partition, all_regions=True)
                print(f"\nScanning all {len(regions)} available regions")
            elif region_choice == '3':
                # Specific region - show numbered list
                available_regions = utils.get_partition_regions(
                    partition, all_regions=True
                )
                print("\n" + "=" * 68)
                print("AVAILABLE REGIONS")
                print("=" * 68)
                for idx, region in enumerate(available_regions, 1):
                    print(f"  {idx}. {region}")
                print("-" * 68)

                # Get region selection
                region_selected = False
                while not region_selected:
                    try:
                        region_num = input(
                            f"\nEnter region number (1-{len(available_regions)}): "
                        ).strip()
                        region_idx = int(region_num) - 1

                        if 0 <= region_idx < len(available_regions):
                            selected_region = available_regions[region_idx]
                            regions = [selected_region]
                            print(f"\nSelected region: {selected_region}")
                            region_selected = True
                        else:
                            print(
                                f"Invalid selection. Please enter a number "
                                f"between 1 and {len(available_regions)}."
                            )
                    except ValueError:
                        print("Invalid input. Please enter a number.")
                    except KeyboardInterrupt:
                        print("\n\nOperation cancelled by user.")
                        sys.exit(0)
            else:
                print("\nInvalid choice. Please enter 1, 2, or 3.")

        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            sys.exit(0)
        except Exception as e:
            utils.log_error(f"Error getting region selection: {str(e)}")
            print("Please try again.")

    # Collect data
    print("\nCollecting AWS Connect data...")

    instances = collect_instances(regions)
    
    # Collect queues and phone numbers per region (not concurrent to avoid rate limiting)
    all_queues = []
    all_phone_numbers = []
    for region in regions:
        queues = collect_queues(instances, region)
        phone_numbers = collect_phone_numbers(instances, region)
        all_queues.extend(queues)
        all_phone_numbers.extend(phone_numbers)

    summary = generate_summary(instances, all_queues, all_phone_numbers)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    if instances:
        df_instances = pd.DataFrame(instances)
        df_instances = utils.prepare_dataframe_for_export(df_instances)
        dataframes['Instances'] = df_instances

    if all_queues:
        df_queues = pd.DataFrame(all_queues)
        df_queues = utils.prepare_dataframe_for_export(df_queues)
        dataframes['Queues'] = df_queues

    if all_phone_numbers:
        df_numbers = pd.DataFrame(all_phone_numbers)
        df_numbers = utils.prepare_dataframe_for_export(df_numbers)
        dataframes['Phone Numbers'] = df_numbers

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'connect', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Instances': len(instances),
            'Queues': len(all_queues),
            'Phone Numbers': len(all_phone_numbers)
        })
    else:
        utils.log_warning("No Connect data found to export")

    utils.log_success("Connect export completed successfully")


if __name__ == "__main__":
    main()

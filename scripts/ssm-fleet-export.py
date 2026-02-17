#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Systems Manager Fleet Export Tool
Version: v0.1.0
Date: NOV-09-2025

Description:
This script exports AWS Systems Manager (SSM) Fleet Manager information into an
Excel file with multiple worksheets. The output includes managed instances,
patch compliance, inventory, and parameters.

Features:
- Managed instances with agent status and platform details
- Patch compliance status for instances
- SSM parameters (SecureString values are masked)
- Parameter Store hierarchy and metadata
- Compliance summary by instance
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
utils.setup_logging("ssm-fleet-export")
utils.log_script_start("ssm-fleet-export.py", "AWS Systems Manager Fleet Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("         AWS SYSTEMS MANAGER FLEET EXPORT TOOL")
    print("====================================================================")
    print("Version: v0.1.0                        Date: NOV-09-2025")
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


def _scan_managed_instances_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for SSM managed instances."""
    instances_data = []

    if not utils.validate_aws_region(region):
        return instances_data

    try:
        ssm_client = utils.get_boto3_client('ssm', region_name=region)

        paginator = ssm_client.get_paginator('describe_instance_information')
        for page in paginator.paginate():
            instances = page.get('InstanceInformationList', [])

            for instance in instances:
                instance_id = instance.get('InstanceId', 'N/A')

                # Instance details
                ping_status = instance.get('PingStatus', 'Unknown')
                last_ping_time = instance.get('LastPingDateTime', '')
                if last_ping_time:
                    last_ping_time = last_ping_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_ping_time, datetime.datetime) else str(last_ping_time)

                # Platform
                platform_type = instance.get('PlatformType', 'N/A')
                platform_name = instance.get('PlatformName', 'N/A')
                platform_version = instance.get('PlatformVersion', 'N/A')

                # Agent version
                agent_version = instance.get('AgentVersion', 'N/A')

                # IP address
                ip_address = instance.get('IPAddress', 'N/A')

                # Computer name
                computer_name = instance.get('ComputerName', 'N/A')

                # Association status
                association_status = instance.get('AssociationStatus', 'Unknown')

                # Last successful association
                last_association = instance.get('LastSuccessfulAssociationExecutionDate', '')
                if last_association:
                    last_association = last_association.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_association, datetime.datetime) else str(last_association)

                # Last association execution
                last_assoc_exec = instance.get('LastAssociationExecutionDate', '')
                if last_assoc_exec:
                    last_assoc_exec = last_assoc_exec.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_assoc_exec, datetime.datetime) else str(last_assoc_exec)

                # Activation ID (for on-prem instances)
                activation_id = instance.get('ActivationId', 'N/A')

                # IAM role
                iam_role = instance.get('IamRole', 'N/A')

                # Registration date
                registration_date = instance.get('RegistrationDate', '')
                if registration_date:
                    registration_date = registration_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(registration_date, datetime.datetime) else str(registration_date)

                instances_data.append({
                    'Region': region,
                    'Instance ID': instance_id,
                    'Ping Status': ping_status,
                    'Last Ping': last_ping_time if last_ping_time else 'Never',
                    'Platform Type': platform_type,
                    'Platform Name': platform_name,
                    'Platform Version': platform_version,
                    'Agent Version': agent_version,
                    'IP Address': ip_address,
                    'Computer Name': computer_name,
                    'Association Status': association_status,
                    'Last Successful Association': last_association if last_association else 'N/A',
                    'Last Association Execution': last_assoc_exec if last_assoc_exec else 'N/A',
                    'Activation ID': activation_id,
                    'IAM Role': iam_role,
                    'Registration Date': registration_date if registration_date else 'N/A'
                })

    except Exception as e:
        utils.log_error(f"Error collecting managed instances in {region}", e)

    return instances_data


@utils.aws_error_handler("Collecting SSM managed instances", default_return=[])
def collect_managed_instances(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect SSM managed instance information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with managed instance information
    """
    print("\n=== COLLECTING SSM MANAGED INSTANCES ===")
    results = utils.scan_regions_concurrent(regions, _scan_managed_instances_region)
    all_instances = [instance for result in results for instance in result]
    utils.log_success(f"Total SSM managed instances collected: {len(all_instances)}")
    return all_instances


def _scan_patch_compliance_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for SSM patch compliance."""
    compliance_data = []

    if not utils.validate_aws_region(region):
        return compliance_data

    try:
        ssm_client = utils.get_boto3_client('ssm', region_name=region)

        # Get instances first
        instances_response = ssm_client.describe_instance_information()
        instances = instances_response.get('InstanceInformationList', [])

        for instance in instances:
            instance_id = instance.get('InstanceId', '')

            try:
                # Get patch compliance for this instance
                compliance_response = ssm_client.list_compliance_items(
                    ResourceIds=[instance_id],
                    Filters=[
                        {
                            'Key': 'ComplianceType',
                            'Values': ['Patch'],
                            'Type': 'EQUAL'
                        }
                    ]
                )

                compliance_items = compliance_response.get('ComplianceItems', [])

                if compliance_items:
                    for item in compliance_items:
                        compliance_type = item.get('ComplianceType', 'N/A')
                        status = item.get('Status', 'UNKNOWN')
                        severity = item.get('Severity', 'UNSPECIFIED')

                        # Execution summary
                        execution_summary = item.get('ExecutionSummary', {})
                        execution_time = execution_summary.get('ExecutionTime', '')
                        if execution_time:
                            execution_time = execution_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(execution_time, datetime.datetime) else str(execution_time)

                        # Details
                        details = item.get('Details', {})
                        patch_group = details.get('PatchGroup', 'N/A')
                        installed_count = details.get('InstalledCount', '0')
                        installed_other_count = details.get('InstalledOtherCount', '0')
                        missing_count = details.get('MissingCount', '0')
                        failed_count = details.get('FailedCount', '0')
                        not_applicable_count = details.get('NotApplicableCount', '0')

                        compliance_data.append({
                            'Region': region,
                            'Instance ID': instance_id,
                            'Compliance Type': compliance_type,
                            'Status': status,
                            'Severity': severity,
                            'Patch Group': patch_group,
                            'Installed Patches': installed_count,
                            'Installed Other': installed_other_count,
                            'Missing Patches': missing_count,
                            'Failed Patches': failed_count,
                            'Not Applicable': not_applicable_count,
                            'Execution Time': execution_time if execution_time else 'N/A'
                        })

            except Exception as e:
                # Some instances may not have compliance data
                pass

    except Exception as e:
        utils.log_error(f"Error collecting patch compliance in {region}", e)

    return compliance_data


@utils.aws_error_handler("Collecting SSM patch compliance", default_return=[])
def collect_patch_compliance(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect SSM patch compliance information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with patch compliance information
    """
    print("\n=== COLLECTING SSM PATCH COMPLIANCE ===")
    results = utils.scan_regions_concurrent(regions, _scan_patch_compliance_region)
    all_compliance = [item for result in results for item in result]
    utils.log_success(f"Total patch compliance items collected: {len(all_compliance)}")
    return all_compliance


def _scan_ssm_parameters_region(region: str) -> List[Dict[str, Any]]:
    """Scan a single region for SSM parameters."""
    parameters_data = []

    if not utils.validate_aws_region(region):
        return parameters_data

    try:
        ssm_client = utils.get_boto3_client('ssm', region_name=region)

        paginator = ssm_client.get_paginator('describe_parameters')
        for page in paginator.paginate():
            parameters = page.get('Parameters', [])

            for parameter in parameters:
                param_name = parameter.get('Name', 'N/A')

                # Parameter details
                param_type = parameter.get('Type', 'String')
                description = parameter.get('Description', 'N/A')

                # Key ID (for SecureString)
                key_id = parameter.get('KeyId', 'N/A')

                # Last modified
                last_modified = parameter.get('LastModifiedDate', '')
                if last_modified:
                    last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_modified, datetime.datetime) else str(last_modified)

                # Last modified user
                last_modified_user = parameter.get('LastModifiedUser', 'N/A')

                # Version
                version = parameter.get('Version', 1)

                # Tier
                tier = parameter.get('Tier', 'Standard')

                # Policies
                policies = parameter.get('Policies', [])
                has_policies = 'Yes' if policies else 'No'

                # Data type
                data_type = parameter.get('DataType', 'text')

                parameters_data.append({
                    'Region': region,
                    'Parameter Name': param_name,
                    'Parameter Type': param_type,
                    'Tier': tier,
                    'Data Type': data_type,
                    'Description': description,
                    'KMS Key ID': key_id,
                    'Last Modified': last_modified if last_modified else 'N/A',
                    'Last Modified User': last_modified_user,
                    'Version': version,
                    'Has Policies': has_policies
                })

    except Exception as e:
        utils.log_error(f"Error collecting SSM parameters in {region}", e)

    return parameters_data


@utils.aws_error_handler("Collecting SSM parameters", default_return=[])
def collect_ssm_parameters(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect SSM Parameter Store parameters from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with parameter information
    """
    print("\n=== COLLECTING SSM PARAMETERS ===")
    results = utils.scan_regions_concurrent(regions, _scan_ssm_parameters_region)
    all_parameters = [parameter for result in results for parameter in result]
    utils.log_success(f"Total SSM parameters collected: {len(all_parameters)}")
    return all_parameters


def export_ssm_fleet_data(account_id: str, account_name: str):
    """
    Export SSM Fleet Manager information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Ask for region selection
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
    all_available_regions = utils.get_partition_regions(partition, all_regions=True)
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        regions = default_regions
        region_text = "default regions"
        region_suffix = ""
        utils.log_info(f"Scanning default regions: {len(regions)} regions")
    elif selection_int == 2:
        regions = all_available_regions
        region_text = "all AWS regions"
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
                    region_text = f"region {selected_region}"
                    region_suffix = f"-{selected_region}"
                    utils.log_info(f"Scanning region: {selected_region}")
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print(f"Please enter a valid number (1-{len(all_available_regions)}).")

    print(f"\nStarting SSM Fleet export process for {region_text}...")
    print("This may take some time depending on the number of regions and resources...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect managed instances
    instances = collect_managed_instances(regions)
    if instances:
        data_frames['Managed Instances'] = pd.DataFrame(instances)

    # STEP 2: Collect patch compliance
    compliance = collect_patch_compliance(regions)
    if compliance:
        data_frames['Patch Compliance'] = pd.DataFrame(compliance)

    # STEP 3: Collect parameters
    parameters = collect_ssm_parameters(regions)
    if parameters:
        data_frames['SSM Parameters'] = pd.DataFrame(parameters)

    # STEP 4: Create summary
    if instances or compliance or parameters:
        summary_data = []

        total_instances = len(instances)
        total_compliance_items = len(compliance)
        total_parameters = len(parameters)

        # Instance status
        online_instances = sum(1 for i in instances if i['Ping Status'] == 'Online')
        offline_instances = sum(1 for i in instances if i['Ping Status'] != 'Online')

        # Platform types
        platform_counts = {}
        for inst in instances:
            platform = inst.get('Platform Type', 'Unknown')
            platform_counts[platform] = platform_counts.get(platform, 0) + 1

        # Compliance status
        compliant_instances = sum(1 for c in compliance if c['Status'] == 'COMPLIANT')
        non_compliant_instances = sum(1 for c in compliance if c['Status'] == 'NON_COMPLIANT')

        # Parameter types
        secure_params = sum(1 for p in parameters if p['Parameter Type'] == 'SecureString')
        string_params = sum(1 for p in parameters if p['Parameter Type'] == 'String')
        stringlist_params = sum(1 for p in parameters if p['Parameter Type'] == 'StringList')

        summary_data.append({'Metric': 'Total Managed Instances', 'Value': total_instances})
        summary_data.append({'Metric': 'Online Instances', 'Value': online_instances})
        summary_data.append({'Metric': 'Offline Instances', 'Value': offline_instances})

        for platform, count in platform_counts.items():
            summary_data.append({'Metric': f'{platform} Instances', 'Value': count})

        summary_data.append({'Metric': 'Total Compliance Items', 'Value': total_compliance_items})
        summary_data.append({'Metric': 'Compliant Instances', 'Value': compliant_instances})
        summary_data.append({'Metric': 'Non-Compliant Instances', 'Value': non_compliant_instances})
        summary_data.append({'Metric': 'Total SSM Parameters', 'Value': total_parameters})
        summary_data.append({'Metric': 'SecureString Parameters', 'Value': secure_params})
        summary_data.append({'Metric': 'String Parameters', 'Value': string_params})
        summary_data.append({'Metric': 'StringList Parameters', 'Value': stringlist_params})

        data_frames['Summary'] = pd.DataFrame(summary_data)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No SSM Fleet data was collected. Nothing to export.")
        print("\nNo SSM Fleet resources found in the selected region(s).")
        return

    # STEP 5: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 6: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'ssm-fleet',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("SSM Fleet data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")

            # Summary of exported data
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

        # Export SSM Fleet data
        export_ssm_fleet_data(account_id, account_name)

        print("\nSSM Fleet export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("ssm-fleet-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

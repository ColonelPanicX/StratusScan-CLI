#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Network Firewall Export Tool
Date: NOV-16-2025

Description:
This script exports AWS Network Firewall information from all regions into an Excel file with
multiple worksheets. The output includes firewall policies, firewalls, rule groups, and
firewall endpoint details.

Features:
- Firewall overview with status and VPC associations
- Firewall policies with stateful and stateless rule group references
- Rule groups (stateful and stateless) with capacity and type
- Firewall endpoints with subnet mappings
- Logging configuration details
- Encryption configuration
- Resource tagging information
- Phase 4B: Concurrent region scanning (4x-10x performance improvement)
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


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("           AWS NETWORK FIREWALL EXPORT TOOL")
    print("====================================================================")
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
@utils.aws_error_handler("Collecting Network Firewalls from region", default_return=[])
def collect_network_firewalls_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect Network Firewall information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with firewall information
    """
    if not utils.validate_aws_region(region):
        return []

    firewalls = []
    nfw = utils.get_boto3_client('network-firewall', region_name=region)

    # Get Network Firewalls in the region
    paginator = nfw.get_paginator('list_firewalls')

    for page in paginator.paginate():
        firewalls_in_page = page.get('Firewalls', [])

        for fw_metadata in firewalls_in_page:
            firewall_arn = fw_metadata.get('FirewallArn', '')
            firewall_name = fw_metadata.get('FirewallName', '')

            print(f"  Processing firewall: {firewall_name}")

            try:
                # Get detailed firewall information
                fw_response = nfw.describe_firewall(FirewallArn=firewall_arn)
                firewall = fw_response.get('Firewall', {})
                firewall_status = fw_response.get('FirewallStatus', {})

                # Basic information
                firewall_id = firewall.get('FirewallId', '')
                vpc_id = firewall.get('VpcId', '')
                description = firewall.get('Description', 'N/A')
                firewall_policy_arn = firewall.get('FirewallPolicyArn', '')
                delete_protection = firewall.get('DeleteProtection', False)
                subnet_change_protection = firewall.get('SubnetChangeProtection', False)
                firewall_policy_change_protection = firewall.get('FirewallPolicyChangeProtection', False)

                # Status information
                status = firewall_status.get('Status', '')
                configuration_sync_state = firewall_status.get('ConfigurationSyncStateSummary', 'N/A')

                # Subnet mappings
                subnet_mappings = firewall.get('SubnetMappings', [])
                subnet_ids = [sm.get('SubnetId', '') for sm in subnet_mappings]
                subnet_ids_str = ', '.join(subnet_ids) if subnet_ids else 'N/A'
                subnet_count = len(subnet_ids)

                # Firewall endpoints (one per AZ)
                sync_states = firewall_status.get('SyncStates', {})
                endpoint_ids = []
                for az, sync_state in sync_states.items():
                    attachment = sync_state.get('Attachment', {})
                    endpoint_id = attachment.get('EndpointId', '')
                    if endpoint_id:
                        endpoint_ids.append(f"{az}:{endpoint_id}")

                endpoints_str = ', '.join(endpoint_ids) if endpoint_ids else 'N/A'

                # Get encryption configuration
                encryption_config = firewall.get('EncryptionConfiguration', {})
                encryption_type = encryption_config.get('Type', 'N/A')
                kms_key_id = encryption_config.get('KeyId', 'N/A')

                # Get tags
                tags = firewall.get('Tags', [])
                tag_dict = {tag['Key']: tag['Value'] for tag in tags}
                tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

                firewalls.append({
                    'Region': region,
                    'Firewall Name': firewall_name,
                    'Firewall ID': firewall_id,
                    'Status': status,
                    'VPC ID': vpc_id,
                    'Subnet Count': subnet_count,
                    'Subnet IDs': subnet_ids_str,
                    'Endpoints': endpoints_str,
                    'Firewall Policy ARN': firewall_policy_arn,
                    'Configuration Sync State': configuration_sync_state,
                    'Delete Protection': delete_protection,
                    'Subnet Change Protection': subnet_change_protection,
                    'Policy Change Protection': firewall_policy_change_protection,
                    'Encryption Type': encryption_type,
                    'KMS Key ID': kms_key_id,
                    'Description': description,
                    'Tags': tags_str,
                    'Firewall ARN': firewall_arn
                })

            except Exception as e:
                utils.log_error(f"Error getting details for firewall {firewall_name}", e)

    utils.log_info(f"Found {len(firewalls)} Network Firewalls in {region}")
    return firewalls


def collect_network_firewalls(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Network Firewall information using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with firewall information
    """
    print("\n=== COLLECTING NETWORK FIREWALLS ===")
    utils.log_info(f"Scanning {len(regions)} regions for Network Firewalls...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_network_firewalls_from_region,
        show_progress=True
    )

    # Flatten results
    all_firewalls = []
    for firewalls_in_region in region_results:
        all_firewalls.extend(firewalls_in_region)

    utils.log_success(f"Total Network Firewalls collected: {len(all_firewalls)}")
    return all_firewalls


@utils.aws_error_handler("Collecting firewall policies from region", default_return=[])
def collect_firewall_policies_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect Network Firewall policy information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with firewall policy information
    """
    if not utils.validate_aws_region(region):
        return []

    policies = []
    nfw = utils.get_boto3_client('network-firewall', region_name=region)

    # Get firewall policies
    paginator = nfw.get_paginator('list_firewall_policies')

    for page in paginator.paginate():
        policies_in_page = page.get('FirewallPolicies', [])

        for policy_metadata in policies_in_page:
            policy_arn = policy_metadata.get('Arn', '')
            policy_name = policy_metadata.get('Name', '')

            print(f"  Processing policy: {policy_name}")

            try:
                # Get detailed policy information
                policy_response = nfw.describe_firewall_policy(FirewallPolicyArn=policy_arn)
                policy = policy_response.get('FirewallPolicy', {})

                # Stateless rule groups
                stateless_default_actions = policy.get('StatelessDefaultActions', [])
                stateless_fragment_default_actions = policy.get('StatelessFragmentDefaultActions', [])
                stateless_rule_groups = policy.get('StatelessRuleGroupReferences', [])
                stateless_count = len(stateless_rule_groups)

                # Stateful rule groups
                stateful_rule_groups = policy.get('StatefulRuleGroupReferences', [])
                stateful_count = len(stateful_rule_groups)

                # Stateful engine options
                stateful_engine_options = policy.get('StatefulEngineOptions', {})
                rule_order = stateful_engine_options.get('RuleOrder', 'N/A')

                # Custom actions
                stateless_custom_actions = policy.get('StatelessCustomActions', [])
                custom_actions_count = len(stateless_custom_actions)

                # Get tags
                tags = policy_response.get('FirewallPolicyResponse', {}).get('Tags', [])
                tag_dict = {tag['Key']: tag['Value'] for tag in tags}
                tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

                # Description
                description = policy_response.get('FirewallPolicyResponse', {}).get('Description', 'N/A')

                policies.append({
                    'Region': region,
                    'Policy Name': policy_name,
                    'Stateless Rule Groups': stateless_count,
                    'Stateful Rule Groups': stateful_count,
                    'Stateless Default Actions': ', '.join(stateless_default_actions),
                    'Stateless Fragment Actions': ', '.join(stateless_fragment_default_actions),
                    'Stateful Rule Order': rule_order,
                    'Custom Actions': custom_actions_count,
                    'Description': description,
                    'Tags': tags_str,
                    'Policy ARN': policy_arn
                })

            except Exception as e:
                utils.log_error(f"Error getting details for policy {policy_name}", e)

    utils.log_info(f"Found {len(policies)} firewall policies in {region}")
    return policies


def collect_firewall_policies(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Network Firewall policy information using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with firewall policy information
    """
    print("\n=== COLLECTING FIREWALL POLICIES ===")
    utils.log_info(f"Scanning {len(regions)} regions for firewall policies...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_firewall_policies_from_region,
        show_progress=True
    )

    # Flatten results
    all_policies = []
    for policies_in_region in region_results:
        all_policies.extend(policies_in_region)

    utils.log_success(f"Total firewall policies collected: {len(all_policies)}")
    return all_policies


@utils.aws_error_handler("Collecting rule groups from region", default_return=[])
def collect_rule_groups_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect Network Firewall rule group information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with rule group information
    """
    if not utils.validate_aws_region(region):
        return []

    rule_groups = []
    nfw = utils.get_boto3_client('network-firewall', region_name=region)

    # Get rule groups
    paginator = nfw.get_paginator('list_rule_groups')

    for page in paginator.paginate():
        rule_groups_in_page = page.get('RuleGroups', [])

        for rg_metadata in rule_groups_in_page:
            rg_arn = rg_metadata.get('Arn', '')
            rg_name = rg_metadata.get('Name', '')

            print(f"  Processing rule group: {rg_name}")

            try:
                # Get detailed rule group information
                rg_response = nfw.describe_rule_group(RuleGroupArn=rg_arn)
                rg_resp = rg_response.get('RuleGroupResponse', {})

                # Basic information
                rule_group_id = rg_resp.get('RuleGroupId', '')
                rule_group_type = rg_resp.get('Type', '')
                capacity = rg_resp.get('Capacity', 0)
                consumed_capacity = rg_resp.get('ConsumedCapacity', 0)
                number_of_associations = rg_resp.get('NumberOfAssociations', 0)

                # Encryption configuration
                encryption_config = rg_resp.get('EncryptionConfiguration', {})
                encryption_type = encryption_config.get('Type', 'N/A')

                # Source metadata
                source_metadata = rg_resp.get('SourceMetadata', {})
                source_arn = source_metadata.get('SourceArn', 'N/A')
                source_update_token = source_metadata.get('SourceUpdateToken', 'N/A')

                # Get tags
                tags = rg_resp.get('Tags', [])
                tag_dict = {tag['Key']: tag['Value'] for tag in tags}
                tags_str = ', '.join([f"{k}={v}" for k, v in tag_dict.items()]) if tag_dict else 'N/A'

                # Description
                description = rg_resp.get('Description', 'N/A')

                rule_groups.append({
                    'Region': region,
                    'Rule Group Name': rg_name,
                    'Rule Group ID': rule_group_id,
                    'Type': rule_group_type,
                    'Capacity': capacity,
                    'Consumed Capacity': consumed_capacity,
                    'Number of Associations': number_of_associations,
                    'Encryption Type': encryption_type,
                    'Source ARN': source_arn,
                    'Description': description,
                    'Tags': tags_str,
                    'Rule Group ARN': rg_arn
                })

            except Exception as e:
                utils.log_error(f"Error getting details for rule group {rg_name}", e)

    utils.log_info(f"Found {len(rule_groups)} rule groups in {region}")
    return rule_groups


def collect_rule_groups(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Network Firewall rule group information using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with rule group information
    """
    print("\n=== COLLECTING RULE GROUPS ===")
    utils.log_info(f"Scanning {len(regions)} regions for rule groups...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_rule_groups_from_region,
        show_progress=True
    )

    # Flatten results
    all_rule_groups = []
    for rule_groups_in_region in region_results:
        all_rule_groups.extend(rule_groups_in_region)

    utils.log_success(f"Total rule groups collected: {len(all_rule_groups)}")
    return all_rule_groups


@utils.aws_error_handler("Collecting logging configurations from region", default_return=[])
def collect_logging_configurations_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect Network Firewall logging configuration information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with logging configuration information
    """
    if not utils.validate_aws_region(region):
        return []

    logging_configs = []
    nfw = utils.get_boto3_client('network-firewall', region_name=region)

    # Get all firewalls to check their logging configurations
    paginator = nfw.get_paginator('list_firewalls')

    for page in paginator.paginate():
        firewalls = page.get('Firewalls', [])

        for fw_metadata in firewalls:
            firewall_arn = fw_metadata.get('FirewallArn', '')
            firewall_name = fw_metadata.get('FirewallName', '')

            try:
                # Get logging configuration for this firewall
                logging_response = nfw.describe_logging_configuration(FirewallArn=firewall_arn)
                logging_config = logging_response.get('LoggingConfiguration', {})

                if logging_config:
                    log_destination_configs = logging_config.get('LogDestinationConfigs', [])

                    for log_config in log_destination_configs:
                        log_type = log_config.get('LogType', '')
                        log_destination_type = log_config.get('LogDestinationType', '')
                        log_destination = log_config.get('LogDestination', {})

                        # Format log destination based on type
                        if log_destination_type == 'S3':
                            destination = log_destination.get('bucketName', 'N/A')
                            prefix = log_destination.get('prefix', 'N/A')
                            destination_str = f"s3://{destination}/{prefix}"
                        elif log_destination_type == 'CloudWatchLogs':
                            destination_str = log_destination.get('logGroup', 'N/A')
                        elif log_destination_type == 'KinesisDataFirehose':
                            destination_str = log_destination.get('deliveryStream', 'N/A')
                        else:
                            destination_str = str(log_destination)

                        logging_configs.append({
                            'Region': region,
                            'Firewall Name': firewall_name,
                            'Log Type': log_type,
                            'Destination Type': log_destination_type,
                            'Destination': destination_str,
                            'Firewall ARN': firewall_arn
                        })

            except Exception as e:
                # Logging configuration might not exist for all firewalls
                utils.log_warning(f"No logging configuration for firewall {firewall_name}: {e}")

    utils.log_info(f"Found {len(logging_configs)} logging configurations in {region}")
    return logging_configs


def collect_logging_configurations(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Network Firewall logging configuration information using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with logging configuration information
    """
    print("\n=== COLLECTING LOGGING CONFIGURATIONS ===")
    utils.log_info(f"Scanning {len(regions)} regions for logging configurations...")

    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_logging_configurations_from_region,
        show_progress=True
    )

    # Flatten results
    all_logging_configs = []
    for logging_configs_in_region in region_results:
        all_logging_configs.extend(logging_configs_in_region)

    utils.log_success(f"Total logging configurations collected: {len(all_logging_configs)}")
    return all_logging_configs


def export_network_firewall_data(account_id: str, account_name: str):
    """
    Export Network Firewall information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect Network Firewalls
    firewalls = collect_network_firewalls(regions)
    if firewalls:
        data_frames['Firewalls'] = pd.DataFrame(firewalls)

    # STEP 2: Collect firewall policies
    policies = collect_firewall_policies(regions)
    if policies:
        data_frames['Firewall Policies'] = pd.DataFrame(policies)

    # STEP 3: Collect rule groups
    rule_groups = collect_rule_groups(regions)
    if rule_groups:
        data_frames['Rule Groups'] = pd.DataFrame(rule_groups)

    # STEP 4: Collect logging configurations
    logging_configs = collect_logging_configurations(regions)
    if logging_configs:
        data_frames['Logging Configurations'] = pd.DataFrame(logging_configs)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No Network Firewall data was collected. Nothing to export.")
        print("\nNo Network Firewalls found in the selected region(s).")
        return

    # STEP 5: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 6: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'network-firewall',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("Network Firewall data exported successfully!")
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
    # Initialize logging
    utils.setup_logging("network-firewall-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("network-firewall-export.py", "AWS Network Firewall Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = print_title()

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            if not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
                print("Exiting script...")
                sys.exit(0)

        # Export Network Firewall data
        export_network_firewall_data(account_id, account_name)

        print("\nNetwork Firewall export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("network-firewall-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS IAM Role Information Collection Script
Version: v2.0.0
Date: SEP-22-2025

Description:
This script collects comprehensive IAM role information from AWS environments including
trust relationships, permission policies, usage patterns, and cross-account access details. The data
is exported to an Excel spreadsheet with AWS-specific naming convention for security
auditing and compliance reporting.

Collected information includes: Role Name, Role Type, Trusted Entities, Trust Policy Summary,
Permission Policies, Last Used, Cross-Account Access, Service Usage, Creation Date, and Tags.
"""

import sys
import datetime
import json
import re
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



def print_title():
    """
    Print the script title and account information.

    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS IAM ROLE INFORMATION COLLECTION")
    print("====================================================================")
    print("Version: v2.0.0                       Date: SEP-22-2025")

    # Get account information
    account_id, account_name = utils.get_account_info()

    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"

    print(f"Environment: {partition_name}")
    print("====================================================================")
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")

    return account_id, account_name

def calculate_days_since_last_used(last_used_date):
    """
    Calculate days since role was last used.

    Args:
        last_used_date: Date object or None

    Returns:
        str: Days since last used or descriptive string
    """
    if last_used_date is None:
        return "Never"

    try:
        # Remove timezone info if present for calculation
        if last_used_date.tzinfo is not None:
            last_used_date = last_used_date.replace(tzinfo=None)

        days_since = (datetime.datetime.now() - last_used_date).days
        return str(days_since)
    except Exception:
        return "Unknown"

def analyze_trust_policy(trust_policy_doc):
    """
    Analyze the trust policy to extract key information.

    Args:
        trust_policy_doc: Trust policy document as dict

    Returns:
        tuple: (trusted_entities, trust_summary, cross_account_info, service_usage)
    """
    trusted_entities = []
    cross_account_accounts = []
    services = []

    try:
        statements = trust_policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if statement.get('Effect') == 'Allow':
                principals = statement.get('Principal', {})

                if isinstance(principals, str):
                    if principals == '*':
                        trusted_entities.append("Anyone (*)")
                    else:
                        trusted_entities.append(principals)
                elif isinstance(principals, dict):
                    # AWS accounts
                    if 'AWS' in principals:
                        aws_principals = principals['AWS']
                        if not isinstance(aws_principals, list):
                            aws_principals = [aws_principals]

                        for principal in aws_principals:
                            if isinstance(principal, str):
                                if principal == '*':
                                    trusted_entities.append("Any AWS Account (*)")
                                elif 'arn:aws' in principal or 'arn:aws' in principal:
                                    # Extract account ID from ARN
                                    match = re.search(r':(\d{12}):', principal)
                                    if match:
                                        account_id = match.group(1)
                                        cross_account_accounts.append(account_id)
                                        trusted_entities.append(f"AWS Account: {account_id}")
                                    else:
                                        trusted_entities.append(f"AWS: {principal}")
                                else:
                                    trusted_entities.append(f"AWS: {principal}")

                    # AWS Services
                    if 'Service' in principals:
                        service_principals = principals['Service']
                        if not isinstance(service_principals, list):
                            service_principals = [service_principals]

                        for service in service_principals:
                            services.append(service)
                            trusted_entities.append(f"Service: {service}")

                    # Federated (SAML, OIDC)
                    if 'Federated' in principals:
                        federated_principals = principals['Federated']
                        if not isinstance(federated_principals, list):
                            federated_principals = [federated_principals]

                        for fed in federated_principals:
                            trusted_entities.append(f"Federated: {fed}")

        # Create summary
        trust_summary_parts = []
        if services:
            trust_summary_parts.append(f"Services: {len(services)}")
        if cross_account_accounts:
            trust_summary_parts.append(f"Cross-Account: {len(cross_account_accounts)}")
        if not services and not cross_account_accounts and trusted_entities:
            trust_summary_parts.append("Other principals")

        trust_summary = ", ".join(trust_summary_parts) if trust_summary_parts else "None"

        # Cross-account info
        cross_account_access = "Yes" if cross_account_accounts else "No"
        cross_account_details = ", ".join(cross_account_accounts) if cross_account_accounts else "None"

        return (
            ", ".join(trusted_entities[:5]) + ("..." if len(trusted_entities) > 5 else ""),
            trust_summary,
            f"{cross_account_access} ({cross_account_details})" if cross_account_accounts else "No",
            ", ".join(services) if services else "None"
        )

    except Exception as e:
        utils.log_warning(f"Error analyzing trust policy: {e}")
        return "Unknown", "Unknown", "Unknown", "Unknown"

def determine_role_type(role_name, role_path, trust_policy_doc):
    """
    Determine the type of IAM role.

    Args:
        role_name: Name of the role
        role_path: Path of the role
        trust_policy_doc: Trust policy document

    Returns:
        str: Role type classification
    """
    # Check for service-linked roles
    if role_path.startswith('/aws-service-role/') or 'ServiceLinkedRole' in role_name:
        return "Service-linked"

    # Check for cross-account roles by analyzing trust policy
    try:
        statements = trust_policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if statement.get('Effect') == 'Allow':
                principals = statement.get('Principal', {})
                if isinstance(principals, dict) and 'AWS' in principals:
                    aws_principals = principals['AWS']
                    if not isinstance(aws_principals, list):
                        aws_principals = [aws_principals]

                    for principal in aws_principals:
                        if isinstance(principal, str) and ('arn:aws' in principal or 'arn:aws' in principal):
                            # Check if it's a different account
                            match = re.search(r':(\d{12}):', principal)
                            if match:
                                return "Cross-account"
    except Exception:
        pass

    return "Standard"

@utils.aws_error_handler("Getting role policies", default_return="Unknown")
def get_role_policies(iam_client, role_name):
    """
    Get all policies attached to a role (both managed and inline).

    Args:
        iam_client: The boto3 IAM client
        role_name: The role name to check

    Returns:
        str: Comma-separated list of policy names
    """
    policies = []

    # Get attached managed policies
    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
    for policy in attached_policies['AttachedPolicies']:
        policies.append(policy['PolicyName'])

    # Get inline policies
    inline_policies = iam_client.list_role_policies(RoleName=role_name)
    for policy_name in inline_policies['PolicyNames']:
        policies.append(f"{policy_name} (Inline)")

    return ", ".join(policies) if policies else "None"

@utils.aws_error_handler("Getting role tags", default_return="Unknown")
def get_role_tags(iam_client, role_name):
    """
    Get tags for a role.

    Args:
        iam_client: The boto3 IAM client
        role_name: The role name to check

    Returns:
        str: Comma-separated list of key=value pairs
    """
    response = iam_client.list_role_tags(RoleName=role_name)
    tags = response.get('Tags', [])
    tag_strings = [f"{tag['Key']}={tag['Value']}" for tag in tags]
    return ", ".join(tag_strings) if tag_strings else "None"

@utils.aws_error_handler("Collecting IAM role information", default_return=[])
def collect_iam_role_information():
    """
    Collect IAM role information from AWS.

    Returns:
        list: List of dictionaries containing role information
    """
    utils.log_info("Collecting IAM role information from AWS environment...")

    # IAM is a global service but we need to specify a region for the client
    # iam is a global service - use partition-aware home region

    home_region = utils.get_partition_default_region()

    iam_client = utils.get_boto3_client('iam', region_name=home_region)

    role_data = []

    # Get all IAM roles
    paginator = iam_client.get_paginator('list_roles')

    total_roles = 0
    for page in paginator.paginate():
        roles = page['Roles']
        total_roles += len(roles)

    utils.log_info(f"Found {total_roles} IAM roles to process")

    # Reset paginator and process roles
    paginator = iam_client.get_paginator('list_roles')
    processed = 0

    for page in paginator.paginate():
        roles = page['Roles']

        for role in roles:
            role_name = role['RoleName']
            processed += 1
            progress = (processed / total_roles) * 100

            utils.log_info(f"[{progress:.1f}%] Processing role {processed}/{total_roles}: {role_name}")

            # Basic role information
            creation_date = role['CreateDate']
            role_path = role.get('Path', '/')
            description = role.get('Description', 'None')
            max_session_duration = role.get('MaxSessionDuration', 3600) // 3600  # Convert to hours

            # Parse trust policy
            trust_policy_doc = role.get('AssumeRolePolicyDocument', {})
            trusted_entities, trust_summary, cross_account_info, service_usage = analyze_trust_policy(trust_policy_doc)

            # Determine role type
            role_type = determine_role_type(role_name, role_path, trust_policy_doc)

            # Get role usage information
            try:
                role_usage = iam_client.get_role(RoleName=role_name)
                role_last_used = role_usage['Role'].get('RoleLastUsed', {})
                last_used_date = role_last_used.get('LastUsedDate')
                last_used_region = role_last_used.get('Region', 'Unknown')

                if last_used_date:
                    last_used_str = last_used_date
                    days_since_used = calculate_days_since_last_used(last_used_date)
                else:
                    last_used_str = "Never"
                    days_since_used = "Never"

            except Exception as e:
                utils.log_warning(f"Could not get usage info for role {role_name}: {e}")
                last_used_str = "Unknown"
                days_since_used = "Unknown"

            # Get additional role information
            permission_policies = get_role_policies(iam_client, role_name)
            tags = get_role_tags(iam_client, role_name)

            # Compile role data
            role_info = {
                'Role Name': role_name,
                'Role Type': role_type,
                'Trusted Entities': trusted_entities,
                'Trust Policy Summary': trust_summary,
                'Permission Policies': permission_policies,
                'Last Used': last_used_str,
                'Days Since Last Used': days_since_used,
                'Max Session Duration (Hours)': max_session_duration,
                'Cross-Account Access': cross_account_info,
                'Service Usage': service_usage,
                'Creation Date': creation_date,
                'Path': role_path,
                'Description': description,
                'Tags': tags
            }

            role_data.append(role_info)

    utils.log_success(f"Successfully collected information for {len(role_data)} roles")
    return role_data

def export_to_excel(role_data, account_id, account_name):
    """
    Export IAM role data to Excel file with AWS naming convention.

    Args:
        role_data: List of role information dictionaries
        account_id: AWS account ID
        account_name: AWS account name

    Returns:
        str: Filename of exported file or None if failed
    """
    if not role_data:
        utils.log_warning("No IAM role data to export.")
        return None

    try:
        # Import pandas after dependency check
        import pandas as pd

        # Create DataFrame
        df = pd.DataFrame(role_data)

        # Apply security sanitization to DataFrame
        df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(df))

        # Generate filename with AWS identifier
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")

        # Use utils module to generate filename and save data with AWS identifier
        filename = utils.create_export_filename(
            account_name,
            "iam-roles",
            "",
            current_date
        )

        # Create data frames for multi-sheet export
        data_frames = {
            'IAM Roles': df
        }

        # Create summary data
        summary_data = {
            'Metric': [
                'Total Roles',
                'Service-linked Roles',
                'Cross-account Roles',
                'Standard Roles',
                'Unused Roles (Never Used)',
                'Unused Roles (>90 days)',
                'Roles with Cross-Account Access',
                'Roles with Multiple Policies'
            ],
            'Count': [
                len(df),
                len(df[df['Role Type'] == 'Service-linked']),
                len(df[df['Role Type'] == 'Cross-account']),
                len(df[df['Role Type'] == 'Standard']),
                len(df[df['Last Used'] == 'Never']),
                len(df[(df['Days Since Last Used'] != 'Never') & (df['Days Since Last Used'] != 'Unknown') & (pd.to_numeric(df['Days Since Last Used'], errors='coerce') > 90)]),
                len(df[df['Cross-Account Access'].str.startswith('Yes', na=False)]),
                len(df[df['Permission Policies'].str.contains(',', na=False)])
            ]
        }

        summary_df = pd.DataFrame(summary_data)
        summary_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(summary_df))
        data_frames['Summary'] = summary_df

        # Save using utils function for multi-sheet Excel
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("AWS IAM role data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data for {len(role_data)} IAM roles")
            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def main():
    """
    Main function to orchestrate the IAM role information collection.
    """
    try:
        # Check dependencies first
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return

        # Import pandas after dependency check
        import pandas as pd

        # Print title and get account info
        account_id, account_name = print_title()

        utils.log_info("Starting IAM role information collection from AWS...")
        print("====================================================================")

        # Collect IAM role information
        role_data = collect_iam_role_information()

        if not role_data:
            utils.log_warning("No IAM role data collected. Exiting.")
            return

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Export to Excel
        filename = export_to_excel(role_data, account_id, account_name)

        if filename:
            utils.log_info(f"Results exported with AWS compliance markers")
            utils.log_info(f"Total roles processed: {len(role_data)}")

            # Display some summary statistics
            df = pd.DataFrame(role_data)
            utils.log_info(f"Service-linked roles: {len(df[df['Role Type'] == 'Service-linked'])}")
            utils.log_info(f"Cross-account roles: {len(df[df['Role Type'] == 'Cross-account'])}")
            utils.log_info(f"Standard roles: {len(df[df['Role Type'] == 'Standard'])}")
            utils.log_info(f"Never used roles: {len(df[df['Last Used'] == 'Never'])}")
            utils.log_info(f"Roles with cross-account access: {len(df[df['Cross-Account Access'].str.startswith('Yes', na=False)])}")

            print("\nScript execution completed.")
        else:
            utils.log_error("Export failed. Please check the logs.")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
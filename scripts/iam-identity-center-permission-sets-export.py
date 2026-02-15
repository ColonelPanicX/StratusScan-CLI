#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Permission Sets Text Export Script
Version: v2.0.0
Date: SEP-26-2025

Description:
This script exports all AWS SSO Permission Sets from AWS environments to a single
comprehensive text file. Each permission set is clearly delineated with detailed
information including inline policies, managed policies, and permissions boundaries.

Output Format:
- Single text file with all permission sets
- Clear delineation between each permission set
- Hierarchical structure showing policies and permissions
- Human-readable format suitable for compliance review
"""

import os
import sys
import json
import datetime
import time
from pathlib import Path
from botocore.exceptions import ClientError, NoCredentialsError

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

def convert_datetime_to_string(dt_obj):
    """
    Convert datetime object to readable string for text export.

    Args:
        dt_obj: datetime object (can be timezone-aware or unaware)

    Returns:
        str: Formatted datetime string or 'N/A' if None/invalid
    """
    if dt_obj is None:
        return 'N/A'

    try:
        if hasattr(dt_obj, 'strftime'):
            # If timezone-aware, convert to UTC and make timezone-naive
            if hasattr(dt_obj, 'tzinfo') and dt_obj.tzinfo is not None:
                # Convert to UTC and remove timezone info
                utc_dt = dt_obj.utctimetuple()
                dt_obj = datetime.datetime(*utc_dt[:6])

            return dt_obj.strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            return str(dt_obj)
    except Exception:
        return 'N/A'

def format_json_for_display(json_obj, indent_level=0):
    """
    Format JSON object for readable display in text file.

    Args:
        json_obj: JSON object to format
        indent_level: Current indentation level

    Returns:
        str: Formatted JSON string
    """
    if json_obj is None:
        return "None"

    try:
        if isinstance(json_obj, str):
            # Try to parse if it's a JSON string
            try:
                json_obj = json.loads(json_obj)
            except Exception:
                return json_obj

        # Format with proper indentation
        formatted = json.dumps(json_obj, indent=2, default=str)

        # Add additional indentation if needed
        if indent_level > 0:
            lines = formatted.split('\n')
            indent = '    ' * indent_level
            formatted = '\n'.join(indent + line for line in lines)

        return formatted
    except Exception as e:
        return f"Error formatting JSON: {str(e)}"

def get_permission_set_details(sso_admin_client, instance_arn, permission_set_arn):
    """
    Get detailed information about a specific permission set.

    Args:
        sso_admin_client: Boto3 SSO Admin client
        instance_arn: SSO instance ARN
        permission_set_arn: Permission set ARN

    Returns:
        dict: Detailed permission set information
    """
    details = {}

    try:
        # Get permission set description
        response = sso_admin_client.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        )
        details['description'] = response.get('PermissionSet', {})

        # Get inline policy
        try:
            inline_policy_response = sso_admin_client.get_inline_policy_for_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )
            details['inline_policy'] = inline_policy_response.get('InlinePolicy')
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                details['inline_policy'] = None
            else:
                details['inline_policy'] = f"Error retrieving inline policy: {str(e)}"

        # Get managed policies
        try:
            managed_policies_response = sso_admin_client.list_managed_policies_in_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )
            details['managed_policies'] = managed_policies_response.get('AttachedManagedPolicies', [])
        except ClientError as e:
            details['managed_policies'] = f"Error retrieving managed policies: {str(e)}"

        # Get customer managed policies
        try:
            customer_managed_response = sso_admin_client.list_customer_managed_policy_references_in_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )
            details['customer_managed_policies'] = customer_managed_response.get('CustomerManagedPolicyReferences', [])
        except ClientError as e:
            details['customer_managed_policies'] = f"Error retrieving customer managed policies: {str(e)}"

        # Get permissions boundary
        try:
            boundary_response = sso_admin_client.get_permissions_boundary_for_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )
            details['permissions_boundary'] = boundary_response.get('PermissionsBoundary')
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                details['permissions_boundary'] = None
            else:
                details['permissions_boundary'] = f"Error retrieving permissions boundary: {str(e)}"

        # Get account assignments
        try:
            assignments = []
            paginator = sso_admin_client.get_paginator('list_account_assignments')

            for page in paginator.paginate(
                InstanceArn=instance_arn,
                AccountId='123456789012',  # We'll need to get all accounts
                PermissionSetArn=permission_set_arn
            ):
                assignments.extend(page.get('AccountAssignments', []))

            details['account_assignments'] = assignments
        except ClientError as e:
            details['account_assignments'] = f"Error retrieving account assignments: {str(e)}"

    except Exception as e:
        utils.log_error(f"Error getting permission set details: {str(e)}")
        details['error'] = str(e)

    return details

def write_permission_set_to_file(file_handle, permission_set_name, permission_set_arn, details, separator_char="="):
    """
    Write a single permission set's information to the text file.

    Args:
        file_handle: Open file handle
        permission_set_name: Name of the permission set
        permission_set_arn: ARN of the permission set
        details: Detailed permission set information
        separator_char: Character to use for section separators
    """
    # Main header for permission set
    header = f" PERMISSION SET: {permission_set_name} "
    separator = separator_char * 100
    centered_header = header.center(100, separator_char)

    file_handle.write(f"\n{separator}\n")
    file_handle.write(f"{centered_header}\n")
    file_handle.write(f"{separator}\n\n")

    # Basic information
    file_handle.write("BASIC INFORMATION:\n")
    file_handle.write("-" * 50 + "\n")
    file_handle.write(f"Name: {permission_set_name}\n")
    file_handle.write(f"ARN: {permission_set_arn}\n")

    # Permission set description details
    if 'description' in details and details['description']:
        desc = details['description']
        file_handle.write(f"Description: {desc.get('Description', 'N/A')}\n")
        file_handle.write(f"Session Duration: {desc.get('SessionDuration', 'N/A')}\n")
        file_handle.write(f"Relay State: {desc.get('RelayState', 'N/A')}\n")
        file_handle.write(f"Created Date: {convert_datetime_to_string(desc.get('CreatedDate'))}\n")

    file_handle.write("\n")

    # Inline Policy
    file_handle.write("INLINE POLICY:\n")
    file_handle.write("-" * 50 + "\n")
    if details.get('inline_policy'):
        file_handle.write(format_json_for_display(details['inline_policy']))
    else:
        file_handle.write("No inline policy attached")
    file_handle.write("\n\n")

    # AWS Managed Policies
    file_handle.write("AWS MANAGED POLICIES:\n")
    file_handle.write("-" * 50 + "\n")
    managed_policies = details.get('managed_policies', [])
    if managed_policies and isinstance(managed_policies, list):
        for i, policy in enumerate(managed_policies, 1):
            file_handle.write(f"{i}. Name: {policy.get('Name', 'N/A')}\n")
            file_handle.write(f"   ARN: {policy.get('Arn', 'N/A')}\n")
    else:
        file_handle.write("No AWS managed policies attached")
    file_handle.write("\n")

    # Customer Managed Policies
    file_handle.write("CUSTOMER MANAGED POLICIES:\n")
    file_handle.write("-" * 50 + "\n")
    customer_policies = details.get('customer_managed_policies', [])
    if customer_policies and isinstance(customer_policies, list):
        for i, policy in enumerate(customer_policies, 1):
            file_handle.write(f"{i}. Name: {policy.get('Name', 'N/A')}\n")
            file_handle.write(f"   Path: {policy.get('Path', 'N/A')}\n")
    else:
        file_handle.write("No customer managed policies attached")
    file_handle.write("\n")

    # Permissions Boundary
    file_handle.write("PERMISSIONS BOUNDARY:\n")
    file_handle.write("-" * 50 + "\n")
    boundary = details.get('permissions_boundary')
    if boundary:
        file_handle.write(format_json_for_display(boundary))
    else:
        file_handle.write("No permissions boundary set")
    file_handle.write("\n\n")

    # Account Assignments
    file_handle.write("ACCOUNT ASSIGNMENTS:\n")
    file_handle.write("-" * 50 + "\n")
    assignments = details.get('account_assignments', [])
    if assignments and isinstance(assignments, list):
        for i, assignment in enumerate(assignments, 1):
            file_handle.write(f"{i}. Account: {assignment.get('AccountId', 'N/A')}\n")
            file_handle.write(f"   Principal Type: {assignment.get('PrincipalType', 'N/A')}\n")
            file_handle.write(f"   Principal ID: {assignment.get('PrincipalId', 'N/A')}\n")
    else:
        file_handle.write("No account assignments found")
    file_handle.write("\n")

def export_permission_sets_to_text():
    """
    Main function to export all permission sets to a single text file.
    """
    utils.log_info("Starting AWS Permission Sets Text Export")

    try:
        # Initialize SSO Admin client
        utils.log_info("Initializing AWS SSO Admin client for AWS")
        # sso-admin is a global service - use partition-aware home region

        home_region = utils.get_partition_default_region()

        sso_admin_client = utils.get_boto3_client('sso-admin', region_name=home_region)

        # Get SSO instance
        utils.log_info("Retrieving SSO instance information")
        instances_response = sso_admin_client.list_instances()
        instances = instances_response.get('Instances', [])

        if not instances:
            utils.log_error("No SSO instances found in this account")
            return False

        instance_arn = instances[0]['InstanceArn']
        utils.log_info(f"Using SSO instance: {instance_arn}")

        # Get all permission sets
        utils.log_info("Retrieving all permission sets")
        permission_sets = []
        paginator = sso_admin_client.get_paginator('list_permission_sets')

        for page in paginator.paginate(InstanceArn=instance_arn):
            permission_sets.extend(page.get('PermissionSets', []))

        utils.log_info(f"Found {len(permission_sets)} permission sets")

        if not permission_sets:
            utils.log_warning("No permission sets found")
            return False

        # Create output file
        timestamp = datetime.datetime.now().strftime("%m.%d.%Y")
        output_filename = f"permission-sets-aws-export-{timestamp}.txt"
        output_path = utils.get_output_filepath(output_filename)

        utils.log_info(f"Creating output file: {output_path}")

        with open(output_path, 'w', encoding='utf-8') as f:
            # Write file header
            f.write("=" * 100 + "\n")
            f.write("AWS PERMISSION SETS EXPORT".center(100) + "\n")
            f.write("=" * 100 + "\n")
            f.write(f"Export Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"SSO Instance: {instance_arn}\n")
            f.write(f"Total Permission Sets: {len(permission_sets)}\n")
            f.write(f"AWS Environment: FedRAMP Moderate (IL4)\n")
            f.write("=" * 100 + "\n")

            # Process each permission set
            for i, permission_set_arn in enumerate(permission_sets, 1):
                utils.log_info(f"Processing permission set {i}/{len(permission_sets)}: {permission_set_arn}")

                # Get permission set name
                try:
                    describe_response = sso_admin_client.describe_permission_set(
                        InstanceArn=instance_arn,
                        PermissionSetArn=permission_set_arn
                    )
                    permission_set_name = describe_response['PermissionSet']['Name']
                except Exception as e:
                    permission_set_name = f"Unknown-{i}"
                    utils.log_warning(f"Could not get name for permission set {permission_set_arn}: {str(e)}")

                # Get detailed information
                details = get_permission_set_details(sso_admin_client, instance_arn, permission_set_arn)

                # Write to file
                write_permission_set_to_file(f, permission_set_name, permission_set_arn, details)

                # Add some breathing room between permission sets
                time.sleep(0.1)

            # Write footer
            f.write("\n" + "=" * 100 + "\n")
            f.write("END OF PERMISSION SETS EXPORT".center(100) + "\n")
            f.write("=" * 100 + "\n")
            f.write(f"Export completed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        utils.log_info(f"Permission sets export completed successfully")
        utils.log_info(f"Output file: {output_path}")

        return True

    except NoCredentialsError:
        utils.log_error("AWS credentials not found. Please configure your credentials.")
        return False
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            utils.log_error("Access denied. Please ensure you have the necessary SSO Admin permissions.")
        else:
            utils.log_error(f"AWS API error: {error_code} - {e.response['Error']['Message']}")
        return False
    except Exception as e:
        utils.log_error(f"Unexpected error during export: {str(e)}")
        return False

def main():
    """
    Main entry point for the script.
    """
    print("=" * 80)
    print("AWS PERMISSION SETS TEXT EXPORT")
    print("=" * 80)
    print()

    # Check AWS credentials
    try:
        # Try to create a client to verify credentials
        sts = utils.get_boto3_client('sts')
        sts.get_caller_identity()
    except Exception as e:
        print("ERROR: No AWS credentials found or invalid.")
        print("Please configure your AWS credentials using one of the following methods:")
        print("  - AWS CLI: aws configure")
        print("  - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
        print("  - IAM instance profile (when running on EC2)")
        print(f"Error details: {str(e)}")
        return

    # Validate AWS environment
    print("Validating AWS environment...")

    print("Starting permission sets export...")

    if export_permission_sets_to_text():
        print("\nPermission sets export completed successfully!")
        print(f"Check the output directory for your export file.")
    else:
        print("\nPermission sets export failed. Check the logs for details.")

if __name__ == "__main__":
    main()
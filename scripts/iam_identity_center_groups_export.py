#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS IAM Identity Center Groups Export Script
Date: SEP-23-2025

Description:
This script specifically exports IAM Identity Center (formerly AWS SSO) groups from AWS
environments. It provides detailed group information including members, external IDs, and metadata
for security auditing and compliance reporting.

Collected information includes: Group details, member counts, external IDs, creation dates,
and modification timestamps for comprehensive group governance analysis.
"""

import sys
import datetime
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


@utils.aws_error_handler("Getting IAM Identity Center instance", default_return=(None, None))
def get_identity_center_instance():
    """
    Get the IAM Identity Center instance ARN and Identity Store ID.

    Returns:
        tuple: (instance_arn, identity_store_id) or (None, None) if not configured
    """
    # sso-admin is a global service - use partition-aware home region

    home_region = utils.get_partition_default_region()

    sso_admin_client = utils.get_boto3_client('sso-admin', region_name=home_region)

    # List Identity Center instances
    response = sso_admin_client.list_instances()
    instances = response.get('Instances', [])

    if not instances:
        utils.log_warning("No IAM Identity Center instances found in this account.")
        utils.log_info("IAM Identity Center may not be enabled or configured.")
        return None, None

    # Use the first instance (typically there's only one)
    instance = instances[0]
    instance_arn = instance['InstanceArn']
    identity_store_id = instance['IdentityStoreId']

    utils.log_success(f"Found IAM Identity Center instance: {instance_arn}")
    return instance_arn, identity_store_id

@utils.aws_error_handler("Getting group members", default_return=[])
def get_group_members(identitystore_client, identity_store_id, group_id):
    """
    Get detailed member information for a group.

    Args:
        identitystore_client: boto3 identitystore client
        identity_store_id: Identity Store ID
        group_id: Group ID

    Returns:
        list: List of member details
    """
    members = []
    paginator = identitystore_client.get_paginator('list_group_memberships')

    for page in paginator.paginate(
        IdentityStoreId=identity_store_id,
        GroupId=group_id
    ):
        for membership in page.get('GroupMemberships', []):
            member_id = membership['MemberId']

            # Get member details
            if 'UserId' in member_id:
                try:
                    user_response = identitystore_client.describe_user(
                        IdentityStoreId=identity_store_id,
                        UserId=member_id['UserId']
                    )
                    member_name = user_response.get('UserName', member_id['UserId'])
                    member_type = 'User'
                    display_name = user_response.get('DisplayName', 'N/A')
                except Exception:
                    member_name = member_id['UserId']
                    member_type = 'User'
                    display_name = 'N/A'
            elif 'GroupId' in member_id:
                try:
                    group_response = identitystore_client.describe_group(
                        IdentityStoreId=identity_store_id,
                        GroupId=member_id['GroupId']
                    )
                    member_name = group_response.get('DisplayName', member_id['GroupId'])
                    member_type = 'Group'
                    display_name = group_response.get('DisplayName', 'N/A')
                except Exception:
                    member_name = member_id['GroupId']
                    member_type = 'Group'
                    display_name = 'N/A'
            else:
                member_name = 'Unknown'
                member_type = 'Unknown'
                display_name = 'N/A'

            members.append({
                'name': member_name,
                'type': member_type,
                'display_name': display_name,
                'membership_id': membership.get('MembershipId', 'N/A')
            })

    return members

@utils.aws_error_handler("Collecting Identity Center groups", default_return=[])
def collect_identity_center_groups(identity_store_id):
    """
    Collect IAM Identity Center groups with detailed information.

    Args:
        identity_store_id: The Identity Store ID

    Returns:
        list: List of group information dictionaries
    """
    if not identity_store_id:
        return []

    groups_data = []

    # identitystore is a global service - use partition-aware home region


    home_region = utils.get_partition_default_region()


    identitystore_client = utils.get_boto3_client('identitystore', region_name=home_region)

    # Get all groups using pagination
    paginator = identitystore_client.get_paginator('list_groups')

    # Count total groups first for progress tracking
    total_groups = 0
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        total_groups += len(page.get('Groups', []))

    if total_groups > 0:
        utils.log_info(f"Found {total_groups} Identity Center groups to process")
    else:
        utils.log_warning("No Identity Center groups found")
        return []

    # Reset paginator and process groups
    paginator = identitystore_client.get_paginator('list_groups')
    processed = 0

    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        groups = page.get('Groups', [])

        for group in groups:
            processed += 1
            progress = (processed / total_groups) * 100 if total_groups > 0 else 0
            group_name = group.get('DisplayName', 'Unknown')

            utils.log_info(f"[{progress:.1f}%] Processing group {processed}/{total_groups}: {group_name}")

            # Get detailed group member information
            members = get_group_members(identitystore_client, identity_store_id, group['GroupId'])

            # Format member information
            member_names = [m['name'] for m in members]
            member_types = [m['type'] for m in members]
            user_members = [m['name'] for m in members if m['type'] == 'User']
            group_members = [m['name'] for m in members if m['type'] == 'Group']

            # Get external ID
            external_ids = group.get('ExternalIds', [])
            external_id = external_ids[0].get('Id', 'N/A') if external_ids else 'N/A'

            group_info = {
                'Group ID': group.get('GroupId', 'N/A'),
                'Group Name': group.get('DisplayName', 'N/A'),
                'Description': group.get('Description', 'N/A'),
                'External ID': external_id,
                'Total Members': len(members),
                'User Members': len(user_members),
                'Group Members': len(group_members),
                'Member Names': ', '.join(member_names) if member_names else 'None',
                'User Member Names': ', '.join(user_members) if user_members else 'None',
                'Group Member Names': ', '.join(group_members) if group_members else 'None',
                'Created Date': group.get('Meta', {}).get('Created', 'N/A'),
                'Last Modified': group.get('Meta', {}).get('LastModified', 'N/A'),
                'Resource Version': group.get('Meta', {}).get('ResourceType', 'N/A')
            }

            groups_data.append(group_info)

    return groups_data

def export_to_excel(groups_data, account_id, account_name):
    """
    Export Identity Center groups data to Excel file with AWS naming convention.

    Args:
        groups_data: List of group information dictionaries
        account_id: AWS account ID
        account_name: AWS account name

    Returns:
        str: Filename of exported file or None if failed
    """
    if not groups_data:
        utils.log_warning("No Identity Center groups data to export.")
        return None

    try:
        # Import pandas after dependency check
        import pandas as pd

        # Generate filename with AWS identifier
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")

        # Use utils module to generate filename and save data with AWS identifier
        filename = utils.create_export_filename(
            account_name,
            "iam-identity-center-groups",
            "",
            current_date
        )

        # Create data frame
        groups_df = pd.DataFrame(groups_data)

        # Apply security sanitization to all DataFrames
        groups_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(groups_df))

        # Create summary data
        total_groups = len(groups_data)
        total_members = sum(group.get('Total Members', 0) for group in groups_data)
        groups_with_users = len([g for g in groups_data if g.get('User Members', 0) > 0])
        groups_with_nested_groups = len([g for g in groups_data if g.get('Group Members', 0) > 0])
        groups_with_external_ids = len([g for g in groups_data if g.get('External ID', 'N/A') != 'N/A'])

        summary_data = {
            'Metric': [
                'Total Groups',
                'Total Members (All Types)',
                'Groups with User Members',
                'Groups with Nested Groups',
                'Groups with External IDs',
                'Empty Groups',
                'Largest Group Size',
                'Average Group Size'
            ],
            'Count': [
                total_groups,
                total_members,
                groups_with_users,
                groups_with_nested_groups,
                groups_with_external_ids,
                len([g for g in groups_data if g.get('Total Members', 0) == 0]),
                max([g.get('Total Members', 0) for g in groups_data]) if groups_data else 0,
                round(total_members / total_groups, 2) if total_groups > 0 else 0
            ]
        }

        summary_df = pd.DataFrame(summary_data)

        # Apply security sanitization to summary DataFrame
        summary_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(summary_df))

        # Prepare data frames for multi-sheet export
        data_frames = {
            'Groups Summary': summary_df,
            'Groups Details': groups_df
        }

        # Save using utils function for multi-sheet Excel
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("AWS IAM Identity Center groups data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains {total_groups} groups with {total_members} total members")
            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def main():
    """
    Main function to orchestrate the Identity Center groups collection.
    """
    try:
        # Check dependencies first
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return

        # Import pandas after dependency check
        import pandas as pd

        # Print title and get account info
        account_id, account_name = utils.print_script_banner("AWS IAM IDENTITY CENTER GROUPS EXPORT")

        utils.log_info("Starting IAM Identity Center groups collection from AWS...")
        print("====================================================================")

        # Get Identity Center instance
        instance_arn, identity_store_id = get_identity_center_instance()

        if not identity_store_id:
            utils.log_error("Could not find IAM Identity Center instance. Exiting.")
            return

        # Collect Identity Center groups
        utils.log_info("Collecting Identity Center groups...")
        groups_data = collect_identity_center_groups(identity_store_id)

        if not groups_data:
            utils.log_warning("No Identity Center groups collected. Exiting.")
            return

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Export to Excel
        filename = export_to_excel(groups_data, account_id, account_name)

        if filename:
            utils.log_info(f"Results exported with AWS compliance markers")
            utils.log_info(f"Total groups processed: {len(groups_data)}")

            # Display some summary statistics
            total_members = sum(group.get('Total Members', 0) for group in groups_data)
            groups_with_members = len([g for g in groups_data if g.get('Total Members', 0) > 0])
            utils.log_info(f"Total members across all groups: {total_members}")
            utils.log_info(f"Groups with members: {groups_with_members}")

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
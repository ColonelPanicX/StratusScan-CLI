#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS IAM Identity Center Information Collection Script
Version: v2.0.0
Date: SEP-23-2025

Description:
This script collects comprehensive IAM Identity Center (formerly AWS SSO) information from AWS
environments including users, groups, permission sets, account assignments, and access patterns. The data
is exported to an Excel spreadsheet with AWS-specific naming convention for security auditing and
compliance reporting.

Collected information includes: Users, Groups, Permission Sets, Account Assignments, Application Assignments,
and Identity Source configuration for comprehensive identity governance analysis.
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

def print_title():
    """
    Print the script title and account information.

    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS IAM IDENTITY CENTER INFORMATION COLLECTION")
    print("====================================================================")
    print("Version: v2.0.0                       Date: SEP-23-2025")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")

    # Get account information
    account_id, account_name = utils.get_account_info()
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")

    return account_id, account_name

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

def get_user_email(user):
    """Extract email from user object."""
    emails = user.get('Emails', [])
    if emails:
        primary_email = next((email['Value'] for email in emails if email.get('Primary', False)), None)
        return primary_email or emails[0].get('Value', 'N/A')
    return 'N/A'

def get_user_external_id(user):
    """Extract external ID from user object."""
    external_ids = user.get('ExternalIds', [])
    if external_ids:
        return external_ids[0].get('Id', 'N/A')
    return 'N/A'

@utils.aws_error_handler("Getting user group memberships", default_return='Unknown')
def get_user_group_memberships(identitystore_client, identity_store_id, user_id):
    """
    Get group memberships for a user.

    Args:
        identitystore_client: boto3 identitystore client
        identity_store_id: Identity Store ID
        user_id: User ID

    Returns:
        str: Comma-separated list of group names
    """
    paginator = identitystore_client.get_paginator('list_group_memberships_for_member')
    group_names = []

    for page in paginator.paginate(
        IdentityStoreId=identity_store_id,
        MemberId={'UserId': user_id}
    ):
        for membership in page.get('GroupMemberships', []):
            group_id = membership['GroupId']

            # Get group details
            try:
                group_response = identitystore_client.describe_group(
                    IdentityStoreId=identity_store_id,
                    GroupId=group_id
                )
                group_name = group_response.get('DisplayName', group_id)
                group_names.append(group_name)
            except Exception:
                group_names.append(group_id)  # Fallback to ID if name unavailable

    return ', '.join(group_names) if group_names else 'None'

@utils.aws_error_handler("Getting user account assignments", default_return='Unknown')
def get_user_account_assignments(sso_admin_client, instance_arn, user_id):
    """
    Get AWS account assignments for a user.

    Args:
        sso_admin_client: boto3 sso-admin client
        instance_arn: IAM Identity Center instance ARN
        user_id: User ID

    Returns:
        str: Comma-separated list of account assignments (account:permission_set format)
    """
    # Get all accounts first to map account IDs to names
    org_client = utils.get_boto3_client('organizations')
    accounts = {}
    try:
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            for account in page.get('Accounts', []):
                accounts[account['Id']] = account.get('Name', account['Id'])
    except Exception:
        # If organizations access fails, we'll use account IDs
        pass

    # Get account assignments for the user
    paginator = sso_admin_client.get_paginator('list_account_assignments')
    assignments = []

    # We need to check across all permission sets and accounts
    # First, get all permission sets
    ps_paginator = sso_admin_client.get_paginator('list_permission_sets')
    permission_sets = []

    for page in ps_paginator.paginate(InstanceArn=instance_arn):
        permission_sets.extend(page.get('PermissionSets', []))

    # For each permission set, check for assignments
    for permission_set_arn in permission_sets:
        try:
            for page in paginator.paginate(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            ):
                for assignment in page.get('AccountAssignments', []):
                    if (assignment.get('PrincipalType') == 'USER' and
                        assignment.get('PrincipalId') == user_id):

                        account_id = assignment.get('TargetId')
                        account_name = accounts.get(account_id, account_id)

                        # Get permission set name
                        try:
                            ps_response = sso_admin_client.describe_permission_set(
                                InstanceArn=instance_arn,
                                PermissionSetArn=permission_set_arn
                            )
                            ps_name = ps_response['PermissionSet'].get('Name', 'Unknown')
                        except Exception:
                            ps_name = permission_set_arn.split('/')[-1]  # Use ARN suffix as fallback

                        assignments.append(f"{account_name}:{ps_name}")
        except Exception as e:
            continue  # Skip permission sets that can't be accessed

    return ', '.join(assignments) if assignments else 'None'

@utils.aws_error_handler("Getting user application assignments", default_return='Service Not Available')
def get_user_application_assignments(sso_admin_client, instance_arn, user_id):
    """
    Get application assignments for a user.

    Args:
        sso_admin_client: boto3 sso-admin client
        instance_arn: IAM Identity Center instance ARN
        user_id: User ID

    Returns:
        str: Comma-separated list of application names
    """
    # List all applications first
    try:
        apps_paginator = sso_admin_client.get_paginator('list_applications')
        applications = []

        for page in apps_paginator.paginate(InstanceArn=instance_arn):
            applications.extend(page.get('Applications', []))
    except Exception:
        # list_applications might not be available in all AWS regions
        return 'Service Not Available'

    user_applications = []

    # For each application, check if user has assignments
    for app in applications:
        app_arn = app.get('ApplicationArn')
        app_name = app.get('Name', app_arn.split('/')[-1] if app_arn else 'Unknown')

        try:
            # List assignments for this application
            assign_paginator = sso_admin_client.get_paginator('list_application_assignments')

            for page in assign_paginator.paginate(ApplicationArn=app_arn):
                for assignment in page.get('ApplicationAssignments', []):
                    if (assignment.get('PrincipalType') == 'USER' and
                        assignment.get('PrincipalId') == user_id):
                        user_applications.append(app_name)
                        break  # Found assignment for this app, move to next
        except Exception:
            # Skip applications that can't be accessed or don't support assignments
            continue

    return ', '.join(user_applications) if user_applications else 'None'

@utils.aws_error_handler("Collecting Identity Center users", default_return=[])
def collect_identity_center_users(identity_store_id, instance_arn):
    """
    Collect IAM Identity Center users.

    Args:
        identity_store_id: The Identity Store ID
        instance_arn: IAM Identity Center instance ARN

    Returns:
        list: List of user information dictionaries
    """
    if not identity_store_id:
        return []

    users_data = []

    # identitystore is a global service - use partition-aware home region


    home_region = utils.get_partition_default_region()


    identitystore_client = utils.get_boto3_client('identitystore', region_name=home_region)
    # sso-admin is a global service - use partition-aware home region

    home_region = utils.get_partition_default_region()

    sso_admin_client = utils.get_boto3_client('sso-admin', region_name=home_region)

    # Get all users using pagination
    paginator = identitystore_client.get_paginator('list_users')

    # Count total users first for progress tracking
    total_users = 0
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        total_users += len(page.get('Users', []))

    if total_users > 0:
        utils.log_info(f"Found {total_users} Identity Center users to process")

    # Reset paginator and process users
    paginator = identitystore_client.get_paginator('list_users')
    processed = 0

    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        users = page.get('Users', [])

        for user in users:
            processed += 1
            progress = (processed / total_users) * 100 if total_users > 0 else 0
            user_name = user.get('UserName', 'Unknown')

            utils.log_info(f"[{progress:.1f}%] Processing user {processed}/{total_users}: {user_name}")

            # Get user group memberships
            group_memberships = get_user_group_memberships(identitystore_client, identity_store_id, user['UserId'])

            # Get user account assignments
            account_assignments = get_user_account_assignments(sso_admin_client, instance_arn, user['UserId'])

            # Get user application assignments
            application_assignments = get_user_application_assignments(sso_admin_client, instance_arn, user['UserId'])

            user_info = {
                'User ID': user.get('UserId', 'N/A'),
                'User Name': user.get('UserName', 'N/A'),
                'Display Name': user.get('DisplayName', 'N/A'),
                'Given Name': user.get('Name', {}).get('GivenName', 'N/A'),
                'Family Name': user.get('Name', {}).get('FamilyName', 'N/A'),
                'Email': get_user_email(user),
                'Status': 'Active' if user.get('Active', True) else 'Inactive',
                'External ID': get_user_external_id(user),
                'Groups': group_memberships,
                'AWS Accounts': account_assignments,
                'Applications': application_assignments,
                'Created Date': user.get('Meta', {}).get('Created', 'N/A'),
                'Last Modified': user.get('Meta', {}).get('LastModified', 'N/A')
            }

            users_data.append(user_info)

    return users_data

def get_group_external_id(group):
    """Extract external ID from group object."""
    external_ids = group.get('ExternalIds', [])
    if external_ids:
        return external_ids[0].get('Id', 'N/A')
    return 'N/A'

@utils.aws_error_handler("Getting group member count", default_return=0)
def get_group_member_count(identitystore_client, identity_store_id, group_id):
    """
    Get the number of members in a group.

    Args:
        identitystore_client: boto3 identitystore client
        identity_store_id: Identity Store ID
        group_id: Group ID

    Returns:
        int: Number of members in the group
    """
    paginator = identitystore_client.get_paginator('list_group_memberships')
    member_count = 0

    for page in paginator.paginate(
        IdentityStoreId=identity_store_id,
        GroupId=group_id
    ):
        member_count += len(page.get('GroupMemberships', []))

    return member_count

@utils.aws_error_handler("Collecting Identity Center groups", default_return=[])
def collect_identity_center_groups(identity_store_id):
    """
    Collect IAM Identity Center groups.

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

            # Get group member count
            member_count = get_group_member_count(identitystore_client, identity_store_id, group['GroupId'])

            group_info = {
                'Group ID': group.get('GroupId', 'N/A'),
                'Group Name': group.get('DisplayName', 'N/A'),
                'Description': group.get('Description', 'N/A'),
                'External ID': get_group_external_id(group),
                'Member Count': member_count,
                'Created Date': group.get('Meta', {}).get('Created', 'N/A'),
                'Last Modified': group.get('Meta', {}).get('LastModified', 'N/A')
            }

            groups_data.append(group_info)

    return groups_data

@utils.aws_error_handler("Getting permission set managed policies", default_return='Unknown')
def get_permission_set_managed_policies(sso_admin_client, instance_arn, permission_set_arn):
    """Get managed policies attached to a permission set."""
    paginator = sso_admin_client.get_paginator('list_managed_policies_in_permission_set')
    policies = []

    for page in paginator.paginate(
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn
    ):
        for policy in page.get('AttachedManagedPolicies', []):
            policies.append(policy.get('Name', policy.get('Arn', 'Unknown')))

    return ', '.join(policies) if policies else 'None'

@utils.aws_error_handler("Getting permission set inline policy", default_return=None)
def get_permission_set_inline_policy(sso_admin_client, instance_arn, permission_set_arn):
    """Check if permission set has an inline policy."""
    response = sso_admin_client.get_inline_policy_for_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn
    )
    return response.get('InlinePolicy', '')

@utils.aws_error_handler("Getting permission set assignments count", default_return=0)
def get_permission_set_assignments_count(sso_admin_client, instance_arn, permission_set_arn):
    """Get the number of account assignments for a permission set."""
    paginator = sso_admin_client.get_paginator('list_account_assignments')
    assignments_count = 0

    for page in paginator.paginate(
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn
    ):
        assignments_count += len(page.get('AccountAssignments', []))

    return assignments_count

@utils.aws_error_handler("Getting permission set tags", default_return='Unknown')
def get_permission_set_tags(sso_admin_client, instance_arn, permission_set_arn):
    """Get tags for a permission set."""
    response = sso_admin_client.list_tags_for_resource(
        InstanceArn=instance_arn,
        ResourceArn=permission_set_arn
    )
    tags = response.get('Tags', [])
    tag_strings = [f"{tag['Key']}={tag['Value']}" for tag in tags]
    return ', '.join(tag_strings) if tag_strings else 'None'

@utils.aws_error_handler("Collecting permission sets", default_return=[])
def collect_permission_sets(instance_arn):
    """
    Collect IAM Identity Center permission sets.

    Args:
        instance_arn: IAM Identity Center instance ARN

    Returns:
        list: List of permission set information dictionaries
    """
    if not instance_arn:
        return []

    permission_sets_data = []

    # sso-admin is a global service - use partition-aware home region


    home_region = utils.get_partition_default_region()


    sso_admin_client = utils.get_boto3_client('sso-admin', region_name=home_region)

    # Get all permission sets using pagination
    paginator = sso_admin_client.get_paginator('list_permission_sets')

    # Count total permission sets first for progress tracking
    total_permission_sets = 0
    for page in paginator.paginate(InstanceArn=instance_arn):
        total_permission_sets += len(page.get('PermissionSets', []))

    if total_permission_sets > 0:
        utils.log_info(f"Found {total_permission_sets} permission sets to process")

    # Reset paginator and process permission sets
    paginator = sso_admin_client.get_paginator('list_permission_sets')
    processed = 0

    for page in paginator.paginate(InstanceArn=instance_arn):
        permission_sets = page.get('PermissionSets', [])

        for permission_set_arn in permission_sets:
            processed += 1
            progress = (processed / total_permission_sets) * 100 if total_permission_sets > 0 else 0

            utils.log_info(f"[{progress:.1f}%] Processing permission set {processed}/{total_permission_sets}")

            # Get permission set details
            try:
                ps_response = sso_admin_client.describe_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                )

                permission_set = ps_response['PermissionSet']

                # Get managed policies
                managed_policies = get_permission_set_managed_policies(sso_admin_client, instance_arn, permission_set_arn)

                # Get inline policy
                inline_policy = get_permission_set_inline_policy(sso_admin_client, instance_arn, permission_set_arn)

                # Get account assignments count
                assignments_count = get_permission_set_assignments_count(sso_admin_client, instance_arn, permission_set_arn)

                permission_set_info = {
                    'Permission Set ARN': permission_set_arn,
                    'Name': permission_set.get('Name', 'N/A'),
                    'Description': permission_set.get('Description', 'N/A'),
                    'Session Duration': permission_set.get('SessionDuration', 'N/A'),
                    'Relay State': permission_set.get('RelayState', 'N/A'),
                    'Managed Policies': managed_policies,
                    'Has Inline Policy': 'Yes' if inline_policy else 'No',
                    'Account Assignments': assignments_count,
                    'Created Date': permission_set.get('CreatedDate', 'N/A'),
                    'Tags': get_permission_set_tags(sso_admin_client, instance_arn, permission_set_arn)
                }

                permission_sets_data.append(permission_set_info)

            except Exception as e:
                utils.log_warning(f"Error processing permission set {permission_set_arn}: {e}")

    return permission_sets_data

def export_to_excel(users_data, groups_data, permission_sets_data, account_id, account_name):
    """
    Export Identity Center data to Excel file with AWS naming convention.

    Args:
        users_data: List of user information dictionaries
        groups_data: List of group information dictionaries
        permission_sets_data: List of permission set information dictionaries
        account_id: AWS account ID
        account_name: AWS account name

    Returns:
        str: Filename of exported file or None if failed
    """
    if not users_data and not groups_data and not permission_sets_data:
        utils.log_warning("No Identity Center data to export.")
        return None

    try:
        # Import pandas after dependency check
        import pandas as pd

        # Generate filename with AWS identifier
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")

        # Use utils module to generate filename and save data with AWS identifier
        filename = utils.create_export_filename(
            account_name,
            "iam-identity-center",
            "",
            current_date
        )

        # Create data frames for multi-sheet export
        data_frames = {}

        if users_data:
            users_df = pd.DataFrame(users_data)
            users_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(users_df))
            data_frames['Identity Center Users'] = users_df

        if groups_data:
            groups_df = pd.DataFrame(groups_data)
            groups_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(groups_df))
            data_frames['Identity Center Groups'] = groups_df

        if permission_sets_data:
            permission_sets_df = pd.DataFrame(permission_sets_data)
            permission_sets_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(permission_sets_df))
            data_frames['Permission Sets'] = permission_sets_df

        # Create summary data
        summary_data = {
            'Metric': [
                'Total Users',
                'Active Users',
                'Inactive Users',
                'Total Groups',
                'Total Permission Sets',
                'Users with Groups',
                'Users with AWS Account Assignments',
                'Users with Application Assignments',
                'Permission Sets with Managed Policies',
                'Permission Sets with Inline Policies'
            ],
            'Count': [
                len(users_data),
                len([u for u in users_data if u.get('Status') == 'Active']),
                len([u for u in users_data if u.get('Status') == 'Inactive']),
                len(groups_data),
                len(permission_sets_data),
                len([u for u in users_data if u.get('Groups', 'None') != 'None']),
                len([u for u in users_data if u.get('AWS Accounts', 'None') not in ['None', 'Unknown']]),
                len([u for u in users_data if u.get('Applications', 'None') not in ['None', 'Unknown', 'Service Not Available']]),
                len([p for p in permission_sets_data if p.get('Managed Policies', 'None') != 'None']),
                len([p for p in permission_sets_data if p.get('Has Inline Policy') == 'Yes'])
            ]
        }

        summary_df = pd.DataFrame(summary_data)
        data_frames['Summary'] = summary_df

        # Save using utils function for multi-sheet Excel
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("AWS IAM Identity Center data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains {len(users_data)} users, {len(groups_data)} groups, and {len(permission_sets_data)} permission sets")
            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def main():
    """
    Main function to orchestrate the Identity Center information collection.
    """
    try:
        # Check dependencies first
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return

        # Import pandas after dependency check
        import pandas as pd

        # Print title and get account info
        account_id, account_name = print_title()

        with utils.handle_aws_operation("Validating AWS credentials"):
            sts = utils.get_boto3_client('sts')
            sts.get_caller_identity()
            utils.log_success("AWS credentials validated")

        utils.log_info("Starting IAM Identity Center information collection from AWS...")
        print("====================================================================")

        # Get Identity Center instance
        instance_arn, identity_store_id = get_identity_center_instance()

        if not instance_arn:
            utils.log_error("Could not find IAM Identity Center instance. Exiting.")
            return

        # Collect Identity Center data
        utils.log_info("Collecting Identity Center users...")
        users_data = collect_identity_center_users(identity_store_id, instance_arn)

        utils.log_info("Collecting Identity Center groups...")
        groups_data = collect_identity_center_groups(identity_store_id)

        utils.log_info("Collecting permission sets...")
        permission_sets_data = collect_permission_sets(instance_arn)

        if not users_data and not groups_data and not permission_sets_data:
            utils.log_warning("No Identity Center data collected. Exiting.")
            return

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Export to Excel
        filename = export_to_excel(users_data, groups_data, permission_sets_data, account_id, account_name)

        if filename:
            utils.log_info(f"Results exported with AWS compliance markers")
            utils.log_info(f"Total users processed: {len(users_data)}")
            utils.log_info(f"Total groups processed: {len(groups_data)}")
            utils.log_info(f"Total permission sets processed: {len(permission_sets_data)}")

            # Display some summary statistics
            if users_data:
                active_users = len([u for u in users_data if u.get('Status') == 'Active'])
                utils.log_info(f"Active users: {active_users}")
                users_with_groups = len([u for u in users_data if u.get('Groups', 'None') != 'None'])
                utils.log_info(f"Users with group memberships: {users_with_groups}")

                users_with_accounts = len([u for u in users_data if u.get('AWS Accounts', 'None') not in ['None', 'Unknown']])
                utils.log_info(f"Users with AWS account assignments: {users_with_accounts}")

                users_with_apps = len([u for u in users_data if u.get('Applications', 'None') not in ['None', 'Unknown', 'Service Not Available']])
                utils.log_info(f"Users with application assignments: {users_with_apps}")

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

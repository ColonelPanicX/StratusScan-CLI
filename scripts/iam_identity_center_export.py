#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS IAM Identity Center Export Script
Date: FEB-22-2026

Description:
This script collects and exports IAM Identity Center (formerly AWS SSO) resources from AWS
environments. It supports exporting Users/Groups/Permission Sets combined, Groups only,
Permission Sets only, or a comprehensive export in a single workbook. All data is exported
to Excel format with AWS-specific naming conventions for security auditing and compliance
reporting.

Menu:
  1. Users, Groups & Permission Sets (combined)
  2. Groups
  3. Permission Sets
  4. Comprehensive
"""

import sys
import datetime
import json
from pathlib import Path
from botocore.exceptions import ClientError

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


# ---------------------------------------------------------------------------
# Instance discovery
# ---------------------------------------------------------------------------

@utils.aws_error_handler("Getting IAM Identity Center instance", default_return=(None, None))
def get_identity_center_instance():
    """
    Get the IAM Identity Center instance ARN and Identity Store ID.

    Returns:
        tuple: (instance_arn, identity_store_id) or (None, None) if not configured
    """
    home_region = utils.get_partition_default_region()
    sso_admin_client = utils.get_boto3_client('sso-admin', region_name=home_region)

    response = sso_admin_client.list_instances()
    instances = response.get('Instances', [])

    if not instances:
        utils.log_warning("No IAM Identity Center instances found in this account.")
        utils.log_info("IAM Identity Center may not be enabled or configured.")
        return None, None

    instance = instances[0]
    instance_arn = instance['InstanceArn']
    identity_store_id = instance['IdentityStoreId']

    utils.log_success(f"Found IAM Identity Center instance: {instance_arn}")
    return instance_arn, identity_store_id


# ---------------------------------------------------------------------------
# User helper functions (from iam_identity_center_export.py)
# ---------------------------------------------------------------------------

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


def get_user_email_verified(user):
    """Check if user email is verified (from comprehensive script)."""
    emails = user.get('Emails', [])
    if emails:
        primary_email = next((email for email in emails if email.get('Primary', False)), emails[0])
        return primary_email.get('Verified', False)
    return False


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
            try:
                group_response = identitystore_client.describe_group(
                    IdentityStoreId=identity_store_id,
                    GroupId=group_id
                )
                group_name = group_response.get('DisplayName', group_id)
                group_names.append(group_name)
            except Exception:
                group_names.append(group_id)

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
    org_client = utils.get_boto3_client('organizations')
    accounts = {}
    try:
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            for account in page.get('Accounts', []):
                accounts[account['Id']] = account.get('Name', account['Id'])
    except Exception:
        pass

    paginator = sso_admin_client.get_paginator('list_account_assignments')
    assignments = []

    ps_paginator = sso_admin_client.get_paginator('list_permission_sets')
    permission_sets = []
    for page in ps_paginator.paginate(InstanceArn=instance_arn):
        permission_sets.extend(page.get('PermissionSets', []))

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
                        try:
                            ps_response = sso_admin_client.describe_permission_set(
                                InstanceArn=instance_arn,
                                PermissionSetArn=permission_set_arn
                            )
                            ps_name = ps_response['PermissionSet'].get('Name', 'Unknown')
                        except Exception:
                            ps_name = permission_set_arn.split('/')[-1]
                        assignments.append(f"{account_name}:{ps_name}")
        except Exception:
            continue

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
    try:
        apps_paginator = sso_admin_client.get_paginator('list_applications')
        applications = []
        for page in apps_paginator.paginate(InstanceArn=instance_arn):
            applications.extend(page.get('Applications', []))
    except Exception:
        return 'Service Not Available'

    user_applications = []

    for app in applications:
        app_arn = app.get('ApplicationArn')
        app_name = app.get('Name', app_arn.split('/')[-1] if app_arn else 'Unknown')

        try:
            assign_paginator = sso_admin_client.get_paginator('list_application_assignments')
            for page in assign_paginator.paginate(ApplicationArn=app_arn):
                for assignment in page.get('ApplicationAssignments', []):
                    if (assignment.get('PrincipalType') == 'USER' and
                            assignment.get('PrincipalId') == user_id):
                        user_applications.append(app_name)
                        break
        except Exception:
            continue

    return ', '.join(user_applications) if user_applications else 'None'


@utils.aws_error_handler("Collecting Identity Center users", default_return=[])
def collect_identity_center_users(identity_store_id, instance_arn):
    """
    Collect IAM Identity Center users (combined export).

    Args:
        identity_store_id: The Identity Store ID
        instance_arn: IAM Identity Center instance ARN

    Returns:
        list: List of user information dictionaries
    """
    if not identity_store_id:
        return []

    users_data = []
    home_region = utils.get_partition_default_region()
    identitystore_client = utils.get_boto3_client('identitystore', region_name=home_region)
    sso_admin_client = utils.get_boto3_client('sso-admin', region_name=home_region)

    paginator = identitystore_client.get_paginator('list_users')

    total_users = 0
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        total_users += len(page.get('Users', []))

    if total_users > 0:
        utils.log_info(f"Found {total_users} Identity Center users to process")

    paginator = identitystore_client.get_paginator('list_users')
    processed = 0

    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        users = page.get('Users', [])

        for user in users:
            processed += 1
            progress = (processed / total_users) * 100 if total_users > 0 else 0
            user_name = user.get('UserName', 'Unknown')

            utils.log_info(f"[{progress:.1f}%] Processing user {processed}/{total_users}: {user_name}")

            group_memberships = get_user_group_memberships(identitystore_client, identity_store_id, user['UserId'])
            account_assignments = get_user_account_assignments(sso_admin_client, instance_arn, user['UserId'])
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


# ---------------------------------------------------------------------------
# Group helper functions
# ---------------------------------------------------------------------------

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
    Collect IAM Identity Center groups (simple version, for combined export option 1).

    Args:
        identity_store_id: The Identity Store ID

    Returns:
        list: List of group information dictionaries
    """
    if not identity_store_id:
        return []

    groups_data = []
    home_region = utils.get_partition_default_region()
    identitystore_client = utils.get_boto3_client('identitystore', region_name=home_region)

    paginator = identitystore_client.get_paginator('list_groups')

    total_groups = 0
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        total_groups += len(page.get('Groups', []))

    if total_groups > 0:
        utils.log_info(f"Found {total_groups} Identity Center groups to process")

    paginator = identitystore_client.get_paginator('list_groups')
    processed = 0

    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        groups = page.get('Groups', [])

        for group in groups:
            processed += 1
            progress = (processed / total_groups) * 100 if total_groups > 0 else 0
            group_name = group.get('DisplayName', 'Unknown')

            utils.log_info(f"[{progress:.1f}%] Processing group {processed}/{total_groups}: {group_name}")

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


@utils.aws_error_handler("Getting group members", default_return=[])
def _get_group_members_detailed(identitystore_client, identity_store_id, group_id):
    """
    Get detailed member information for a group (from iam_identity_center_groups_export.py).

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


@utils.aws_error_handler("Collecting Identity Center groups (detailed)", default_return=[])
def collect_identity_center_groups_detailed(identity_store_id):
    """
    Collect IAM Identity Center groups with detailed member information.
    Used for Groups-only export (option 2).

    Args:
        identity_store_id: The Identity Store ID

    Returns:
        list: List of group information dictionaries with member details
    """
    if not identity_store_id:
        return []

    groups_data = []
    home_region = utils.get_partition_default_region()
    identitystore_client = utils.get_boto3_client('identitystore', region_name=home_region)

    paginator = identitystore_client.get_paginator('list_groups')

    total_groups = 0
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        total_groups += len(page.get('Groups', []))

    if total_groups > 0:
        utils.log_info(f"Found {total_groups} Identity Center groups to process")
    else:
        utils.log_warning("No Identity Center groups found")
        return []

    paginator = identitystore_client.get_paginator('list_groups')
    processed = 0

    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        groups = page.get('Groups', [])

        for group in groups:
            processed += 1
            progress = (processed / total_groups) * 100 if total_groups > 0 else 0
            group_name = group.get('DisplayName', 'Unknown')

            utils.log_info(f"[{progress:.1f}%] Processing group {processed}/{total_groups}: {group_name}")

            members = _get_group_members_detailed(identitystore_client, identity_store_id, group['GroupId'])

            member_names = [m['name'] for m in members]
            user_members = [m['name'] for m in members if m['type'] == 'User']
            group_members = [m['name'] for m in members if m['type'] == 'Group']

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


# ---------------------------------------------------------------------------
# Permission set helper functions (from iam_identity_center_export.py)
# ---------------------------------------------------------------------------

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
    home_region = utils.get_partition_default_region()
    sso_admin_client = utils.get_boto3_client('sso-admin', region_name=home_region)

    paginator = sso_admin_client.get_paginator('list_permission_sets')

    total_permission_sets = 0
    for page in paginator.paginate(InstanceArn=instance_arn):
        total_permission_sets += len(page.get('PermissionSets', []))

    if total_permission_sets > 0:
        utils.log_info(f"Found {total_permission_sets} permission sets to process")

    paginator = sso_admin_client.get_paginator('list_permission_sets')
    processed = 0

    for page in paginator.paginate(InstanceArn=instance_arn):
        permission_sets = page.get('PermissionSets', [])

        for permission_set_arn in permission_sets:
            processed += 1
            progress = (processed / total_permission_sets) * 100 if total_permission_sets > 0 else 0

            utils.log_info(f"[{progress:.1f}%] Processing permission set {processed}/{total_permission_sets}")

            try:
                ps_response = sso_admin_client.describe_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                )

                permission_set = ps_response['PermissionSet']

                managed_policies = get_permission_set_managed_policies(sso_admin_client, instance_arn, permission_set_arn)
                inline_policy = get_permission_set_inline_policy(sso_admin_client, instance_arn, permission_set_arn)
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


# ---------------------------------------------------------------------------
# Comprehensive collection functions (from iam_identity_center_comprehensive_export.py)
# ---------------------------------------------------------------------------

@utils.aws_error_handler("Collecting comprehensive Identity Center users", default_return=[])
def collect_comprehensive_users(identity_store_id, instance_arn):
    """
    Collect comprehensive IAM Identity Center user information.

    Args:
        identity_store_id: The Identity Store ID
        instance_arn: IAM Identity Center instance ARN

    Returns:
        list: List of comprehensive user information dictionaries
    """
    if not identity_store_id:
        return []

    users_data = []
    home_region = utils.get_partition_default_region()
    identitystore_client = utils.get_boto3_client('identitystore', region_name=home_region)
    sso_admin_client = utils.get_boto3_client('sso-admin', region_name=home_region)

    paginator = identitystore_client.get_paginator('list_users')

    total_users = 0
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        total_users += len(page.get('Users', []))

    if total_users > 0:
        utils.log_info(f"Found {total_users} Identity Center users to process")

    paginator = identitystore_client.get_paginator('list_users')
    processed = 0

    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        users = page.get('Users', [])

        for user in users:
            processed += 1
            progress = (processed / total_users) * 100 if total_users > 0 else 0
            user_name = user.get('UserName', 'Unknown')

            utils.log_info(f"[{progress:.1f}%] Processing user {processed}/{total_users}: {user_name}")

            group_memberships = get_user_group_memberships(identitystore_client, identity_store_id, user['UserId'])
            account_assignments = get_user_account_assignments(sso_admin_client, instance_arn, user['UserId'])
            application_assignments = get_user_application_assignments(sso_admin_client, instance_arn, user['UserId'])

            addresses = user.get('Addresses', [])
            phone_numbers = user.get('PhoneNumbers', [])

            primary_address = 'N/A'
            if addresses:
                primary_addr = next((addr for addr in addresses if addr.get('Primary', False)), addresses[0])
                if primary_addr:
                    addr_parts = []
                    if primary_addr.get('StreetAddress'):
                        addr_parts.append(primary_addr['StreetAddress'])
                    if primary_addr.get('Locality'):
                        addr_parts.append(primary_addr['Locality'])
                    if primary_addr.get('Region'):
                        addr_parts.append(primary_addr['Region'])
                    if primary_addr.get('PostalCode'):
                        addr_parts.append(primary_addr['PostalCode'])
                    primary_address = ', '.join(addr_parts)

            primary_phone = 'N/A'
            if phone_numbers:
                primary_ph = next((phone for phone in phone_numbers if phone.get('Primary', False)), phone_numbers[0])
                if primary_ph:
                    primary_phone = primary_ph.get('Value', 'N/A')

            user_info = {
                'User ID': user.get('UserId', 'N/A'),
                'User Name': user.get('UserName', 'N/A'),
                'Display Name': user.get('DisplayName', 'N/A'),
                'Nick Name': user.get('NickName', 'N/A'),
                'Profile URL': user.get('ProfileUrl', 'N/A'),
                'Given Name': user.get('Name', {}).get('GivenName', 'N/A'),
                'Middle Name': user.get('Name', {}).get('MiddleName', 'N/A'),
                'Family Name': user.get('Name', {}).get('FamilyName', 'N/A'),
                'Formatted Name': user.get('Name', {}).get('Formatted', 'N/A'),
                'Honorific Prefix': user.get('Name', {}).get('HonorificPrefix', 'N/A'),
                'Honorific Suffix': user.get('Name', {}).get('HonorificSuffix', 'N/A'),
                'Email': get_user_email(user),
                'Email Verified': 'Yes' if get_user_email_verified(user) else 'No',
                'Primary Phone': primary_phone,
                'Primary Address': primary_address[:200],
                'User Type': user.get('UserType', 'N/A'),
                'Title': user.get('Title', 'N/A'),
                'Preferred Language': user.get('PreferredLanguage', 'N/A'),
                'Locale': user.get('Locale', 'N/A'),
                'Timezone': user.get('Timezone', 'N/A'),
                'Status': 'Active' if user.get('Active', True) else 'Inactive',
                'External ID': get_user_external_id(user),
                'Groups': group_memberships,
                'AWS Accounts': account_assignments,
                'Applications': application_assignments,
                'Group Count': len(group_memberships.split(', ')) if group_memberships != 'None' else 0,
                'Account Assignment Count': len(account_assignments.split(', ')) if account_assignments not in ['None', 'Unknown'] else 0,
                'Application Assignment Count': len(application_assignments.split(', ')) if application_assignments not in ['None', 'Unknown', 'Service Not Available'] else 0,
                'Created Date': user.get('Meta', {}).get('Created', 'N/A'),
                'Last Modified': user.get('Meta', {}).get('LastModified', 'N/A'),
                'Resource Type': user.get('Meta', {}).get('ResourceType', 'N/A')
            }

            users_data.append(user_info)

    return users_data


@utils.aws_error_handler("Getting group member details", default_return='Unknown')
def get_group_member_details(identitystore_client, identity_store_id, group_id):
    """Get detailed member information for a group (comprehensive version)."""
    paginator = identitystore_client.get_paginator('list_group_memberships')
    member_names = []

    for page in paginator.paginate(
        IdentityStoreId=identity_store_id,
        GroupId=group_id
    ):
        for membership in page.get('GroupMemberships', []):
            member_id = membership['MemberId']

            if 'UserId' in member_id:
                try:
                    user_response = identitystore_client.describe_user(
                        IdentityStoreId=identity_store_id,
                        UserId=member_id['UserId']
                    )
                    user_name = user_response.get('UserName', member_id['UserId'])
                    member_names.append(f"User: {user_name}")
                except Exception:
                    member_names.append(f"User: {member_id['UserId']}")

    return ', '.join(member_names) if member_names else 'No Members'


@utils.aws_error_handler("Getting group account assignments", default_return='Unknown')
def get_group_account_assignments(sso_admin_client, instance_arn, group_id):
    """Get AWS account assignments for a group."""
    org_client = utils.get_boto3_client('organizations')
    accounts = {}
    try:
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            for account in page.get('Accounts', []):
                accounts[account['Id']] = account.get('Name', account['Id'])
    except Exception:
        pass

    paginator = sso_admin_client.get_paginator('list_account_assignments')
    assignments = []

    ps_paginator = sso_admin_client.get_paginator('list_permission_sets')
    permission_sets = []
    for page in ps_paginator.paginate(InstanceArn=instance_arn):
        permission_sets.extend(page.get('PermissionSets', []))

    for permission_set_arn in permission_sets:
        try:
            for page in paginator.paginate(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            ):
                for assignment in page.get('AccountAssignments', []):
                    if (assignment.get('PrincipalType') == 'GROUP' and
                            assignment.get('PrincipalId') == group_id):
                        account_id = assignment.get('TargetId')
                        account_name = accounts.get(account_id, account_id)
                        try:
                            ps_response = sso_admin_client.describe_permission_set(
                                InstanceArn=instance_arn,
                                PermissionSetArn=permission_set_arn
                            )
                            ps_name = ps_response['PermissionSet'].get('Name', 'Unknown')
                        except Exception:
                            ps_name = permission_set_arn.split('/')[-1]
                        assignments.append(f"{account_name}:{ps_name}")
        except Exception:
            continue

    return ', '.join(assignments) if assignments else 'None'


@utils.aws_error_handler("Collecting comprehensive Identity Center groups", default_return=[])
def collect_comprehensive_groups(identity_store_id, instance_arn):
    """
    Collect comprehensive IAM Identity Center group information.

    Args:
        identity_store_id: The Identity Store ID
        instance_arn: IAM Identity Center instance ARN

    Returns:
        list: List of comprehensive group information dictionaries
    """
    if not identity_store_id:
        return []

    groups_data = []
    home_region = utils.get_partition_default_region()
    identitystore_client = utils.get_boto3_client('identitystore', region_name=home_region)
    sso_admin_client = utils.get_boto3_client('sso-admin', region_name=home_region)

    paginator = identitystore_client.get_paginator('list_groups')

    total_groups = 0
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        total_groups += len(page.get('Groups', []))

    if total_groups > 0:
        utils.log_info(f"Found {total_groups} Identity Center groups to process")

    paginator = identitystore_client.get_paginator('list_groups')
    processed = 0

    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        groups = page.get('Groups', [])

        for group in groups:
            processed += 1
            progress = (processed / total_groups) * 100 if total_groups > 0 else 0
            group_name = group.get('DisplayName', 'Unknown')

            utils.log_info(f"[{progress:.1f}%] Processing group {processed}/{total_groups}: {group_name}")

            member_count = get_group_member_count(identitystore_client, identity_store_id, group['GroupId'])
            member_details = get_group_member_details(identitystore_client, identity_store_id, group['GroupId'])
            account_assignments = get_group_account_assignments(sso_admin_client, instance_arn, group['GroupId'])

            group_info = {
                'Group ID': group.get('GroupId', 'N/A'),
                'Group Name': group.get('DisplayName', 'N/A'),
                'Description': group.get('Description', 'N/A'),
                'External ID': get_group_external_id(group),
                'Member Count': member_count,
                'Member Details': member_details[:500],
                'Account Assignments': account_assignments,
                'Assignment Count': len(account_assignments.split(', ')) if account_assignments not in ['None', 'Unknown'] else 0,
                'Created Date': group.get('Meta', {}).get('Created', 'N/A'),
                'Last Modified': group.get('Meta', {}).get('LastModified', 'N/A'),
                'Resource Type': group.get('Meta', {}).get('ResourceType', 'N/A')
            }

            groups_data.append(group_info)

    return groups_data


# ---------------------------------------------------------------------------
# Comprehensive permission set collection helpers
# ---------------------------------------------------------------------------

def get_permission_set_managed_policies_detailed(sso_admin_client, instance_arn, permission_set_arn):
    """Get detailed managed policies information for a permission set."""
    try:
        paginator = sso_admin_client.get_paginator('list_managed_policies_in_permission_set')
        policies = []
        aws_managed = []
        customer_managed = []

        for page in paginator.paginate(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        ):
            for policy in page.get('AttachedManagedPolicies', []):
                policy_name = policy.get('Name', policy.get('Arn', 'Unknown'))
                policy_arn = policy.get('Arn', '')

                policies.append(policy_name)

                if 'aws:policy/' in policy_arn:
                    aws_managed.append(policy_name)
                else:
                    customer_managed.append(policy_name)

        return {
            'count': len(policies),
            'names': ', '.join(policies),
            'aws_managed': ', '.join(aws_managed),
            'customer_managed': ', '.join(customer_managed)
        }

    except Exception:
        return {
            'count': 0,
            'names': 'Unknown',
            'aws_managed': 'Unknown',
            'customer_managed': 'Unknown'
        }


@utils.aws_error_handler("Getting permission set inline policy (detailed)", default_return={'exists': False, 'size': 0, 'summary': 'Unknown'})
def get_permission_set_inline_policy_detailed(sso_admin_client, instance_arn, permission_set_arn):
    """Get detailed inline policy information for a permission set."""
    try:
        response = sso_admin_client.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        )
        inline_policy = response.get('InlinePolicy', '')

        if inline_policy:
            try:
                policy_doc = json.loads(inline_policy)
                statements = policy_doc.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]

                statement_count = len(statements)
                actions = []
                resources = []

                for stmt in statements:
                    stmt_actions = stmt.get('Action', [])
                    if isinstance(stmt_actions, str):
                        stmt_actions = [stmt_actions]
                    actions.extend(stmt_actions)

                    stmt_resources = stmt.get('Resource', [])
                    if isinstance(stmt_resources, str):
                        stmt_resources = [stmt_resources]
                    resources.extend(stmt_resources)

                summary = f"Statements: {statement_count}, Actions: {len(set(actions))}, Resources: {len(set(resources))}"

                return {
                    'exists': True,
                    'size': len(inline_policy),
                    'summary': summary
                }
            except json.JSONDecodeError:
                return {
                    'exists': True,
                    'size': len(inline_policy),
                    'summary': f"Policy size: {len(inline_policy)} characters"
                }
        else:
            return {
                'exists': False,
                'size': 0,
                'summary': 'No inline policy'
            }

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return {
                'exists': False,
                'size': 0,
                'summary': 'No inline policy'
            }
        raise


@utils.aws_error_handler("Getting permission set permissions boundary", default_return='Unknown')
def get_permission_set_permissions_boundary(sso_admin_client, instance_arn, permission_set_arn):
    """Get permissions boundary for a permission set."""
    try:
        response = sso_admin_client.get_permissions_boundary_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        )

        boundary = response.get('PermissionsBoundary', {})
        if boundary:
            boundary_type = boundary.get('ManagedPolicyArn')
            if boundary_type:
                return f"Managed Policy: {boundary_type}"
            else:
                return 'Configured (Unknown Type)'
        else:
            return 'Not Set'

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return 'Not Set'
        raise


def get_permission_set_assignments_detailed(sso_admin_client, instance_arn, permission_set_arn):
    """Get detailed assignment information for a permission set."""
    try:
        paginator = sso_admin_client.get_paginator('list_account_assignments')
        assignments = []
        user_count = 0
        group_count = 0

        for page in paginator.paginate(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        ):
            for assignment in page.get('AccountAssignments', []):
                principal_type = assignment.get('PrincipalType')
                principal_id = assignment.get('PrincipalId')
                account_id = assignment.get('TargetId')

                if principal_type == 'USER':
                    user_count += 1
                elif principal_type == 'GROUP':
                    group_count += 1

                assignments.append(f"{principal_type}: {principal_id} -> Account: {account_id}")

        assignment_details = '; '.join(assignments[:10])
        if len(assignments) > 10:
            assignment_details += f" (and {len(assignments) - 10} more)"

        return {
            'total_assignments': len(assignments),
            'user_assignments': user_count,
            'group_assignments': group_count,
            'details': assignment_details
        }

    except Exception:
        return {
            'total_assignments': 0,
            'user_assignments': 0,
            'group_assignments': 0,
            'details': 'Unknown'
        }


def parse_duration_to_hours(duration):
    """Parse ISO 8601 duration to hours."""
    try:
        if duration.startswith('PT') and duration.endswith('H'):
            hours_str = duration[2:-1]
            return float(hours_str)
        elif duration.startswith('PT') and 'M' in duration:
            minutes_str = duration[2:duration.find('M')]
            return float(minutes_str) / 60
        else:
            return 'N/A'
    except Exception:
        return 'N/A'


def get_average_session_duration(permission_sets_data):
    """Calculate average session duration across permission sets."""
    try:
        durations = []
        for ps in permission_sets_data:
            duration = ps.get('Session Duration (Hours)')
            if isinstance(duration, (int, float)) and duration > 0:
                durations.append(duration)

        if durations:
            return round(sum(durations) / len(durations), 2)
        else:
            return 'N/A'
    except Exception:
        return 'N/A'


@utils.aws_error_handler("Collecting comprehensive permission sets", default_return=[])
def collect_comprehensive_permission_sets(instance_arn):
    """
    Collect comprehensive IAM Identity Center permission set information.

    Args:
        instance_arn: IAM Identity Center instance ARN

    Returns:
        list: List of comprehensive permission set information dictionaries
    """
    if not instance_arn:
        return []

    permission_sets_data = []
    home_region = utils.get_partition_default_region()
    sso_admin_client = utils.get_boto3_client('sso-admin', region_name=home_region)

    paginator = sso_admin_client.get_paginator('list_permission_sets')

    total_permission_sets = 0
    for page in paginator.paginate(InstanceArn=instance_arn):
        total_permission_sets += len(page.get('PermissionSets', []))

    if total_permission_sets > 0:
        utils.log_info(f"Found {total_permission_sets} permission sets to process")

    paginator = sso_admin_client.get_paginator('list_permission_sets')
    processed = 0

    for page in paginator.paginate(InstanceArn=instance_arn):
        permission_sets = page.get('PermissionSets', [])

        for permission_set_arn in permission_sets:
            processed += 1
            progress = (processed / total_permission_sets) * 100 if total_permission_sets > 0 else 0

            utils.log_info(f"[{progress:.1f}%] Processing permission set {processed}/{total_permission_sets}")

            try:
                ps_response = sso_admin_client.describe_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                )

                permission_set = ps_response['PermissionSet']

                managed_policies = get_permission_set_managed_policies_detailed(sso_admin_client, instance_arn, permission_set_arn)
                inline_policy = get_permission_set_inline_policy_detailed(sso_admin_client, instance_arn, permission_set_arn)
                permissions_boundary = get_permission_set_permissions_boundary(sso_admin_client, instance_arn, permission_set_arn)
                assignments_details = get_permission_set_assignments_detailed(sso_admin_client, instance_arn, permission_set_arn)
                tags = get_permission_set_tags(sso_admin_client, instance_arn, permission_set_arn)

                session_duration = permission_set.get('SessionDuration', 'PT1H')
                session_hours = parse_duration_to_hours(session_duration)

                permission_set_info = {
                    'Permission Set ARN': permission_set_arn,
                    'Name': permission_set.get('Name', 'N/A'),
                    'Description': permission_set.get('Description', 'N/A'),
                    'Session Duration': session_duration,
                    'Session Duration (Hours)': session_hours,
                    'Relay State': permission_set.get('RelayState', 'N/A'),
                    'Managed Policies Count': managed_policies['count'],
                    'Managed Policies': managed_policies['names'][:500],
                    'AWS Managed Policies': managed_policies['aws_managed'][:300],
                    'Customer Managed Policies': managed_policies['customer_managed'][:300],
                    'Has Inline Policy': 'Yes' if inline_policy['exists'] else 'No',
                    'Inline Policy Size (Chars)': inline_policy['size'],
                    'Inline Policy Summary': inline_policy['summary'][:200],
                    'Permissions Boundary': permissions_boundary,
                    'Total Account Assignments': assignments_details['total_assignments'],
                    'User Assignments': assignments_details['user_assignments'],
                    'Group Assignments': assignments_details['group_assignments'],
                    'Assignment Details': assignments_details['details'][:500],
                    'Created Date': permission_set.get('CreatedDate', 'N/A'),
                    'Tags': tags[:300]
                }

                permission_sets_data.append(permission_set_info)

            except Exception as e:
                utils.log_warning(f"Error processing permission set {permission_set_arn}: {e}")

    return permission_sets_data


# ---------------------------------------------------------------------------
# Export functions (private, prefixed with _)
# ---------------------------------------------------------------------------

def _export_combined_to_excel(users_data, groups_data, permission_sets_data, account_id, account_name):
    """
    Export combined Identity Center data (users, groups, permission sets) to Excel.

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
        import pandas as pd

        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        filename = utils.create_export_filename(account_name, "iam-identity-center", "", current_date)

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


def _export_groups_to_excel(groups_data, account_id, account_name):
    """
    Export Identity Center groups data to Excel file.

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
        import pandas as pd

        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        filename = utils.create_export_filename(account_name, "iam-identity-center-groups", "", current_date)

        groups_df = pd.DataFrame(groups_data)
        groups_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(groups_df))

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
        summary_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(summary_df))

        data_frames = {
            'Groups Summary': summary_df,
            'Groups Details': groups_df
        }

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


def _export_permission_sets_to_excel(permission_sets_data, account_id, account_name):
    """
    Export Identity Center permission sets data to Excel file.

    Args:
        permission_sets_data: List of permission set information dictionaries
        account_id: AWS account ID
        account_name: AWS account name

    Returns:
        str: Filename of exported file or None if failed
    """
    if not permission_sets_data:
        utils.log_warning("No Identity Center permission sets data to export.")
        return None

    try:
        import pandas as pd

        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        filename = utils.create_export_filename(account_name, "iam-identity-center-permission-sets", "", current_date)

        ps_df = pd.DataFrame(permission_sets_data)
        ps_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(ps_df))

        total_ps = len(permission_sets_data)
        ps_with_managed = len([p for p in permission_sets_data if p.get('Managed Policies', 'None') != 'None'])
        ps_with_inline = len([p for p in permission_sets_data if p.get('Has Inline Policy') == 'Yes'])
        total_assignments = sum(p.get('Account Assignments', 0) for p in permission_sets_data)

        summary_data = {
            'Metric': [
                'Total Permission Sets',
                'With Managed Policies',
                'With Inline Policies',
                'Total Account Assignments'
            ],
            'Count': [
                total_ps,
                ps_with_managed,
                ps_with_inline,
                total_assignments
            ]
        }

        summary_df = pd.DataFrame(summary_data)
        summary_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(summary_df))

        data_frames = {
            'Permission Sets': ps_df,
            'Summary': summary_df
        }

        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("AWS IAM Identity Center permission sets exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains {total_ps} permission sets")
            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None


def _export_comprehensive_to_excel(users_data, groups_data, permission_sets_data, account_id, account_name):
    """
    Export comprehensive IAM Identity Center data to Excel.

    Args:
        users_data: List of comprehensive user information dictionaries
        groups_data: List of comprehensive group information dictionaries
        permission_sets_data: List of comprehensive permission set information dictionaries
        account_id: AWS account ID
        account_name: AWS account name

    Returns:
        str: Filename of exported file or None if failed
    """
    if not users_data and not groups_data and not permission_sets_data:
        utils.log_warning("No IAM Identity Center data to export.")
        return None

    try:
        import pandas as pd

        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        filename = utils.create_export_filename(account_name, "iam-identity-center-comprehensive", "", current_date)

        data_frames = {}

        if users_data:
            users_df = pd.DataFrame(users_data)
            users_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(users_df))
            data_frames['Users'] = users_df

        if groups_data:
            groups_df = pd.DataFrame(groups_data)
            groups_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(groups_df))
            data_frames['Groups'] = groups_df

        if permission_sets_data:
            permission_sets_df = pd.DataFrame(permission_sets_data)
            permission_sets_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(permission_sets_df))
            data_frames['Permission Sets'] = permission_sets_df

        summary_data = {
            'Category': [
                'Total Users',
                'Active Users',
                'Inactive Users',
                'Users with Groups',
                'Users with Account Access',
                'Users with Application Access',
                'Total Groups',
                'Groups with Members',
                'Groups with Account Assignments',
                'Total Permission Sets',
                'Permission Sets with Managed Policies',
                'Permission Sets with Inline Policies',
                'Permission Sets with Permissions Boundaries',
                'Average Session Duration (Hours)',
                'Total Account Assignments',
                'User-Based Assignments',
                'Group-Based Assignments'
            ],
            'Count': [
                len(users_data),
                len([u for u in users_data if u.get('Status') == 'Active']),
                len([u for u in users_data if u.get('Status') == 'Inactive']),
                len([u for u in users_data if u.get('Group Count', 0) > 0]),
                len([u for u in users_data if u.get('Account Assignment Count', 0) > 0]),
                len([u for u in users_data if u.get('Application Assignment Count', 0) > 0]),
                len(groups_data),
                len([g for g in groups_data if g.get('Member Count', 0) > 0]),
                len([g for g in groups_data if g.get('Assignment Count', 0) > 0]),
                len(permission_sets_data),
                len([p for p in permission_sets_data if p.get('Managed Policies Count', 0) > 0]),
                len([p for p in permission_sets_data if p.get('Has Inline Policy') == 'Yes']),
                len([p for p in permission_sets_data if p.get('Permissions Boundary', 'Not Set') != 'Not Set']),
                get_average_session_duration(permission_sets_data),
                sum([p.get('Total Account Assignments', 0) for p in permission_sets_data]),
                sum([p.get('User Assignments', 0) for p in permission_sets_data]),
                sum([p.get('Group Assignments', 0) for p in permission_sets_data])
            ]
        }

        summary_df = pd.DataFrame(summary_data)
        summary_df = utils.sanitize_for_export(utils.prepare_dataframe_for_export(summary_df))
        data_frames['Summary'] = summary_df

        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("AWS IAM Identity Center comprehensive data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains {len(users_data)} users, {len(groups_data)} groups, and {len(permission_sets_data)} permission sets")
            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None


# ---------------------------------------------------------------------------
# Run functions
# ---------------------------------------------------------------------------

def _run_combined_export(account_id, account_name):
    """Collect Identity Center users, groups, and permission sets; export combined workbook."""
    instance_arn, identity_store_id = get_identity_center_instance()
    if not instance_arn:
        utils.log_error("Could not find IAM Identity Center instance. Exiting.")
        return

    utils.log_info("Collecting Identity Center users...")
    users_data = collect_identity_center_users(identity_store_id, instance_arn)

    utils.log_info("Collecting Identity Center groups...")
    groups_data = collect_identity_center_groups(identity_store_id)

    utils.log_info("Collecting permission sets...")
    permission_sets_data = collect_permission_sets(instance_arn)

    if not users_data and not groups_data and not permission_sets_data:
        utils.log_warning("No Identity Center data collected.")
        return

    _export_combined_to_excel(users_data, groups_data, permission_sets_data, account_id, account_name)


def _run_groups_export(account_id, account_name):
    """Collect Identity Center groups with detailed member info; export groups workbook."""
    instance_arn, identity_store_id = get_identity_center_instance()
    if not identity_store_id:
        utils.log_error("Could not find IAM Identity Center instance. Exiting.")
        return

    utils.log_info("Collecting Identity Center groups (detailed)...")
    groups_data = collect_identity_center_groups_detailed(identity_store_id)

    if not groups_data:
        utils.log_warning("No Identity Center groups collected.")
        return

    _export_groups_to_excel(groups_data, account_id, account_name)


def _run_permission_sets_export(account_id, account_name):
    """Collect Identity Center permission sets; export permission sets workbook."""
    instance_arn, identity_store_id = get_identity_center_instance()
    if not instance_arn:
        utils.log_error("Could not find IAM Identity Center instance. Exiting.")
        return

    utils.log_info("Collecting permission sets...")
    permission_sets_data = collect_permission_sets(instance_arn)

    if not permission_sets_data:
        utils.log_warning("No permission sets collected.")
        return

    _export_permission_sets_to_excel(permission_sets_data, account_id, account_name)


def _run_comprehensive_export(account_id, account_name):
    """Collect all Identity Center resources; export comprehensive workbook."""
    instance_arn, identity_store_id = get_identity_center_instance()
    if not instance_arn:
        utils.log_error("Could not find IAM Identity Center instance. Exiting.")
        return

    utils.log_info("Collecting comprehensive Identity Center users...")
    users_data = collect_comprehensive_users(identity_store_id, instance_arn)

    utils.log_info("Collecting comprehensive Identity Center groups...")
    groups_data = collect_comprehensive_groups(identity_store_id, instance_arn)

    utils.log_info("Collecting comprehensive permission sets...")
    permission_sets_data = collect_comprehensive_permission_sets(instance_arn)

    if not users_data and not groups_data and not permission_sets_data:
        utils.log_warning("No Identity Center data collected.")
        return

    _export_comprehensive_to_excel(users_data, groups_data, permission_sets_data, account_id, account_name)


# ---------------------------------------------------------------------------
# Main — state machine with b/x navigation (simpler: step 1 → confirm → execute)
# ---------------------------------------------------------------------------

def main():
    """Main function — state machine with b/x navigation and internal Identity Center menu."""
    try:
        if not utils.ensure_dependencies('pandas', 'openpyxl', 'boto3'):
            return

        utils.setup_logging("iam-identity-center-export")
        account_id, account_name = utils.print_script_banner("AWS IAM IDENTITY CENTER EXPORT")

        step = 1
        choice = None

        while True:
            if step == 1:
                result = utils.prompt_menu(
                    "IAM IDENTITY CENTER EXPORT OPTIONS",
                    [
                        "Users, Groups & Permission Sets (combined)",
                        "Groups",
                        "Permission Sets",
                        "Comprehensive",
                    ],
                )
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                choice = result
                step = 2

            elif step == 2:
                choice_labels = {
                    1: "Users, Groups & Permission Sets (combined)",
                    2: "Groups (with member details)",
                    3: "Permission Sets",
                    4: "Comprehensive (all data, extended fields)",
                }
                msg = f"Ready to export: {choice_labels[choice]}."
                result = utils.prompt_confirmation(msg)
                if result == 'back':
                    step = 1
                    continue
                if result == 'exit':
                    sys.exit(11)
                step = 3

            elif step == 3:
                if choice == 1:
                    _run_combined_export(account_id, account_name)
                elif choice == 2:
                    _run_groups_export(account_id, account_name)
                elif choice == 3:
                    _run_permission_sets_export(account_id, account_name)
                elif choice == 4:
                    _run_comprehensive_export(account_id, account_name)

                print("\nScript execution completed.")
                break

    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS IAM User Information Collection Script
Version: v0.1.0
Date: AUG-26-2025

Description:
This script collects comprehensive IAM user information from AWS environments including 
authentication details, access patterns, group memberships, and policy attachments. The data 
is exported to an Excel spreadsheet with AWS-specific naming convention for security 
auditing and compliance reporting.

Collected information includes: User Name, Groups, MFA Status, Password Age, Console Last Sign-in,
Access Key ID, Active Key Age, Access Key Last Used, Creation Date, Console Access, and Permission Policies.
"""

import os
import sys
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
@utils.aws_error_handler("Getting account information", default_return=("Unknown", "Unknown-AWS-Account"))
def get_account_info():
    """
    Get the current AWS account ID and name with AWS validation.

    Returns:
        tuple: (account_id, account_name)
    """
    sts = utils.get_boto3_client('sts')
    account_id = sts.get_caller_identity()['Account']

    # Validate AWS environment
    caller_arn = sts.get_caller_identity()['Arn']
    try:
        iam_client = utils.get_boto3_client('iam')
        aliases = iam_client.list_account_aliases()['AccountAliases']
        if aliases:
            account_name = aliases[0]
        else:
            # Use utils module for account name mapping
            account_name = utils.get_account_name(account_id, default=f"AWS-ACCOUNT-{account_id}")
    except Exception:
        # Use utils module for account name mapping
        account_name = utils.get_account_name(account_id, default=f"AWS-ACCOUNT-{account_id}")

    return account_id, account_name

def print_title():
    """
    Print the script title and account information.

    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS IAM USER INFORMATION COLLECTION")
    print("====================================================================")
    print("Version: v0.1.0                       Date: AUG-26-2025")

    # Get account information
    account_id, account_name = get_account_info()

    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"

    print(f"Environment: {partition_name}")
    print("====================================================================")
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")

    return account_id, account_name

def calculate_age_in_days(date_obj):
    """
    Calculate the age of a date object in days.
    
    Args:
        date_obj: Date object to calculate age for
        
    Returns:
        int or str: Age in days or descriptive string
    """
    if date_obj is None:
        return "Never"
    
    if isinstance(date_obj, str):
        return date_obj
    
    try:
        # Remove timezone info if present for calculation
        if date_obj.tzinfo is not None:
            date_obj = date_obj.replace(tzinfo=None)
        
        age = datetime.datetime.now() - date_obj
        return age.days
    except Exception:
        return "Unknown"

@utils.aws_error_handler("Getting user MFA devices", default_return="Unknown")
def get_user_mfa_devices(iam_client, username):
    """
    Get MFA devices for a user.

    Args:
        iam_client: The boto3 IAM client
        username: The username to check

    Returns:
        str: MFA status (Enabled/Disabled/Unknown)
    """
    # Check for virtual MFA devices
    virtual_mfa = iam_client.list_mfa_devices(UserName=username)
    mfa_devices = virtual_mfa.get('MFADevices', [])

    if mfa_devices:
        return "Enabled"
    else:
        return "Disabled"

@utils.aws_error_handler("Getting user groups", default_return="Unknown")
def get_user_groups(iam_client, username):
    """
    Get groups that a user belongs to.

    Args:
        iam_client: The boto3 IAM client
        username: The username to check

    Returns:
        str: Comma-separated list of group names or descriptive string
    """
    response = iam_client.get_groups_for_user(UserName=username)
    groups = [group['GroupName'] for group in response['Groups']]
    return ", ".join(groups) if groups else "None"

@utils.aws_error_handler("Getting user policies", default_return="Unknown")
def get_user_policies(iam_client, username):
    """
    Get all policies attached to a user (both attached and inline).

    Args:
        iam_client: The boto3 IAM client
        username: The username to check

    Returns:
        str: Comma-separated list of policy names or descriptive string
    """
    policies = []

    # Get attached managed policies
    attached_policies = iam_client.list_attached_user_policies(UserName=username)
    for policy in attached_policies['AttachedPolicies']:
        policies.append(policy['PolicyName'])

    # Get inline policies
    inline_policies = iam_client.list_user_policies(UserName=username)
    for policy_name in inline_policies['PolicyNames']:
        policies.append(f"{policy_name} (Inline)")

    return ", ".join(policies) if policies else "None"

def get_password_info(iam_client, username):
    """
    Get password-related information for a user.

    Args:
        iam_client: The boto3 IAM client
        username: The username to check

    Returns:
        tuple: (password_age, console_access)
    """
    # Keep try-except for business logic: NoSuchEntity means user has no password
    try:
        login_profile = iam_client.get_login_profile(UserName=username)
        password_creation = login_profile['LoginProfile']['CreateDate']
        password_age = calculate_age_in_days(password_creation)
        console_access = "Enabled"
        return password_age, console_access
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return "No Password", "Disabled"
        else:
            return "Unknown", "Unknown"
    except Exception as e:
        utils.log_warning(f"Could not get password info for user {username}: {e}")
        return "Unknown", "Unknown"

@utils.aws_error_handler("Getting access key information", default_return=("Unknown", "Unknown", "Unknown"))
def get_access_key_info(iam_client, username):
    """
    Get access key information for a user.

    Args:
        iam_client: The boto3 IAM client
        username: The username to check

    Returns:
        tuple: (access_key_ids, active_key_age, access_key_last_used)
    """
    response = iam_client.list_access_keys(UserName=username)
    access_keys = response['AccessKeyMetadata']

    if not access_keys:
        return "None", "No Keys", "Never"

    # Process all access keys
    key_info = []
    active_ages = []
    last_used_dates = []

    for key in access_keys:
        key_id = key['AccessKeyId']
        status = key['Status']
        created_date = key['CreateDate']

        key_info.append(f"{key_id} ({status})")

        if status == 'Active':
            key_age = calculate_age_in_days(created_date)
            active_ages.append(str(key_age))

            # Get last used information
            try:
                last_used_response = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                last_used_date = last_used_response.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                if last_used_date:
                    days_since_used = calculate_age_in_days(last_used_date)
                    last_used_dates.append(f"{days_since_used} days ago")
                else:
                    last_used_dates.append("Never")
            except Exception:
                last_used_dates.append("Unknown")

    # Format return values
    access_key_ids = ", ".join(key_info)
    active_key_age = ", ".join(active_ages) if active_ages else "No Active Keys"
    access_key_last_used = ", ".join(last_used_dates) if last_used_dates else "Never"

    return access_key_ids, active_key_age, access_key_last_used

def collect_iam_user_information():
    """
    Collect IAM user information from AWS.
    
    Returns:
        list: List of dictionaries containing user information
    """
    utils.log_info("Collecting IAM user information from AWS environment...")
    
    try:
        # IAM is a global service but we need to specify a region for the client
        # In AWS, IAM endpoints are region-specific but the service is still global
        # IAM is a global service - use partition-aware home region

        home_region = utils.get_partition_default_region()

        iam_client = utils.get_boto3_client('iam', region_name=home_region)
    except Exception as e:
        utils.log_error("Error creating IAM client", e)
        return []
    
    user_data = []
    
    try:
        # Get all IAM users
        paginator = iam_client.get_paginator('list_users')
        
        total_users = 0
        for page in paginator.paginate():
            users = page['Users']
            total_users += len(users)
        
        utils.log_info(f"Found {total_users} IAM users to process")
        
        # Reset paginator and process users
        paginator = iam_client.get_paginator('list_users')
        processed = 0
        
        for page in paginator.paginate():
            users = page['Users']
            
            for user in users:
                username = user['UserName']
                processed += 1
                progress = (processed / total_users) * 100
                
                utils.log_info(f"[{progress:.1f}%] Processing user {processed}/{total_users}: {username}")
                
                # Basic user information
                creation_date = user['CreateDate'].strftime('%Y-%m-%d %H:%M:%S UTC') if user['CreateDate'] else "Unknown"
                password_last_used = user.get('PasswordLastUsed')
                
                # Format console last sign-in
                if password_last_used:
                    console_last_signin = password_last_used.strftime('%Y-%m-%d %H:%M:%S UTC')
                else:
                    console_last_signin = "Never"
                
                # Get additional user information
                groups = get_user_groups(iam_client, username)
                mfa_status = get_user_mfa_devices(iam_client, username)
                password_age, console_access = get_password_info(iam_client, username)
                access_key_id, active_key_age, access_key_last_used = get_access_key_info(iam_client, username)
                permission_policies = get_user_policies(iam_client, username)
                
                # Compile user data
                user_info = {
                    'User Name': username,
                    'Groups': groups,
                    'MFA': mfa_status,
                    'Password Age': f"{password_age} days" if isinstance(password_age, int) else password_age,
                    'Console Last Sign-in': console_last_signin,
                    'Access Key ID': access_key_id,
                    'Active Key Age': f"{active_key_age} days" if isinstance(active_key_age, int) else active_key_age,
                    'Access Key Last Used': access_key_last_used,
                    'Creation Date': creation_date,
                    'Console Access': console_access,
                    'Permission Policies': permission_policies
                }

                user_data.append(user_info)
    
    except Exception as e:
        utils.log_error("Error collecting IAM user information", e)
        return []
    
    utils.log_success(f"Successfully collected information for {len(user_data)} users")
    return user_data

def export_to_excel(user_data, account_id, account_name):
    """
    Export IAM user data to Excel file with AWS naming convention.
    
    Args:
        user_data: List of user information dictionaries
        account_id: AWS account ID
        account_name: AWS account name
        
    Returns:
        str: Filename of exported file or None if failed
    """
    if not user_data:
        utils.log_warning("No IAM user data to export.")
        return None
    
    try:
        # Import pandas after dependency check
        import pandas as pd
        
        # Create DataFrame
        df = pd.DataFrame(user_data)
        
        # Generate filename with AWS identifier
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        
        # Use utils module to generate filename and save data with AWS identifier
        filename = utils.create_export_filename(
            account_name, 
            "iam-users", 
            "", 
            current_date
        )
        
        # Create data frames for multi-sheet export
        data_frames = {
            'IAM Users': df
        }
        
        # Create summary data
        summary_data = {
            'Metric': [
                'Total Users',
                'Users with Console Access',
                'Users with MFA Enabled',
                'Users with Access Keys',
                'Users Never Signed In'
            ],
            'Count': [
                len(df),
                len(df[df['Console Access'] == 'Enabled']),
                len(df[df['MFA'] == 'Enabled']),
                len(df[df['Access Key ID'] != 'None']),
                len(df[df['Console Last Sign-in'] == 'Never'])
            ]
        }
        
        summary_df = pd.DataFrame(summary_data)
        data_frames['Summary'] = summary_df
        
        # Save using utils function for multi-sheet Excel
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)
        
        if output_path:
            utils.log_success("AWS IAM user data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data for {len(user_data)} IAM users")
            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None
    
    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def main():
    """
    Main function to orchestrate the IAM user information collection.
    """
    try:
        # Check dependencies first
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return
        
        # Import pandas after dependency check
        import pandas as pd
        
        # Print title and get account info
        account_id, account_name = print_title()

        try:
            # Test AWS credentials
            sts = utils.get_boto3_client('sts')
            sts.get_caller_identity()
            utils.log_success("AWS credentials validated")
            
        except NoCredentialsError:
            utils.log_error("AWS credentials not found. Please configure your credentials using:")
            print("  - AWS CLI: aws configure")
            print("  - Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
            print("  - IAM role (if running on EC2)")
            return
        except Exception as e:
            utils.log_error("Error validating AWS credentials", e)
            return
        
        utils.log_info("Starting IAM user information collection from AWS...")
        print("====================================================================")
        
        # Collect IAM user information
        user_data = collect_iam_user_information()
        
        if not user_data:
            utils.log_warning("No IAM user data collected. Exiting.")
            return
        
        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")
        
        # Export to Excel
        filename = export_to_excel(user_data, account_id, account_name)
        
        if filename:
            utils.log_info(f"Results exported with AWS compliance markers")
            utils.log_info(f"Total users processed: {len(user_data)}")
            
            # Display some summary statistics
            df = pd.DataFrame(user_data)
            utils.log_info(f"Users with console access: {len(df[df['Console Access'] == 'Enabled'])}")
            utils.log_info(f"Users with MFA enabled: {len(df[df['MFA'] == 'Enabled'])}")
            utils.log_info(f"Users with access keys: {len(df[df['Access Key ID'] != 'None'])}")
            utils.log_info(f"Users never signed in: {len(df[df['Console Last Sign-in'] == 'Never'])}")
            
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
#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Organizations Information Collection Script
Version: v2.0.0
Date: SEP-25-2025

Description:
This script collects comprehensive AWS Organizations information from AWS
environments including organizational units (OUs), accounts, service control policies
(SCPs), policy attachments, and organizational hierarchy. The data is exported to
an Excel spreadsheet with AWS-specific naming convention for governance
auditing and compliance reporting.

Collected information includes:
- Organizational structure with complete OU hierarchy
- Account details with status, email, and organizational placement
- Service Control Policies with content analysis and risk assessment
- Policy attachments showing which policies apply to which OUs/accounts
- Root organization configuration and settings
- Comprehensive summary analytics for governance oversight
"""

import os
import sys
import boto3
import datetime
import time
import json
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
    Convert datetime object to timezone-unaware string for Excel compatibility.

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

def check_dependencies():
    """
    Check if required dependencies are installed and offer to install them if missing.

    Returns:
        bool: True if all dependencies are satisfied, False otherwise
    """
    required_packages = ['pandas', 'openpyxl']
    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
            utils.log_info(f"[OK] {package} is already installed")
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        utils.log_warning(f"Packages required but not installed: {', '.join(missing_packages)}")
        response = input("Would you like to install these packages now? (y/n): ").lower().strip()

        if response == 'y':
            import subprocess
            for package in missing_packages:
                utils.log_info(f"Installing {package}...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    utils.log_success(f"{package} installed successfully")
                except subprocess.CalledProcessError as e:
                    utils.log_error(f"Error installing {package}", e)
                    return False
        else:
            print("Cannot continue without required packages. Exiting.")
            return False

    return True

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
    print("AWS ORGANIZATIONS INFORMATION COLLECTION")
    print("====================================================================")
    print("Version: v2.0.0                       Date: SEP-25-2025")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")

    # Get account information
    account_id, account_name = get_account_info()
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")

    return account_id, account_name

def get_organization_info():
    """
    Get basic organization information.

    Returns:
        dict: Organization information or None if not available
    """
    # Keep try-except for business logic: specific error handling for Organizations errors
    try:
        org_client = utils.get_boto3_client('organizations')

        # Describe organization
        org_response = org_client.describe_organization()
        organization = org_response['Organization']

        utils.log_success(f"Found AWS Organization: {organization['Id']}")
        return organization

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AWSOrganizationsNotInUseException':
            utils.log_warning("AWS Organizations is not enabled in this account.")
        elif error_code == 'AccessDeniedException':
            utils.log_error("Access denied to AWS Organizations. This script must be run from the management account with appropriate permissions.")
        else:
            utils.log_error(f"Error accessing AWS Organizations: {e}")
        return None
    except Exception as e:
        utils.log_error("Error getting organization information", e)
        return None

def collect_organizational_units():
    """
    Collect all organizational units (OUs) in the organization.

    Returns:
        list: List of OU information dictionaries
    """
    ou_data = []

    try:
        org_client = utils.get_boto3_client('organizations')

        # Get root first
        roots = org_client.list_roots()['Roots']
        if not roots:
            utils.log_error("No organization root found")
            return []

        root = roots[0]  # There should only be one root
        root_id = root['Id']

        utils.log_info("Collecting organizational units...")

        # Process root as an OU
        root_info = {
            'OU ID': root_id,
            'OU Name': root.get('Name', 'Root'),
            'OU Type': 'ROOT',
            'Parent ID': 'N/A',
            'Parent Name': 'N/A',
            'Level': 0,
            'Path': 'Root',
            'Policy Types': ', '.join([pt['Type'] for pt in root.get('PolicyTypes', [])]),
            'ARN': root.get('Arn', 'N/A')
        }
        ou_data.append(root_info)

        # Recursively collect all OUs
        collected_ous = collect_ous_recursive(org_client, root_id, "Root", 1)
        ou_data.extend(collected_ous)

        utils.log_success(f"Collected {len(ou_data)} organizational units")

    except Exception as e:
        utils.log_error("Error collecting organizational units", e)

    return ou_data

def collect_ous_recursive(org_client, parent_id, parent_path, level):
    """
    Recursively collect OUs under a parent.

    Args:
        org_client: boto3 organizations client
        parent_id: Parent OU ID
        parent_path: Full path to parent
        level: Current nesting level

    Returns:
        list: List of OU information dictionaries
    """
    ou_data = []

    try:
        # Get direct children OUs
        paginator = org_client.get_paginator('list_organizational_units_for_parent')

        for page in paginator.paginate(ParentId=parent_id):
            for ou in page.get('OrganizationalUnits', []):
                ou_id = ou['Id']
                ou_name = ou.get('Name', 'Unnamed OU')
                ou_path = f"{parent_path}/{ou_name}"

                # Get parent name
                try:
                    if parent_id.startswith('r-'):  # Root
                        parent_name = 'Root'
                    else:
                        parent_response = org_client.describe_organizational_unit(OrganizationalUnitId=parent_id)
                        parent_name = parent_response['OrganizationalUnit'].get('Name', 'Unknown')
                except Exception:
                    parent_name = 'Unknown'

                ou_info = {
                    'OU ID': ou_id,
                    'OU Name': ou_name,
                    'OU Type': 'ORGANIZATIONAL_UNIT',
                    'Parent ID': parent_id,
                    'Parent Name': parent_name,
                    'Level': level,
                    'Path': ou_path,
                    'Policy Types': 'N/A',  # Will be filled later if needed
                    'ARN': ou.get('Arn', 'N/A')
                }
                ou_data.append(ou_info)

                utils.log_info(f"Found OU: {ou_path}")

                # Recursively get children
                children = collect_ous_recursive(org_client, ou_id, ou_path, level + 1)
                ou_data.extend(children)

    except Exception as e:
        utils.log_warning(f"Error collecting OUs for parent {parent_id}: {e}")

    return ou_data

def collect_accounts():
    """
    Collect all accounts in the organization.

    Returns:
        list: List of account information dictionaries
    """
    accounts_data = []

    try:
        org_client = utils.get_boto3_client('organizations')

        utils.log_info("Collecting organization accounts...")

        # Get all accounts
        paginator = org_client.get_paginator('list_accounts')
        total_accounts = 0

        # Count accounts first
        for page in paginator.paginate():
            total_accounts += len(page.get('Accounts', []))

        utils.log_info(f"Found {total_accounts} accounts to process")

        # Reset paginator and process accounts
        paginator = org_client.get_paginator('list_accounts')
        processed = 0

        for page in paginator.paginate():
            accounts = page.get('Accounts', [])

            for account in accounts:
                processed += 1
                progress = (processed / total_accounts) * 100 if total_accounts > 0 else 0
                account_name = account.get('Name', 'Unnamed Account')

                utils.log_info(f"[{progress:.1f}%] Processing account {processed}/{total_accounts}: {account_name}")

                # Get account's parent OU
                parent_info = get_account_parent(org_client, account['Id'])

                # Get account tags if available
                account_tags = get_account_tags(org_client, account['Id'])

                account_info = {
                    'Account ID': account.get('Id', 'N/A'),
                    'Account Name': account_name,
                    'Email': account.get('Email', 'N/A'),
                    'Status': account.get('Status', 'N/A'),
                    'Join Method': account.get('JoinedMethod', 'N/A'),
                    'Joined Date': convert_datetime_to_string(account.get('JoinedTimestamp')),
                    'Parent ID': parent_info['parent_id'],
                    'Parent Name': parent_info['parent_name'],
                    'Parent Type': parent_info['parent_type'],
                    'Full Path': parent_info['full_path'],
                    'ARN': account.get('Arn', 'N/A'),
                    'Tags': account_tags
                }

                accounts_data.append(account_info)

    except Exception as e:
        utils.log_error("Error collecting accounts", e)

    return accounts_data

def get_account_parent(org_client, account_id):
    """
    Get the parent OU information for an account.

    Args:
        org_client: boto3 organizations client
        account_id: Account ID

    Returns:
        dict: Parent information
    """
    try:
        response = org_client.list_parents(ChildId=account_id)
        parents = response.get('Parents', [])

        if not parents:
            return {
                'parent_id': 'N/A',
                'parent_name': 'N/A',
                'parent_type': 'N/A',
                'full_path': 'N/A'
            }

        parent = parents[0]  # Should only be one parent
        parent_id = parent['Id']
        parent_type = parent['Type']

        # Get parent name and build full path
        if parent_type == 'ROOT':
            parent_name = 'Root'
            full_path = 'Root'
        else:
            try:
                parent_response = org_client.describe_organizational_unit(OrganizationalUnitId=parent_id)
                parent_name = parent_response['OrganizationalUnit'].get('Name', 'Unknown OU')

                # Build full path by walking up the hierarchy
                full_path = build_ou_path(org_client, parent_id)
            except Exception:
                parent_name = 'Unknown OU'
                full_path = 'Unknown Path'

        return {
            'parent_id': parent_id,
            'parent_name': parent_name,
            'parent_type': parent_type,
            'full_path': full_path
        }

    except Exception as e:
        return {
            'parent_id': 'Unknown',
            'parent_name': 'Unknown',
            'parent_type': 'Unknown',
            'full_path': 'Unknown'
        }

def build_ou_path(org_client, ou_id):
    """
    Build the full path for an OU by walking up the hierarchy.

    Args:
        org_client: boto3 organizations client
        ou_id: OU ID

    Returns:
        str: Full path string
    """
    path_parts = []
    current_id = ou_id

    try:
        while current_id:
            if current_id.startswith('r-'):  # Root
                path_parts.append('Root')
                break

            # Get current OU info
            ou_response = org_client.describe_organizational_unit(OrganizationalUnitId=current_id)
            ou_name = ou_response['OrganizationalUnit'].get('Name', 'Unknown')
            path_parts.append(ou_name)

            # Get parent
            parents_response = org_client.list_parents(ChildId=current_id)
            parents = parents_response.get('Parents', [])

            if not parents:
                break

            current_id = parents[0]['Id']

        # Reverse to get root-to-leaf order
        path_parts.reverse()
        return '/'.join(path_parts)

    except Exception:
        return f"Error building path for {ou_id}"

def get_account_tags(org_client, account_id):
    """
    Get tags for an account.

    Args:
        org_client: boto3 organizations client
        account_id: Account ID

    Returns:
        str: Formatted tags string
    """
    try:
        response = org_client.list_tags_for_resource(ResourceId=account_id)
        tags = response.get('Tags', [])

        if tags:
            tag_strings = [f"{tag['Key']}={tag['Value']}" for tag in tags]
            return ', '.join(tag_strings)
        else:
            return 'No Tags'

    except Exception as e:
        return 'Unable to retrieve tags'

def collect_policies():
    """
    Collect all service control policies (SCPs) and other policies.

    Returns:
        list: List of policy information dictionaries
    """
    policies_data = []

    try:
        org_client = utils.get_boto3_client('organizations')

        utils.log_info("Collecting organization policies...")

        # Get all policy types
        policy_types = ['SERVICE_CONTROL_POLICY', 'TAG_POLICY', 'BACKUP_POLICY', 'AISERVICES_OPT_OUT_POLICY']

        for policy_type in policy_types:
            try:
                paginator = org_client.get_paginator('list_policies')

                for page in paginator.paginate(Filter=policy_type):
                    policies = page.get('Policies', [])

                    for policy in policies:
                        policy_id = policy['Id']
                        policy_name = policy.get('Name', 'Unnamed Policy')

                        utils.log_info(f"Processing {policy_type}: {policy_name}")

                        # Get detailed policy information
                        try:
                            policy_response = org_client.describe_policy(PolicyId=policy_id)
                            policy_details = policy_response['Policy']

                            # Get policy content if it's an SCP
                            policy_content = ''
                            policy_summary = ''
                            if policy_type == 'SERVICE_CONTROL_POLICY':
                                policy_content = policy_details.get('Content', '')
                                policy_summary = analyze_scp_content(policy_content)

                            # Get policy targets (what it's attached to)
                            targets = get_policy_targets(org_client, policy_id)

                            policy_info = {
                                'Policy ID': policy_id,
                                'Policy Name': policy_name,
                                'Policy Type': policy_type,
                                'Description': policy_details.get('PolicySummary', {}).get('Description', 'N/A'),
                                'AWS Managed': 'Yes' if policy_details.get('PolicySummary', {}).get('AwsManaged', False) else 'No',
                                'Content Size': len(policy_content) if policy_content else 0,
                                'Policy Summary': policy_summary[:500] if policy_summary else 'N/A',
                                'Attached To Count': len(targets),
                                'Attached To': ', '.join(targets)[:500] if targets else 'Not Attached',
                                'ARN': policy_details.get('PolicySummary', {}).get('Arn', 'N/A')
                            }

                            policies_data.append(policy_info)

                        except Exception as e:
                            utils.log_warning(f"Error getting details for policy {policy_id}: {e}")

            except ClientError as e:
                if 'PolicyTypeNotEnabledException' in str(e):
                    utils.log_info(f"Policy type {policy_type} is not enabled in this organization")
                else:
                    utils.log_warning(f"Error collecting {policy_type} policies: {e}")
            except Exception as e:
                utils.log_warning(f"Error collecting {policy_type} policies: {e}")

        utils.log_success(f"Collected {len(policies_data)} policies")

    except Exception as e:
        utils.log_error("Error collecting policies", e)

    return policies_data

def analyze_scp_content(policy_content):
    """
    Analyze SCP content to provide a summary.

    Args:
        policy_content: Policy JSON content

    Returns:
        str: Summary of the policy
    """
    try:
        if not policy_content:
            return 'No content available'

        policy_doc = json.loads(policy_content)
        statements = policy_doc.get('Statement', [])

        if not isinstance(statements, list):
            statements = [statements]

        summary_parts = []

        for i, stmt in enumerate(statements):
            effect = stmt.get('Effect', 'Unknown')
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]

            conditions = stmt.get('Condition', {})

            stmt_summary = f"Statement {i+1}: {effect}"

            if actions:
                if len(actions) <= 3:
                    stmt_summary += f" on {', '.join(actions)}"
                else:
                    stmt_summary += f" on {len(actions)} actions"

            if resources and resources != ['*']:
                if len(resources) <= 2:
                    stmt_summary += f" for {', '.join(resources[:2])}"
                else:
                    stmt_summary += f" for {len(resources)} resources"

            if conditions:
                stmt_summary += f" with conditions"

            summary_parts.append(stmt_summary)

        return '; '.join(summary_parts)

    except Exception as e:
        return f"Error analyzing policy: {str(e)}"

def get_policy_targets(org_client, policy_id):
    """
    Get the targets (OUs/accounts) that a policy is attached to.

    Args:
        org_client: boto3 organizations client
        policy_id: Policy ID

    Returns:
        list: List of target descriptions
    """
    targets = []

    try:
        paginator = org_client.get_paginator('list_targets_for_policy')

        for page in paginator.paginate(PolicyId=policy_id):
            for target in page.get('Targets', []):
                target_id = target['TargetId']
                target_type = target['Type']

                if target_type == 'ROOT':
                    targets.append('Root')
                elif target_type == 'ORGANIZATIONAL_UNIT':
                    try:
                        ou_response = org_client.describe_organizational_unit(OrganizationalUnitId=target_id)
                        ou_name = ou_response['OrganizationalUnit'].get('Name', target_id)
                        targets.append(f"OU: {ou_name}")
                    except Exception:
                        targets.append(f"OU: {target_id}")
                elif target_type == 'ACCOUNT':
                    try:
                        account_response = org_client.describe_account(AccountId=target_id)
                        account_name = account_response['Account'].get('Name', target_id)
                        targets.append(f"Account: {account_name}")
                    except Exception:
                        targets.append(f"Account: {target_id}")

    except Exception as e:
        utils.log_warning(f"Error getting targets for policy {policy_id}: {e}")

    return targets

def clean_dataframe_datetimes(df):
    """
    Clean timezone-aware datetimes in a pandas DataFrame for Excel compatibility.

    Args:
        df: pandas DataFrame

    Returns:
        pandas DataFrame: DataFrame with timezone-unaware datetime strings
    """
    try:
        import pandas as pd

        # Convert any datetime columns to strings
        for col in df.columns:
            if df[col].dtype == 'datetime64[ns, UTC]' or any(isinstance(val, datetime.datetime) for val in df[col].dropna()):
                # Convert datetime objects to strings
                df[col] = df[col].apply(lambda x: convert_datetime_to_string(x) if pd.notna(x) else 'N/A')

        return df
    except Exception as e:
        utils.log_warning(f"Error cleaning datetime objects in dataframe: {e}")
        return df

def export_to_excel(org_info, ou_data, accounts_data, policies_data, account_id, account_name):
    """
    Export Organizations data to Excel file with AWS naming convention.

    Args:
        org_info: Organization information dictionary
        ou_data: List of OU information dictionaries
        accounts_data: List of account information dictionaries
        policies_data: List of policy information dictionaries
        account_id: AWS account ID
        account_name: AWS account name

    Returns:
        str: Filename of exported file or None if failed
    """
    if not org_info and not ou_data and not accounts_data and not policies_data:
        utils.log_warning("No Organizations data to export.")
        return None

    try:
        # Import pandas after dependency check
        import pandas as pd

        # Generate filename with AWS identifier
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")

        # Use utils module to generate filename and save data with AWS identifier
        filename = utils.create_export_filename(
            account_name,
            "organizations",
            "",
            current_date
        )

        # Create data frames for multi-sheet export
        data_frames = {}

        # Organization overview sheet
        if org_info:
            org_overview = {
                'Property': [
                    'Organization ID',
                    'Master Account ID',
                    'Master Account Email',
                    'Feature Set',
                    'Available Policy Types',
                    'ARN'
                ],
                'Value': [
                    org_info.get('Id', 'N/A'),
                    org_info.get('MasterAccountId', 'N/A'),
                    org_info.get('MasterAccountEmail', 'N/A'),
                    org_info.get('FeatureSet', 'N/A'),
                    ', '.join([pt['Type'] for pt in org_info.get('AvailablePolicyTypes', [])]),
                    org_info.get('Arn', 'N/A')
                ]
            }
            org_df = pd.DataFrame(org_overview)
            data_frames['Organization Overview'] = org_df

        # Organizational Units sheet
        if ou_data:
            ou_df = pd.DataFrame(ou_data)
            ou_df = clean_dataframe_datetimes(ou_df)
            data_frames['Organizational Units'] = ou_df

        # Accounts sheet
        if accounts_data:
            accounts_df = pd.DataFrame(accounts_data)
            accounts_df = clean_dataframe_datetimes(accounts_df)
            data_frames['Accounts'] = accounts_df

        # Policies sheet
        if policies_data:
            policies_df = pd.DataFrame(policies_data)
            policies_df = clean_dataframe_datetimes(policies_df)
            data_frames['Policies'] = policies_df

        # Create comprehensive summary data
        summary_data = {
            'Metric': [
                'Total Organizational Units',
                'Total Accounts',
                'Active Accounts',
                'Suspended Accounts',
                'Total Policies',
                'Service Control Policies',
                'AWS Managed Policies',
                'Custom Policies',
                'Maximum OU Depth',
                'Accounts in Root',
                'Policies Attached to Root'
            ],
            'Count': [
                len([ou for ou in ou_data if ou.get('OU Type') == 'ORGANIZATIONAL_UNIT']),
                len(accounts_data),
                len([acc for acc in accounts_data if acc.get('Status') == 'ACTIVE']),
                len([acc for acc in accounts_data if acc.get('Status') == 'SUSPENDED']),
                len(policies_data),
                len([pol for pol in policies_data if pol.get('Policy Type') == 'SERVICE_CONTROL_POLICY']),
                len([pol for pol in policies_data if pol.get('AWS Managed') == 'Yes']),
                len([pol for pol in policies_data if pol.get('AWS Managed') == 'No']),
                max([ou.get('Level', 0) for ou in ou_data] + [0]),
                len([acc for acc in accounts_data if acc.get('Parent Type') == 'ROOT']),
                len([pol for pol in policies_data if 'Root' in pol.get('Attached To', '')])
            ]
        }

        summary_df = pd.DataFrame(summary_data)
        data_frames['Summary'] = summary_df

        # Save using utils function for multi-sheet Excel
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("AWS Organizations data exported successfully!")
            utils.log_info(f"File location: {output_path}")

            # Log summary statistics
            total_ous = len([ou for ou in ou_data if ou.get('OU Type') == 'ORGANIZATIONAL_UNIT'])
            total_accounts = len(accounts_data)
            total_policies = len(policies_data)
            utils.log_info(f"Export contains {total_ous} OUs, {total_accounts} accounts, and {total_policies} policies")

            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def main():
    """
    Main function to orchestrate the Organizations information collection.
    """
    try:
        # Check dependencies first
        if not check_dependencies():
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

        utils.log_info("Starting Organizations information collection from AWS...")
        print("====================================================================")

        # Get organization information
        utils.log_info("Getting organization information...")
        org_info = get_organization_info()

        if not org_info:
            utils.log_error("Could not access AWS Organizations. This script must be run from the management account.")
            utils.log_info("Please ensure you have the necessary permissions and are running from the management account.")
            return

        # Collect organizational data
        utils.log_info("Collecting organizational units...")
        ou_data = collect_organizational_units()

        utils.log_info("Collecting accounts...")
        accounts_data = collect_accounts()

        utils.log_info("Collecting policies...")
        policies_data = collect_policies()

        if not ou_data and not accounts_data and not policies_data:
            utils.log_warning("No Organizations data collected. Exiting.")
            return

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Export to Excel
        filename = export_to_excel(org_info, ou_data, accounts_data, policies_data, account_id, account_name)

        if filename:
            utils.log_info(f"Results exported with AWS compliance markers")
            utils.log_info(f"Organization ID: {org_info.get('Id', 'Unknown')}")
            utils.log_info(f"Total OUs processed: {len([ou for ou in ou_data if ou.get('OU Type') == 'ORGANIZATIONAL_UNIT'])}")
            utils.log_info(f"Total accounts processed: {len(accounts_data)}")
            utils.log_info(f"Total policies processed: {len(policies_data)}")

            # Display summary statistics
            if accounts_data:
                active_accounts = len([acc for acc in accounts_data if acc.get('Status') == 'ACTIVE'])
                utils.log_info(f"Active accounts: {active_accounts}")

            if policies_data:
                scps = len([pol for pol in policies_data if pol.get('Policy Type') == 'SERVICE_CONTROL_POLICY'])
                utils.log_info(f"Service Control Policies: {scps}")

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
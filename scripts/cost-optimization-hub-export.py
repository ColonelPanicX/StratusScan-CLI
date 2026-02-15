#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Cost Optimization Hub Export
Version: v1.0.0
Date: OCT-08-2025

Description:
This script exports AWS Cost Optimization Hub recommendations 
to an Excel file with summary and detailed tabs for each 
recommendation type. Aggregates savings across all sources
(Trusted Advisor, Compute Optimizer, Cost Explorer).

"""

import os
import sys
import subprocess
import datetime
import boto3
from botocore.exceptions import ClientError
from pathlib import Path

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

def check_and_install_dependencies():
    """
    Check if required dependencies are installed and offer to install them if not.
    """
    required_packages = ['pandas', 'openpyxl']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("The following dependencies are required but not installed:")
        for package in missing_packages:
            print(f"  - {package}")
        
        user_input = input("Would you like to install these packages? (y/n): ").strip().lower()
        
        if user_input == 'y':
            print("Installing required packages...")
            for package in missing_packages:
                print(f"Installing {package}...")
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print("All required packages have been installed.")
        else:
            print("Required packages were not installed. Script cannot continue.")
            sys.exit(1)
    
    import pandas as pd
    global pd

@utils.aws_error_handler("Getting account ID", default_return="UNKNOWN")
def get_account_id():
    """
    Get the AWS account ID of the current session.

    Returns:
        str: The AWS account ID
    """
    sts_client = utils.get_boto3_client('sts')
    account_id = sts_client.get_caller_identity()["Account"]
    return account_id

@utils.aws_error_handler("Checking enrollment status", default_return=[])
def check_enrollment_status(client):
    """
    Check if Cost Optimization Hub is enabled.

    Args:
        client: Cost Optimization Hub boto3 client

    Returns:
        dict: Enrollment status information
    """
    paginator = client.get_paginator('list_enrollment_statuses')
    page_iterator = paginator.paginate(includeOrganizationInfo=True)

    statuses = []
    for page in page_iterator:
        statuses.extend(page.get('items', []))

    return statuses

def get_all_recommendations(client):
    """
    Get all cost optimization recommendations from Cost Optimization Hub.

    Args:
        client: Cost Optimization Hub boto3 client

    Returns:
        list: List of all recommendations
    """
    utils.log_info("Fetching Cost Optimization Hub recommendations...")
    recommendations = []

    try:
        paginator = client.get_paginator('list_recommendations')
        page_iterator = paginator.paginate(
            includeAllRecommendations=True,
            PaginationConfig={
                'MaxItems': 10000,
                'PageSize': 100
            }
        )

        for page in page_iterator:
            recommendations.extend(page.get('items', []))
            utils.log_info(f"Fetched {len(recommendations)} recommendations so far...")

        utils.log_success(f"Total recommendations fetched: {len(recommendations)}")
        return recommendations

    except ClientError as e:
        # Business logic: Special handling for opt-in errors
        if 'OptInRequiredException' in str(e) or 'not subscribed' in str(e):
            utils.log_error("Cost Optimization Hub is not enabled for this account.")
            print("Please enable Cost Optimization Hub in the AWS Console:")
            print("  1. Go to AWS Billing and Cost Management Console")
            print("  2. Select 'Cost Optimization Hub' from the left menu")
            print("  3. Click 'Enable'")
            print("  4. Wait 24 hours for initial data population")
        else:
            utils.log_error(f"Error fetching recommendations: {e}")
        sys.exit(1)

def process_recommendations(recommendations):
    """
    Process recommendations into DataFrames for Excel export.

    Args:
        recommendations (list): List of recommendation dictionaries

    Returns:
        tuple: (summary_df, detail_dfs_dict)
    """
    if not recommendations:
        utils.log_warning("No recommendations found.")
        return pd.DataFrame(), {}
    
    # Convert to DataFrame for easier processing
    import pandas as pd
    df = pd.DataFrame(recommendations)
    
    # Create summary by action type
    summary_data = []
    total_savings = 0
    total_resources = 0
    
    action_types = df['actionType'].unique() if 'actionType' in df.columns else []
    
    for action_type in action_types:
        action_recs = df[df['actionType'] == action_type]
        count = len(action_recs)
        savings = action_recs['estimatedMonthlySavings'].sum() if 'estimatedMonthlySavings' in action_recs.columns else 0
        
        summary_data.append({
            'Action Type': action_type,
            'Number of Recommendations': count,
            'Estimated Monthly Savings': f"${savings:,.2f}"
        })
        
        total_savings += savings
        total_resources += count
    
    # Add total row
    summary_data.append({
        'Action Type': 'TOTAL',
        'Number of Recommendations': total_resources,
        'Estimated Monthly Savings': f"${total_savings:,.2f}"
    })
    
    summary_df = pd.DataFrame(summary_data)
    
    # Create detailed tabs by action type
    detail_dfs = {}
    
    for action_type in action_types:
        action_recs = df[df['actionType'] == action_type].copy()
        
        # Select and rename columns for better readability
        detail_columns = {
            'accountId': 'Account ID',
            'region': 'Region',
            'resourceId': 'Resource ID',
            'currentResourceType': 'Current Resource Type',
            'recommendedResourceType': 'Recommended Resource Type',
            'estimatedMonthlySavings': 'Estimated Monthly Savings ($)',
            'estimatedSavingsPercentage': 'Estimated Savings (%)',
            'implementationEffort': 'Implementation Effort',
            'restartNeeded': 'Restart Required',
            'rollbackPossible': 'Rollback Possible',
            'actionType': 'Action Type',
            'source': 'Source'
        }
        
        # Only include columns that exist
        cols_to_use = {k: v for k, v in detail_columns.items() if k in action_recs.columns}
        detail_df = action_recs[list(cols_to_use.keys())].copy()
        detail_df.rename(columns=cols_to_use, inplace=True)
        
        # Format numeric columns
        if 'Estimated Monthly Savings ($)' in detail_df.columns:
            detail_df['Estimated Monthly Savings ($)'] = detail_df['Estimated Monthly Savings ($)'].apply(
                lambda x: f"${x:,.2f}" if pd.notna(x) else "$0.00"
            )
        
        if 'Estimated Savings (%)' in detail_df.columns:
            detail_df['Estimated Savings (%)'] = detail_df['Estimated Savings (%)'].apply(
                lambda x: f"{x:.2f}%" if pd.notna(x) else "0.00%"
            )
        
        # Clean sheet name (Excel has restrictions)
        sheet_name = action_type.replace('/', '-')[:31]
        detail_dfs[sheet_name] = detail_df
    
    # Create an "All Recommendations" tab
    all_recs_df = df.copy()
    cols_to_use = {k: v for k, v in {
        'accountId': 'Account ID',
        'region': 'Region',
        'resourceId': 'Resource ID',
        'currentResourceType': 'Current Resource Type',
        'recommendedResourceType': 'Recommended Resource Type',
        'estimatedMonthlySavings': 'Estimated Monthly Savings ($)',
        'estimatedSavingsPercentage': 'Estimated Savings (%)',
        'implementationEffort': 'Implementation Effort',
        'restartNeeded': 'Restart Required',
        'rollbackPossible': 'Rollback Possible',
        'actionType': 'Action Type',
        'source': 'Source'
    }.items() if k in all_recs_df.columns}
    
    all_recs_df = all_recs_df[list(cols_to_use.keys())].copy()
    all_recs_df.rename(columns=cols_to_use, inplace=True)
    
    if 'Estimated Monthly Savings ($)' in all_recs_df.columns:
        all_recs_df['Estimated Monthly Savings ($)'] = all_recs_df['Estimated Monthly Savings ($)'].apply(
            lambda x: f"${x:,.2f}" if pd.notna(x) else "$0.00"
        )
    
    if 'Estimated Savings (%)' in all_recs_df.columns:
        all_recs_df['Estimated Savings (%)'] = all_recs_df['Estimated Savings (%)'].apply(
            lambda x: f"{x:.2f}%" if pd.notna(x) else "0.00%"
        )
    
    detail_dfs['All Recommendations'] = all_recs_df
    
    return summary_df, detail_dfs

def export_to_excel(summary_df, detail_dfs, account_name):
    """
    Export the data to an Excel file with multiple tabs.

    Args:
        summary_df (DataFrame): Summary data
        detail_dfs (dict): Dictionary of detail DataFrames
        account_name (str): AWS account name

    Returns:
        str: Path to the created Excel file
    """
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")

    filename = utils.create_export_filename(
        account_name,
        "cost-optimization-hub",
        "",
        current_date
    )

    # Prepare DataFrames dictionary with summary first
    all_dfs = {'Summary': summary_df}
    all_dfs.update(detail_dfs)

    output_path = utils.save_multiple_dataframes_to_excel(all_dfs, filename)

    if output_path:
        utils.log_success(f"Data exported to: {output_path}")
        return output_path
    else:
        utils.log_error("Error exporting data to Excel.")
        return None

def main():
    """
    Main function to execute the script.
    """
    try:
        check_and_install_dependencies()

        import pandas as pd

        print("====================================================================")
        print("                  AWS RESOURCE SCANNER                              ")
        print("====================================================================")
        print("AWS COST OPTIMIZATION HUB - DATA EXPORT")
        print("====================================================================")

        # Validate AWS credentials
        try:
            sts = utils.get_boto3_client('sts')
            sts.get_caller_identity()
            utils.log_success("AWS credentials validated")
        except Exception as e:
            utils.log_error("AWS credentials not found or invalid. Please configure your credentials.")
            print("  - AWS CLI: aws configure")
            print("  - Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
            print("  - IAM role (if running on EC2)")
            return

        account_id = get_account_id()
        account_name = utils.get_account_name(account_id, default=account_id)

        print(f"Account ID: {account_id}")
        print(f"Account Name: {account_name}")
        print("====================================================================")

        # Important note about Cost Optimization Hub
        print("\n" + "="*70)
        print("IMPORTANT: AWS Cost Optimization Hub must be enabled in your account.")
        print("Cost Optimization Hub API is only available in the us-east-1 region.")
        print("Cost Optimization Hub aggregates recommendations from:")
        print("  - AWS Compute Optimizer")
        print("  - AWS Trusted Advisor")
        print("  - AWS Cost Explorer")
        print("="*70)

        confirm = input("\nHave you enabled Cost Optimization Hub? (y/n): ").lower()
        if confirm != 'y':
            print("Please enable Cost Optimization Hub first:")
            print("  1. Go to AWS Billing and Cost Management Console")
            print("  2. Select 'Cost Optimization Hub' from the left menu")
            print("  3. Click 'Enable'")
            print("  4. Wait 24 hours for initial data population")
            return

        # Cost Optimization Hub is a global service - use partition-aware home region
        home_region = utils.get_partition_default_region()
        client = utils.get_boto3_client('cost-optimization-hub', region_name=home_region)

        # Check enrollment status
        utils.log_info("Checking Cost Optimization Hub enrollment status...")
        statuses = check_enrollment_status(client)

        if statuses:
            print("\nEnrollment Status:")
            for status in statuses:
                acc_id = status.get('accountId', 'Unknown')
                acc_status = status.get('status', 'Unknown')
                print(f"  Account {acc_id}: {acc_status}")

        # Get all recommendations
        recommendations = get_all_recommendations(client)

        if not recommendations:
            utils.log_info("No cost optimization recommendations found.")
            print("This could mean:")
            print("  1. Cost Optimization Hub was recently enabled (wait 24 hours)")
            print("  2. All resources are already optimized")
            print("  3. No recommendations are available for your current resources")
            sys.exit(0)

        utils.log_info(f"Processing {len(recommendations)} recommendations...")
        summary_df, detail_dfs = process_recommendations(recommendations)

        if summary_df.empty:
            utils.log_warning("No data to export.")
            sys.exit(0)

        utils.log_info("Exporting results to Excel...")
        filename = export_to_excel(summary_df, detail_dfs, account_name)

        if filename:
            print("====================================================================")
            print(f"Export complete! Full details available in: {filename}")
            print("====================================================================")
            utils.log_success(f"Cost Optimization Hub export completed: {filename}")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An error occurred during script execution", e)
        sys.exit(1)

if __name__ == "__main__":
    main()

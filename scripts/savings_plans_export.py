#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Savings Plans Export Tool
Date: NOV-09-2025

Description:
This script exports AWS Savings Plans information into an Excel file with multiple
worksheets. The output includes active and queued savings plans with commitment details,
savings estimates, and usage tracking.

Features:
- Active savings plans with commitment details and expiration
- Queued (pending) savings plans
- Savings plan types: Compute, EC2, SageMaker
- Payment options and term lengths
- Hourly commitment amounts and currencies
- Savings estimates and utilization tracking
"""

import sys
import datetime
from pathlib import Path
from typing import List, Dict, Any
from decimal import Decimal

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
    print("                AWS SAVINGS PLANS EXPORT TOOL")
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


@utils.aws_error_handler("Collecting Savings Plans", default_return=[])
def collect_savings_plans(states: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Savings Plans information.

    Args:
        states: List of states to filter (e.g., ['active', 'queued'])

    Returns:
        list: List of dictionaries with savings plan information
    """
    print(f"\n=== COLLECTING SAVINGS PLANS (States: {', '.join(states)}) ===")
    all_plans = []

    # Savings Plans is a global service but requires a region
    # Savings Plans is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    sp_client = utils.get_boto3_client('savingsplans', region_name=home_region)

    for state in states:
        print(f"\nProcessing state: {state}")

        try:
            paginator = sp_client.get_paginator('describe_savings_plans')
            page_iterator = paginator.paginate(states=[state])

            for page in page_iterator:
                savings_plans = page.get('savingsPlans', [])

                for plan in savings_plans:
                    plan_id = plan.get('savingsPlanId', 'N/A')
                    plan_arn = plan.get('savingsPlanArn', 'N/A')

                    print(f"  Processing savings plan: {plan_id}")

                    # Basic info
                    plan_type = plan.get('savingsPlanType', 'N/A')
                    payment_option = plan.get('paymentOption', 'N/A')
                    state_val = plan.get('state', 'N/A')

                    # Commitment
                    commitment = plan.get('commitment', '0')
                    currency = plan.get('currency', 'USD')

                    # Convert Decimal to float for Excel
                    if isinstance(commitment, Decimal):
                        commitment = float(commitment)

                    # Term
                    term_duration = plan.get('termDurationInSeconds', 0)
                    # Convert seconds to years
                    term_years = term_duration / (365.25 * 24 * 60 * 60)

                    # Dates
                    start = plan.get('start', '')
                    if start:
                        start = start.strftime('%Y-%m-%d %H:%M:%S') if isinstance(start, datetime.datetime) else str(start)

                    end = plan.get('end', '')
                    if end:
                        end = end.strftime('%Y-%m-%d %H:%M:%S') if isinstance(end, datetime.datetime) else str(end)

                    # EC2 instance family (if applicable)
                    ec2_instance_family = plan.get('ec2InstanceFamily', 'N/A')

                    # Region (if applicable)
                    region = plan.get('region', 'N/A')

                    # Upfront payment
                    upfront = plan.get('upfrontPaymentAmount', '0')
                    if isinstance(upfront, Decimal):
                        upfront = float(upfront)

                    # Recurring payment
                    recurring = plan.get('recurringPaymentAmount', '0')
                    if isinstance(recurring, Decimal):
                        recurring = float(recurring)

                    # Description/offering ID
                    offering_id = plan.get('offeringId', 'N/A')

                    # Tags
                    tags = plan.get('tags', {})
                    tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'None'

                    all_plans.append({
                        'Savings Plan ID': plan_id,
                        'State': state_val,
                        'Savings Plan Type': plan_type,
                        'Payment Option': payment_option,
                        'Hourly Commitment': commitment,
                        'Currency': currency,
                        'Term (Years)': round(term_years, 1),
                        'Start Date': start if start else 'N/A',
                        'End Date': end if end else 'N/A',
                        'EC2 Instance Family': ec2_instance_family,
                        'Region': region,
                        'Upfront Payment': upfront,
                        'Recurring Payment': recurring,
                        'Offering ID': offering_id,
                        'Tags': tags_str,
                        'Savings Plan ARN': plan_arn
                    })

        except Exception as e:
            utils.log_error(f"Error collecting savings plans in state {state}", e)

    utils.log_success(f"Total savings plans collected: {len(all_plans)}")
    return all_plans


def export_savings_plans_data(account_id: str, account_name: str):
    """
    Export Savings Plans information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    print("\nStarting Savings Plans export process...")
    print("This may take some time depending on the number of savings plans...")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect active savings plans
    active_plans = collect_savings_plans(['active'])
    if active_plans:
        data_frames['Active Savings Plans'] = pd.DataFrame(active_plans)

    # STEP 2: Collect queued (pending) savings plans
    queued_plans = collect_savings_plans(['queued'])
    if queued_plans:
        data_frames['Queued Savings Plans'] = pd.DataFrame(queued_plans)

    # STEP 3: Create summary
    if active_plans or queued_plans:
        summary_data = []

        # Total active plans
        total_active = len(active_plans)
        total_queued = len(queued_plans)

        # Commitment totals by type
        compute_commitment = sum(float(p['Hourly Commitment']) for p in active_plans if p['Savings Plan Type'] == 'Compute')
        ec2_commitment = sum(float(p['Hourly Commitment']) for p in active_plans if p['Savings Plan Type'] == 'EC2Instance')
        sagemaker_commitment = sum(float(p['Hourly Commitment']) for p in active_plans if p['Savings Plan Type'] == 'SageMaker')

        summary_data.append({
            'Metric': 'Total Active Savings Plans',
            'Value': total_active
        })
        summary_data.append({
            'Metric': 'Total Queued Savings Plans',
            'Value': total_queued
        })
        summary_data.append({
            'Metric': 'Compute Savings Plans Hourly Commitment (USD)',
            'Value': round(compute_commitment, 2)
        })
        summary_data.append({
            'Metric': 'EC2 Instance Savings Plans Hourly Commitment (USD)',
            'Value': round(ec2_commitment, 2)
        })
        summary_data.append({
            'Metric': 'SageMaker Savings Plans Hourly Commitment (USD)',
            'Value': round(sagemaker_commitment, 2)
        })
        summary_data.append({
            'Metric': 'Total Hourly Commitment (USD)',
            'Value': round(compute_commitment + ec2_commitment + sagemaker_commitment, 2)
        })

        data_frames['Summary'] = pd.DataFrame(summary_data)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No Savings Plans data was collected. Nothing to export.")
        print("\nNo Savings Plans found in this account.")
        return

    # STEP 4: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 5: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'savings-plans',
        '',
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("Savings Plans data exported successfully!")
            utils.log_info(f"File location: {output_path}")

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
    utils.setup_logging("savings-plans-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("savings-plans-export.py", "AWS Savings Plans Export Tool")

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

        # Export Savings Plans data
        export_savings_plans_data(account_id, account_name)

        print("\nSavings Plans export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("savings-plans-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

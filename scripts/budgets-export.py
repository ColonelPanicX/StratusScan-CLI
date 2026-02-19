#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Budgets Export Tool
Version: v0.1.0
Date: NOV-09-2025

Description:
This script exports AWS Budgets information into an Excel file with multiple
worksheets. The output includes budget configurations, alerts, notifications,
and spending thresholds.

Features:
- Budget configurations with amounts and time periods
- Budget types: Cost, Usage, Savings Plans, Reservations
- Alert thresholds and notification subscribers
- Actual vs forecasted spend tracking
- Budget filters and dimensions
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

# Initialize logging
SCRIPT_START_TIME = datetime.datetime.now()
utils.setup_logging("budgets-export")
utils.log_script_start("budgets-export.py", "AWS Budgets Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("                   AWS BUDGETS EXPORT TOOL")
    print("====================================================================")
    print("Version: v0.1.0                        Date: NOV-09-2025")
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


@utils.aws_error_handler("Collecting Budgets", default_return=[])
def collect_budgets(account_id: str) -> List[Dict[str, Any]]:
    """
    Collect AWS Budgets information.

    Args:
        account_id: AWS account ID

    Returns:
        list: List of dictionaries with budget information
    """
    print("\n=== COLLECTING AWS BUDGETS ===")
    all_budgets = []

    # Budgets is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    budgets_client = utils.get_boto3_client('budgets', region_name=home_region)

    try:
        paginator = budgets_client.get_paginator('describe_budgets')
        page_iterator = paginator.paginate(AccountId=account_id)

        for page in page_iterator:
            budgets = page.get('Budgets', [])

            for budget in budgets:
                budget_name = budget.get('BudgetName', 'N/A')

                print(f"  Processing budget: {budget_name}")

                # Budget type
                budget_type = budget.get('BudgetType', 'N/A')

                # Time unit
                time_unit = budget.get('TimeUnit', 'N/A')

                # Time period
                time_period = budget.get('TimePeriod', {})
                start_date = time_period.get('Start', '')
                if start_date:
                    start_date = start_date.strftime('%Y-%m-%d') if isinstance(start_date, datetime.datetime) else str(start_date)
                end_date = time_period.get('End', '')
                if end_date:
                    end_date = end_date.strftime('%Y-%m-%d') if isinstance(end_date, datetime.datetime) else str(end_date)

                # Budget limit
                budget_limit = budget.get('BudgetLimit', {})
                limit_amount = budget_limit.get('Amount', '0')
                if isinstance(limit_amount, Decimal):
                    limit_amount = float(limit_amount)
                limit_unit = budget_limit.get('Unit', 'USD')

                # Calculated spend
                calculated_spend = budget.get('CalculatedSpend', {})

                # Actual spend
                actual_spend = calculated_spend.get('ActualSpend', {})
                actual_amount = actual_spend.get('Amount', '0')
                if isinstance(actual_amount, Decimal):
                    actual_amount = float(actual_amount)

                # Forecasted spend
                forecasted_spend = calculated_spend.get('ForecastedSpend', {})
                forecasted_amount = forecasted_spend.get('Amount', '0')
                if isinstance(forecasted_amount, Decimal):
                    forecasted_amount = float(forecasted_amount)

                # Cost filters
                cost_filters = budget.get('CostFilters', {})
                filters_str = ', '.join([f"{k}={','.join(v)}" for k, v in cost_filters.items()]) if cost_filters else 'None'

                # Cost types
                cost_types = budget.get('CostTypes', {})
                include_tax = cost_types.get('IncludeTax', False)
                include_subscription = cost_types.get('IncludeSubscription', False)
                include_support = cost_types.get('IncludeSupport', False)
                include_refund = cost_types.get('IncludeRefund', False)
                include_credit = cost_types.get('IncludeCredit', False)

                # Last updated
                last_updated = budget.get('LastUpdatedTime', '')
                if last_updated:
                    last_updated = last_updated.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_updated, datetime.datetime) else str(last_updated)

                all_budgets.append({
                    'Budget Name': budget_name,
                    'Budget Type': budget_type,
                    'Time Unit': time_unit,
                    'Start Date': start_date if start_date else 'N/A',
                    'End Date': end_date if end_date else 'Ongoing',
                    'Budget Limit': limit_amount,
                    'Currency': limit_unit,
                    'Actual Spend': actual_amount,
                    'Forecasted Spend': forecasted_amount,
                    'Spend %': round((actual_amount / limit_amount * 100) if limit_amount > 0 else 0, 2),
                    'Cost Filters': filters_str,
                    'Include Tax': include_tax,
                    'Include Subscription': include_subscription,
                    'Include Support': include_support,
                    'Include Refund': include_refund,
                    'Include Credit': include_credit,
                    'Last Updated': last_updated if last_updated else 'N/A'
                })

    except Exception as e:
        utils.log_error("Error collecting budgets", e)

    utils.log_success(f"Total budgets collected: {len(all_budgets)}")
    return all_budgets


@utils.aws_error_handler("Collecting Budget Notifications", default_return=[])
def collect_budget_notifications(account_id: str, budget_names: List[str]) -> List[Dict[str, Any]]:
    """
    Collect notification configurations for budgets.

    Args:
        account_id: AWS account ID
        budget_names: List of budget names

    Returns:
        list: List of dictionaries with notification information
    """
    print("\n=== COLLECTING BUDGET NOTIFICATIONS ===")
    all_notifications = []

    # Budgets is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    budgets_client = utils.get_boto3_client('budgets', region_name=home_region)

    for budget_name in budget_names:
        print(f"  Processing notifications for budget: {budget_name}")

        try:
            paginator = budgets_client.get_paginator('describe_notifications_for_budget')
            page_iterator = paginator.paginate(
                AccountId=account_id,
                BudgetName=budget_name
            )

            for page in page_iterator:
                notifications = page.get('Notifications', [])

                for notification in notifications:
                    # Notification details
                    notification_type = notification.get('NotificationType', 'N/A')
                    comparison_operator = notification.get('ComparisonOperator', 'N/A')
                    threshold = notification.get('Threshold', 0)
                    threshold_type = notification.get('ThresholdType', 'N/A')
                    notification_state = notification.get('NotificationState', 'N/A')

                    # Get subscribers for this notification
                    try:
                        subscribers_response = budgets_client.describe_subscribers_for_notification(
                            AccountId=account_id,
                            BudgetName=budget_name,
                            Notification=notification
                        )

                        subscribers = subscribers_response.get('Subscribers', [])
                        subscriber_list = []

                        for subscriber in subscribers:
                            sub_type = subscriber.get('SubscriptionType', 'N/A')
                            address = subscriber.get('Address', 'N/A')
                            subscriber_list.append(f"{sub_type}:{address}")

                        subscribers_str = ', '.join(subscriber_list) if subscriber_list else 'None'

                    except Exception as e:
                        utils.log_warning(f"Could not get subscribers for notification: {e}")
                        subscribers_str = 'Error retrieving'

                    all_notifications.append({
                        'Budget Name': budget_name,
                        'Notification Type': notification_type,
                        'Threshold': threshold,
                        'Threshold Type': threshold_type,
                        'Comparison Operator': comparison_operator,
                        'State': notification_state,
                        'Subscribers': subscribers_str
                    })

        except Exception as e:
            utils.log_warning(f"Could not get notifications for budget {budget_name}: {e}")

    utils.log_success(f"Total budget notifications collected: {len(all_notifications)}")
    return all_notifications


def export_budgets_data(account_id: str, account_name: str):
    """
    Export AWS Budgets information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    print("\nStarting Budgets export process...")
    print("This may take some time depending on the number of budgets...")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect budgets
    budgets = collect_budgets(account_id)
    if budgets:
        data_frames['Budgets'] = pd.DataFrame(budgets)

        # STEP 2: Collect notifications for all budgets
        budget_names = [b['Budget Name'] for b in budgets]
        notifications = collect_budget_notifications(account_id, budget_names)
        if notifications:
            data_frames['Notifications'] = pd.DataFrame(notifications)

        # STEP 3: Create summary
        summary_data = []

        total_budgets = len(budgets)
        total_notifications = len(notifications) if notifications else 0

        # Budget types
        cost_budgets = sum(1 for b in budgets if b['Budget Type'] == 'COST')
        usage_budgets = sum(1 for b in budgets if b['Budget Type'] == 'USAGE')
        ri_budgets = sum(1 for b in budgets if b['Budget Type'] == 'RI_UTILIZATION')
        sp_budgets = sum(1 for b in budgets if b['Budget Type'] == 'SAVINGS_PLANS_UTILIZATION')

        # Total budget amounts
        total_budget_limit = sum(float(b['Budget Limit']) for b in budgets)
        total_actual_spend = sum(float(b['Actual Spend']) for b in budgets)
        total_forecasted_spend = sum(float(b['Forecasted Spend']) for b in budgets)

        # Budgets over threshold
        budgets_over_80 = sum(1 for b in budgets if b['Spend %'] >= 80)
        budgets_over_100 = sum(1 for b in budgets if b['Spend %'] >= 100)

        summary_data.append({'Metric': 'Total Budgets', 'Value': total_budgets})
        summary_data.append({'Metric': 'Total Notifications', 'Value': total_notifications})
        summary_data.append({'Metric': 'Cost Budgets', 'Value': cost_budgets})
        summary_data.append({'Metric': 'Usage Budgets', 'Value': usage_budgets})
        summary_data.append({'Metric': 'RI Utilization Budgets', 'Value': ri_budgets})
        summary_data.append({'Metric': 'Savings Plans Utilization Budgets', 'Value': sp_budgets})
        summary_data.append({'Metric': 'Total Budget Limit (USD)', 'Value': round(total_budget_limit, 2)})
        summary_data.append({'Metric': 'Total Actual Spend (USD)', 'Value': round(total_actual_spend, 2)})
        summary_data.append({'Metric': 'Total Forecasted Spend (USD)', 'Value': round(total_forecasted_spend, 2)})
        summary_data.append({'Metric': 'Budgets Over 80% Threshold', 'Value': budgets_over_80})
        summary_data.append({'Metric': 'Budgets Over 100% (Exceeded)', 'Value': budgets_over_100})

        data_frames['Summary'] = pd.DataFrame(summary_data)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No Budgets data was collected. Nothing to export.")
        print("\nNo Budgets found in this account.")
        return

    # STEP 4: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 5: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'budgets',
        '',
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("Budgets data exported successfully!")
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
    """Main function to execute the script."""
    try:
        # Print title and get account information
        account_id, account_name = print_title()

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            proceed = input("Unable to determine account name. Proceed anyway? (y/n): ").lower()
            if proceed != 'y':
                print("Exiting script...")
                sys.exit(0)

        # Export Budgets data
        export_budgets_data(account_id, account_name)

        print("\nBudgets export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("budgets-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

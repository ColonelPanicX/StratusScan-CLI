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

import datetime
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

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
args = utils.parse_script_args("Export AWS Savings Plans to Excel")


def _build_savings_plan_row(plan: dict[str, Any]) -> dict[str, Any]:
    """
    Build the export row for a single Savings Plan.

    Extracted so per-plan processing can be wrapped in try/except by the
    caller: a malformed plan entry must not sink the whole account-scope
    collection. All fields are read with ``.get()`` and a safe default for
    the same reason (the ``plan['Hourly Commitment']`` style hard subscript
    flagged in .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md
    is a deterministic ``KeyError`` candidate on divergent plan variants).

    Args:
        plan: A single savingsPlans entry from describe_savings_plans.

    Returns:
        dict: The assembled savings plan row.
    """
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
    tags = plan.get('tags', {}) or {}
    tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'None'

    return {
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
    }


def collect_savings_plans(states: list[str]) -> list[dict[str, Any]]:
    """
    Collect Savings Plans information.

    Not wrapped in ``aws_error_handler`` and does not swallow errors to an
    empty list: a swallowed error here would be indistinguishable from a
    genuinely empty account (no savings plans purchased), producing silent
    data loss (see the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits). Savings Plans is a global, account-scope service (not
    multi-region — see scripts/shield_export.py for the account-scope
    reference pattern this follows). Account-scope failures (client
    creation, pagination) are allowed to raise so the caller (main) can
    record this scope as *failed* rather than *empty*. Per-plan errors are
    contained internally (logged and skipped).

    Args:
        states: List of states to filter (e.g., ['active', 'queued'])

    Returns:
        list: List of dictionaries with savings plan information.

    Raises:
        Exception: Any AWS/pagination error for the account scope (caller
            records it as a failed scope; it is never masked as empty).
    """
    print(f"\n=== COLLECTING SAVINGS PLANS (States: {', '.join(states)}) ===")
    all_plans = []
    total_processed = 0
    skipped = 0

    # Savings Plans is a global service but requires a region
    # Savings Plans is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    sp_client = utils.get_boto3_client('savingsplans', region_name=home_region)

    for state in states:
        print(f"\nProcessing state: {state}")

        # describe_savings_plans has no boto3 paginator; page manually via nextToken.
        next_token = None
        while True:
            params: dict[str, Any] = {'states': [state], 'maxResults': 100}
            if next_token:
                params['nextToken'] = next_token

            page = sp_client.describe_savings_plans(**params)
            savings_plans = page.get('savingsPlans', [])

            # Process each plan. One malformed plan must not sink the whole
            # scope, so each is built inside try/except; failures are logged
            # and skipped.
            for plan in savings_plans:
                total_processed += 1

                try:
                    all_plans.append(_build_savings_plan_row(plan))
                except Exception as e:
                    skipped += 1
                    plan_id = plan.get('savingsPlanId', 'Unknown') if isinstance(plan, dict) else 'Unknown'
                    utils.log_error(f"Skipping savings plan '{plan_id}' due to a processing error", e)
                    continue

            next_token = page.get('nextToken')
            if not next_token:
                break

    if skipped:
        utils.log_warning(
            f"{skipped} of {total_processed} savings plan(s) were skipped due to "
            "processing errors (see log above); the remaining plans were still collected."
        )

    utils.log_success(f"Total savings plans collected: {len(all_plans)}")
    return all_plans


def export_savings_plans_data(account_id: str, account_name: str):
    """
    Export Savings Plans information to an Excel file.

    Savings Plans is a global, account-scope service (not multi-region), so
    failures are tracked per account-scope collector call rather than via
    ``utils.scan_regions_concurrent`` (see scripts/shield_export.py for the
    account-scope reference pattern). Each ``collect_savings_plans`` call
    (PRIMARY scope) is allowed to raise; a real API error is recorded in
    ``failed_scopes`` and the export continues with whatever data was
    already collected — it is never silently collapsed into "no savings
    plans" (see .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).

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

    # Account-scope failure tracking (see scripts/shield_export.py).
    failed_scopes: list[tuple[str, str]] = []

    # STEP 1: Collect active savings plans (PRIMARY scope — a real API error
    # here must propagate to failed_scopes, never collapse into an empty
    # list that reads as "no active savings plans").
    try:
        active_plans = collect_savings_plans(['active'])
    except Exception as e:
        failed_scopes.append(('savings_plans', str(e)))
        utils.log_error(f"Active savings plans collection failed: {e}")
        active_plans = []
    if active_plans:
        data_frames['Active Savings Plans'] = pd.DataFrame(active_plans)

    # STEP 2: Collect queued (pending) savings plans (PRIMARY scope — same
    # failure handling as STEP 1).
    try:
        queued_plans = collect_savings_plans(['queued'])
    except Exception as e:
        failed_scopes.append(('savings_plans', str(e)))
        utils.log_error(f"Queued savings plans collection failed: {e}")
        queued_plans = []
    if queued_plans:
        data_frames['Queued Savings Plans'] = pd.DataFrame(queued_plans)

    # STEP 3: Create summary
    if active_plans or queued_plans:
        summary_data = []

        # Total active plans
        total_active = len(active_plans)
        total_queued = len(queued_plans)

        # Commitment totals by type
        compute_commitment = sum(float(p.get('Hourly Commitment', 0)) for p in active_plans if p.get('Savings Plan Type') == 'Compute')
        ec2_commitment = sum(float(p.get('Hourly Commitment', 0)) for p in active_plans if p.get('Savings Plan Type') == 'EC2Instance')
        sagemaker_commitment = sum(float(p.get('Hourly Commitment', 0)) for p in active_plans if p.get('Savings Plan Type') == 'SageMaker')

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

    # Check if we have any data. A genuinely empty result (no data AND no
    # failed scopes) gets a plain warning; a failed scope is handled below
    # regardless of whether a partial export was written.
    if not data_frames:
        if not failed_scopes:
            utils.log_warning("No Savings Plans data was collected. Nothing to export.")
            print("\nNo Savings Plans found in this account.")
    else:
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
                utils.log_success(f"File location: {output_path}")

                # Summary of exported data
                for sheet_name, df in data_frames.items():
                    utils.log_info(f"  - {sheet_name}: {len(df)} records")
                    print(f"  - {sheet_name}: {len(df)} records")
            else:
                utils.log_error("Error creating Excel file. Please check the logs.")

        except Exception as e:
            utils.log_error("Error creating Excel file", e)

    # If any primary-scope collection failed, make it loud: write a marker
    # and exit non-zero, even if a partial export (the other scope, or the
    # Summary sheet) was written. A partial export that looks complete is
    # exactly the failure mode this guards against.
    if failed_scopes:
        utils.report_collection_failures(account_name, 'savings-plans', failed_scopes)
        print(
            "\nERROR: Savings Plans export completed with failures — data is "
            "incomplete. See the *-savings-plans-FAILED-*.txt marker in the "
            "output directory."
        )
        sys.exit(1)


def main():
    # Initialize logging
    utils.setup_logging("savings-plans-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("savings-plans-export.py", "AWS Savings Plans Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS SAVINGS PLANS EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown" and not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
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

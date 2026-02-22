#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Trusted Advisor Cost Optimization Export
Date: FEB-28-2025

Description:
This script exports AWS Trusted Advisor Cost Optimization
recommendations to an Excel file with a summary tab and
detailed tabs for each cost saving opportunity.

"""

import sys
import json
import datetime
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

utils.setup_logging("trusted-advisor-cost-optimization-export")

# Define the cost optimization check IDs
COST_OPTIMIZATION_CHECKS = {
    "Qch7DwouX1": "Low Utilization Amazon EC2 Instances",
    "djGHe3YM57": "Amazon RDS Idle DB Instances",
    "Ti39halfu8": "Underutilized Amazon EBS Volumes",
    "a2jU9xbpdD": "Underutilized Amazon Redshift Clusters",
    "G31sQ1E9U": "Unassociated Elastic IP Addresses",
    "iqdCTZKCUp": "Idle Load Balancers",
    "DAvU99Dc4C": "Underutilized Amazon EBS Volumes with IOPS",
    "Z4AUBRNSmz": "Underutilized Amazon Redshift Reserved Nodes",
    "PUQNanKh2f": "Amazon EC2 Reserved Instance Lease Expiration",
    "rQRjQHDRMi": "Amazon EC2 Reserved Instances Optimization",
    "I13nqtS9KM": "AWS Lambda Functions Using Deprecated Runtimes",
    "jEKWUjrcr5": "Amazon S3 Bucket Versioning",
    "7ujbJOwtK2": "AWS CloudFront Content Delivery Optimization",
    "G7HW2saBrz": "Amazon RDS Multi-AZ",
    "R365s2Qddf": "Amazon EC2 to Amazon RDS MySQL"
}


def get_trusted_advisor_checks():
    """
    Get all Trusted Advisor checks related to cost optimization.

    Returns:
        list: List of Trusted Advisor check results
    """
    try:
        # Support/Trusted Advisor is a global service - use partition-aware home region
        home_region = utils.get_partition_default_region()
        support_client = utils.get_boto3_client('support', region_name=home_region)

        # Get all Trusted Advisor checks
        response = support_client.describe_trusted_advisor_checks(language='en')

        # Filter to only cost optimization checks
        cost_checks = [check for check in response['checks'] if check['category'] == 'cost_optimizing']

        return cost_checks
    except ClientError as e:
        if 'SubscriptionRequiredException' in str(e):
            utils.log_error("AWS Business or Enterprise Support plan is required to access Trusted Advisor API.")
        else:
            utils.log_error(f"Error accessing Trusted Advisor checks: {e}")
        sys.exit(1)


@utils.aws_error_handler("Getting Trusted Advisor check result", default_return=None)
def get_check_result(check_id):
    """
    Get the detailed results for a specific Trusted Advisor check.

    Args:
        check_id (str): The ID of the Trusted Advisor check

    Returns:
        dict: The detailed results of the check
    """
    # Support/Trusted Advisor is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    support_client = utils.get_boto3_client('support', region_name=home_region)

    # Get the check result
    response = support_client.describe_trusted_advisor_check_result(
        checkId=check_id,
        language='en'
    )

    return response['result']


def get_all_check_results():
    """
    Get results for all cost optimization checks.

    Returns:
        dict: A dictionary with check details and results
    """
    # Get all cost optimization checks
    checks = get_trusted_advisor_checks()

    # Get results for each check
    results = {}
    for check in checks:
        check_id = check['id']
        check_name = check['name']
        utils.log_info(f"Fetching results for: {check_name}")

        result = get_check_result(check_id)
        if result:
            results[check_id] = {
                'name': check_name,
                'description': check['description'],
                'result': result
            }

    return results


def extract_savings(metadata, index):
    """
    Safely extract savings value from metadata at the given index.

    Args:
        metadata (list): The metadata list
        index (int): Index to extract from

    Returns:
        float: The extracted savings value, or 0 if not found
    """
    try:
        if len(metadata) > index and metadata[index] and isinstance(metadata[index], str):
            if "$" in metadata[index]:
                savings_text = metadata[index].replace("$", "").replace(",", "")
                return float(savings_text)
    except (ValueError, IndexError, AttributeError):
        pass
    return 0


def process_check_results(results):
    """
    Process the check results into a format suitable for Excel.

    Args:
        results (dict): The check results

    Returns:
        tuple: (summary_df, detail_dfs) containing the summary dataframe and detail dataframes
    """
    import pandas as pd

    # Create a list to store summary data
    summary_data = []

    # Dictionary to store detail dataframes for each check
    detail_dfs = {}

    # Total estimated savings
    total_savings = 0

    # Process each check result
    for check_id, check_info in results.items():
        check_name = check_info['name']
        result = check_info['result']

        # Skip if there are no resources to optimize (flaggedResources is empty)
        if not result.get('flaggedResources', []):
            continue

        # Calculate estimated savings
        estimated_savings = 0
        resources_count = len(result.get('flaggedResources', []))

        # Extract detail data for this check
        detail_data = []

        for resource in result.get('flaggedResources', []):
            # Extract metadata fields
            metadata = resource.get('metadata', [])

            # Process metadata based on the check type
            resource_metadata = {}

            # Process the metadata fields (skip index 0 which is typically Region)
            for i, field in enumerate(metadata):
                if i == 0:  # Skip the first metadata field (metadata_0)
                    continue

                # Get the field name
                field_name = result.get('metadata', [])[i] if i < len(result.get('metadata', [])) else f"Field_{i}"

                # Special column mapping for "Idle Load Balancers" (check ID: iqdCTZKCUp)
                if check_id == "iqdCTZKCUp":
                    if i == 2:
                        field_name = "Description"
                    elif i == 3:
                        field_name = "Potential Cost Savings"

                # Special column mapping for "Low Utilization Amazon EC2 Instances" (check ID: Qch7DwouX1)
                elif check_id == "Qch7DwouX1":
                    if i == 4:
                        field_name = "Estimated Monthly Savings"

                resource_metadata[field_name] = field

            # Extract resource savings based on check type
            resource_savings = 0

            if check_id == "Qch7DwouX1":  # Low Utilization EC2
                resource_savings = extract_savings(metadata, 4)
            elif check_id == "djGHe3YM57":  # RDS Idle Instances
                resource_savings = extract_savings(metadata, 3)
            elif check_id == "Ti39halfu8":  # Underutilized EBS
                resource_savings = extract_savings(metadata, 6)
            elif check_id == "iqdCTZKCUp":  # Idle Load Balancers
                resource_savings = extract_savings(metadata, 3)
            else:
                # Generic approach to find a savings field
                for field in metadata:
                    if field and isinstance(field, str) and "$" in field:
                        try:
                            savings_text = field.replace("$", "").replace(",", "")
                            resource_savings = float(savings_text)
                            break
                        except (ValueError, AttributeError):
                            pass

            # Add to estimated savings total
            if resource_savings > 0:
                estimated_savings += resource_savings

            # Create detail row for this resource
            detail_row = {
                'Status': resource.get('status', 'Unknown'),
                'Estimated Monthly Savings': f"${resource_savings:.2f}" if resource_savings > 0 else "Unknown"
            }

            # Add all metadata fields
            detail_row.update(resource_metadata)

            detail_data.append(detail_row)

        # Create detail dataframe for this check
        if detail_data:
            detail_df = pd.DataFrame(detail_data)
            detail_dfs[check_name] = detail_df

            # Add to summary data
            summary_data.append({
                'Check ID': check_id,
                'Check Name': check_name,
                'Resources to Optimize': resources_count,
                'Estimated Monthly Savings': f"${estimated_savings:.2f}" if estimated_savings > 0 else "Unknown"
            })

            # Add to total savings
            if estimated_savings > 0:
                total_savings += estimated_savings

    # Add total to summary data
    summary_data.append({
        'Check ID': 'TOTAL',
        'Check Name': 'All Checks',
        'Resources to Optimize': sum(item['Resources to Optimize'] for item in summary_data),
        'Estimated Monthly Savings': f"${total_savings:.2f}"
    })

    # Create summary dataframe
    summary_df = pd.DataFrame(summary_data)

    return summary_df, detail_dfs


def _run_export(account_id: str, account_name: str) -> None:
    """Collect Trusted Advisor data and write the Excel export."""
    if not utils.ensure_dependencies('pandas', 'openpyxl', 'boto3'):
        return

    import pandas as pd

    utils.log_info("IMPORTANT: AWS Trusted Advisor requires Business or Enterprise Support.")
    utils.log_info("Trusted Advisor API is only available in the us-east-1 region.")

    utils.log_info("Fetching Trusted Advisor Cost Optimization checks...")
    results = get_all_check_results()

    if not results:
        utils.log_warning("No cost optimization results found or error occurred.")
        sys.exit(1)

    utils.log_info("Processing check results...")
    summary_df, detail_dfs = process_check_results(results)

    if summary_df.empty:
        utils.log_info("No resources to optimize were found.")
        sys.exit(0)

    utils.log_info("Exporting results to Excel...")

    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    filename = utils.create_export_filename(
        account_name,
        "trusted-advisor-cost-optimization",
        "",
        current_date
    )

    # Combine summary and details into a dictionary for utils
    all_dfs = {'Summary': summary_df}
    all_dfs.update(detail_dfs)

    output_path = utils.save_multiple_dataframes_to_excel(all_dfs, filename)

    if output_path:
        utils.log_success(f"Data exported to: {output_path}")
        utils.log_success(f"Trusted Advisor cost optimization export completed: {output_path}")
    else:
        utils.log_error("Failed to export results")
        sys.exit(1)


def main():
    """Main execution function — 2-step state machine (confirm -> export) for global service."""
    try:
        account_id, account_name = utils.print_script_banner("AWS TRUSTED ADVISOR COST OPTIMIZATION EXPORT")

        # GovCloud availability guard — Trusted Advisor is not available in GovCloud
        partition = utils.detect_partition()
        if not utils.is_service_available_in_partition("trustedadvisor", partition):
            utils.log_warning("Trusted Advisor is not available in AWS GovCloud. Skipping.")
            sys.exit(0)

        step = 1

        while True:
            if step == 1:
                msg = "Ready to export Trusted Advisor Cost Optimization data (global service, us-east-1). Requires Business or Enterprise Support."
                result = utils.prompt_confirmation(msg)
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                step = 2

            elif step == 2:
                _run_export(account_id, account_name)
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

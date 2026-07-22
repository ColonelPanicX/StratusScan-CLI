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

import datetime
import sys
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
args = utils.parse_script_args("Export Trusted Advisor cost optimization checks to Excel")

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


class TrustedAdvisorNotSubscribedError(Exception):
    """
    Raised when the account's support plan does not include Trusted
    Advisor API access (``SubscriptionRequiredException``).

    This is a legitimate, graceful "service not available" state — NOT a
    collection failure. Business/Enterprise Support is a paid prerequisite
    for the Trusted Advisor API; a Basic/Developer support account will
    always see this. See scripts/shield_export.py's ``check_subscription``
    for the equivalent account-scope pattern (07.16.2026 audit).
    """


def _is_subscription_required_error(error: ClientError) -> bool:
    """Return True if a ClientError is Trusted Advisor's SubscriptionRequiredException."""
    error_code = error.response.get('Error', {}).get('Code', '')
    return error_code == 'SubscriptionRequiredException' or 'SubscriptionRequiredException' in str(error)


def get_trusted_advisor_checks():
    """
    Get all Trusted Advisor checks related to cost optimization.

    Not wrapped in ``aws_error_handler`` and does not swallow errors to an
    empty list: a swallowed error here would be indistinguishable from a
    genuinely empty/not-yet-run check set, producing silent data loss (see
    the 07.16.2026 silent-collection-failure audit).

    Returns:
        list: List of Trusted Advisor check results

    Raises:
        TrustedAdvisorNotSubscribedError: the account's support plan does
            not include Trusted Advisor API access — a legitimate, graceful
            "not available" state (caller must not report it as a failure).
        Exception: any other real error listing checks — the caller records
            this as a failed 'cost_checks' scope; it must never be silently
            swallowed into an empty check list.
    """
    # Support/Trusted Advisor is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    support_client = utils.get_boto3_client('support', region_name=home_region)

    try:
        # Get all Trusted Advisor checks
        response = support_client.describe_trusted_advisor_checks(language='en')
    except ClientError as e:
        if _is_subscription_required_error(e):
            raise TrustedAdvisorNotSubscribedError(str(e)) from e
        raise

    # Filter to only cost optimization checks
    cost_checks = [check for check in response.get('checks', []) if check.get('category') == 'cost_optimizing']

    return cost_checks


def get_check_result(check_id):
    """
    Get the detailed results for a specific Trusted Advisor check.

    This is the PRIMARY scope collector. It used to be decorated with
    ``@utils.aws_error_handler(..., default_return=None)``, which swallowed
    every error (throttling, access-denied, etc.) into ``None`` —
    indistinguishable from "this check legitimately has no result yet."
    Real errors now raise so the caller can tell a *failed* check apart
    from a genuinely empty one (07.16.2026 audit).

    Args:
        check_id (str): The ID of the Trusted Advisor check

    Returns:
        dict: The detailed results of the check, or None if the API
            returned no result for it.

    Raises:
        TrustedAdvisorNotSubscribedError: graceful not-available state.
        Exception: any other real API error fetching this check's result.
    """
    # Support/Trusted Advisor is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    support_client = utils.get_boto3_client('support', region_name=home_region)

    try:
        # Get the check result
        response = support_client.describe_trusted_advisor_check_result(
            checkId=check_id,
            language='en'
        )
    except ClientError as e:
        if _is_subscription_required_error(e):
            raise TrustedAdvisorNotSubscribedError(str(e)) from e
        raise

    return response.get('result')


def _build_check_row(check):
    """
    Build the ``(check_id, entry)`` pair for a single Trusted Advisor check.

    Extracted so per-check processing can be wrapped in try/except by the
    caller: a malformed check entry or a real API error fetching its
    result must not silently disappear or abort the whole collection.
    Required fields are read with ``.get()`` so a missing key never raises
    a bare ``KeyError`` (the ``check['id']`` subscript here was the
    confirmed KeyError candidate in the 07.16.2026 audit).

    Args:
        check (dict): A single check entry from describe_trusted_advisor_checks.

    Returns:
        tuple: ``(check_id, entry_dict)``. ``entry_dict`` is None if the
        check had no result to report.

    Raises:
        ValueError: the check entry has no 'id' — cannot be looked up.
        TrustedAdvisorNotSubscribedError: forwarded from get_check_result().
        Exception: any other real API error fetching this check's result.
    """
    check_id = check.get('id')
    check_name = check.get('name', 'Unknown Check')
    check_description = check.get('description', '')

    if not check_id:
        raise ValueError(f"Trusted Advisor check entry is missing 'id': {check!r}")

    utils.log_info(f"Fetching results for: {check_name}")
    result = get_check_result(check_id)

    if not result:
        return check_id, None

    return check_id, {
        'name': check_name,
        'description': check_description,
        'result': result
    }


def get_all_check_results():
    """
    Get results for all cost optimization checks.

    Iterates the cost-optimization checks (PRIMARY scope) calling
    ``get_check_result`` for each. A malformed check entry or a real API
    error on a single check is logged and skipped (per-item guard) rather
    than aborting the whole collection — but it is also recorded in
    ``failed_checks`` so the caller can surface it instead of silently
    treating a partial result set as "nothing to optimize."

    Returns:
        tuple: ``(results, failed_checks)`` where ``results`` is a dict
        keyed by check_id and ``failed_checks`` is a list of
        ``(check_id, error_message)`` tuples for checks that could not be
        fetched due to a real error.

    Raises:
        TrustedAdvisorNotSubscribedError: forwarded immediately — this
            applies to the whole service, not a single check, so it is not
            accumulated into ``failed_checks``.
    """
    # Get all cost optimization checks
    checks = get_trusted_advisor_checks()

    # Get results for each check
    results = {}
    failed_checks = []

    for check in checks:
        try:
            check_id, entry = _build_check_row(check)
        except TrustedAdvisorNotSubscribedError:
            # Not-available is a whole-service state, not a per-check one —
            # propagate immediately rather than accumulating it as a failure.
            raise
        except Exception as e:
            check_id_for_log = check.get('id', 'Unknown') if isinstance(check, dict) else 'Unknown'
            utils.log_error(f"Skipping Trusted Advisor check '{check_id_for_log}' due to a processing error", e)
            failed_checks.append((check_id_for_log, str(e)))
            continue

        if entry:
            results[check_id] = entry

    return results, failed_checks


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
        if len(metadata) > index and metadata[index] and isinstance(metadata[index], str) and "$" in metadata[index]:
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
                elif check_id == "Qch7DwouX1" and i == 4:
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
    """
    Collect Trusted Advisor data and write the Excel export.

    Trusted Advisor is a global, account-scope service (not multi-region —
    see scripts/shield_export.py for the account-scope reference pattern
    this follows). The account's support plan not including Trusted Advisor
    API access (SubscriptionRequiredException) is a legitimate, graceful
    "service not available" state (exit 0, no marker) and must not be
    confused with a real collection failure on the 'cost_checks' scope,
    which is always surfaced via utils.report_collection_failures + a
    non-zero exit — it must never be silently collapsed into "no cost
    optimization opportunities" (07.16.2026 audit).
    """
    if not utils.ensure_dependencies('pandas', 'openpyxl', 'boto3'):
        return

    utils.log_info("IMPORTANT: AWS Trusted Advisor requires Business or Enterprise Support.")
    utils.log_info("Trusted Advisor API is only available in the us-east-1 region.")

    utils.log_info("Fetching Trusted Advisor Cost Optimization checks...")

    # Account-scope failure tracking (see scripts/shield_export.py).
    failed_scopes = []

    try:
        results, failed_checks = get_all_check_results()
    except TrustedAdvisorNotSubscribedError:
        # Graceful skip — not having Business/Enterprise Support is a
        # legitimate, expected state, NOT a collection failure. No failure
        # marker is written.
        utils.log_warning("AWS Business or Enterprise Support plan is required to access Trusted Advisor API. Skipping.")
        sys.exit(0)
    except Exception as e:
        # A real error listing/collecting the cost-checks scope — must
        # propagate to failed_scopes, never collapse into an empty result
        # that reads as "no cost optimization opportunities."
        utils.log_error(f"Trusted Advisor cost-checks collection failed: {e}")
        failed_scopes.append(('cost_checks', str(e)))
        results, failed_checks = {}, []

    if failed_checks:
        summary = "; ".join(f"{check_id}: {msg}" for check_id, msg in failed_checks)
        failed_scopes.append(('cost_checks', f"{len(failed_checks)} check(s) failed: {summary}"))
        utils.log_error(f"{len(failed_checks)} Trusted Advisor check(s) failed to fetch results.")

    output_path = None
    write_failed = False

    # Export whatever succeeded — a partial export is required even when
    # some checks failed (see .collab/audit/07.16.2026-...).
    if results:
        utils.log_info("Processing check results...")
        summary_df, detail_dfs = process_check_results(results)

        if not summary_df.empty:
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
                write_failed = True

    if not output_path and not write_failed and not failed_scopes:
        # Genuinely empty: the checks scope succeeded and there is simply
        # nothing to optimize.
        utils.log_info("No cost optimization opportunities found.")

    # If the cost-checks scope failed (wholly or partially), make it loud:
    # write a marker and exit non-zero, even if a partial export was
    # written. A partial export that looks complete is exactly the failure
    # mode this guards against.
    if failed_scopes:
        utils.report_collection_failures(account_name, 'trusted-advisor-cost-optimization', failed_scopes)
        print(
            "\nERROR: Trusted Advisor cost optimization export completed with "
            "failures — data is incomplete. See the "
            "*-trusted-advisor-cost-optimization-FAILED-*.txt marker in the "
            "output directory."
        )
        sys.exit(1)

    # Excel write failure is a local I/O problem, not an AWS collection
    # failure — exit non-zero but do not write a *-FAILED-*.txt marker
    # (there was nothing wrong with the collected data itself).
    if write_failed:
        sys.exit(1)

    if not output_path:
        sys.exit(0)


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

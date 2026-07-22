#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Systems Manager Fleet Export Tool
Date: NOV-09-2025

Description:
This script exports AWS Systems Manager (SSM) Fleet Manager information into an
Excel file with multiple worksheets. The output includes managed instances,
patch compliance, inventory, and parameters.

Features:
- Managed instances with agent status and platform details
- Patch compliance status for instances
- SSM parameters (SecureString values are masked)
- Parameter Store hierarchy and metadata
- Compliance summary by instance
"""

import datetime
import sys
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
args = utils.parse_script_args("Export Systems Manager fleet and patch data to Excel")


def _build_instance_row(instance: dict, region: str) -> dict[str, Any]:
    """
    Build the export row for a single SSM managed instance.

    Extracted so the per-instance processing can be wrapped in try/except by
    the caller: a malformed instance entry is logged and skipped rather than
    discarding the whole region's results. Every field is read with ``.get()``
    and a safe default for the same reason.
    """
    instance_id = instance.get('InstanceId', 'N/A')

    # Instance details
    ping_status = instance.get('PingStatus', 'Unknown')
    last_ping_time = instance.get('LastPingDateTime', '')
    if last_ping_time:
        last_ping_time = last_ping_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_ping_time, datetime.datetime) else str(last_ping_time)

    # Platform
    platform_type = instance.get('PlatformType', 'N/A')
    platform_name = instance.get('PlatformName', 'N/A')
    platform_version = instance.get('PlatformVersion', 'N/A')

    # Agent version
    agent_version = instance.get('AgentVersion', 'N/A')

    # IP address
    ip_address = instance.get('IPAddress', 'N/A')

    # Computer name
    computer_name = instance.get('ComputerName', 'N/A')

    # Association status
    association_status = instance.get('AssociationStatus', 'Unknown')

    # Last successful association
    last_association = instance.get('LastSuccessfulAssociationExecutionDate', '')
    if last_association:
        last_association = last_association.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_association, datetime.datetime) else str(last_association)

    # Last association execution
    last_assoc_exec = instance.get('LastAssociationExecutionDate', '')
    if last_assoc_exec:
        last_assoc_exec = last_assoc_exec.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_assoc_exec, datetime.datetime) else str(last_assoc_exec)

    # Activation ID (for on-prem instances)
    activation_id = instance.get('ActivationId', 'N/A')

    # IAM role
    iam_role = instance.get('IamRole', 'N/A')

    # Registration date
    registration_date = instance.get('RegistrationDate', '')
    if registration_date:
        registration_date = registration_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(registration_date, datetime.datetime) else str(registration_date)

    return {
        'Region': region,
        'Instance ID': instance_id,
        'Ping Status': ping_status,
        'Last Ping': last_ping_time if last_ping_time else 'Never',
        'Platform Type': platform_type,
        'Platform Name': platform_name,
        'Platform Version': platform_version,
        'Agent Version': agent_version,
        'IP Address': ip_address,
        'Computer Name': computer_name,
        'Association Status': association_status,
        'Last Successful Association': last_association if last_association else 'N/A',
        'Last Association Execution': last_assoc_exec if last_assoc_exec else 'N/A',
        'Activation ID': activation_id,
        'IAM Role': iam_role,
        'Registration Date': registration_date if registration_date else 'N/A'
    }


def _scan_managed_instances_region(region: str) -> list[dict[str, Any]]:
    """
    Collect SSM managed instances from a single region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the region
    as failed instead of silently reporting "no managed instances" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed instances are skipped (logged) rather than aborting
    the whole region.
    """
    if not utils.is_aws_region(region):
        return []

    instances_data = []
    ssm_client = utils.get_boto3_client('ssm', region_name=region)

    paginator = ssm_client.get_paginator('describe_instance_information')
    for page in paginator.paginate():
        instances = page.get('InstanceInformationList', [])

        for instance in instances:
            try:
                instances_data.append(_build_instance_row(instance, region))
            except Exception as e:
                # One malformed instance is skipped, not fatal to the region.
                utils.log_error(
                    f"Skipping malformed SSM managed instance in {region}: "
                    f"{instance.get('InstanceId', '<unknown>')}",
                    e,
                )
                continue

    return instances_data


def collect_managed_instances(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect SSM managed instance information across regions, surfacing failures.

    Primary scope. Uses ``collect_failures=True`` so a region whose collection
    errors is reported as a failed scope rather than silently collapsed into
    an empty result.

    Returns:
        tuple: ``(instances, failed_regions)`` where ``failed_regions`` is a
        list of ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING SSM MANAGED INSTANCES ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_managed_instances_region,
        show_progress=True,
        collect_failures=True,
    )
    all_instances = [instance for result in region_results for instance in result]
    utils.log_success(f"Total SSM managed instances collected: {len(all_instances)}")
    return all_instances, failed_regions


def _build_compliance_row(item: dict, region: str, instance_id: str) -> dict[str, Any]:
    """Build the export row for a single SSM patch compliance item."""
    compliance_type = item.get('ComplianceType', 'N/A')
    status = item.get('Status', 'UNKNOWN')
    severity = item.get('Severity', 'UNSPECIFIED')

    # Execution summary
    execution_summary = item.get('ExecutionSummary', {})
    execution_time = execution_summary.get('ExecutionTime', '')
    if execution_time:
        execution_time = execution_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(execution_time, datetime.datetime) else str(execution_time)

    # Details
    details = item.get('Details', {})
    patch_group = details.get('PatchGroup', 'N/A')
    installed_count = details.get('InstalledCount', '0')
    installed_other_count = details.get('InstalledOtherCount', '0')
    missing_count = details.get('MissingCount', '0')
    failed_count = details.get('FailedCount', '0')
    not_applicable_count = details.get('NotApplicableCount', '0')

    return {
        'Region': region,
        'Instance ID': instance_id,
        'Compliance Type': compliance_type,
        'Status': status,
        'Severity': severity,
        'Patch Group': patch_group,
        'Installed Patches': installed_count,
        'Installed Other': installed_other_count,
        'Missing Patches': missing_count,
        'Failed Patches': failed_count,
        'Not Applicable': not_applicable_count,
        'Execution Time': execution_time if execution_time else 'N/A'
    }


def _scan_patch_compliance_region(region: str) -> list[dict[str, Any]]:
    """
    Collect SSM patch compliance from a single region.

    Region-scanned scope collector — its (region, error) results accumulate
    into the combined ``failed_regions`` list alongside managed instances and
    parameters (see the blast-radius audit referenced above). A region-level
    API failure (e.g. ``describe_instance_information`` throttled or denied)
    propagates rather than being swallowed into an empty list.

    A per-instance ``list_compliance_items`` lookup failing is left graceful
    (best-effort enrichment): many instances legitimately have no compliance
    data attached, and one instance's lookup failure must not discard the
    whole region.
    """
    compliance_data = []

    if not utils.is_aws_region(region):
        return compliance_data

    ssm_client = utils.get_boto3_client('ssm', region_name=region)

    # Get instances first
    instances_paginator = ssm_client.get_paginator('describe_instance_information')
    instances = []
    for inst_page in instances_paginator.paginate():
        instances.extend(inst_page.get('InstanceInformationList', []))

    for instance in instances:
        instance_id = instance.get('InstanceId', '')

        try:
            # Get patch compliance for this instance
            compliance_response = ssm_client.list_compliance_items(
                ResourceIds=[instance_id],
                Filters=[
                    {
                        'Key': 'ComplianceType',
                        'Values': ['Patch'],
                        'Type': 'EQUAL'
                    }
                ]
            )

            compliance_items = compliance_response.get('ComplianceItems', [])

            for item in compliance_items:
                try:
                    compliance_data.append(_build_compliance_row(item, region, instance_id))
                except Exception as e:
                    utils.log_error(
                        f"Skipping malformed compliance item in {region} for {instance_id}", e
                    )
                    continue

        except Exception:
            # Some instances may not have compliance data - best-effort enrichment.
            pass

    return compliance_data


def collect_patch_compliance(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect SSM patch compliance information across regions, surfacing failures.

    Returns:
        tuple: ``(compliance_items, failed_regions)``.
    """
    print("\n=== COLLECTING SSM PATCH COMPLIANCE ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_patch_compliance_region,
        show_progress=True,
        collect_failures=True,
    )
    all_compliance = [item for result in region_results for item in result]
    utils.log_success(f"Total patch compliance items collected: {len(all_compliance)}")
    return all_compliance, failed_regions


def _build_parameter_row(parameter: dict, region: str) -> dict[str, Any]:
    """Build the export row for a single SSM parameter."""
    param_name = parameter.get('Name', 'N/A')

    # Parameter details
    param_type = parameter.get('Type', 'String')
    description = parameter.get('Description', 'N/A')

    # Key ID (for SecureString)
    key_id = parameter.get('KeyId', 'N/A')

    # Last modified
    last_modified = parameter.get('LastModifiedDate', '')
    if last_modified:
        last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S') if isinstance(last_modified, datetime.datetime) else str(last_modified)

    # Last modified user
    last_modified_user = parameter.get('LastModifiedUser', 'N/A')

    # Version
    version = parameter.get('Version', 1)

    # Tier
    tier = parameter.get('Tier', 'Standard')

    # Policies
    policies = parameter.get('Policies', [])
    has_policies = 'Yes' if policies else 'No'

    # Data type
    data_type = parameter.get('DataType', 'text')

    return {
        'Region': region,
        'Parameter Name': param_name,
        'Parameter Type': param_type,
        'Tier': tier,
        'Data Type': data_type,
        'Description': description,
        'KMS Key ID': key_id,
        'Last Modified': last_modified if last_modified else 'N/A',
        'Last Modified User': last_modified_user,
        'Version': version,
        'Has Policies': has_policies
    }


def _scan_ssm_parameters_region(region: str) -> list[dict[str, Any]]:
    """
    Collect SSM Parameter Store parameters from a single region.

    Region-scanned scope collector — its (region, error) results accumulate
    into the combined ``failed_regions`` list alongside managed instances and
    patch compliance. Propagates region-level API errors rather than
    swallowing them into an empty list.
    """
    parameters_data = []

    if not utils.is_aws_region(region):
        return parameters_data

    ssm_client = utils.get_boto3_client('ssm', region_name=region)

    paginator = ssm_client.get_paginator('describe_parameters')
    for page in paginator.paginate():
        parameters = page.get('Parameters', [])

        for parameter in parameters:
            try:
                parameters_data.append(_build_parameter_row(parameter, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed SSM parameter in {region}: "
                    f"{parameter.get('Name', '<unknown>')}",
                    e,
                )
                continue

    return parameters_data


def collect_ssm_parameters(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect SSM Parameter Store parameters across regions, surfacing failures.

    Returns:
        tuple: ``(parameters, failed_regions)``.
    """
    print("\n=== COLLECTING SSM PARAMETERS ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_ssm_parameters_region,
        show_progress=True,
        collect_failures=True,
    )
    all_parameters = [parameter for result in region_results for parameter in result]
    utils.log_success(f"Total SSM parameters collected: {len(all_parameters)}")
    return all_parameters, failed_regions


def export_ssm_fleet_data(account_id: str, account_name: str):
    """
    Export SSM Fleet Manager information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Ask for region selection
    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}
    # Accumulates (region, error_message) tuples across all three
    # region-scanned scope collectors so a single marker + exit covers
    # every scope that failed (see blast-radius audit).
    failed_regions: list = []

    # STEP 1: Collect managed instances (primary scope)
    instances, failed_1 = collect_managed_instances(regions)
    failed_regions.extend(failed_1)
    if instances:
        data_frames['Managed Instances'] = pd.DataFrame(instances)

    # STEP 2: Collect patch compliance
    compliance, failed_2 = collect_patch_compliance(regions)
    failed_regions.extend(failed_2)
    if compliance:
        data_frames['Patch Compliance'] = pd.DataFrame(compliance)

    # STEP 3: Collect parameters
    parameters, failed_3 = collect_ssm_parameters(regions)
    failed_regions.extend(failed_3)
    if parameters:
        data_frames['SSM Parameters'] = pd.DataFrame(parameters)

    # STEP 4: Create summary
    if instances or compliance or parameters:
        summary_data = []

        total_instances = len(instances)
        total_compliance_items = len(compliance)
        total_parameters = len(parameters)

        # Instance status
        online_instances = sum(1 for i in instances if i.get('Ping Status') == 'Online')
        offline_instances = sum(1 for i in instances if i.get('Ping Status') != 'Online')

        # Platform types
        platform_counts = {}
        for inst in instances:
            platform = inst.get('Platform Type', 'Unknown')
            platform_counts[platform] = platform_counts.get(platform, 0) + 1

        # Compliance status
        compliant_instances = sum(1 for c in compliance if c.get('Status') == 'COMPLIANT')
        non_compliant_instances = sum(1 for c in compliance if c.get('Status') == 'NON_COMPLIANT')

        # Parameter types
        secure_params = sum(1 for p in parameters if p.get('Parameter Type') == 'SecureString')
        string_params = sum(1 for p in parameters if p.get('Parameter Type') == 'String')
        stringlist_params = sum(1 for p in parameters if p.get('Parameter Type') == 'StringList')

        summary_data.append({'Metric': 'Total Managed Instances', 'Value': total_instances})
        summary_data.append({'Metric': 'Online Instances', 'Value': online_instances})
        summary_data.append({'Metric': 'Offline Instances', 'Value': offline_instances})

        for platform, count in platform_counts.items():
            summary_data.append({'Metric': f'{platform} Instances', 'Value': count})

        summary_data.append({'Metric': 'Total Compliance Items', 'Value': total_compliance_items})
        summary_data.append({'Metric': 'Compliant Instances', 'Value': compliant_instances})
        summary_data.append({'Metric': 'Non-Compliant Instances', 'Value': non_compliant_instances})
        summary_data.append({'Metric': 'Total SSM Parameters', 'Value': total_parameters})
        summary_data.append({'Metric': 'SecureString Parameters', 'Value': secure_params})
        summary_data.append({'Metric': 'String Parameters', 'Value': string_params})
        summary_data.append({'Metric': 'StringList Parameters', 'Value': stringlist_params})

        data_frames['Summary'] = pd.DataFrame(summary_data)

    # Export whatever succeeded first — a partial export is required even when
    # some regions failed (see the silent-collection-failure blast-radius audit).
    if data_frames:
        # STEP 5: Prepare all DataFrames for export
        for sheet_name in data_frames:
            data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

        # STEP 6: Create filename and export
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        final_excel_file = utils.create_export_filename(
            account_name,
            'ssm-fleet',
            region_suffix,
            current_date
        )

        # Save using utils module for consistent formatting
        try:
            output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

            if output_path:
                utils.log_success("SSM Fleet data exported successfully!")
                utils.log_success(f"File location: {output_path}")
                utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")

                # Summary of exported data
                for sheet_name, df in data_frames.items():
                    utils.log_info(f"  - {sheet_name}: {len(df)} records")
                    print(f"  - {sheet_name}: {len(df)} records")
            else:
                utils.log_error("Error creating Excel file. Please check the logs.")

        except Exception as e:
            utils.log_error("Error creating Excel file", e)
    elif not failed_regions:
        # Genuinely empty account: every region succeeded across every scope
        # and returned nothing.
        utils.log_warning("No SSM Fleet data was collected. Nothing to export.")
        print("\nNo SSM Fleet resources found in the selected region(s).")

    # If ANY region failed ANY of the three scope collections, make it loud:
    # write a marker and exit non-zero, even if some data was exported. A
    # partial export that looks complete is exactly the failure mode this guards.
    if failed_regions:
        utils.report_collection_failures(account_name, 'ssm-fleet', failed_regions)
        print(
            "\nERROR: SSM Fleet export completed with failures — data is incomplete. "
            "See the *-ssm-fleet-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    # Initialize logging
    utils.setup_logging("ssm-fleet-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("ssm-fleet-export.py", "AWS Systems Manager Fleet Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS SYSTEMS MANAGER FLEET EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown" and not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
            print("Exiting script...")
            sys.exit(0)

        # Export SSM Fleet data
        export_ssm_fleet_data(account_id, account_name)

        print("\nSSM Fleet export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("ssm-fleet-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

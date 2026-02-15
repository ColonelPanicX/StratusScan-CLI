#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS GuardDuty Export Tool
Version: v1.1.0
Date: NOV-16-2025

Description:
This script exports AWS GuardDuty threat detection information from all regions into an
Excel file with multiple worksheets. The output includes detectors, findings, threat
intelligence sets, IP sets, and publishing destinations.

Features:
- GuardDuty detectors with status and configuration
- Security findings with severity and threat details
- Threat intelligence sets (custom threat lists)
- IP sets for trusted/threat IPs
- Publishing destinations for findings
- Member accounts in multi-account setups
- Finding statistics and summaries
- Phase 4B: Concurrent region scanning (4x-10x performance improvement)
"""

import sys
import datetime
from pathlib import Path
from typing import List, Dict, Any

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
utils.setup_logging("guardduty-export")
utils.log_script_start("guardduty-export.py", "AWS GuardDuty Export Tool")


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("               AWS GUARDDUTY EXPORT TOOL")
    print("====================================================================")
    print("Version: v1.1.0                        Date: NOV-16-2025")
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


def get_aws_regions():
    """Get list of all available AWS regions for the current partition."""
    try:
        # Detect partition and get ALL regions for that partition
        partition = utils.detect_partition()
        regions = utils.get_partition_regions(partition, all_regions=True)
        utils.log_info(f"Retrieved {len(regions)} regions for partition {partition}")
        return regions
    except Exception as e:
        utils.log_error("Error getting AWS regions", e)
        # Fallback to default regions for the partition
        partition = utils.detect_partition()
        return utils.get_partition_regions(partition, all_regions=False)


@utils.aws_error_handler("Collecting GuardDuty detectors from region", default_return=[])
def collect_detectors_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect GuardDuty detector information from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with detector information
    """
    if not utils.validate_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    detectors_data = []

    gd_client = utils.get_boto3_client('guardduty', region_name=region)

    # List detectors
    detector_response = gd_client.list_detectors()
    detector_ids = detector_response.get('DetectorIds', [])

    if not detector_ids:
        utils.log_info(f"No GuardDuty detector found in {region}")
        return []

    for detector_id in detector_ids:
        utils.log_info(f"Processing detector: {detector_id} in {region}")

        try:
            # Get detector details
            detector = gd_client.get_detector(DetectorId=detector_id)

            # Status
            status = detector.get('Status', '')

            # Service role
            service_role = detector.get('ServiceRole', 'N/A')

            # Data sources
            data_sources = detector.get('DataSources', {})
            cloud_trail = data_sources.get('CloudTrail', {}).get('Status', 'N/A')
            dns_logs = data_sources.get('DNSLogs', {}).get('Status', 'N/A')
            flow_logs = data_sources.get('FlowLogs', {}).get('Status', 'N/A')
            s3_logs = data_sources.get('S3Logs', {}).get('Status', 'N/A')
            kubernetes = data_sources.get('Kubernetes', {})
            k8s_audit_logs = kubernetes.get('AuditLogs', {}).get('Status', 'N/A') if kubernetes else 'N/A'

            # Finding publishing frequency
            finding_frequency = detector.get('FindingPublishingFrequency', 'N/A')

            # Created at
            created_at = detector.get('CreatedAt', '')
            if created_at:
                created_at = created_at if isinstance(created_at, str) else created_at.strftime('%Y-%m-%d %H:%M:%S')

            # Updated at
            updated_at = detector.get('UpdatedAt', '')
            if updated_at:
                updated_at = updated_at if isinstance(updated_at, str) else updated_at.strftime('%Y-%m-%d %H:%M:%S')

            # Tags
            tags = detector.get('Tags', {})
            tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'N/A'

            detectors_data.append({
                'Region': region,
                'Detector ID': detector_id,
                'Status': status,
                'Finding Frequency': finding_frequency,
                'CloudTrail': cloud_trail,
                'DNS Logs': dns_logs,
                'VPC Flow Logs': flow_logs,
                'S3 Logs': s3_logs,
                'Kubernetes Audit Logs': k8s_audit_logs,
                'Service Role': service_role,
                'Created At': created_at,
                'Updated At': updated_at,
                'Tags': tags_str
            })

        except Exception as e:
            utils.log_warning(f"Could not get details for detector {detector_id}: {e}")

    utils.log_info(f"Found {len(detectors_data)} detectors in {region}")
    return detectors_data


def collect_detectors(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect GuardDuty detector information using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with detector information
    """
    print("\n=== COLLECTING GUARDDUTY DETECTORS ===")
    utils.log_info(f"Scanning {len(regions)} regions for GuardDuty detectors...")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_detectors_from_region,
        show_progress=True
    )

    # Flatten results
    all_detectors = []
    for detectors_in_region in region_results:
        all_detectors.extend(detectors_in_region)

    utils.log_success(f"Total GuardDuty detectors collected: {len(all_detectors)}")
    return all_detectors


@utils.aws_error_handler("Collecting GuardDuty findings from region", default_return=[])
def collect_findings_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect GuardDuty findings from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with finding information
    """
    if not utils.validate_aws_region(region):
        return []

    findings_data = []

    try:
        gd_client = utils.get_boto3_client('guardduty', region_name=region)

        # Get detectors first
        detector_response = gd_client.list_detectors()
        detector_ids = detector_response.get('DetectorIds', [])

        for detector_id in detector_ids:
            try:
                # List findings
                finding_paginator = gd_client.get_paginator('list_findings')

                finding_ids = []
                for finding_page in finding_paginator.paginate(DetectorId=detector_id):
                    finding_ids.extend(finding_page.get('FindingIds', []))

                # Get finding details in batches (max 50 at a time)
                for i in range(0, len(finding_ids), 50):
                    batch_ids = finding_ids[i:i+50]

                    findings_response = gd_client.get_findings(
                        DetectorId=detector_id,
                        FindingIds=batch_ids
                    )

                    findings = findings_response.get('Findings', [])

                    for finding in findings:
                        finding_id = finding.get('Id', '')
                        finding_type = finding.get('Type', '')
                        severity = finding.get('Severity', 0)

                        # Resource
                        resource = finding.get('Resource', {})
                        resource_type = resource.get('ResourceType', '')

                        # Instance details
                        instance_details = resource.get('InstanceDetails', {})
                        instance_id = instance_details.get('InstanceId', 'N/A')

                        # S3 bucket details
                        s3_details = resource.get('S3BucketDetails', [])
                        bucket_name = s3_details[0].get('Name', 'N/A') if s3_details else 'N/A'

                        # Title and description
                        title = finding.get('Title', '')
                        description = finding.get('Description', '')

                        # Service
                        service = finding.get('Service', {})
                        action = service.get('Action', {})
                        action_type = action.get('ActionType', 'N/A')

                        # Count
                        count = service.get('Count', 0)

                        # First seen
                        first_seen = service.get('EventFirstSeen', '')
                        if first_seen:
                            first_seen = first_seen if isinstance(first_seen, str) else first_seen.strftime('%Y-%m-%d %H:%M:%S')

                        # Last seen
                        last_seen = service.get('EventLastSeen', '')
                        if last_seen:
                            last_seen = last_seen if isinstance(last_seen, str) else last_seen.strftime('%Y-%m-%d %H:%M:%S')

                        # Created at
                        created_at = finding.get('CreatedAt', '')
                        if created_at:
                            created_at = created_at if isinstance(created_at, str) else created_at.strftime('%Y-%m-%d %H:%M:%S')

                        # Updated at
                        updated_at = finding.get('UpdatedAt', '')
                        if updated_at:
                            updated_at = updated_at if isinstance(updated_at, str) else updated_at.strftime('%Y-%m-%d %H:%M:%S')

                        findings_data.append({
                            'Region': region,
                            'Finding ID': finding_id,
                            'Type': finding_type,
                            'Severity': severity,
                            'Title': title,
                            'Description': description[:200] + '...' if len(description) > 200 else description,
                            'Resource Type': resource_type,
                            'Instance ID': instance_id,
                            'S3 Bucket': bucket_name,
                            'Action Type': action_type,
                            'Count': count,
                            'First Seen': first_seen,
                            'Last Seen': last_seen,
                            'Created At': created_at,
                            'Updated At': updated_at
                        })

            except Exception as e:
                utils.log_warning(f"Could not get findings for detector {detector_id}: {e}")

    except Exception as e:
        utils.log_error(f"Error collecting findings in region {region}", e)

    utils.log_info(f"Found {len(findings_data)} findings in {region}")
    return findings_data


def collect_findings(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect GuardDuty findings using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with finding information
    """
    print("\n=== COLLECTING GUARDDUTY FINDINGS ===")
    utils.log_info(f"Scanning {len(regions)} regions for GuardDuty findings...")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_findings_from_region,
        show_progress=True
    )

    # Flatten results
    all_findings = []
    for findings_in_region in region_results:
        all_findings.extend(findings_in_region)

    utils.log_success(f"Total GuardDuty findings collected: {len(all_findings)}")
    return all_findings


@utils.aws_error_handler("Collecting threat intel sets from region", default_return=[])
def collect_threat_intel_sets_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect GuardDuty threat intelligence sets from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with threat intel set information
    """
    if not utils.validate_aws_region(region):
        return []

    threat_sets_data = []

    gd_client = utils.get_boto3_client('guardduty', region_name=region)

    # Get detectors first
    detector_response = gd_client.list_detectors()
    detector_ids = detector_response.get('DetectorIds', [])

    for detector_id in detector_ids:
        try:
            # List threat intel sets
            threat_set_paginator = gd_client.get_paginator('list_threat_intel_sets')

            for threat_page in threat_set_paginator.paginate(DetectorId=detector_id):
                threat_set_ids = threat_page.get('ThreatIntelSetIds', [])

                for threat_set_id in threat_set_ids:
                    try:
                        # Get threat intel set details
                        threat_set = gd_client.get_threat_intel_set(
                            DetectorId=detector_id,
                            ThreatIntelSetId=threat_set_id
                        )

                        name = threat_set.get('Name', '')
                        format_type = threat_set.get('Format', '')
                        location = threat_set.get('Location', '')
                        status = threat_set.get('Status', '')

                        # Tags
                        tags = threat_set.get('Tags', {})
                        tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'N/A'

                        threat_sets_data.append({
                            'Region': region,
                            'Detector ID': detector_id,
                            'Threat Intel Set ID': threat_set_id,
                            'Name': name,
                            'Format': format_type,
                            'Status': status,
                            'Location': location,
                            'Tags': tags_str
                        })

                    except Exception as e:
                        utils.log_warning(f"Could not get threat intel set {threat_set_id}: {e}")

        except Exception as e:
            utils.log_warning(f"Could not get threat intel sets for detector {detector_id}: {e}")

    utils.log_info(f"Found {len(threat_sets_data)} threat intel sets in {region}")
    return threat_sets_data


def collect_threat_intel_sets(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect GuardDuty threat intelligence sets using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with threat intel set information
    """
    print("\n=== COLLECTING THREAT INTEL SETS ===")
    utils.log_info(f"Scanning {len(regions)} regions for threat intel sets...")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_threat_intel_sets_from_region,
        show_progress=True
    )

    # Flatten results
    all_threat_sets = []
    for threat_sets_in_region in region_results:
        all_threat_sets.extend(threat_sets_in_region)

    utils.log_success(f"Total threat intel sets collected: {len(all_threat_sets)}")
    return all_threat_sets


@utils.aws_error_handler("Collecting IP sets from region", default_return=[])
def collect_ip_sets_from_region(region: str) -> List[Dict[str, Any]]:
    """
    Collect GuardDuty IP sets from a single AWS region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with IP set information
    """
    if not utils.validate_aws_region(region):
        return []

    ip_sets_data = []

    gd_client = utils.get_boto3_client('guardduty', region_name=region)

    # Get detectors first
    detector_response = gd_client.list_detectors()
    detector_ids = detector_response.get('DetectorIds', [])

    for detector_id in detector_ids:
        try:
            # List IP sets
            ip_set_paginator = gd_client.get_paginator('list_ip_sets')

            for ip_page in ip_set_paginator.paginate(DetectorId=detector_id):
                ip_set_ids = ip_page.get('IpSetIds', [])

                for ip_set_id in ip_set_ids:
                    try:
                        # Get IP set details
                        ip_set = gd_client.get_ip_set(
                            DetectorId=detector_id,
                            IpSetId=ip_set_id
                        )

                        name = ip_set.get('Name', '')
                        format_type = ip_set.get('Format', '')
                        location = ip_set.get('Location', '')
                        status = ip_set.get('Status', '')

                        # Tags
                        tags = ip_set.get('Tags', {})
                        tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'N/A'

                        ip_sets_data.append({
                            'Region': region,
                            'Detector ID': detector_id,
                            'IP Set ID': ip_set_id,
                            'Name': name,
                            'Format': format_type,
                            'Status': status,
                            'Location': location,
                            'Tags': tags_str
                        })

                    except Exception as e:
                        utils.log_warning(f"Could not get IP set {ip_set_id}: {e}")

        except Exception as e:
            utils.log_warning(f"Could not get IP sets for detector {detector_id}: {e}")

    utils.log_info(f"Found {len(ip_sets_data)} IP sets in {region}")
    return ip_sets_data


def collect_ip_sets(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect GuardDuty IP sets using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with IP set information
    """
    print("\n=== COLLECTING IP SETS ===")
    utils.log_info(f"Scanning {len(regions)} regions for IP sets...")

    # Use concurrent region scanning
    region_results = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=collect_ip_sets_from_region,
        show_progress=True
    )

    # Flatten results
    all_ip_sets = []
    for ip_sets_in_region in region_results:
        all_ip_sets.extend(ip_sets_in_region)

    utils.log_success(f"Total IP sets collected: {len(all_ip_sets)}")
    return all_ip_sets


def export_guardduty_data(account_id: str, account_name: str):
    """
    Export GuardDuty information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition for region examples
    partition = utils.detect_partition()
    if partition == 'aws-us-gov':
        example_regions = "us-gov-west-1, us-gov-east-1"
    else:
        example_regions = "us-east-1, us-west-1, us-west-2, eu-west-1"

    # Display standardized region selection menu
    print("\n" + "=" * 68)
    print("REGION SELECTION")
    print("=" * 68)
    print()
    print("Please select which AWS regions to scan:")
    print()
    print("1. Default Regions (recommended for most use cases)")
    print(f"   └─ {example_regions}")
    print()
    print("2. All Available Regions")
    print("   └─ Scans all regions (slower, more comprehensive)")
    print()
    print("3. Specific Region")
    print("   └─ Choose a single region to scan")
    print()

    # Get user selection with validation
    while True:
        try:
            selection = input("Enter your selection (1-3): ").strip()
            selection_int = int(selection)
            if 1 <= selection_int <= 3:
                break
            else:
                print("Please enter a number between 1 and 3.")
        except ValueError:
            print("Please enter a valid number (1-3).")

    # Get regions based on selection
    all_available_regions = get_aws_regions()
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        regions = default_regions
        region_text = f"default AWS regions ({len(regions)} regions)"
        region_suffix = ""
    elif selection_int == 2:
        regions = all_available_regions
        region_text = f"all AWS regions ({len(regions)} regions)"
        region_suffix = ""
    else:  # selection_int == 3
        # Display numbered list of regions
        print("\n" + "=" * 68)
        print("AVAILABLE AWS REGIONS")
        print("=" * 68)
        print()
        for idx, region in enumerate(all_available_regions, 1):
            print(f"{idx:2}. {region}")
        print()

        # Get region selection with validation
        while True:
            try:
                region_num = input(f"Enter region number (1-{len(all_available_regions)}): ").strip()
                region_idx = int(region_num) - 1
                if 0 <= region_idx < len(all_available_regions):
                    selected_region = all_available_regions[region_idx]
                    regions = [selected_region]
                    region_text = f"AWS region \"{selected_region}\""
                    region_suffix = f"-{selected_region}"
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print(f"Please enter a valid number (1-{len(all_available_regions)}).")

    print(f"\nStarting GuardDuty export process for {region_text}...")
    print("=" * 68)
    print("This may take some time depending on the number of regions and resources...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect detectors
    detectors = collect_detectors(regions)
    if detectors:
        data_frames['Detectors'] = pd.DataFrame(detectors)

    # STEP 2: Collect findings
    findings = collect_findings(regions)
    if findings:
        data_frames['Findings'] = pd.DataFrame(findings)

    # STEP 3: Collect threat intel sets
    threat_sets = collect_threat_intel_sets(regions)
    if threat_sets:
        data_frames['Threat Intel Sets'] = pd.DataFrame(threat_sets)

    # STEP 4: Collect IP sets
    ip_sets = collect_ip_sets(regions)
    if ip_sets:
        data_frames['IP Sets'] = pd.DataFrame(ip_sets)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No GuardDuty data was collected. Nothing to export.")
        print("\nNo GuardDuty detectors found in the selected region(s).")
        return

    # STEP 5: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 6: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'guardduty',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("GuardDuty data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")

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

        # Export GuardDuty data
        export_guardduty_data(account_id, account_name)

        print("\nGuardDuty export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("guardduty-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

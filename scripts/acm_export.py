#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Certificate Manager (ACM) Export Tool
Date: NOV-09-2025

Description:
This script exports AWS Certificate Manager certificate information from all regions
into an Excel file. The output includes SSL/TLS certificates, validation methods,
domain names, renewal status, and usage information.

Features:
- SSL/TLS certificate inventory with status and expiration
- Domain validation methods (DNS, email)
- Subject Alternative Names (SANs)
- Certificate usage tracking (where certificates are in use)
- Renewal eligibility and auto-renewal status
- Certificate transparency logging status
- Key algorithm and signature information
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


def scan_acm_certificates_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan ACM certificates in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with certificate information from this region
    """
    regional_certificates = []

    try:
        acm_client = utils.get_boto3_client('acm', region_name=region)

        # Get certificates
        paginator = acm_client.get_paginator('list_certificates')

        for page in paginator.paginate():
            certificates = page.get('CertificateSummaryList', [])

            for cert_summary in certificates:
                cert_arn = cert_summary.get('CertificateArn', '')
                domain_name = cert_summary.get('DomainName', '')

                try:
                    # Get detailed certificate information
                    cert_response = acm_client.describe_certificate(CertificateArn=cert_arn)
                    cert = cert_response.get('Certificate', {})

                    # Status
                    status = cert.get('Status', '')

                    # Type
                    cert_type = cert.get('Type', '')

                    # Key algorithm
                    key_algorithm = cert.get('KeyAlgorithm', 'N/A')

                    # Signature algorithm
                    signature_algorithm = cert.get('SignatureAlgorithm', 'N/A')

                    # Subject Alternative Names
                    subject_alternative_names = cert.get('SubjectAlternativeNames', [])
                    san_count = len(subject_alternative_names)
                    san_str = ', '.join(subject_alternative_names[:5])  # First 5 SANs
                    if san_count > 5:
                        san_str += f" ... ({san_count - 5} more)"

                    # Validation method
                    domain_validation_options = cert.get('DomainValidationOptions', [])
                    validation_method = 'N/A'
                    if domain_validation_options:
                        validation_method = domain_validation_options[0].get('ValidationMethod', 'N/A')

                    # Validation status
                    validation_status = 'N/A'
                    if domain_validation_options:
                        validation_status = domain_validation_options[0].get('ValidationStatus', 'N/A')

                    # In use by (resources using this certificate)
                    in_use_by = cert.get('InUseBy', [])
                    in_use_count = len(in_use_by)
                    in_use_str = ', '.join([arn.split('/')[-1] for arn in in_use_by[:3]])  # First 3 resources
                    if in_use_count > 3:
                        in_use_str += f" ... ({in_use_count - 3} more)"
                    if not in_use_str:
                        in_use_str = 'Not in use'

                    # Created date
                    created_at = cert.get('CreatedAt', '')
                    if created_at:
                        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(created_at, datetime.datetime) else str(created_at)

                    # Issued date
                    issued_at = cert.get('IssuedAt', '')
                    if issued_at:
                        issued_at = issued_at.strftime('%Y-%m-%d %H:%M:%S') if isinstance(issued_at, datetime.datetime) else str(issued_at)

                    # Not before
                    not_before = cert.get('NotBefore', '')
                    if not_before:
                        not_before = not_before.strftime('%Y-%m-%d %H:%M:%S') if isinstance(not_before, datetime.datetime) else str(not_before)

                    # Not after (expiration)
                    not_after = cert.get('NotAfter', '')
                    days_to_expiry = 'N/A'
                    if not_after:
                        not_after_dt = not_after if isinstance(not_after, datetime.datetime) else datetime.datetime.fromisoformat(str(not_after))
                        not_after = not_after_dt.strftime('%Y-%m-%d %H:%M:%S')
                        # Calculate days to expiry
                        days_to_expiry = (not_after_dt.replace(tzinfo=None) - datetime.datetime.now()).days

                    # Renewal eligibility
                    renewal_eligibility = cert.get('RenewalEligibility', 'N/A')

                    # Renewal summary
                    renewal_summary = cert.get('RenewalSummary', {})
                    renewal_status = renewal_summary.get('RenewalStatus', 'N/A')

                    # Certificate transparency logging
                    options = cert.get('Options', {})
                    certificate_transparency_logging = options.get('CertificateTransparencyLoggingPreference', 'N/A')

                    # Issuer
                    issuer = cert.get('Issuer', 'N/A')

                    # Subject
                    subject = cert.get('Subject', 'N/A')

                    # Serial
                    serial = cert.get('Serial', 'N/A')

                    regional_certificates.append({
                        'Region': region,
                        'Domain Name': domain_name,
                        'Status': status,
                        'Type': cert_type,
                        'Validation Method': validation_method,
                        'Validation Status': validation_status,
                        'SAN Count': san_count,
                        'Subject Alternative Names': san_str,
                        'In Use By Count': in_use_count,
                        'In Use By': in_use_str,
                        'Days to Expiry': days_to_expiry,
                        'Expiration Date': not_after if not_after else 'N/A',
                        'Renewal Eligibility': renewal_eligibility,
                        'Renewal Status': renewal_status,
                        'Key Algorithm': key_algorithm,
                        'Signature Algorithm': signature_algorithm,
                        'Certificate Transparency': certificate_transparency_logging,
                        'Issuer': issuer,
                        'Subject': subject,
                        'Serial': serial,
                        'Created Date': created_at,
                        'Issued Date': issued_at if issued_at else 'N/A',
                        'Not Before': not_before if not_before else 'N/A',
                        'Certificate ARN': cert_arn
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for certificate {cert_arn}: {e}")

        utils.log_info(f"Found {len(regional_certificates)} ACM certificates in {region}")

    except Exception as e:
        utils.log_error(f"Error processing region {region} for ACM certificates", e)

    return regional_certificates


@utils.aws_error_handler("Collecting ACM certificates", default_return=[])
def collect_acm_certificates(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect ACM certificate information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with certificate information
    """
    print("\n=== COLLECTING ACM CERTIFICATES ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_certificates = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_acm_certificates_in_region,
        resource_type="ACM certificates"
    )

    utils.log_success(f"Total ACM certificates collected: {len(all_certificates)}")
    return all_certificates


def scan_certificate_validation_details_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan certificate validation details in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with validation details from this region
    """
    regional_validations = []

    try:
        acm_client = utils.get_boto3_client('acm', region_name=region)

        # Get all certificates first
        cert_paginator = acm_client.get_paginator('list_certificates')

        for cert_page in cert_paginator.paginate():
            certificates = cert_page.get('CertificateSummaryList', [])

            for cert_summary in certificates:
                cert_arn = cert_summary.get('CertificateArn', '')
                domain_name = cert_summary.get('DomainName', '')

                try:
                    # Get certificate details
                    cert_response = acm_client.describe_certificate(CertificateArn=cert_arn)
                    cert = cert_response.get('Certificate', {})

                    # Domain validation options
                    domain_validation_options = cert.get('DomainValidationOptions', [])

                    for validation_option in domain_validation_options:
                        validation_domain = validation_option.get('DomainName', '')
                        validation_method = validation_option.get('ValidationMethod', '')
                        validation_status = validation_option.get('ValidationStatus', '')

                        # Resource record (for DNS validation)
                        resource_record = validation_option.get('ResourceRecord', {})
                        record_name = resource_record.get('Name', 'N/A')
                        record_type = resource_record.get('Type', 'N/A')
                        record_value = resource_record.get('Value', 'N/A')

                        # Validation emails (for email validation)
                        validation_emails = validation_option.get('ValidationEmails', [])
                        validation_emails_str = ', '.join(validation_emails) if validation_emails else 'N/A'

                        regional_validations.append({
                            'Region': region,
                            'Certificate Domain': domain_name,
                            'Validation Domain': validation_domain,
                            'Validation Method': validation_method,
                            'Validation Status': validation_status,
                            'DNS Record Name': record_name,
                            'DNS Record Type': record_type,
                            'DNS Record Value': record_value,
                            'Validation Emails': validation_emails_str
                        })

                except Exception as e:
                    utils.log_warning(f"Could not get validation details for {cert_arn}: {e}")

        utils.log_info(f"Found {len(regional_validations)} certificate validation details in {region}")

    except Exception as e:
        utils.log_error(f"Error collecting validation details in region {region}", e)

    return regional_validations


@utils.aws_error_handler("Collecting certificate validation details", default_return=[])
def collect_certificate_validation_details(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect detailed validation information for ACM certificates using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with validation details
    """
    print("\n=== COLLECTING CERTIFICATE VALIDATION DETAILS ===")
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_validations = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_certificate_validation_details_in_region,
        resource_type="certificate validation details"
    )

    utils.log_success(f"Total validation details collected: {len(all_validations)}")
    return all_validations


def export_acm_data(account_id: str, account_name: str):
    """
    Export ACM information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
    # Detect partition and set partition-aware example regions
    regions = utils.prompt_region_selection()
    region_suffix = 'all'
    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect certificates
    certificates = collect_acm_certificates(regions)
    if certificates:
        data_frames['Certificates'] = pd.DataFrame(certificates)

    # STEP 2: Collect validation details
    validations = collect_certificate_validation_details(regions)
    if validations:
        data_frames['Validation Details'] = pd.DataFrame(validations)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No ACM data was collected. Nothing to export.")
        print("\nNo ACM certificates found in the selected region(s).")
        return

    # STEP 3: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 4: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'acm',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("ACM data exported successfully!")
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
    # Initialize logging
    utils.setup_logging("acm-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("acm-export.py", "AWS ACM Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = utils.print_script_banner("AWS CERTIFICATE MANAGER (ACM) EXPORT")

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            if not utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False):
                print("Exiting script...")
                sys.exit(0)

        # Export ACM data
        export_acm_data(account_id, account_name)

        print("\nACM export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("acm-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

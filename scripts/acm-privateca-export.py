#!/usr/bin/env python3
"""
ACM Private CA Export Script for StratusScan

Exports comprehensive AWS Certificate Manager Private Certificate Authority information including:
- Private Certificate Authorities with configuration details
- Issued certificates and certificate templates
- Certificate revocation lists (CRLs)
- Audit reports and permissions

Output: Multi-worksheet Excel file with ACM Private CA resources
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import json

try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

try:
    import pandas as pd
except ImportError:
    print("Error: pandas is not installed. Please install it using 'pip install pandas'")
    sys.exit(1)


def check_dependencies():
    """Check if required dependencies are installed."""
    utils.log_info("Checking dependencies...")

    missing = []

    try:
        import pandas
        utils.log_info("✓ pandas is installed")
    except ImportError:
        missing.append("pandas")

    try:
        import openpyxl
        utils.log_info("✓ openpyxl is installed")
    except ImportError:
        missing.append("openpyxl")

    try:
        import boto3
        utils.log_info("✓ boto3 is installed")
    except ImportError:
        missing.append("boto3")

    if missing:
        utils.log_error(f"Missing dependencies: {', '.join(missing)}")
        utils.log_error("Please install using: pip install " + " ".join(missing))
        sys.exit(1)

    utils.log_success("All dependencies are installed")


def _scan_private_cas_region(region: str) -> List[Dict[str, Any]]:
    """Scan Private CAs in a single region."""
    regional_cas = []
    acmpca_client = utils.get_boto3_client('acm-pca', region_name=region)

    try:
        paginator = acmpca_client.get_paginator('list_certificate_authorities')
        for page in paginator.paginate():
            cas = page.get('CertificateAuthorities', [])

            for ca in cas:
                ca_arn = ca.get('Arn', 'N/A')

                # Get detailed CA information
                try:
                    ca_response = acmpca_client.describe_certificate_authority(
                        CertificateAuthorityArn=ca_arn
                    )
                    ca_details = ca_response.get('CertificateAuthority', {})

                    # Basic information
                    ca_arn = ca_details.get('Arn', 'N/A')
                    ca_type = ca_details.get('Type', 'N/A')
                    status = ca_details.get('Status', 'N/A')
                    key_algorithm = ca_details.get('CertificateAuthorityConfiguration', {}).get('KeyAlgorithm', 'N/A')
                    signing_algorithm = ca_details.get('CertificateAuthorityConfiguration', {}).get('SigningAlgorithm', 'N/A')

                    # Subject information
                    subject = ca_details.get('CertificateAuthorityConfiguration', {}).get('Subject', {})
                    common_name = subject.get('CommonName', 'N/A')
                    organization = subject.get('Organization', 'N/A')
                    organizational_unit = subject.get('OrganizationalUnit', 'N/A')
                    country = subject.get('Country', 'N/A')
                    state = subject.get('State', 'N/A')
                    locality = subject.get('Locality', 'N/A')

                    # Dates
                    created_at = ca_details.get('CreatedAt', 'N/A')
                    if created_at != 'N/A':
                        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')

                    not_before = ca_details.get('NotBefore', 'N/A')
                    if not_before != 'N/A':
                        not_before = not_before.strftime('%Y-%m-%d %H:%M:%S')

                    not_after = ca_details.get('NotAfter', 'N/A')
                    if not_after != 'N/A':
                        not_after = not_after.strftime('%Y-%m-%d %H:%M:%S')

                    last_state_change = ca_details.get('LastStateChangeAt', 'N/A')
                    if last_state_change != 'N/A':
                        last_state_change = last_state_change.strftime('%Y-%m-%d %H:%M:%S')

                    # Revocation configuration
                    revocation_config = ca_details.get('RevocationConfiguration', {})
                    crl_config = revocation_config.get('CrlConfiguration', {})
                    crl_enabled = crl_config.get('Enabled', False)
                    crl_s3_bucket = crl_config.get('S3BucketName', 'N/A')
                    crl_s3_object_acl = crl_config.get('S3ObjectAcl', 'N/A')
                    crl_expiration_days = crl_config.get('ExpirationInDays', 'N/A')

                    ocsp_config = revocation_config.get('OcspConfiguration', {})
                    ocsp_enabled = ocsp_config.get('Enabled', False)
                    ocsp_custom_cname = ocsp_config.get('OcspCustomCname', 'N/A')

                    # Key storage security standard
                    key_storage = ca_details.get('KeyStorageSecurityStandard', 'N/A')

                    # Usage mode
                    usage_mode = ca_details.get('UsageMode', 'N/A')

                    # Owner account
                    owner_account = ca_details.get('OwnerAccount', 'N/A')

                    # Failure reason
                    failure_reason = ca_details.get('FailureReason', 'N/A')

                    # Serial number
                    serial = ca_details.get('Serial', 'N/A')

                    # Get tags
                    tags_str = 'N/A'
                    try:
                        tags_response = acmpca_client.list_tags(
                            CertificateAuthorityArn=ca_arn
                        )
                        tags = tags_response.get('Tags', [])
                        if tags:
                            tags_str = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags])
                    except Exception:
                        pass

                    regional_cas.append({
                        'Region': region,
                        'CA ARN': ca_arn,
                        'Type': ca_type,
                        'Status': status,
                        'Common Name': common_name,
                        'Organization': organization,
                        'Organizational Unit': organizational_unit,
                        'Country': country,
                        'State': state,
                        'Locality': locality,
                        'Key Algorithm': key_algorithm,
                        'Signing Algorithm': signing_algorithm,
                        'Key Storage Security Standard': key_storage,
                        'Usage Mode': usage_mode,
                        'Serial Number': serial,
                        'Created At': created_at,
                        'Not Before': not_before,
                        'Not After': not_after,
                        'Last State Change': last_state_change,
                        'CRL Enabled': crl_enabled,
                        'CRL S3 Bucket': crl_s3_bucket,
                        'CRL S3 Object ACL': crl_s3_object_acl,
                        'CRL Expiration Days': crl_expiration_days,
                        'OCSP Enabled': ocsp_enabled,
                        'OCSP Custom CNAME': ocsp_custom_cname,
                        'Owner Account': owner_account,
                        'Failure Reason': failure_reason,
                        'Tags': tags_str
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for CA {ca_arn} in {region}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error listing Private CAs in {region}: {str(e)}")

    return regional_cas


@utils.aws_error_handler("Collecting Private Certificate Authorities", default_return=[])
def collect_private_cas(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect ACM Private CA certificate authority information from AWS regions."""
    print("\n=== COLLECTING PRIVATE CERTIFICATE AUTHORITIES ===")
    results = utils.scan_regions_concurrent(regions, _scan_private_cas_region)
    all_cas = [ca for result in results for ca in result]
    utils.log_success(f"Total Private CAs collected: {len(all_cas)}")
    return all_cas


def _scan_issued_certificates_region(region: str) -> List[Dict[str, Any]]:
    """Scan issued certificates in a single region."""
    regional_certificates = []
    acmpca_client = utils.get_boto3_client('acm-pca', region_name=region)

    try:
        # First get all CAs
        ca_paginator = acmpca_client.get_paginator('list_certificate_authorities')
        for ca_page in ca_paginator.paginate():
            cas = ca_page.get('CertificateAuthorities', [])

            for ca in cas:
                ca_arn = ca.get('Arn', 'N/A')
                ca_status = ca.get('Status', 'N/A')

                # Skip if CA is not active
                if ca_status != 'ACTIVE':
                    continue

                try:
                    # List certificates for this CA (limit to first 50)
                    cert_count = 0
                    cert_paginator = acmpca_client.get_paginator('list_certificates')
                    for cert_page in cert_paginator.paginate(
                        CertificateAuthorityArn=ca_arn,
                        PaginationConfig={'MaxItems': 50}
                    ):
                        certificates = cert_page.get('Certificates', [])

                        for cert in certificates:
                            cert_arn = cert.get('CertificateArn', 'N/A')
                            serial = cert.get('Serial', 'N/A')
                            status = cert.get('Status', 'N/A')

                            created_at = cert.get('CreatedAt', 'N/A')
                            if created_at != 'N/A':
                                created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')

                            not_before = cert.get('NotBefore', 'N/A')
                            if not_before != 'N/A':
                                not_before = not_before.strftime('%Y-%m-%d %H:%M:%S')

                            not_after = cert.get('NotAfter', 'N/A')
                            if not_after != 'N/A':
                                not_after = not_after.strftime('%Y-%m-%d %H:%M:%S')

                            # Try to get certificate details
                            try:
                                cert_response = acmpca_client.get_certificate(
                                    CertificateAuthorityArn=ca_arn,
                                    CertificateArn=cert_arn
                                )
                                certificate_pem = cert_response.get('Certificate', 'N/A')
                                # Truncate PEM for display
                                if certificate_pem != 'N/A':
                                    certificate_pem = 'Present (PEM truncated)'
                            except Exception:
                                certificate_pem = 'N/A'

                            regional_certificates.append({
                                'Region': region,
                                'CA ARN': ca_arn,
                                'Certificate ARN': cert_arn,
                                'Serial Number': serial,
                                'Status': status,
                                'Created At': created_at,
                                'Not Before': not_before,
                                'Not After': not_after,
                                'Certificate': certificate_pem
                            })

                            cert_count += 1

                        if cert_count >= 50:
                            break

                except Exception as e:
                    utils.log_warning(f"Could not list certificates for CA {ca_arn}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error collecting certificates in {region}: {str(e)}")

    return regional_certificates


@utils.aws_error_handler("Collecting issued certificates", default_return=[])
def collect_issued_certificates(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect issued certificates from Private CAs (limited sample)."""
    print("\n=== COLLECTING ISSUED CERTIFICATES ===")
    results = utils.scan_regions_concurrent(regions, _scan_issued_certificates_region)
    all_certificates = [cert for result in results for cert in result]
    utils.log_success(f"Total certificates collected: {len(all_certificates)} (sample limited to 50 per CA)")
    return all_certificates


def _scan_certificate_templates_region(region: str) -> List[Dict[str, Any]]:
    """Scan certificate templates in a single region."""
    regional_templates = []
    acmpca_client = utils.get_boto3_client('acm-pca', region_name=region)

    try:
        paginator = acmpca_client.get_paginator('list_certificate_templates')
        for page in paginator.paginate():
            templates = page.get('CertificateTemplates', [])

            for template_summary in templates:
                template_arn = template_summary.get('Arn', 'N/A')

                # Get detailed template information
                try:
                    template_response = acmpca_client.describe_certificate_template(
                        CertificateTemplateArn=template_arn
                    )
                    template = template_response.get('CertificateTemplate', {})

                    template_name = template.get('TemplateName', 'N/A')
                    object_identifier = template.get('ObjectIdentifier', 'N/A')

                    # Creation and update dates
                    created_at = template.get('CreatedAt', 'N/A')
                    if created_at != 'N/A':
                        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')

                    updated_at = template.get('UpdatedAt', 'N/A')
                    if updated_at != 'N/A':
                        updated_at = updated_at.strftime('%Y-%m-%d %H:%M:%S')

                    # Validity
                    validity = template.get('Validity', {})
                    validity_value = validity.get('Value', 'N/A')
                    validity_type = validity.get('Type', 'N/A')
                    validity_str = f"{validity_value} {validity_type}" if validity_value != 'N/A' else 'N/A'

                    # Renewal
                    renewal = template.get('Renewal', {})
                    renewal_enabled = renewal.get('Enabled', False)

                    # Key usage and extensions
                    extensions = template.get('Extensions', {})
                    key_usage = extensions.get('KeyUsage', {})
                    extended_key_usage = extensions.get('ExtendedKeyUsage', [])

                    # Key usage flags
                    digital_signature = key_usage.get('DigitalSignature', False)
                    non_repudiation = key_usage.get('NonRepudiation', False)
                    key_encipherment = key_usage.get('KeyEncipherment', False)
                    data_encipherment = key_usage.get('DataEncipherment', False)
                    key_agreement = key_usage.get('KeyAgreement', False)
                    key_cert_sign = key_usage.get('KeyCertSign', False)
                    crl_sign = key_usage.get('CRLSign', False)

                    key_usage_flags = []
                    if digital_signature:
                        key_usage_flags.append('DigitalSignature')
                    if non_repudiation:
                        key_usage_flags.append('NonRepudiation')
                    if key_encipherment:
                        key_usage_flags.append('KeyEncipherment')
                    if data_encipherment:
                        key_usage_flags.append('DataEncipherment')
                    if key_agreement:
                        key_usage_flags.append('KeyAgreement')
                    if key_cert_sign:
                        key_usage_flags.append('KeyCertSign')
                    if crl_sign:
                        key_usage_flags.append('CRLSign')

                    key_usage_str = ', '.join(key_usage_flags) if key_usage_flags else 'None'

                    # Extended key usage
                    extended_key_usage_oids = [eku.get('ObjectIdentifier', 'N/A') for eku in extended_key_usage]
                    extended_key_usage_str = ', '.join(extended_key_usage_oids) if extended_key_usage_oids else 'None'

                    # Subject alternative names
                    subject_alt_names = extensions.get('SubjectAlternativeNames', [])
                    san_count = len(subject_alt_names)

                    regional_templates.append({
                        'Region': region,
                        'Template Name': template_name,
                        'Template ARN': template_arn,
                        'Object Identifier': object_identifier,
                        'Created At': created_at,
                        'Updated At': updated_at,
                        'Validity': validity_str,
                        'Renewal Enabled': renewal_enabled,
                        'Key Usage': key_usage_str,
                        'Extended Key Usage': extended_key_usage_str,
                        'Subject Alternative Names Count': san_count
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for template {template_arn}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error listing certificate templates in {region}: {str(e)}")

    return regional_templates


@utils.aws_error_handler("Collecting certificate templates", default_return=[])
def collect_certificate_templates(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect certificate template information from AWS regions."""
    print("\n=== COLLECTING CERTIFICATE TEMPLATES ===")
    results = utils.scan_regions_concurrent(regions, _scan_certificate_templates_region)
    all_templates = [template for result in results for template in result]
    utils.log_success(f"Total certificate templates collected: {len(all_templates)}")
    return all_templates


def _scan_ca_permissions_region(region: str) -> List[Dict[str, Any]]:
    """Scan CA permissions in a single region."""
    regional_permissions = []
    acmpca_client = utils.get_boto3_client('acm-pca', region_name=region)

    try:
        # First get all CAs
        ca_paginator = acmpca_client.get_paginator('list_certificate_authorities')
        for ca_page in ca_paginator.paginate():
            cas = ca_page.get('CertificateAuthorities', [])

            for ca in cas:
                ca_arn = ca.get('Arn', 'N/A')

                try:
                    # Get policy for this CA
                    policy_response = acmpca_client.get_policy(
                        ResourceArn=ca_arn
                    )
                    policy_str = policy_response.get('Policy', 'N/A')

                    if policy_str != 'N/A':
                        try:
                            policy_json = json.loads(policy_str)
                            statements = policy_json.get('Statement', [])

                            for idx, statement in enumerate(statements):
                                sid = statement.get('Sid', f'Statement{idx}')
                                effect = statement.get('Effect', 'N/A')
                                principal = statement.get('Principal', {})

                                # Extract principal information
                                if isinstance(principal, dict):
                                    service = principal.get('Service', 'N/A')
                                    aws = principal.get('AWS', 'N/A')
                                    if isinstance(service, list):
                                        service = ', '.join(service)
                                    if isinstance(aws, list):
                                        aws = ', '.join(aws)
                                    principal_str = f"Service: {service}, AWS: {aws}"
                                else:
                                    principal_str = str(principal)

                                # Extract actions
                                actions = statement.get('Action', [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                actions_str = ', '.join(actions)

                                # Extract conditions
                                conditions = statement.get('Condition', {})
                                conditions_str = json.dumps(conditions) if conditions else 'None'

                                regional_permissions.append({
                                    'Region': region,
                                    'CA ARN': ca_arn,
                                    'Statement ID': sid,
                                    'Effect': effect,
                                    'Principal': principal_str,
                                    'Actions': actions_str,
                                    'Conditions': conditions_str
                                })

                        except Exception as e:
                            utils.log_warning(f"Could not parse policy for CA {ca_arn}: {str(e)}")
                            continue

                except Exception as e:
                    # No policy attached is normal, skip
                    if 'ResourceNotFoundException' not in str(e):
                        utils.log_warning(f"Could not get policy for CA {ca_arn}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error collecting CA permissions in {region}: {str(e)}")

    return regional_permissions


@utils.aws_error_handler("Collecting CA permissions", default_return=[])
def collect_ca_permissions(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect permission policies for Private CAs."""
    print("\n=== COLLECTING CA PERMISSIONS ===")
    results = utils.scan_regions_concurrent(regions, _scan_ca_permissions_region)
    all_permissions = [perm for result in results for perm in result]
    utils.log_success(f"Total CA permission statements collected: {len(all_permissions)}")
    return all_permissions


def generate_summary(cas: List[Dict[str, Any]],
                     certificates: List[Dict[str, Any]],
                     templates: List[Dict[str, Any]],
                     permissions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for ACM Private CA resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # CAs summary
    total_cas = len(cas)
    active_cas = sum(1 for ca in cas if ca.get('Status', '') == 'ACTIVE')
    root_cas = sum(1 for ca in cas if ca.get('Type', '') == 'ROOT')
    subordinate_cas = sum(1 for ca in cas if ca.get('Type', '') == 'SUBORDINATE')

    summary.append({
        'Metric': 'Total Private CAs',
        'Count': total_cas,
        'Details': f'Root: {root_cas}, Subordinate: {subordinate_cas}'
    })

    summary.append({
        'Metric': 'Active CAs',
        'Count': active_cas,
        'Details': 'Certificate authorities in ACTIVE status'
    })

    # CRL enabled
    crl_enabled = sum(1 for ca in cas if ca.get('CRL Enabled', False))
    summary.append({
        'Metric': 'CAs with CRL Enabled',
        'Count': crl_enabled,
        'Details': 'Certificate Revocation Lists configured'
    })

    # OCSP enabled
    ocsp_enabled = sum(1 for ca in cas if ca.get('OCSP Enabled', False))
    summary.append({
        'Metric': 'CAs with OCSP Enabled',
        'Count': ocsp_enabled,
        'Details': 'Online Certificate Status Protocol configured'
    })

    # Certificates summary
    total_certificates = len(certificates)
    issued_certs = sum(1 for cert in certificates if cert.get('Status', '') == 'ISSUED')
    revoked_certs = sum(1 for cert in certificates if cert.get('Status', '') == 'REVOKED')

    summary.append({
        'Metric': 'Total Certificates (Sample)',
        'Count': total_certificates,
        'Details': f'Issued: {issued_certs}, Revoked: {revoked_certs} (Limited to 50 per CA)'
    })

    # Templates summary
    total_templates = len(templates)
    renewal_enabled_templates = sum(1 for t in templates if t.get('Renewal Enabled', False))

    summary.append({
        'Metric': 'Total Certificate Templates',
        'Count': total_templates,
        'Details': f'Renewal enabled: {renewal_enabled_templates}'
    })

    # Permissions summary
    total_permissions = len(permissions)
    summary.append({
        'Metric': 'Total Permission Statements',
        'Count': total_permissions,
        'Details': 'Resource-based policy statements across all CAs'
    })

    # Security standards
    if cas:
        df = pd.DataFrame(cas)
        if 'Key Storage Security Standard' in df.columns:
            fips_count = sum(1 for std in df['Key Storage Security Standard'] if 'FIPS' in str(std))
            summary.append({
                'Metric': 'CAs with FIPS 140-2 Level 3',
                'Count': fips_count,
                'Details': 'CAs using FIPS-certified hardware security modules'
            })

    # Regional distribution
    if cas:
        df = pd.DataFrame(cas)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'CAs in {region}',
                'Count': count,
                'Details': 'Regional distribution'
            })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    print("\n" + "="*60)
    print("ACM Private CA Export Tool")
    print("="*60)

    # Check dependencies
    check_dependencies()

    # Get AWS account information
    account_id, account_name = utils.get_account_info()
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({account_id})")

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
    print("\nACM Private CA is a regional service.")
    print("\nPlease select an option for region selection:")
    print("\n  1. Default Regions")
    print(f"     ({example_regions})")
    print("\n  2. All Available Regions")
    print("     (Scan all regions where ACM Private CA is available)")
    print("\n  3. Specific Region")
    print("     (Enter a specific AWS region code)")
    print("\n" + "-" * 68)

    # Get and validate region choice
    regions = []
    while not regions:
        try:
            region_choice = input("\nEnter your choice (1, 2, or 3): ").strip()

            if region_choice == '1':
                # Default regions based on partition
                regions = utils.get_partition_default_regions()
                print(f"\nUsing default regions: {', '.join(regions)}")

            elif region_choice == '2':
                # All available regions
                regions = utils.get_partition_regions()
                print(f"\nScanning all {len(regions)} available regions")

            elif region_choice == '3':
                # Specific region - get list and show numbered menu
                available_regions = utils.get_partition_regions()
                print("\n" + "=" * 68)
                print("AVAILABLE REGIONS")
                print("=" * 68)
                for idx, region in enumerate(available_regions, 1):
                    print(f"  {idx:2d}. {region}")
                print("=" * 68)

                region_input = input("\nEnter region number or region code: ").strip()

                # Check if input is a number (region index)
                if region_input.isdigit():
                    region_idx = int(region_input)
                    if 1 <= region_idx <= len(available_regions):
                        regions = [available_regions[region_idx - 1]]
                        print(f"\nUsing region: {regions[0]}")
                    else:
                        print(f"\nInvalid region number. Please enter a number between 1 and {len(available_regions)}.")
                else:
                    # Treat as region code
                    if region_input in available_regions:
                        regions = [region_input]
                        print(f"\nUsing region: {regions[0]}")
                    else:
                        print(f"\nInvalid region code: {region_input}")
                        print("Please enter a valid region code from the list above.")

            else:
                print("\nInvalid choice. Please enter 1, 2, or 3.")

        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            sys.exit(0)
        except Exception as e:
            utils.log_error(f"Error getting region selection: {str(e)}")
            print("Please try again.")

    if not regions:
        utils.log_error("No regions selected. Exiting.")
        return

    # Collect data
    print("\nCollecting ACM Private CA data...")

    cas = collect_private_cas(regions)
    certificates = collect_issued_certificates(regions)
    templates = collect_certificate_templates(regions)
    permissions = collect_ca_permissions(regions)
    summary = generate_summary(cas, certificates, templates, permissions)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if cas:
        df_cas = pd.DataFrame(cas)
        df_cas = utils.prepare_dataframe_for_export(df_cas)
        dataframes['Private CAs'] = df_cas

    if certificates:
        df_certificates = pd.DataFrame(certificates)
        df_certificates = utils.prepare_dataframe_for_export(df_certificates)
        dataframes['Certificates'] = df_certificates

    if templates:
        df_templates = pd.DataFrame(templates)
        df_templates = utils.prepare_dataframe_for_export(df_templates)
        dataframes['Certificate Templates'] = df_templates

    if permissions:
        df_permissions = pd.DataFrame(permissions)
        df_permissions = utils.prepare_dataframe_for_export(df_permissions)
        dataframes['CA Permissions'] = df_permissions

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'acm-privateca', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Private CAs': len(cas),
            'Certificates': len(certificates),
            'Certificate Templates': len(templates),
            'CA Permissions': len(permissions)
        })
    else:
        utils.log_warning("No ACM Private CA data found to export")

    utils.log_success("ACM Private CA export completed successfully")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
SES (Simple Email Service) Export Script for StratusScan

Exports comprehensive AWS SES information including:
- Email identities (verified emails and domains)
- Configuration sets with event destinations
- Email templates
- Sending statistics and quotas
- Suppression list (bounces, complaints)
- Custom verification email templates

Output: Multi-worksheet Excel file with SES resources
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

# Setup logging
logger = utils.setup_logging('ses-export')

try:
    import pandas as pd
except ImportError:
    print("Error: pandas is not installed. Please install it using 'pip install pandas'")
    sys.exit(1)
def _scan_email_identities_region(region: str) -> List[Dict[str, Any]]:
    """Scan email identities in a single region."""
    regional_identities = []
    ses_client = utils.get_boto3_client('sesv2', region_name=region)

    try:
        paginator = ses_client.get_paginator('list_email_identities')
        for page in paginator.paginate():
            identities = page.get('EmailIdentities', [])

            for identity_summary in identities:
                identity_name = identity_summary.get('IdentityName', 'N/A')
                identity_type = identity_summary.get('IdentityType', 'N/A')

                try:
                    # Get detailed identity information
                    identity_response = ses_client.get_email_identity(
                        EmailIdentity=identity_name
                    )

                    verified = identity_response.get('VerifiedForSendingStatus', False)
                    dkim_enabled = False
                    dkim_status = 'N/A'
                    dkim_tokens = 'N/A'

                    dkim_attributes = identity_response.get('DkimAttributes', {})
                    if dkim_attributes:
                        dkim_enabled = dkim_attributes.get('SigningEnabled', False)
                        dkim_status = dkim_attributes.get('Status', 'N/A')
                        tokens = dkim_attributes.get('Tokens', [])
                        if tokens:
                            dkim_tokens = ', '.join(tokens[:3])  # First 3 tokens

                    # Mail FROM domain
                    mail_from_attributes = identity_response.get('MailFromAttributes', {})
                    mail_from_domain = mail_from_attributes.get('MailFromDomain', 'N/A')
                    mail_from_status = mail_from_attributes.get('MailFromDomainStatus', 'N/A')

                    # Feedback forwarding
                    feedback_attributes = identity_response.get('FeedbackForwardingStatus', False)

                    # Get tags
                    tags_str = 'N/A'
                    try:
                        tags_response = ses_client.list_tags_for_resource(
                            ResourceArn=identity_response.get('IdentityArn', '')
                        )
                        tags = tags_response.get('Tags', [])
                        if tags:
                            tags_str = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags])
                    except Exception:
                        pass

                    regional_identities.append({
                        'Region': region,
                        'Identity Name': identity_name,
                        'Identity Type': identity_type,
                        'Verified': verified,
                        'DKIM Enabled': dkim_enabled,
                        'DKIM Status': dkim_status,
                        'DKIM Tokens': dkim_tokens,
                        'Mail From Domain': mail_from_domain,
                        'Mail From Status': mail_from_status,
                        'Feedback Forwarding': feedback_attributes,
                        'Tags': tags_str
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for identity {identity_name} in {region}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error listing email identities in {region}: {str(e)}")

    return regional_identities


@utils.aws_error_handler("Collecting email identities", default_return=[])
def collect_email_identities(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect SES email identity information from AWS regions."""
    print("\n=== COLLECTING EMAIL IDENTITIES ===")
    results = utils.scan_regions_concurrent(regions, _scan_email_identities_region)
    all_identities = [identity for result in results for identity in result]
    utils.log_success(f"Total email identities collected: {len(all_identities)}")
    return all_identities


def _scan_configuration_sets_region(region: str) -> List[Dict[str, Any]]:
    """Scan configuration sets in a single region."""
    regional_config_sets = []
    ses_client = utils.get_boto3_client('sesv2', region_name=region)

    try:
        paginator = ses_client.get_paginator('list_configuration_sets')
        for page in paginator.paginate():
            config_sets = page.get('ConfigurationSets', [])

            for config_set_name in config_sets:
                try:
                    # Get configuration set details
                    config_response = ses_client.get_configuration_set(
                        ConfigurationSetName=config_set_name
                    )

                    # Tracking options
                    tracking_options = config_response.get('TrackingOptions', {})
                    custom_redirect_domain = tracking_options.get('CustomRedirectDomain', 'N/A')

                    # Delivery options
                    delivery_options = config_response.get('DeliveryOptions', {})
                    tls_policy = delivery_options.get('TlsPolicy', 'N/A')
                    sending_pool_name = delivery_options.get('SendingPoolName', 'N/A')

                    # Reputation options
                    reputation_options = config_response.get('ReputationOptions', {})
                    reputation_metrics_enabled = reputation_options.get('ReputationMetricsEnabled', False)
                    last_fresh_start = reputation_options.get('LastFreshStart', 'N/A')
                    if last_fresh_start != 'N/A':
                        last_fresh_start = last_fresh_start.strftime('%Y-%m-%d %H:%M:%S')

                    # Suppression options
                    suppression_options = config_response.get('SuppressionOptions', {})
                    suppressed_reasons = suppression_options.get('SuppressedReasons', [])
                    suppressed_reasons_str = ', '.join(suppressed_reasons) if suppressed_reasons else 'None'

                    # Get event destinations
                    event_destinations = 'N/A'
                    try:
                        events_response = ses_client.get_configuration_set_event_destinations(
                            ConfigurationSetName=config_set_name
                        )
                        destinations = events_response.get('EventDestinations', [])
                        if destinations:
                            dest_list = []
                            for dest in destinations:
                                dest_name = dest.get('Name', 'N/A')
                                enabled = dest.get('Enabled', False)
                                matching_types = dest.get('MatchingEventTypes', [])
                                dest_list.append(f"{dest_name} ({'enabled' if enabled else 'disabled'}, {len(matching_types)} events)")
                            event_destinations = '; '.join(dest_list)
                    except Exception:
                        pass

                    regional_config_sets.append({
                        'Region': region,
                        'Configuration Set Name': config_set_name,
                        'TLS Policy': tls_policy,
                        'Sending Pool': sending_pool_name,
                        'Custom Redirect Domain': custom_redirect_domain,
                        'Reputation Metrics Enabled': reputation_metrics_enabled,
                        'Last Fresh Start': last_fresh_start,
                        'Suppressed Reasons': suppressed_reasons_str,
                        'Event Destinations': event_destinations
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for configuration set {config_set_name} in {region}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error listing configuration sets in {region}: {str(e)}")

    return regional_config_sets


@utils.aws_error_handler("Collecting configuration sets", default_return=[])
def collect_configuration_sets(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect SES configuration set information from AWS regions."""
    print("\n=== COLLECTING CONFIGURATION SETS ===")
    results = utils.scan_regions_concurrent(regions, _scan_configuration_sets_region)
    all_config_sets = [config_set for result in results for config_set in result]
    utils.log_success(f"Total configuration sets collected: {len(all_config_sets)}")
    return all_config_sets


def _scan_email_templates_region(region: str) -> List[Dict[str, Any]]:
    """Scan email templates in a single region."""
    regional_templates = []
    ses_client = utils.get_boto3_client('sesv2', region_name=region)

    try:
        paginator = ses_client.get_paginator('list_email_templates')
        for page in paginator.paginate():
            templates = page.get('TemplatesMetadata', [])

            for template_metadata in templates:
                template_name = template_metadata.get('TemplateName', 'N/A')
                created_timestamp = template_metadata.get('CreatedTimestamp', 'N/A')
                if created_timestamp != 'N/A':
                    created_timestamp = created_timestamp.strftime('%Y-%m-%d %H:%M:%S')

                try:
                    # Get template details
                    template_response = ses_client.get_email_template(
                        TemplateName=template_name
                    )

                    template_content = template_response.get('TemplateContent', {})
                    subject = template_content.get('Subject', 'N/A')
                    text_part = template_content.get('Text', 'N/A')
                    html_part = template_content.get('Html', 'N/A')

                    # Truncate for display
                    if text_part != 'N/A' and len(text_part) > 100:
                        text_part = text_part[:100] + '...'
                    if html_part != 'N/A' and len(html_part) > 100:
                        html_part = html_part[:100] + '...'

                    regional_templates.append({
                        'Region': region,
                        'Template Name': template_name,
                        'Created': created_timestamp,
                        'Subject': subject,
                        'Text Part Preview': text_part,
                        'HTML Part Preview': html_part
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for template {template_name} in {region}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error listing email templates in {region}: {str(e)}")

    return regional_templates


@utils.aws_error_handler("Collecting email templates", default_return=[])
def collect_email_templates(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect SES email template information from AWS regions."""
    print("\n=== COLLECTING EMAIL TEMPLATES ===")
    results = utils.scan_regions_concurrent(regions, _scan_email_templates_region)
    all_templates = [template for result in results for template in result]
    utils.log_success(f"Total email templates collected: {len(all_templates)}")
    return all_templates


@utils.aws_error_handler("Collecting sending quotas", default_return=[])
def collect_sending_quotas(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect SES sending quota information from AWS regions."""
    print("\n=== COLLECTING SENDING QUOTAS ===")
    all_quotas = []

    for region in regions:
        ses_client = utils.get_boto3_client('sesv2', region_name=region)

        try:
            # Get account details including sending quota
            account_response = ses_client.get_account()

            # Sending enabled
            sending_enabled = account_response.get('SendingEnabled', False)
            production_access_enabled = account_response.get('ProductionAccessEnabled', False)

            # Send quota
            send_quota = account_response.get('SendQuota', {})
            max_24_hour_send = send_quota.get('Max24HourSend', 0)
            max_send_rate = send_quota.get('MaxSendRate', 0)
            sent_last_24_hours = send_quota.get('SentLast24Hours', 0)

            # Suppression attributes
            suppression_attributes = account_response.get('SuppressionAttributes', {})
            suppressed_reasons = suppression_attributes.get('SuppressedReasons', [])
            suppressed_reasons_str = ', '.join(suppressed_reasons) if suppressed_reasons else 'None'

            all_quotas.append({
                'Region': region,
                'Sending Enabled': sending_enabled,
                'Production Access': production_access_enabled,
                'Max 24h Send': max_24_hour_send,
                'Max Send Rate (per second)': max_send_rate,
                'Sent Last 24h': sent_last_24_hours,
                'Remaining 24h Quota': max_24_hour_send - sent_last_24_hours,
                'Quota Utilization %': round((sent_last_24_hours / max_24_hour_send * 100) if max_24_hour_send > 0 else 0, 2),
                'Suppressed Reasons': suppressed_reasons_str
            })

        except Exception as e:
            utils.log_warning(f"Error getting sending quota in {region}: {str(e)}")
            continue

    utils.log_success(f"Total sending quotas collected: {len(all_quotas)}")
    return all_quotas


def generate_summary(identities: List[Dict[str, Any]],
                     config_sets: List[Dict[str, Any]],
                     templates: List[Dict[str, Any]],
                     quotas: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for SES resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Identities summary
    total_identities = len(identities)
    verified_identities = sum(1 for i in identities if i.get('Verified', False))
    email_identities = sum(1 for i in identities if i.get('Identity Type', '') == 'EMAIL_ADDRESS')
    domain_identities = sum(1 for i in identities if i.get('Identity Type', '') == 'DOMAIN')
    dkim_enabled = sum(1 for i in identities if i.get('DKIM Enabled', False))

    summary.append({
        'Metric': 'Total Email Identities',
        'Count': total_identities,
        'Details': f'Verified: {verified_identities}, Email: {email_identities}, Domain: {domain_identities}'
    })

    summary.append({
        'Metric': 'DKIM Enabled Identities',
        'Count': dkim_enabled,
        'Details': 'Identities with DKIM signing enabled'
    })

    # Configuration sets
    summary.append({
        'Metric': 'Total Configuration Sets',
        'Count': len(config_sets),
        'Details': 'Email sending configurations'
    })

    # Templates
    summary.append({
        'Metric': 'Total Email Templates',
        'Count': len(templates),
        'Details': 'Reusable email templates'
    })

    # Quotas summary
    if quotas:
        production_regions = sum(1 for q in quotas if q.get('Production Access', False))
        total_24h_quota = sum(q.get('Max 24h Send', 0) for q in quotas)
        total_sent_24h = sum(q.get('Sent Last 24h', 0) for q in quotas)

        summary.append({
            'Metric': 'Regions with Production Access',
            'Count': production_regions,
            'Details': f'Out of {len(quotas)} regions checked'
        })

        summary.append({
            'Metric': 'Total 24h Send Quota',
            'Count': total_24h_quota,
            'Details': f'Sent: {total_sent_24h}, Remaining: {total_24h_quota - total_sent_24h}'
        })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    print("\n" + "="*60)
    print("SES (Simple Email Service) Export Tool")
    print("="*60)

    # Check dependencies
    utils.ensure_dependencies('pandas', 'openpyxl')

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
    all_available_regions = utils.get_partition_regions(partition, all_regions=True)
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        regions = default_regions
        region_suffix = ""
        utils.log_info(f"Scanning default regions: {len(regions)} regions")
    elif selection_int == 2:
        regions = all_available_regions
        region_suffix = ""
        utils.log_info(f"Scanning all {len(regions)} AWS regions")
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
                    region_suffix = selected_region
                    utils.log_info(f"Scanning region: {selected_region}")
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print(f"Please enter a valid number (1-{len(all_available_regions)}).")
            region_suffix = ""

    # Collect data
    print("\nCollecting SES data...")

    identities = collect_email_identities(regions)
    config_sets = collect_configuration_sets(regions)
    templates = collect_email_templates(regions)
    quotas = collect_sending_quotas(regions)
    summary = generate_summary(identities, config_sets, templates, quotas)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    if identities:
        df_identities = pd.DataFrame(identities)
        df_identities = utils.prepare_dataframe_for_export(df_identities)
        dataframes['Email Identities'] = df_identities

    if config_sets:
        df_config_sets = pd.DataFrame(config_sets)
        df_config_sets = utils.prepare_dataframe_for_export(df_config_sets)
        dataframes['Configuration Sets'] = df_config_sets

    if templates:
        df_templates = pd.DataFrame(templates)
        df_templates = utils.prepare_dataframe_for_export(df_templates)
        dataframes['Email Templates'] = df_templates

    if quotas:
        df_quotas = pd.DataFrame(quotas)
        df_quotas = utils.prepare_dataframe_for_export(df_quotas)
        dataframes['Sending Quotas'] = df_quotas

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'ses', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Email Identities': len(identities),
            'Configuration Sets': len(config_sets),
            'Email Templates': len(templates),
            'Sending Quotas': len(quotas)
        })
    else:
        utils.log_warning("No SES data found to export")

    utils.log_success("SES export completed successfully")


if __name__ == "__main__":
    main()

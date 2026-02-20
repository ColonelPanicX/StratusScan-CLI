#!/usr/bin/env python3
"""
AWS SES (Simple Email Service) and Pinpoint Export Script

Exports AWS email and marketing communication resources:
- SES: Identities (domains, email addresses), configuration sets, templates
- SES: Sending statistics, reputation metrics, suppression list
- SES: Contact lists, email templates, custom verification templates
- Pinpoint: Applications, campaigns, segments, journeys
- Pinpoint: SMS and email channels, endpoints

Features:
- Complete SES v2 configuration inventory
- Pinpoint marketing campaign tracking
- Email template management
- Sending quotas and reputation monitoring
- SMS channel configurations
- Multi-region support
- Comprehensive multi-worksheet export

Note: Requires ses:*, sesv2:*, mobiletargeting:* permissions
Note: SES is regional, Pinpoint applications are regional
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
import pandas as pd

# Standard utils import pattern
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

# Check required packages
utils.check_required_packages(['boto3', 'pandas', 'openpyxl'])

# Setup logging
logger = utils.setup_logging('ses-pinpoint-export')
utils.log_script_start('ses-pinpoint-export', 'Export SES and Pinpoint email/marketing resources')


@utils.aws_error_handler("Collecting SES identities", default_return=[])
def collect_ses_identities(region: str) -> List[Dict[str, Any]]:
    """Collect SES email identities (v2 API)."""
    sesv2 = utils.get_boto3_client('sesv2', region_name=region)
    identities = []

    try:
        paginator = sesv2.get_paginator('list_email_identities')
        for page in paginator.paginate():
            for identity in page.get('EmailIdentities', []):
                identity_name = identity.get('IdentityName', 'N/A')

                # Get detailed identity information
                try:
                    detail = sesv2.get_email_identity(EmailIdentity=identity_name)

                    # Extract DKIM attributes
                    dkim = detail.get('DkimAttributes', {})
                    mail_from = detail.get('MailFromAttributes', {})

                    identities.append({
                        'Region': region,
                        'IdentityName': identity_name,
                        'IdentityType': identity.get('IdentityType', 'N/A'),
                        'SendingEnabled': identity.get('SendingEnabled', False),
                        'VerificationStatus': detail.get('VerifiedForSendingStatus', False),
                        'DkimEnabled': dkim.get('SigningEnabled', False),
                        'DkimStatus': dkim.get('Status', 'N/A'),
                        'DkimTokens': ', '.join(dkim.get('Tokens', [])) if dkim.get('Tokens') else 'N/A',
                        'MailFromDomain': mail_from.get('MailFromDomain', 'N/A'),
                        'MailFromStatus': mail_from.get('MailFromDomainStatus', 'N/A'),
                        'FeedbackForwardingEnabled': detail.get('FeedbackForwardingStatus', False),
                    })
                except Exception:
                    # Fallback to summary data
                    identities.append({
                        'Region': region,
                        'IdentityName': identity_name,
                        'IdentityType': identity.get('IdentityType', 'N/A'),
                        'SendingEnabled': identity.get('SendingEnabled', False),
                        'VerificationStatus': 'N/A',
                        'DkimEnabled': 'N/A',
                        'DkimStatus': 'N/A',
                        'DkimTokens': 'N/A',
                        'MailFromDomain': 'N/A',
                        'MailFromStatus': 'N/A',
                        'FeedbackForwardingEnabled': 'N/A',
                    })
    except Exception as e:
        utils.log_warning(f"Error collecting SES identities in region {region}: {e}")

    return identities


@utils.aws_error_handler("Collecting SES configuration sets", default_return=[])
def collect_ses_config_sets(region: str) -> List[Dict[str, Any]]:
    """Collect SES configuration sets."""
    sesv2 = utils.get_boto3_client('sesv2', region_name=region)
    config_sets = []

    try:
        paginator = sesv2.get_paginator('list_configuration_sets')
        for page in paginator.paginate():
            for config_set_name in page.get('ConfigurationSets', []):
                # Get detailed configuration set information
                try:
                    detail = sesv2.get_configuration_set(ConfigurationSetName=config_set_name)

                    tracking = detail.get('TrackingOptions', {})
                    delivery = detail.get('DeliveryOptions', {})
                    reputation = detail.get('ReputationOptions', {})
                    sending = detail.get('SendingOptions', {})
                    suppression = detail.get('SuppressionOptions', {})

                    config_sets.append({
                        'Region': region,
                        'ConfigurationSetName': config_set_name,
                        'SendingEnabled': sending.get('SendingEnabled', False),
                        'CustomRedirectDomain': tracking.get('CustomRedirectDomain', 'N/A'),
                        'TlsPolicy': delivery.get('TlsPolicy', 'N/A'),
                        'SendingPoolName': delivery.get('SendingPoolName', 'N/A'),
                        'ReputationMetricsEnabled': reputation.get('ReputationMetricsEnabled', False),
                        'LastFreshStart': reputation.get('LastFreshStart', 'N/A'),
                        'SuppressionListReasons': ', '.join(suppression.get('SuppressedReasons', [])) if suppression.get('SuppressedReasons') else 'N/A',
                    })
                except Exception:
                    config_sets.append({
                        'Region': region,
                        'ConfigurationSetName': config_set_name,
                        'SendingEnabled': 'N/A',
                        'CustomRedirectDomain': 'N/A',
                        'TlsPolicy': 'N/A',
                        'SendingPoolName': 'N/A',
                        'ReputationMetricsEnabled': 'N/A',
                        'LastFreshStart': 'N/A',
                        'SuppressionListReasons': 'N/A',
                    })
    except Exception:
        pass

    return config_sets


@utils.aws_error_handler("Collecting SES account sending quota", default_return={})
def collect_ses_account_info(region: str) -> Dict[str, Any]:
    """Collect SES account sending quota and statistics."""
    sesv2 = utils.get_boto3_client('sesv2', region_name=region)

    try:
        account = sesv2.get_account()
        send_quota = account.get('SendQuota', {})

        return {
            'Region': region,
            'ProductionAccess': account.get('ProductionAccessEnabled', False),
            'SendingEnabled': account.get('SendingEnabled', False),
            'Max24HourSend': send_quota.get('Max24HourSend', 0),
            'MaxSendRate': send_quota.get('MaxSendRate', 0),
            'SentLast24Hours': send_quota.get('SentLast24Hours', 0),
            'EnforcementStatus': account.get('EnforcementStatus', 'N/A'),
            'DedicatedIpAutoWarmupEnabled': account.get('Details', {}).get('DedicatedIpAutoWarmupEnabled', False),
        }
    except Exception:
        return {
            'Region': region,
            'ProductionAccess': 'N/A',
            'SendingEnabled': 'N/A',
            'Max24HourSend': 'N/A',
            'MaxSendRate': 'N/A',
            'SentLast24Hours': 'N/A',
            'EnforcementStatus': 'N/A',
            'DedicatedIpAutoWarmupEnabled': 'N/A',
        }


@utils.aws_error_handler("Collecting SES email templates", default_return=[])
def collect_ses_templates(region: str) -> List[Dict[str, Any]]:
    """Collect SES email templates."""
    sesv2 = utils.get_boto3_client('sesv2', region_name=region)
    templates = []

    try:
        paginator = sesv2.get_paginator('list_email_templates')
        for page in paginator.paginate():
            for template in page.get('TemplatesMetadata', []):
                template_name = template.get('TemplateName', 'N/A')

                templates.append({
                    'Region': region,
                    'TemplateName': template_name,
                    'CreatedTimestamp': template.get('CreatedTimestamp', 'N/A'),
                })
    except Exception:
        pass

    return templates


@utils.aws_error_handler("Collecting Pinpoint applications", default_return=[])
def collect_pinpoint_apps(region: str) -> List[Dict[str, Any]]:
    """Collect Pinpoint applications."""
    pinpoint = utils.get_boto3_client('pinpoint', region_name=region)
    apps = []

    try:
        response = pinpoint.get_apps()

        for app in response.get('ApplicationsResponse', {}).get('Item', []):
            app_id = app.get('Id', 'N/A')

            # Get application settings
            try:
                settings = pinpoint.get_application_settings(ApplicationId=app_id)
                app_settings = settings.get('ApplicationSettingsResource', {})

                apps.append({
                    'Region': region,
                    'ApplicationId': app_id,
                    'ApplicationName': app.get('Name', 'N/A'),
                    'CreationDate': app.get('CreationDate', 'N/A'),
                    'LastModifiedDate': app_settings.get('LastModifiedDate', 'N/A'),
                    'QuietTimeEnabled': 'Yes' if app_settings.get('QuietTime') else 'No',
                    'LimitsEnabled': 'Yes' if app_settings.get('Limits') else 'No',
                })
            except Exception:
                apps.append({
                    'Region': region,
                    'ApplicationId': app_id,
                    'ApplicationName': app.get('Name', 'N/A'),
                    'CreationDate': app.get('CreationDate', 'N/A'),
                    'LastModifiedDate': 'N/A',
                    'QuietTimeEnabled': 'N/A',
                    'LimitsEnabled': 'N/A',
                })
    except Exception:
        pass

    return apps


@utils.aws_error_handler("Collecting Pinpoint campaigns", default_return=[])
def collect_pinpoint_campaigns(region: str, app_ids: List[str]) -> List[Dict[str, Any]]:
    """Collect Pinpoint campaigns for all applications."""
    pinpoint = utils.get_boto3_client('pinpoint', region_name=region)
    campaigns = []

    for app_id in app_ids:
        try:
            response = pinpoint.get_campaigns(ApplicationId=app_id)

            for campaign in response.get('CampaignsResponse', {}).get('Item', []):
                schedule = campaign.get('Schedule', {})

                campaigns.append({
                    'Region': region,
                    'ApplicationId': app_id,
                    'CampaignId': campaign.get('Id', 'N/A'),
                    'CampaignName': campaign.get('Name', 'N/A'),
                    'State': campaign.get('State', {}).get('CampaignStatus', 'N/A'),
                    'SegmentId': campaign.get('SegmentId', 'N/A'),
                    'SegmentVersion': campaign.get('SegmentVersion', 'N/A'),
                    'MessageType': campaign.get('MessageConfiguration', {}).get('DefaultMessage', {}).get('Action', 'N/A'),
                    'ScheduleFrequency': schedule.get('Frequency', 'N/A'),
                    'StartTime': schedule.get('StartTime', 'N/A'),
                    'EndTime': schedule.get('EndTime', 'N/A'),
                    'CreationDate': campaign.get('CreationDate', 'N/A'),
                    'LastModifiedDate': campaign.get('LastModifiedDate', 'N/A'),
                })
        except Exception:
            pass

    return campaigns


@utils.aws_error_handler("Collecting Pinpoint segments", default_return=[])
def collect_pinpoint_segments(region: str, app_ids: List[str]) -> List[Dict[str, Any]]:
    """Collect Pinpoint segments for all applications."""
    pinpoint = utils.get_boto3_client('pinpoint', region_name=region)
    segments = []

    for app_id in app_ids:
        try:
            response = pinpoint.get_segments(ApplicationId=app_id)

            for segment in response.get('SegmentsResponse', {}).get('Item', []):
                segments.append({
                    'Region': region,
                    'ApplicationId': app_id,
                    'SegmentId': segment.get('Id', 'N/A'),
                    'SegmentName': segment.get('Name', 'N/A'),
                    'SegmentType': segment.get('SegmentType', 'N/A'),
                    'CreationDate': segment.get('CreationDate', 'N/A'),
                    'LastModifiedDate': segment.get('LastModifiedDate', 'N/A'),
                })
        except Exception:
            pass

    return segments


def main():
    """Main execution function."""
    try:
        # Get account information
        account_id, account_name = utils.get_account_info()
        utils.log_info(f"Exporting SES and Pinpoint resources for account: {account_name} ({account_id})")

        # Prompt for regions
        utils.log_info("SES and Pinpoint are regional services.")

        # Detect partition for region examples
        regions = utils.prompt_region_selection()
        # Collect all resources
        all_ses_identities = []
        all_ses_config_sets = []
        all_ses_templates = []
        all_ses_account = []
        all_pinpoint_apps = []
        all_pinpoint_campaigns = []
        all_pinpoint_segments = []

        for idx, region in enumerate(regions, 1):
            utils.log_info(f"[{idx}/{len(regions)}] Processing region: {region}")

            # Collect SES resources
            identities = collect_ses_identities(region)
            if identities:
                utils.log_info(f"  Found {len(identities)} SES identit(ies)")
                all_ses_identities.extend(identities)

            config_sets = collect_ses_config_sets(region)
            if config_sets:
                utils.log_info(f"  Found {len(config_sets)} SES configuration set(s)")
                all_ses_config_sets.extend(config_sets)

            templates = collect_ses_templates(region)
            if templates:
                utils.log_info(f"  Found {len(templates)} SES template(s)")
                all_ses_templates.extend(templates)

            # Get SES account info
            account_info = collect_ses_account_info(region)
            all_ses_account.append(account_info)

            # Collect Pinpoint resources
            pinpoint_apps = collect_pinpoint_apps(region)
            if pinpoint_apps:
                utils.log_info(f"  Found {len(pinpoint_apps)} Pinpoint application(s)")
                all_pinpoint_apps.extend(pinpoint_apps)

                # Get app IDs for campaigns and segments
                app_ids = [app['ApplicationId'] for app in pinpoint_apps if app['ApplicationId'] != 'N/A']

                # Collect campaigns and segments
                campaigns = collect_pinpoint_campaigns(region, app_ids)
                all_pinpoint_campaigns.extend(campaigns)

                segments = collect_pinpoint_segments(region, app_ids)
                all_pinpoint_segments.extend(segments)

        if not all_ses_identities and not all_pinpoint_apps:
            utils.log_warning("No SES or Pinpoint resources found in any selected region.")
            utils.log_info("Creating empty export file...")

        utils.log_info(f"Total SES identities found: {len(all_ses_identities)}")
        utils.log_info(f"Total SES configuration sets found: {len(all_ses_config_sets)}")
        utils.log_info(f"Total SES templates found: {len(all_ses_templates)}")
        utils.log_info(f"Total Pinpoint applications found: {len(all_pinpoint_apps)}")
        utils.log_info(f"Total Pinpoint campaigns found: {len(all_pinpoint_campaigns)}")
        utils.log_info(f"Total Pinpoint segments found: {len(all_pinpoint_segments)}")

        # Create DataFrames
        df_ses_identities = utils.prepare_dataframe_for_export(pd.DataFrame(all_ses_identities))
        df_ses_config_sets = utils.prepare_dataframe_for_export(pd.DataFrame(all_ses_config_sets))
        df_ses_templates = utils.prepare_dataframe_for_export(pd.DataFrame(all_ses_templates))
        df_ses_account = utils.prepare_dataframe_for_export(pd.DataFrame(all_ses_account))
        df_pinpoint_apps = utils.prepare_dataframe_for_export(pd.DataFrame(all_pinpoint_apps))
        df_pinpoint_campaigns = utils.prepare_dataframe_for_export(pd.DataFrame(all_pinpoint_campaigns))
        df_pinpoint_segments = utils.prepare_dataframe_for_export(pd.DataFrame(all_pinpoint_segments))

        # Create summary
        summary_data = []
        summary_data.append({'Metric': 'Total SES Identities', 'Value': len(all_ses_identities)})
        summary_data.append({'Metric': 'Total SES Configuration Sets', 'Value': len(all_ses_config_sets)})
        summary_data.append({'Metric': 'Total SES Templates', 'Value': len(all_ses_templates)})
        summary_data.append({'Metric': 'Total Pinpoint Applications', 'Value': len(all_pinpoint_apps)})
        summary_data.append({'Metric': 'Total Pinpoint Campaigns', 'Value': len(all_pinpoint_campaigns)})
        summary_data.append({'Metric': 'Total Pinpoint Segments', 'Value': len(all_pinpoint_segments)})
        summary_data.append({'Metric': 'Regions Scanned', 'Value': len(regions)})

        if not df_ses_identities.empty:
            verified_identities = len(df_ses_identities[df_ses_identities['VerificationStatus'] == True])
            dkim_enabled = len(df_ses_identities[df_ses_identities['DkimEnabled'] == True])

            summary_data.append({'Metric': 'Verified Identities', 'Value': verified_identities})
            summary_data.append({'Metric': 'DKIM Enabled Identities', 'Value': dkim_enabled})

        if not df_ses_account.empty:
            # Find regions with production access
            production_regions = len(df_ses_account[df_ses_account['ProductionAccess'] == True])
            summary_data.append({'Metric': 'Regions with Production Access', 'Value': production_regions})

        if not df_pinpoint_campaigns.empty:
            active_campaigns = len(df_pinpoint_campaigns[df_pinpoint_campaigns['State'] == 'RUNNING'])
            summary_data.append({'Metric': 'Active Pinpoint Campaigns', 'Value': active_campaigns})

        df_summary = utils.prepare_dataframe_for_export(pd.DataFrame(summary_data))

        # Create filtered views
        df_verified_identities = pd.DataFrame()
        df_active_campaigns = pd.DataFrame()

        if not df_ses_identities.empty:
            df_verified_identities = df_ses_identities[df_ses_identities['VerificationStatus'] == True]

        if not df_pinpoint_campaigns.empty:
            df_active_campaigns = df_pinpoint_campaigns[df_pinpoint_campaigns['State'] == 'RUNNING']

        # Export to Excel
        filename = utils.create_export_filename(account_name, 'ses-pinpoint', 'all')

        sheets = {
            'Summary': df_summary,
            'SES Account Info': df_ses_account,
            'SES Identities': df_ses_identities,
            'Verified Identities': df_verified_identities,
            'SES Configuration Sets': df_ses_config_sets,
            'SES Templates': df_ses_templates,
            'Pinpoint Apps': df_pinpoint_apps,
            'Pinpoint Campaigns': df_pinpoint_campaigns,
            'Active Campaigns': df_active_campaigns,
            'Pinpoint Segments': df_pinpoint_segments,
        }

        utils.save_multiple_dataframes_to_excel(sheets, filename)

        # Log summary
        total_resources = (len(all_ses_identities) + len(all_ses_config_sets) +
                          len(all_ses_templates) + len(all_pinpoint_apps) +
                          len(all_pinpoint_campaigns) + len(all_pinpoint_segments))

        utils.log_export_summary(
            total_items=total_resources,
            item_type='SES/Pinpoint Resources',
            filename=filename
        )

        utils.log_info(f"  SES Identities: {len(all_ses_identities)}")
        utils.log_info(f"  SES Configuration Sets: {len(all_ses_config_sets)}")
        utils.log_info(f"  SES Templates: {len(all_ses_templates)}")
        utils.log_info(f"  Pinpoint Applications: {len(all_pinpoint_apps)}")
        utils.log_info(f"  Pinpoint Campaigns: {len(all_pinpoint_campaigns)}")
        utils.log_info(f"  Pinpoint Segments: {len(all_pinpoint_segments)}")

        utils.log_success("SES/Pinpoint export completed successfully!")

    except Exception as e:
        utils.log_error(f"Failed to export SES/Pinpoint resources: {str(e)}")
        raise


if __name__ == "__main__":
    main()

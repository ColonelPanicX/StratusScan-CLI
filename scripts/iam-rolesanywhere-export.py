#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS IAM Roles Anywhere Export Script
Version: v0.1.0
Date: NOV-11-2025

Description:
This script performs a comprehensive export of AWS IAM Roles Anywhere resources from AWS environments.
IAM Roles Anywhere enables workloads that run outside of AWS to assume IAM roles using X.509 certificates.
This includes trust anchors, profiles, CRLs (Certificate Revocation Lists), and subject mappings.

Collected information includes: Trust Anchors (with source types and status), Profiles (with role
assumptions and session durations), CRLs (with revocation data), and comprehensive summary analytics.

Note: IAM Roles Anywhere is a global service but requires region specification. This script uses
us-west-2 as the primary endpoint for API operations.
"""

import sys
import datetime
import json
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
    import utils

def print_title():
    """
    Print the script title and account information.

    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS IAM ROLES ANYWHERE COMPREHENSIVE EXPORT")
    print("====================================================================")
    print("Version: v0.1.0                       Date: NOV-11-2025")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")

    # Get account information using utils
    account_id, account_name = utils.get_account_info()
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")

    return account_id, account_name

def format_tags(tags: List[Dict[str, str]]) -> str:
    """Format tags for display."""
    if not tags:
        return "None"
    tag_strings = [f"{tag['key']}={tag['value']}" for tag in tags]
    return ", ".join(tag_strings)

@utils.aws_error_handler("Collecting Trust Anchors", default_return=[])
def collect_trust_anchors() -> List[Dict[str, Any]]:
    """Collect IAM Roles Anywhere Trust Anchors."""
    utils.log_info("Collecting IAM Roles Anywhere Trust Anchors...")

    # IAM Roles Anywhere is a global service - use partition-aware home region


    home_region = utils.get_partition_default_region()


    rolesanywhere = utils.get_boto3_client('rolesanywhere', region_name=home_region)
    trust_anchors = []

    try:
        # List all trust anchors
        paginator = rolesanywhere.get_paginator('list_trust_anchors')

        for page in paginator.paginate():
            for anchor in page.get('trustAnchors', []):
                trust_anchor_id = anchor.get('trustAnchorId', 'N/A')
                utils.log_info(f"Processing trust anchor: {anchor.get('name', trust_anchor_id)}")

                # Get detailed information
                try:
                    detail_response = rolesanywhere.get_trust_anchor(trustAnchorId=trust_anchor_id)
                    anchor_detail = detail_response.get('trustAnchor', {})

                    source = anchor_detail.get('source', {})
                    source_type = source.get('sourceType', 'N/A')
                    source_data = source.get('sourceData', {})

                    # Extract source ARN for ACM PCA
                    if source_type == 'AWS_ACM_PCA':
                        source_arn = source_data.get('acmPcaArn', 'N/A')
                    elif source_type == 'CERTIFICATE_BUNDLE':
                        source_arn = 'Certificate Bundle'
                    else:
                        source_arn = 'N/A'

                    trust_anchor_info = {
                        'Trust Anchor ARN': anchor_detail.get('trustAnchorArn', 'N/A'),
                        'Trust Anchor ID': trust_anchor_id,
                        'Name': anchor_detail.get('name', 'N/A'),
                        'Status': 'Enabled' if anchor_detail.get('enabled', False) else 'Disabled',
                        'Source Type': source_type,
                        'Source ARN/Reference': source_arn,
                        'Created At': anchor_detail.get('createdAt', 'N/A').strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(anchor_detail.get('createdAt'), datetime.datetime) else 'N/A',
                        'Updated At': anchor_detail.get('updatedAt', 'N/A').strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(anchor_detail.get('updatedAt'), datetime.datetime) else 'N/A',
                        'Tags': format_tags(anchor_detail.get('tags', []))
                    }

                    trust_anchors.append(trust_anchor_info)

                except Exception as e:
                    utils.log_warning(f"Could not get details for trust anchor {trust_anchor_id}: {e}")
                    # Add basic info even if details fail
                    trust_anchors.append({
                        'Trust Anchor ARN': anchor.get('trustAnchorArn', 'N/A'),
                        'Trust Anchor ID': trust_anchor_id,
                        'Name': anchor.get('name', 'N/A'),
                        'Status': 'Enabled' if anchor.get('enabled', False) else 'Disabled',
                        'Source Type': 'Unknown',
                        'Source ARN/Reference': 'Unknown',
                        'Created At': 'Unknown',
                        'Updated At': 'Unknown',
                        'Tags': 'Unknown'
                    })

        utils.log_success(f"Successfully collected {len(trust_anchors)} trust anchors")

    except Exception as e:
        utils.log_warning(f"No trust anchors found or service not configured: {e}")

    return trust_anchors

@utils.aws_error_handler("Collecting Profiles", default_return=[])
def collect_profiles() -> List[Dict[str, Any]]:
    """Collect IAM Roles Anywhere Profiles."""
    utils.log_info("Collecting IAM Roles Anywhere Profiles...")

    # IAM Roles Anywhere is a global service - use partition-aware home region


    home_region = utils.get_partition_default_region()


    rolesanywhere = utils.get_boto3_client('rolesanywhere', region_name=home_region)
    profiles = []

    try:
        # List all profiles
        paginator = rolesanywhere.get_paginator('list_profiles')

        for page in paginator.paginate():
            for profile in page.get('profiles', []):
                profile_id = profile.get('profileId', 'N/A')
                utils.log_info(f"Processing profile: {profile.get('name', profile_id)}")

                # Get detailed information
                try:
                    detail_response = rolesanywhere.get_profile(profileId=profile_id)
                    profile_detail = detail_response.get('profile', {})

                    # Extract role ARNs
                    role_arns = profile_detail.get('roleArns', [])
                    role_arns_str = ", ".join(role_arns) if role_arns else "None"

                    # Extract managed policy ARNs
                    managed_policies = profile_detail.get('managedPolicyArns', [])
                    managed_policies_str = ", ".join(managed_policies) if managed_policies else "None"

                    # Count inline policies
                    inline_policy_count = len(profile_detail.get('sessionPolicy', ''))

                    # Session duration in seconds
                    session_duration = profile_detail.get('durationSeconds', 3600)
                    session_duration_hours = session_duration / 3600

                    profile_info = {
                        'Profile ARN': profile_detail.get('profileArn', 'N/A'),
                        'Profile ID': profile_id,
                        'Name': profile_detail.get('name', 'N/A'),
                        'Status': 'Enabled' if profile_detail.get('enabled', False) else 'Disabled',
                        'Session Duration (Hours)': f"{session_duration_hours:.2f}",
                        'Session Duration (Seconds)': session_duration,
                        'Role ARNs': role_arns_str,
                        'Role Count': len(role_arns),
                        'Managed Policy ARNs': managed_policies_str,
                        'Managed Policy Count': len(managed_policies),
                        'Has Inline Policy': 'Yes' if inline_policy_count > 0 else 'No',
                        'Require Instance Properties': 'Yes' if profile_detail.get('requireInstanceProperties', False) else 'No',
                        'Created At': profile_detail.get('createdAt', 'N/A').strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(profile_detail.get('createdAt'), datetime.datetime) else 'N/A',
                        'Updated At': profile_detail.get('updatedAt', 'N/A').strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(profile_detail.get('updatedAt'), datetime.datetime) else 'N/A',
                        'Tags': format_tags(profile_detail.get('tags', []))
                    }

                    profiles.append(profile_info)

                except Exception as e:
                    utils.log_warning(f"Could not get details for profile {profile_id}: {e}")
                    # Add basic info even if details fail
                    profiles.append({
                        'Profile ARN': profile.get('profileArn', 'N/A'),
                        'Profile ID': profile_id,
                        'Name': profile.get('name', 'N/A'),
                        'Status': 'Enabled' if profile.get('enabled', False) else 'Disabled',
                        'Session Duration (Hours)': 'Unknown',
                        'Session Duration (Seconds)': 'Unknown',
                        'Role ARNs': 'Unknown',
                        'Role Count': 0,
                        'Managed Policy ARNs': 'Unknown',
                        'Managed Policy Count': 0,
                        'Has Inline Policy': 'Unknown',
                        'Require Instance Properties': 'Unknown',
                        'Created At': 'Unknown',
                        'Updated At': 'Unknown',
                        'Tags': 'Unknown'
                    })

        utils.log_success(f"Successfully collected {len(profiles)} profiles")

    except Exception as e:
        utils.log_warning(f"No profiles found or service not configured: {e}")

    return profiles

@utils.aws_error_handler("Collecting CRLs", default_return=[])
def collect_crls() -> List[Dict[str, Any]]:
    """Collect IAM Roles Anywhere Certificate Revocation Lists (CRLs)."""
    utils.log_info("Collecting IAM Roles Anywhere CRLs...")

    # IAM Roles Anywhere is a global service - use partition-aware home region


    home_region = utils.get_partition_default_region()


    rolesanywhere = utils.get_boto3_client('rolesanywhere', region_name=home_region)
    crls = []

    try:
        # List all CRLs
        paginator = rolesanywhere.get_paginator('list_crls')

        for page in paginator.paginate():
            for crl in page.get('crls', []):
                crl_id = crl.get('crlId', 'N/A')
                utils.log_info(f"Processing CRL: {crl.get('name', crl_id)}")

                # Get detailed information
                try:
                    detail_response = rolesanywhere.get_crl(crlId=crl_id)
                    crl_detail = detail_response.get('crl', {})

                    # Extract CRL data source (S3)
                    crl_data = crl_detail.get('crlData', 'N/A')
                    if crl_data and crl_data != 'N/A':
                        crl_data_display = f"S3 Bucket Object (Length: {len(crl_data)} bytes)"
                    else:
                        crl_data_display = "N/A"

                    # Trust anchor association
                    trust_anchor_arn = crl_detail.get('trustAnchorArn', 'N/A')

                    crl_info = {
                        'CRL ARN': crl_detail.get('crlArn', 'N/A'),
                        'CRL ID': crl_id,
                        'Name': crl_detail.get('name', 'N/A'),
                        'Status': 'Enabled' if crl_detail.get('enabled', False) else 'Disabled',
                        'CRL Data Source': crl_data_display,
                        'Trust Anchor ARN': trust_anchor_arn,
                        'Created At': crl_detail.get('createdAt', 'N/A').strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(crl_detail.get('createdAt'), datetime.datetime) else 'N/A',
                        'Updated At': crl_detail.get('updatedAt', 'N/A').strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(crl_detail.get('updatedAt'), datetime.datetime) else 'N/A',
                        'Tags': format_tags(crl_detail.get('tags', []))
                    }

                    crls.append(crl_info)

                except Exception as e:
                    utils.log_warning(f"Could not get details for CRL {crl_id}: {e}")
                    # Add basic info even if details fail
                    crls.append({
                        'CRL ARN': crl.get('crlArn', 'N/A'),
                        'CRL ID': crl_id,
                        'Name': crl.get('name', 'N/A'),
                        'Status': 'Enabled' if crl.get('enabled', False) else 'Disabled',
                        'CRL Data Source': 'Unknown',
                        'Trust Anchor ARN': 'Unknown',
                        'Created At': 'Unknown',
                        'Updated At': 'Unknown',
                        'Tags': 'Unknown'
                    })

        utils.log_success(f"Successfully collected {len(crls)} CRLs")

    except Exception as e:
        utils.log_warning(f"No CRLs found or service not configured: {e}")

    return crls

def create_summary(trust_anchors: List[Dict], profiles: List[Dict], crls: List[Dict]) -> Dict[str, Any]:
    """Create summary statistics for IAM Roles Anywhere."""
    summary = {
        'Category': [
            'Trust Anchors',
            'Trust Anchors - Enabled',
            'Trust Anchors - Disabled',
            'Trust Anchors - ACM PCA Source',
            'Trust Anchors - Certificate Bundle Source',
            '',
            'Profiles',
            'Profiles - Enabled',
            'Profiles - Disabled',
            'Profiles - Require Instance Properties',
            'Profiles - Session Duration < 1 Hour',
            'Profiles - Session Duration 1-12 Hours',
            'Profiles - Session Duration > 12 Hours',
            '',
            'CRLs',
            'CRLs - Enabled',
            'CRLs - Disabled',
            '',
            'Configuration Status',
        ],
        'Count': [
            len(trust_anchors),
            len([ta for ta in trust_anchors if ta.get('Status') == 'Enabled']),
            len([ta for ta in trust_anchors if ta.get('Status') == 'Disabled']),
            len([ta for ta in trust_anchors if ta.get('Source Type') == 'AWS_ACM_PCA']),
            len([ta for ta in trust_anchors if ta.get('Source Type') == 'CERTIFICATE_BUNDLE']),
            '',
            len(profiles),
            len([p for p in profiles if p.get('Status') == 'Enabled']),
            len([p for p in profiles if p.get('Status') == 'Disabled']),
            len([p for p in profiles if p.get('Require Instance Properties') == 'Yes']),
            len([p for p in profiles if isinstance(p.get('Session Duration (Seconds)'), int) and p.get('Session Duration (Seconds)') < 3600]),
            len([p for p in profiles if isinstance(p.get('Session Duration (Seconds)'), int) and 3600 <= p.get('Session Duration (Seconds)') <= 43200]),
            len([p for p in profiles if isinstance(p.get('Session Duration (Seconds)'), int) and p.get('Session Duration (Seconds)') > 43200]),
            '',
            len(crls),
            len([c for c in crls if c.get('Status') == 'Enabled']),
            len([c for c in crls if c.get('Status') == 'Disabled']),
            '',
            'Configured' if (trust_anchors or profiles or crls) else 'Not Configured'
        ]
    }

    return summary

def export_to_excel(trust_anchors: List[Dict], profiles: List[Dict], crls: List[Dict],
                   account_id: str, account_name: str) -> str:
    """Export IAM Roles Anywhere data to Excel with multiple sheets."""
    try:
        import pandas as pd

        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        filename = utils.create_export_filename(account_name, "iam-rolesanywhere", "comprehensive", current_date)

        # Prepare data frames
        data_frames = {}

        # Summary sheet (always include, even if empty)
        summary_data = create_summary(trust_anchors, profiles, crls)
        summary_df = pd.DataFrame(summary_data)
        data_frames['Summary'] = summary_df

        # Trust Anchors sheet
        if trust_anchors:
            trust_anchors_df = pd.DataFrame(trust_anchors)
            trust_anchors_df = utils.prepare_dataframe_for_export(trust_anchors_df)
            data_frames['Trust Anchors'] = trust_anchors_df
        else:
            # Create empty placeholder
            data_frames['Trust Anchors'] = pd.DataFrame({
                'Status': ['No trust anchors configured'],
                'Note': ['IAM Roles Anywhere may not be in use or configured in this account']
            })

        # Profiles sheet
        if profiles:
            profiles_df = pd.DataFrame(profiles)
            profiles_df = utils.prepare_dataframe_for_export(profiles_df)
            data_frames['Profiles'] = profiles_df
        else:
            data_frames['Profiles'] = pd.DataFrame({
                'Status': ['No profiles configured'],
                'Note': ['IAM Roles Anywhere may not be in use or configured in this account']
            })

        # CRLs sheet
        if crls:
            crls_df = pd.DataFrame(crls)
            crls_df = utils.prepare_dataframe_for_export(crls_df)
            data_frames['CRLs'] = crls_df
        else:
            data_frames['CRLs'] = pd.DataFrame({
                'Status': ['No CRLs configured'],
                'Note': ['Certificate Revocation Lists are optional for IAM Roles Anywhere']
            })

        # Save using utils function
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("IAM Roles Anywhere data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains {len(trust_anchors)} trust anchors, {len(profiles)} profiles, and {len(crls)} CRLs")
            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def main():
    """Main function to orchestrate IAM Roles Anywhere data collection."""
    try:
        # Check dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return

        # Print title and get account info
        account_id, account_name = print_title()

        # Validate AWS credentials
        is_valid, validated_account_id, error_message = utils.validate_aws_credentials()
        if not is_valid:
            utils.log_error(f"AWS credentials validation failed: {error_message}")
            print("\nPlease configure your credentials using:")
            print("  - AWS CLI: aws configure")
            print("  - Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
            print("  - IAM role (if running on EC2)")
            return

        utils.log_success("AWS credentials validated")

        utils.log_info("Starting IAM Roles Anywhere data collection...")
        print("====================================================================")
        print("\nNOTE: IAM Roles Anywhere enables workloads outside AWS to assume")
        print("IAM roles using X.509 certificates. If not configured, this export")
        print("will create a report indicating the service is not in use.")
        print("====================================================================\n")

        # Collect data
        utils.log_info("Phase 1: Collecting Trust Anchors...")
        trust_anchors = collect_trust_anchors()

        utils.log_info("Phase 2: Collecting Profiles...")
        profiles = collect_profiles()

        utils.log_info("Phase 3: Collecting CRLs...")
        crls = collect_crls()

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Export even if empty (with helpful messaging)
        filename = export_to_excel(trust_anchors, profiles, crls, account_id, account_name)

        if filename:
            if not trust_anchors and not profiles and not crls:
                utils.log_info("IAM Roles Anywhere is not configured in this account")
                utils.log_info("The export file contains informational placeholders")
            else:
                utils.log_info(f"Total trust anchors: {len(trust_anchors)}")
                utils.log_info(f"Total profiles: {len(profiles)}")
                utils.log_info(f"Total CRLs: {len(crls)}")

            print("\nScript execution completed successfully.")
        else:
            utils.log_error("Export failed. Please check the logs.")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()

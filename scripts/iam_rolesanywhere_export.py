#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS IAM Roles Anywhere Export Script
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
    import utils
args = utils.parse_script_args("Export IAM Roles Anywhere profiles and trust anchors to Excel")

def format_tags(tags: list[dict[str, str]]) -> str:
    """Format tags for display."""
    if not tags:
        return "None"
    tag_strings = [f"{tag.get('key', 'N/A')}={tag.get('value', 'N/A')}" for tag in tags]
    return ", ".join(tag_strings)


def _build_trust_anchor_row(rolesanywhere, anchor: dict[str, Any]) -> dict[str, Any]:
    """
    Build the export row for a single IAM Roles Anywhere trust anchor.

    Extracted so per-item processing can be wrapped in try/except by the
    caller: a malformed trust anchor entry must not sink the whole
    account-scope collection. Fields are read with ``.get()`` and a safe
    default for the same reason.

    Args:
        rolesanywhere: The boto3 IAM Roles Anywhere client.
        anchor: A single trustAnchors entry from list_trust_anchors.

    Returns:
        dict: The assembled trust anchor row.
    """
    trust_anchor_id = anchor.get('trustAnchorId', 'N/A')
    utils.log_info(f"Processing trust anchor: {anchor.get('name', trust_anchor_id)}")

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

    created_at = anchor_detail.get('createdAt')
    updated_at = anchor_detail.get('updatedAt')

    return {
        'Trust Anchor ARN': anchor_detail.get('trustAnchorArn', 'N/A'),
        'Trust Anchor ID': trust_anchor_id,
        'Name': anchor_detail.get('name', 'N/A'),
        'Status': 'Enabled' if anchor_detail.get('enabled', False) else 'Disabled',
        'Source Type': source_type,
        'Source ARN/Reference': source_arn,
        'Created At': created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(created_at, datetime.datetime) else 'N/A',
        'Updated At': updated_at.strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(updated_at, datetime.datetime) else 'N/A',
        'Tags': format_tags(anchor_detail.get('tags', []))
    }


def collect_trust_anchors() -> list[dict[str, Any]]:
    """
    Collect IAM Roles Anywhere Trust Anchors.

    Not wrapped in ``aws_error_handler`` and does not swallow errors to an
    empty list: a swallowed error here would be indistinguishable from a
    genuinely empty account (no trust anchors configured), producing silent
    data loss (see the 07.15.2026 / 07.16.2026 silent-collection-failure
    audits). IAM Roles Anywhere is a global, account-scope service (not
    multi-region -- see scripts/iam_export.py for the account-scope
    reference pattern this follows, and scripts/shield_export.py /
    scripts/lambda_export.py for the same fix applied there). Account-scope
    failures (client creation, pagination, a real API error) are allowed to
    raise so the caller (main) can record this scope as *failed* rather than
    *empty*. Per-item errors are contained internally (logged and skipped).

    Returns:
        list: List of trust anchor information dictionaries.

    Raises:
        Exception: Any AWS/pagination error for the account scope (caller
            records it as a failed scope; it is never masked as empty).
    """
    utils.log_info("Collecting IAM Roles Anywhere Trust Anchors...")

    # IAM Roles Anywhere is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    rolesanywhere = utils.get_boto3_client('rolesanywhere', region_name=home_region)
    trust_anchors = []

    # List all trust anchors
    paginator = rolesanywhere.get_paginator('list_trust_anchors')
    total_anchors = 0
    skipped = 0

    for page in paginator.paginate():
        anchors = page.get('trustAnchors', [])
        total_anchors += len(anchors)

        for anchor in anchors:
            try:
                trust_anchors.append(_build_trust_anchor_row(rolesanywhere, anchor))
            except Exception as e:
                skipped += 1
                anchor_id = anchor.get('trustAnchorId', 'Unknown') if isinstance(anchor, dict) else 'Unknown'
                utils.log_error(f"Skipping trust anchor '{anchor_id}' due to a processing error", e)
                continue

    if skipped:
        utils.log_warning(
            f"{skipped} of {total_anchors} trust anchor(s) were skipped due to "
            "processing errors (see log above); the remaining trust anchors were still collected."
        )

    utils.log_success(f"Successfully collected {len(trust_anchors)} trust anchors")

    return trust_anchors

def _build_profile_row(rolesanywhere, profile: dict[str, Any]) -> dict[str, Any]:
    """
    Build the export row for a single IAM Roles Anywhere profile.

    Extracted so per-item processing can be wrapped in try/except by the
    caller: a malformed profile entry must not sink the whole account-scope
    collection. Fields are read with ``.get()`` and a safe default for the
    same reason.

    Args:
        rolesanywhere: The boto3 IAM Roles Anywhere client.
        profile: A single profiles entry from list_profiles.

    Returns:
        dict: The assembled profile row.
    """
    profile_id = profile.get('profileId', 'N/A')
    utils.log_info(f"Processing profile: {profile.get('name', profile_id)}")

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

    created_at = profile_detail.get('createdAt')
    updated_at = profile_detail.get('updatedAt')

    return {
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
        'Created At': created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(created_at, datetime.datetime) else 'N/A',
        'Updated At': updated_at.strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(updated_at, datetime.datetime) else 'N/A',
        'Tags': format_tags(profile_detail.get('tags', []))
    }


def collect_profiles() -> list[dict[str, Any]]:
    """
    Collect IAM Roles Anywhere Profiles.

    Not wrapped in ``aws_error_handler`` and does not swallow errors to an
    empty list: a swallowed error here would be indistinguishable from a
    genuinely empty account (no profiles configured), producing silent data
    loss (see the 07.15.2026 / 07.16.2026 silent-collection-failure audits).
    IAM Roles Anywhere is a global, account-scope service (not multi-region
    -- see scripts/iam_export.py for the account-scope reference pattern
    this follows, and scripts/shield_export.py / scripts/lambda_export.py
    for the same fix applied there). Account-scope failures (client
    creation, pagination, a real API error) are allowed to raise so the
    caller (main) can record this scope as *failed* rather than *empty*.
    Per-item errors are contained internally (logged and skipped).

    Returns:
        list: List of profile information dictionaries.

    Raises:
        Exception: Any AWS/pagination error for the account scope (caller
            records it as a failed scope; it is never masked as empty).
    """
    utils.log_info("Collecting IAM Roles Anywhere Profiles...")

    # IAM Roles Anywhere is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    rolesanywhere = utils.get_boto3_client('rolesanywhere', region_name=home_region)
    profiles = []

    # List all profiles
    paginator = rolesanywhere.get_paginator('list_profiles')
    total_profiles = 0
    skipped = 0

    for page in paginator.paginate():
        page_profiles = page.get('profiles', [])
        total_profiles += len(page_profiles)

        for profile in page_profiles:
            try:
                profiles.append(_build_profile_row(rolesanywhere, profile))
            except Exception as e:
                skipped += 1
                profile_id = profile.get('profileId', 'Unknown') if isinstance(profile, dict) else 'Unknown'
                utils.log_error(f"Skipping profile '{profile_id}' due to a processing error", e)
                continue

    if skipped:
        utils.log_warning(
            f"{skipped} of {total_profiles} profile(s) were skipped due to "
            "processing errors (see log above); the remaining profiles were still collected."
        )

    utils.log_success(f"Successfully collected {len(profiles)} profiles")

    return profiles

@utils.aws_error_handler("Collecting CRLs", default_return=[])
def collect_crls() -> list[dict[str, Any]]:
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

def create_summary(trust_anchors: list[dict], profiles: list[dict], crls: list[dict]) -> dict[str, Any]:
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

def export_to_excel(trust_anchors: list[dict], profiles: list[dict], crls: list[dict],
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
            utils.log_success(f"File location: {output_path}")
            utils.log_info(f"Export contains {len(trust_anchors)} trust anchors, {len(profiles)} profiles, and {len(crls)} CRLs")
            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def main():
    """
    Main function to orchestrate IAM Roles Anywhere data collection.

    IAM Roles Anywhere is a global, account-scope service (not
    multi-region), so failures are tracked per account-scope collector
    rather than via ``utils.scan_regions_concurrent`` (see
    scripts/iam_export.py for the account-scope reference pattern, and
    scripts/shield_export.py / scripts/lambda_export.py for the finalize
    shape this follows). Trust anchors and profiles are the two PRIMARY
    scopes: a real API error in either must propagate to ``failed_scopes``,
    never collapse into "not configured". This exporter always writes a
    workbook (a forced Summary sheet plus placeholder sheets for empty
    categories), so a partial/failed export still lands a file -- but a
    failed scope is always also surfaced via
    ``utils.report_collection_failures`` + a non-zero exit; it must never be
    silently collapsed into "genuinely empty" (07.15.2026 / 07.16.2026
    audits). CRLs remain an enrichment scope that degrades gracefully via
    its own ``aws_error_handler`` decorator.
    """
    try:
        # Check dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return

        # Print title and get account info
        utils.setup_logging("iam-rolesanywhere-export")
        account_id, account_name = utils.print_script_banner("AWS IAM ROLES ANYWHERE COMPREHENSIVE EXPORT")

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

        # Account-scope failure tracking (see scripts/iam_export.py).
        failed_scopes = []

        # Collect data
        # STEP 1: Collect Trust Anchors (PRIMARY scope -- a real API error
        # here must propagate to failed_scopes, never collapse into an
        # empty list that reads as "not configured").
        utils.log_info("Phase 1: Collecting Trust Anchors...")
        try:
            trust_anchors = collect_trust_anchors()
        except Exception as e:
            failed_scopes.append(('trust_anchors', str(e)))
            utils.log_error(f"Trust anchors collection failed: {e}")
            trust_anchors = []

        # STEP 2: Collect Profiles (PRIMARY scope -- same rule as above).
        utils.log_info("Phase 2: Collecting Profiles...")
        try:
            profiles = collect_profiles()
        except Exception as e:
            failed_scopes.append(('profiles', str(e)))
            utils.log_error(f"Profiles collection failed: {e}")
            profiles = []

        # STEP 3: Collect CRLs (enrichment -- degrades gracefully via its
        # own aws_error_handler decorator; a failure here does not fail the
        # whole export).
        utils.log_info("Phase 3: Collecting CRLs...")
        crls = collect_crls()

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Export whatever succeeded -- this exporter always writes a
        # workbook (forced Summary sheet + placeholder sheets), even when a
        # primary scope failed (see
        # .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).
        filename = export_to_excel(trust_anchors, profiles, crls, account_id, account_name)

        if filename:
            if not trust_anchors and not profiles and not crls and not failed_scopes:
                # Genuinely empty: both primary scopes succeeded and there is
                # simply nothing configured.
                utils.log_info("IAM Roles Anywhere is not configured in this account")
                utils.log_info("The export file contains informational placeholders")
            else:
                utils.log_info(f"Total trust anchors: {len(trust_anchors)}")
                utils.log_info(f"Total profiles: {len(profiles)}")
                utils.log_info(f"Total CRLs: {len(crls)}")

            print("\nScript execution completed successfully.")
        else:
            utils.log_error("Export failed. Please check the logs.")

        # If a primary scope (trust anchors or profiles) failed, make it
        # loud: write a marker and exit non-zero, even though a workbook
        # (with the forced Summary sheet) was still written. A partial
        # export that looks complete is exactly the failure mode this
        # guards against.
        if failed_scopes:
            utils.report_collection_failures(account_name, 'iam-rolesanywhere', failed_scopes)
            print(
                "\nERROR: IAM Roles Anywhere export completed with failures — data is "
                "incomplete. See the *-iam-rolesanywhere-FAILED-*.txt marker in the "
                "output directory."
            )
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()

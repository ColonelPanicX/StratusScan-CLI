#!/usr/bin/env python3
"""
IAM Identity Providers Export Script for StratusScan

Exports comprehensive IAM identity provider information including:
- SAML Providers for federated access
- OIDC (OpenID Connect) Providers for web identity federation
- Provider metadata and trust relationships
- Detailed policy and thumbprint information

Output: Multi-worksheet Excel file with IAM identity provider resources
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
@utils.aws_error_handler("Collecting SAML providers", default_return=[])
def collect_saml_providers() -> List[Dict[str, Any]]:
    """Collect IAM SAML provider information."""
    utils.log_info("Collecting SAML providers...")
    all_saml_providers = []

    # IAM is global, use us-west-2 as the region
    # iam is a global service - use partition-aware home region

    home_region = utils.get_partition_default_region()

    iam_client = utils.get_boto3_client('iam', region_name=home_region)

    try:
        # List all SAML providers
        response = iam_client.list_saml_providers()
        saml_provider_list = response.get('SAMLProviderList', [])

        utils.log_info(f"Found {len(saml_provider_list)} SAML providers")

        for provider in saml_provider_list:
            provider_arn = provider.get('Arn', 'N/A')

            try:
                # Get detailed information about the SAML provider
                provider_response = iam_client.get_saml_provider(SAMLProviderArn=provider_arn)

                saml_metadata = provider_response.get('SAMLMetadataDocument', 'N/A')
                create_date = provider_response.get('CreateDate', 'N/A')
                valid_until = provider_response.get('ValidUntil', 'N/A')

                # Format dates
                if create_date != 'N/A':
                    create_date = create_date.strftime('%Y-%m-%d %H:%M:%S')

                if valid_until != 'N/A':
                    valid_until = valid_until.strftime('%Y-%m-%d %H:%M:%S')

                # Extract provider name from ARN
                # ARN format: arn:aws:iam::account-id:saml-provider/provider-name
                provider_name = provider_arn.split('/')[-1] if '/' in provider_arn else 'N/A'

                # Truncate SAML metadata for display
                saml_metadata_display = 'N/A'
                if saml_metadata != 'N/A':
                    # Extract some information from metadata if possible
                    if 'entityID' in saml_metadata:
                        try:
                            # Try to extract entity ID from XML
                            entity_id_start = saml_metadata.find('entityID="') + 10
                            entity_id_end = saml_metadata.find('"', entity_id_start)
                            entity_id = saml_metadata[entity_id_start:entity_id_end]
                            saml_metadata_display = f"Entity ID: {entity_id} (metadata truncated)"
                        except Exception:
                            saml_metadata_display = "Metadata present (truncated)"
                    else:
                        saml_metadata_display = "Metadata present (truncated)"

                # Get tags for this provider
                tags_str = 'N/A'
                try:
                    tags_response = iam_client.list_saml_provider_tags(SAMLProviderArn=provider_arn)
                    tags = tags_response.get('Tags', [])
                    if tags:
                        tags_str = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags])
                except Exception:
                    pass

                all_saml_providers.append({
                    'Provider Name': provider_name,
                    'ARN': provider_arn,
                    'Created': create_date,
                    'Valid Until': valid_until,
                    'SAML Metadata': saml_metadata_display,
                    'Tags': tags_str
                })

            except Exception as e:
                utils.log_warning(f"Could not get details for SAML provider {provider_arn}: {str(e)}")
                # Add basic info
                provider_name = provider_arn.split('/')[-1] if '/' in provider_arn else 'N/A'
                all_saml_providers.append({
                    'Provider Name': provider_name,
                    'ARN': provider_arn,
                    'Created': 'N/A',
                    'Valid Until': 'N/A',
                    'SAML Metadata': 'Error retrieving',
                    'Tags': 'N/A'
                })

    except Exception as e:
        utils.log_warning(f"Error listing SAML providers: {str(e)}")

    utils.log_info(f"Collected {len(all_saml_providers)} SAML providers")
    return all_saml_providers


@utils.aws_error_handler("Collecting OIDC providers", default_return=[])
def collect_oidc_providers() -> List[Dict[str, Any]]:
    """Collect IAM OIDC (OpenID Connect) provider information."""
    utils.log_info("Collecting OIDC providers...")
    all_oidc_providers = []

    # IAM is global, use us-west-2 as the region
    # iam is a global service - use partition-aware home region

    home_region = utils.get_partition_default_region()

    iam_client = utils.get_boto3_client('iam', region_name=home_region)

    try:
        # List all OIDC providers
        response = iam_client.list_open_id_connect_providers()
        oidc_provider_list = response.get('OpenIDConnectProviderList', [])

        utils.log_info(f"Found {len(oidc_provider_list)} OIDC providers")

        for provider in oidc_provider_list:
            provider_arn = provider.get('Arn', 'N/A')

            try:
                # Get detailed information about the OIDC provider
                provider_response = iam_client.get_open_id_connect_provider(
                    OpenIDConnectProviderArn=provider_arn
                )

                url = provider_response.get('Url', 'N/A')
                client_id_list = provider_response.get('ClientIDList', [])
                thumbprint_list = provider_response.get('ThumbprintList', [])
                create_date = provider_response.get('CreateDate', 'N/A')

                # Format date
                if create_date != 'N/A':
                    create_date = create_date.strftime('%Y-%m-%d %H:%M:%S')

                # Extract provider name from ARN
                # ARN format: arn:aws:iam::account-id:oidc-provider/provider-url
                provider_name = provider_arn.split('/')[-1] if '/' in provider_arn else 'N/A'

                # Format client IDs
                client_ids_str = ', '.join(client_id_list) if client_id_list else 'None'

                # Format thumbprints
                thumbprints_str = ', '.join(thumbprint_list) if thumbprint_list else 'None'
                thumbprint_count = len(thumbprint_list)

                # Get tags for this provider
                tags_str = 'N/A'
                try:
                    tags_response = iam_client.list_open_id_connect_provider_tags(
                        OpenIDConnectProviderArn=provider_arn
                    )
                    tags = tags_response.get('Tags', [])
                    if tags:
                        tags_str = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags])
                except Exception:
                    pass

                # Determine provider type based on URL
                provider_type = 'Generic OIDC'
                if 'amazonaws.com' in url:
                    if 'eks' in url:
                        provider_type = 'Amazon EKS'
                    else:
                        provider_type = 'AWS Service'
                elif 'accounts.google.com' in url:
                    provider_type = 'Google'
                elif 'login.microsoftonline.com' in url or 'sts.windows.net' in url:
                    provider_type = 'Microsoft Azure AD'
                elif 'appleid.apple.com' in url:
                    provider_type = 'Apple'
                elif 'token.actions.githubusercontent.com' in url:
                    provider_type = 'GitHub Actions'

                all_oidc_providers.append({
                    'Provider Name': provider_name,
                    'ARN': provider_arn,
                    'Provider Type': provider_type,
                    'URL': url,
                    'Created': create_date,
                    'Client IDs': client_ids_str,
                    'Client ID Count': len(client_id_list),
                    'Thumbprints': thumbprints_str,
                    'Thumbprint Count': thumbprint_count,
                    'Tags': tags_str
                })

            except Exception as e:
                utils.log_warning(f"Could not get details for OIDC provider {provider_arn}: {str(e)}")
                # Add basic info
                provider_name = provider_arn.split('/')[-1] if '/' in provider_arn else 'N/A'
                all_oidc_providers.append({
                    'Provider Name': provider_name,
                    'ARN': provider_arn,
                    'Provider Type': 'Unknown',
                    'URL': 'N/A',
                    'Created': 'N/A',
                    'Client IDs': 'Error retrieving',
                    'Client ID Count': 0,
                    'Thumbprints': 'Error retrieving',
                    'Thumbprint Count': 0,
                    'Tags': 'N/A'
                })

    except Exception as e:
        utils.log_warning(f"Error listing OIDC providers: {str(e)}")

    utils.log_info(f"Collected {len(all_oidc_providers)} OIDC providers")
    return all_oidc_providers


@utils.aws_error_handler("Collecting roles using identity providers", default_return=[])
def collect_roles_using_providers(saml_providers: List[Dict[str, Any]],
                                   oidc_providers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collect IAM roles that trust identity providers."""
    utils.log_info("Collecting roles using identity providers...")
    roles_with_providers = []

    # Create a set of provider ARNs for lookup
    provider_arns = set()
    for provider in saml_providers:
        provider_arns.add(provider.get('ARN', ''))
    for provider in oidc_providers:
        provider_arns.add(provider.get('ARN', ''))

    # IAM is global, use us-west-2 as the region
    # iam is a global service - use partition-aware home region

    home_region = utils.get_partition_default_region()

    iam_client = utils.get_boto3_client('iam', region_name=home_region)

    try:
        # List all roles
        paginator = iam_client.get_paginator('list_roles')
        role_count = 0

        for page in paginator.paginate():
            roles = page.get('Roles', [])

            for role in roles:
                role_name = role.get('RoleName', 'N/A')
                role_arn = role.get('Arn', 'N/A')
                assume_role_policy = role.get('AssumeRolePolicyDocument', {})

                # Check if this role trusts any identity provider
                if isinstance(assume_role_policy, dict):
                    statements = assume_role_policy.get('Statement', [])

                    for statement in statements:
                        principal = statement.get('Principal', {})

                        # Check for Federated principal (used by SAML and OIDC)
                        federated = principal.get('Federated', '')

                        if federated and federated in provider_arns:
                            # This role trusts an identity provider
                            action = statement.get('Action', '')
                            effect = statement.get('Effect', 'N/A')
                            condition = statement.get('Condition', {})

                            # Determine provider type
                            provider_type = 'Unknown'
                            provider_name = 'N/A'

                            if 'saml-provider' in federated:
                                provider_type = 'SAML'
                                provider_name = federated.split('/')[-1]
                            elif 'oidc-provider' in federated:
                                provider_type = 'OIDC'
                                provider_name = federated.split('/')[-1]

                            # Extract SAML or OIDC specific conditions
                            saml_aud = 'N/A'
                            oidc_aud = 'N/A'
                            oidc_sub = 'N/A'

                            if isinstance(condition, dict):
                                # SAML conditions
                                string_equals = condition.get('StringEquals', {})
                                saml_aud = string_equals.get('SAML:aud', 'N/A')

                                # OIDC conditions
                                oidc_aud = string_equals.get(f'{provider_name}:aud', 'N/A')
                                oidc_sub = string_equals.get(f'{provider_name}:sub', 'N/A')

                            create_date = role.get('CreateDate', 'N/A')
                            if create_date != 'N/A':
                                create_date = create_date.strftime('%Y-%m-%d %H:%M:%S')

                            max_session = role.get('MaxSessionDuration', 'N/A')
                            if max_session != 'N/A':
                                max_session_hours = max_session / 3600
                                max_session = f"{max_session_hours:.1f} hours"

                            roles_with_providers.append({
                                'Role Name': role_name,
                                'Role ARN': role_arn,
                                'Provider Type': provider_type,
                                'Provider Name': provider_name,
                                'Provider ARN': federated,
                                'Trust Effect': effect,
                                'Trust Action': action,
                                'SAML Audience': saml_aud,
                                'OIDC Audience': oidc_aud,
                                'OIDC Subject': oidc_sub,
                                'Max Session Duration': max_session,
                                'Created': create_date
                            })

                role_count += 1

        utils.log_info(f"Scanned {role_count} roles")

    except Exception as e:
        utils.log_warning(f"Error collecting roles using providers: {str(e)}")

    utils.log_info(f"Found {len(roles_with_providers)} roles using identity providers")
    return roles_with_providers


def generate_summary(saml_providers: List[Dict[str, Any]],
                     oidc_providers: List[Dict[str, Any]],
                     roles_with_providers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for IAM identity providers."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # SAML providers summary
    total_saml = len(saml_providers)
    summary.append({
        'Metric': 'Total SAML Providers',
        'Count': total_saml,
        'Details': 'Security Assertion Markup Language providers for enterprise SSO'
    })

    # OIDC providers summary
    total_oidc = len(oidc_providers)
    summary.append({
        'Metric': 'Total OIDC Providers',
        'Count': total_oidc,
        'Details': 'OpenID Connect providers for web identity federation'
    })

    # OIDC provider types
    if oidc_providers:
        df = pd.DataFrame(oidc_providers)
        provider_types = df['Provider Type'].value_counts().to_dict()
        for provider_type, count in provider_types.items():
            summary.append({
                'Metric': f'OIDC - {provider_type}',
                'Count': count,
                'Details': f'{provider_type} identity providers'
            })

    # Roles using providers
    total_roles = len(roles_with_providers)
    saml_roles = sum(1 for r in roles_with_providers if r.get('Provider Type', '') == 'SAML')
    oidc_roles = sum(1 for r in roles_with_providers if r.get('Provider Type', '') == 'OIDC')

    summary.append({
        'Metric': 'Total Roles Using Providers',
        'Count': total_roles,
        'Details': f'SAML: {saml_roles}, OIDC: {oidc_roles}'
    })

    # EKS-specific roles
    eks_roles = sum(1 for r in roles_with_providers
                    if 'eks' in r.get('Provider ARN', '').lower())
    if eks_roles > 0:
        summary.append({
            'Metric': 'EKS IRSA Roles',
            'Count': eks_roles,
            'Details': 'Roles using EKS IAM Roles for Service Accounts (IRSA)'
        })

    # GitHub Actions roles
    github_roles = sum(1 for r in roles_with_providers
                       if 'github' in r.get('Provider ARN', '').lower())
    if github_roles > 0:
        summary.append({
            'Metric': 'GitHub Actions Roles',
            'Count': github_roles,
            'Details': 'Roles trusting GitHub Actions OIDC provider'
        })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    print("\n" + "="*60)
    print("IAM Identity Providers Export Tool")
    print("="*60)

    # Check dependencies
    utils.ensure_dependencies('pandas', 'openpyxl')

    # Get AWS account information
    account_id, account_name = utils.get_account_info()
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({account_id})")

    # Collect data (IAM is global)
    print("\nCollecting IAM identity provider data...")

    saml_providers = collect_saml_providers()
    oidc_providers = collect_oidc_providers()
    roles_with_providers = collect_roles_using_providers(saml_providers, oidc_providers)
    summary = generate_summary(saml_providers, oidc_providers, roles_with_providers)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if saml_providers:
        df_saml = pd.DataFrame(saml_providers)
        df_saml = utils.prepare_dataframe_for_export(df_saml)
        dataframes['SAML Providers'] = df_saml

    if oidc_providers:
        df_oidc = pd.DataFrame(oidc_providers)
        df_oidc = utils.prepare_dataframe_for_export(df_oidc)
        dataframes['OIDC Providers'] = df_oidc

    if roles_with_providers:
        df_roles = pd.DataFrame(roles_with_providers)
        df_roles = utils.prepare_dataframe_for_export(df_roles)
        dataframes['Roles Using Providers'] = df_roles

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export to Excel
    if dataframes:
        filename = utils.create_export_filename(account_name, 'iam-identity-providers', 'global')

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'SAML Providers': len(saml_providers),
            'OIDC Providers': len(oidc_providers),
            'Roles Using Providers': len(roles_with_providers)
        })
    else:
        utils.log_warning("No IAM identity provider data found to export")

    utils.log_success("IAM Identity Providers export completed successfully")


if __name__ == "__main__":
    main()

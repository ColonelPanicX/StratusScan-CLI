#!/usr/bin/env python3
"""
Cognito Export Script for StratusScan

Exports comprehensive Amazon Cognito information including:
- User Pools with authentication settings
- Identity Pools (Federated Identities)
- User Pool Clients and app integrations
- Identity Providers (SAML, OIDC, Social)
- User Pool Groups and sample users

Output: Multi-worksheet Excel file with Cognito resources
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
def scan_user_pools_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan Cognito user pools in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with user pool information from this region
    """
    regional_pools = []
    cognito_client = utils.get_boto3_client('cognito-idp', region_name=region)

    try:
        paginator = cognito_client.get_paginator('list_user_pools')
        for page in paginator.paginate(MaxResults=60):
            pools = page.get('UserPools', [])

            for pool_summary in pools:
                pool_id = pool_summary.get('Id', 'N/A')

                # Get detailed pool information
                try:
                    pool_response = cognito_client.describe_user_pool(UserPoolId=pool_id)
                    pool = pool_response.get('UserPool', {})

                    # Basic information
                    pool_name = pool.get('Name', 'N/A')
                    pool_id = pool.get('Id', 'N/A')
                    pool_arn = pool.get('Arn', 'N/A')
                    status = pool.get('Status', 'N/A')

                    # Creation and modification dates
                    creation_date = pool.get('CreationDate', 'N/A')
                    if creation_date != 'N/A':
                        creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S')

                    last_modified = pool.get('LastModifiedDate', 'N/A')
                    if last_modified != 'N/A':
                        last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')

                    # MFA Configuration
                    mfa_config = pool.get('MfaConfiguration', 'OFF')

                    # Password policy
                    policies = pool.get('Policies', {})
                    password_policy = policies.get('PasswordPolicy', {})
                    min_length = password_policy.get('MinimumLength', 'N/A')
                    require_uppercase = password_policy.get('RequireUppercase', False)
                    require_lowercase = password_policy.get('RequireLowercase', False)
                    require_numbers = password_policy.get('RequireNumbers', False)
                    require_symbols = password_policy.get('RequireSymbols', False)
                    temp_password_validity = password_policy.get('TemporaryPasswordValidityDays', 'N/A')

                    # Auto-verified attributes
                    auto_verified = pool.get('AutoVerifiedAttributes', [])
                    auto_verified_str = ', '.join(auto_verified) if auto_verified else 'None'

                    # Username attributes
                    username_attrs = pool.get('UsernameAttributes', [])
                    username_attrs_str = ', '.join(username_attrs) if username_attrs else 'username'

                    # Email configuration
                    email_config = pool.get('EmailConfiguration', {})
                    email_source = email_config.get('SourceArn', 'Default')
                    email_sending = email_config.get('EmailSendingAccount', 'COGNITO_DEFAULT')

                    # SMS configuration
                    sms_config = pool.get('SmsConfiguration', {})
                    sms_role = sms_config.get('SnsCallerArn', 'N/A')

                    # Advanced security
                    user_pool_add_ons = pool.get('UserPoolAddOns', {})
                    advanced_security = user_pool_add_ons.get('AdvancedSecurityMode', 'OFF')

                    # Account recovery
                    account_recovery = pool.get('AccountRecoverySetting', {})
                    recovery_mechanisms = account_recovery.get('RecoveryMechanisms', [])
                    recovery_str = ', '.join([m.get('Name', 'N/A') for m in recovery_mechanisms])

                    # Device tracking
                    device_config = pool.get('DeviceConfiguration', {})
                    challenge_required = device_config.get('ChallengeRequiredOnNewDevice', False)
                    device_only_remembered = device_config.get('DeviceOnlyRememberedOnUserPrompt', False)

                    # User attribute update settings
                    user_attr_update = pool.get('UserAttributeUpdateSettings', {})
                    attrs_require_verification = user_attr_update.get('AttributesRequireVerificationBeforeUpdate', [])
                    attrs_verify_str = ', '.join(attrs_require_verification) if attrs_require_verification else 'None'

                    # Lambda triggers
                    lambda_config = pool.get('LambdaConfig', {})
                    triggers = []
                    for trigger_name, trigger_arn in lambda_config.items():
                        if trigger_arn:
                            triggers.append(trigger_name)
                    triggers_str = ', '.join(triggers) if triggers else 'None'

                    # Estimated number of users
                    estimated_users = pool.get('EstimatedNumberOfUsers', 0)

                    regional_pools.append({
                        'Region': region,
                        'Pool Name': pool_name,
                        'Pool ID': pool_id,
                        'ARN': pool_arn,
                        'Status': status,
                        'Created': creation_date,
                        'Last Modified': last_modified,
                        'Estimated Users': estimated_users,
                        'MFA': mfa_config,
                        'Advanced Security': advanced_security,
                        'Min Password Length': min_length,
                        'Require Uppercase': require_uppercase,
                        'Require Lowercase': require_lowercase,
                        'Require Numbers': require_numbers,
                        'Require Symbols': require_symbols,
                        'Temp Password Validity (Days)': temp_password_validity,
                        'Auto Verified Attributes': auto_verified_str,
                        'Username Attributes': username_attrs_str,
                        'Email Sending Account': email_sending,
                        'Email Source ARN': email_source,
                        'SMS Role ARN': sms_role,
                        'Account Recovery': recovery_str,
                        'Device Challenge Required': challenge_required,
                        'Device Only Remembered on Prompt': device_only_remembered,
                        'Attributes Require Verification': attrs_verify_str,
                        'Lambda Triggers': triggers_str
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for pool {pool_id} in {region}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error listing user pools in {region}: {str(e)}")

    utils.log_info(f"Found {len(regional_pools)} user pools in {region}")
    return regional_pools


@utils.aws_error_handler("Collecting Cognito user pools", default_return=[])
def collect_user_pools(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Cognito user pool information from AWS regions using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with user pool information
    """
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_pools = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_user_pools_in_region,
    )

    utils.log_info(f"Collected {len(all_pools)} user pools")
    return all_pools


def scan_identity_pools_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan Cognito identity pools in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with identity pool information from this region
    """
    regional_identity_pools = []
    identity_client = utils.get_boto3_client('cognito-identity', region_name=region)

    try:
        paginator = identity_client.get_paginator('list_identity_pools')
        for page in paginator.paginate(MaxResults=60):
            pools = page.get('IdentityPools', [])

            for pool_summary in pools:
                pool_id = pool_summary.get('IdentityPoolId', 'N/A')

                # Get detailed pool information
                try:
                    pool = identity_client.describe_identity_pool(IdentityPoolId=pool_id)

                    pool_name = pool.get('IdentityPoolName', 'N/A')
                    allow_unauthenticated = pool.get('AllowUnauthenticatedIdentities', False)
                    allow_classic_flow = pool.get('AllowClassicFlow', False)

                    # Supported login providers
                    login_providers = pool.get('SupportedLoginProviders', {})
                    providers_str = ', '.join(login_providers.keys()) if login_providers else 'None'

                    # Cognito identity providers
                    cognito_providers = pool.get('CognitoIdentityProviders', [])
                    cognito_provider_arns = [p.get('ProviderName', 'N/A') for p in cognito_providers]
                    cognito_providers_str = ', '.join(cognito_provider_arns) if cognito_provider_arns else 'None'

                    # SAML providers
                    saml_providers = pool.get('SamlProviderARNs', [])
                    saml_providers_str = ', '.join(saml_providers) if saml_providers else 'None'

                    # OpenID Connect providers
                    oidc_providers = pool.get('OpenIdConnectProviderARNs', [])
                    oidc_providers_str = ', '.join(oidc_providers) if oidc_providers else 'None'

                    # Identity pool tags
                    tags = pool.get('IdentityPoolTags', {})
                    tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'None'

                    regional_identity_pools.append({
                        'Region': region,
                        'Identity Pool Name': pool_name,
                        'Identity Pool ID': pool_id,
                        'Allow Unauthenticated Identities': allow_unauthenticated,
                        'Allow Classic Flow': allow_classic_flow,
                        'Social Login Providers': providers_str,
                        'Cognito User Pool Providers': cognito_providers_str,
                        'SAML Providers': saml_providers_str,
                        'OIDC Providers': oidc_providers_str,
                        'Tags': tags_str
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for identity pool {pool_id} in {region}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error listing identity pools in {region}: {str(e)}")

    utils.log_info(f"Found {len(regional_identity_pools)} identity pools in {region}")
    return regional_identity_pools


@utils.aws_error_handler("Collecting Cognito identity pools", default_return=[])
def collect_identity_pools(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Cognito identity pool (federated identities) information using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with identity pool information
    """
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_identity_pools = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_identity_pools_in_region,
    )

    utils.log_info(f"Collected {len(all_identity_pools)} identity pools")
    return all_identity_pools


def scan_user_pool_clients_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan Cognito user pool clients in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with user pool client information from this region
    """
    regional_clients = []
    cognito_client = utils.get_boto3_client('cognito-idp', region_name=region)

    try:
        # First get all user pools
        pool_paginator = cognito_client.get_paginator('list_user_pools')
        for pool_page in pool_paginator.paginate(MaxResults=60):
            pools = pool_page.get('UserPools', [])

            for pool_summary in pools:
                pool_id = pool_summary.get('Id', 'N/A')
                pool_name = pool_summary.get('Name', 'N/A')

                try:
                    # Get clients for this user pool
                    client_paginator = cognito_client.get_paginator('list_user_pool_clients')
                    for client_page in client_paginator.paginate(UserPoolId=pool_id, MaxResults=60):
                        clients = client_page.get('UserPoolClients', [])

                        for client_summary in clients:
                            client_id = client_summary.get('ClientId', 'N/A')

                            # Get detailed client information
                            try:
                                client_response = cognito_client.describe_user_pool_client(
                                    UserPoolId=pool_id,
                                    ClientId=client_id
                                )
                                client = client_response.get('UserPoolClient', {})

                                client_name = client.get('ClientName', 'N/A')

                                # OAuth flows
                                allowed_oauth_flows = client.get('AllowedOAuthFlows', [])
                                oauth_flows_str = ', '.join(allowed_oauth_flows) if allowed_oauth_flows else 'None'

                                # OAuth scopes
                                allowed_oauth_scopes = client.get('AllowedOAuthScopes', [])
                                oauth_scopes_str = ', '.join(allowed_oauth_scopes) if allowed_oauth_scopes else 'None'

                                # Callback and logout URLs
                                callback_urls = client.get('CallbackURLs', [])
                                callback_str = ', '.join(callback_urls) if callback_urls else 'None'

                                logout_urls = client.get('LogoutURLs', [])
                                logout_str = ', '.join(logout_urls) if logout_urls else 'None'

                                # Authentication flows
                                explicit_auth_flows = client.get('ExplicitAuthFlows', [])
                                auth_flows_str = ', '.join(explicit_auth_flows) if explicit_auth_flows else 'None'

                                # Tokens
                                refresh_token_validity = client.get('RefreshTokenValidity', 'N/A')
                                access_token_validity = client.get('AccessTokenValidity', 'N/A')
                                id_token_validity = client.get('IdTokenValidity', 'N/A')

                                token_validity_units = client.get('TokenValidityUnits', {})
                                refresh_unit = token_validity_units.get('RefreshToken', 'days')
                                access_unit = token_validity_units.get('AccessToken', 'hours')
                                id_unit = token_validity_units.get('IdToken', 'hours')

                                # Read and write attributes
                                read_attributes = client.get('ReadAttributes', [])
                                read_attrs_count = len(read_attributes)

                                write_attributes = client.get('WriteAttributes', [])
                                write_attrs_count = len(write_attributes)

                                # Prevention settings
                                prevent_user_existence = client.get('PreventUserExistenceErrors', 'LEGACY')
                                enable_token_revocation = client.get('EnableTokenRevocation', True)
                                enable_propagate_additional = client.get('EnablePropagateAdditionalUserContextData', False)

                                regional_clients.append({
                                    'Region': region,
                                    'User Pool Name': pool_name,
                                    'User Pool ID': pool_id,
                                    'Client Name': client_name,
                                    'Client ID': client_id,
                                    'OAuth Flows': oauth_flows_str,
                                    'OAuth Scopes': oauth_scopes_str,
                                    'Callback URLs': callback_str,
                                    'Logout URLs': logout_str,
                                    'Explicit Auth Flows': auth_flows_str,
                                    'Refresh Token Validity': f"{refresh_token_validity} {refresh_unit}",
                                    'Access Token Validity': f"{access_token_validity} {access_unit}",
                                    'ID Token Validity': f"{id_token_validity} {id_unit}",
                                    'Read Attributes Count': read_attrs_count,
                                    'Write Attributes Count': write_attrs_count,
                                    'Prevent User Existence Errors': prevent_user_existence,
                                    'Enable Token Revocation': enable_token_revocation,
                                    'Enable Propagate Additional Context': enable_propagate_additional
                                })

                            except Exception as e:
                                utils.log_warning(f"Could not get details for client {client_id}: {str(e)}")
                                continue

                except Exception as e:
                    utils.log_warning(f"Could not list clients for pool {pool_id}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error collecting user pool clients in {region}: {str(e)}")

    utils.log_info(f"Found {len(regional_clients)} user pool clients in {region}")
    return regional_clients


@utils.aws_error_handler("Collecting user pool clients", default_return=[])
def collect_user_pool_clients(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Cognito user pool client (app) information using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with user pool client information
    """
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_clients = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_user_pool_clients_in_region,
    )

    utils.log_info(f"Collected {len(all_clients)} user pool clients")
    return all_clients


def scan_identity_providers_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan Cognito identity providers in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with identity provider information from this region
    """
    regional_providers = []
    cognito_client = utils.get_boto3_client('cognito-idp', region_name=region)

    try:
        # First get all user pools
        pool_paginator = cognito_client.get_paginator('list_user_pools')
        for pool_page in pool_paginator.paginate(MaxResults=60):
            pools = pool_page.get('UserPools', [])

            for pool_summary in pools:
                pool_id = pool_summary.get('Id', 'N/A')
                pool_name = pool_summary.get('Name', 'N/A')

                try:
                    # Get identity providers for this user pool
                    provider_paginator = cognito_client.get_paginator('list_identity_providers')
                    for provider_page in provider_paginator.paginate(UserPoolId=pool_id, MaxResults=60):
                        providers = provider_page.get('Providers', [])

                        for provider_summary in providers:
                            provider_name = provider_summary.get('ProviderName', 'N/A')
                            provider_type = provider_summary.get('ProviderType', 'N/A')

                            # Get detailed provider information
                            try:
                                provider_response = cognito_client.describe_identity_provider(
                                    UserPoolId=pool_id,
                                    ProviderName=provider_name
                                )
                                provider = provider_response.get('IdentityProvider', {})

                                creation_date = provider.get('CreationDate', 'N/A')
                                if creation_date != 'N/A':
                                    creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S')

                                last_modified = provider.get('LastModifiedDate', 'N/A')
                                if last_modified != 'N/A':
                                    last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')

                                # Provider details
                                provider_details = provider.get('ProviderDetails', {})

                                # Extract relevant details based on provider type
                                if provider_type == 'SAML':
                                    metadata_url = provider_details.get('MetadataURL', 'N/A')
                                    metadata_file = provider_details.get('MetadataFile', 'N/A')
                                    if metadata_file != 'N/A':
                                        metadata_file = 'Present (truncated)'
                                    details_str = f"MetadataURL: {metadata_url}, MetadataFile: {metadata_file}"
                                elif provider_type == 'OIDC':
                                    client_id = provider_details.get('client_id', 'N/A')
                                    issuer = provider_details.get('oidc_issuer', 'N/A')
                                    authorize_scopes = provider_details.get('authorize_scopes', 'N/A')
                                    details_str = f"ClientID: {client_id}, Issuer: {issuer}, Scopes: {authorize_scopes}"
                                else:  # Social providers (Facebook, Google, etc.)
                                    client_id = provider_details.get('client_id', 'N/A')
                                    authorize_scopes = provider_details.get('authorize_scopes', 'N/A')
                                    details_str = f"ClientID: {client_id}, Scopes: {authorize_scopes}"

                                # Attribute mapping
                                attribute_mapping = provider.get('AttributeMapping', {})
                                mapping_count = len(attribute_mapping)

                                # ID token providers
                                idp_identifiers = provider.get('IdpIdentifiers', [])
                                idp_ids_str = ', '.join(idp_identifiers) if idp_identifiers else 'None'

                                regional_providers.append({
                                    'Region': region,
                                    'User Pool Name': pool_name,
                                    'User Pool ID': pool_id,
                                    'Provider Name': provider_name,
                                    'Provider Type': provider_type,
                                    'Created': creation_date,
                                    'Last Modified': last_modified,
                                    'Provider Details': details_str,
                                    'Attribute Mappings': mapping_count,
                                    'IDP Identifiers': idp_ids_str
                                })

                            except Exception as e:
                                utils.log_warning(f"Could not get details for provider {provider_name}: {str(e)}")
                                continue

                except Exception as e:
                    utils.log_warning(f"Could not list providers for pool {pool_id}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error collecting identity providers in {region}: {str(e)}")

    utils.log_info(f"Found {len(regional_providers)} identity providers in {region}")
    return regional_providers


@utils.aws_error_handler("Collecting identity providers", default_return=[])
def collect_identity_providers(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Cognito identity provider information (SAML, OIDC, Social) using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with identity provider information
    """
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_providers = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_identity_providers_in_region,
    )

    utils.log_info(f"Collected {len(all_providers)} identity providers")
    return all_providers


def scan_user_pool_groups_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Scan Cognito user pool groups in a single region.

    Args:
        region: AWS region to scan

    Returns:
        list: List of dictionaries with user pool group information from this region
    """
    regional_groups = []
    cognito_client = utils.get_boto3_client('cognito-idp', region_name=region)

    try:
        # First get all user pools
        pool_paginator = cognito_client.get_paginator('list_user_pools')
        for pool_page in pool_paginator.paginate(MaxResults=60):
            pools = pool_page.get('UserPools', [])

            for pool_summary in pools:
                pool_id = pool_summary.get('Id', 'N/A')
                pool_name = pool_summary.get('Name', 'N/A')

                try:
                    # Get groups for this user pool
                    group_paginator = cognito_client.get_paginator('list_groups')
                    for group_page in group_paginator.paginate(UserPoolId=pool_id):
                        groups = group_page.get('Groups', [])

                        for group in groups:
                            group_name = group.get('GroupName', 'N/A')
                            description = group.get('Description', 'N/A')
                            role_arn = group.get('RoleArn', 'N/A')
                            precedence = group.get('Precedence', 'N/A')

                            creation_date = group.get('CreationDate', 'N/A')
                            if creation_date != 'N/A':
                                creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S')

                            last_modified = group.get('LastModifiedDate', 'N/A')
                            if last_modified != 'N/A':
                                last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')

                            regional_groups.append({
                                'Region': region,
                                'User Pool Name': pool_name,
                                'User Pool ID': pool_id,
                                'Group Name': group_name,
                                'Description': description,
                                'IAM Role ARN': role_arn,
                                'Precedence': precedence,
                                'Created': creation_date,
                                'Last Modified': last_modified
                            })

                except Exception as e:
                    utils.log_warning(f"Could not list groups for pool {pool_id}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error collecting user pool groups in {region}: {str(e)}")

    utils.log_info(f"Found {len(regional_groups)} user pool groups in {region}")
    return regional_groups


@utils.aws_error_handler("Collecting user pool groups", default_return=[])
def collect_user_pool_groups(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Cognito user pool group information using concurrent scanning.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with user pool group information
    """
    utils.log_info("Using concurrent region scanning for improved performance")

    # Use concurrent scanning
    all_groups = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=scan_user_pool_groups_in_region,
    )

    utils.log_info(f"Collected {len(all_groups)} user pool groups")
    return all_groups


def generate_summary(user_pools: List[Dict[str, Any]],
                     identity_pools: List[Dict[str, Any]],
                     clients: List[Dict[str, Any]],
                     providers: List[Dict[str, Any]],
                     groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Cognito resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # User pools summary
    total_user_pools = len(user_pools)
    mfa_enabled = sum(1 for p in user_pools if p.get('MFA', 'OFF') != 'OFF')
    advanced_security_enabled = sum(1 for p in user_pools if p.get('Advanced Security', 'OFF') != 'OFF')

    summary.append({
        'Metric': 'Total User Pools',
        'Count': total_user_pools,
        'Details': 'Amazon Cognito User Pools for user authentication'
    })

    summary.append({
        'Metric': 'User Pools with MFA',
        'Count': mfa_enabled,
        'Details': 'Pools with multi-factor authentication enabled'
    })

    summary.append({
        'Metric': 'User Pools with Advanced Security',
        'Count': advanced_security_enabled,
        'Details': 'Pools with advanced security features (risk-based auth, compromised credentials)'
    })

    # Identity pools summary
    total_identity_pools = len(identity_pools)
    allow_unauth = sum(1 for p in identity_pools if p.get('Allow Unauthenticated Identities', False))

    summary.append({
        'Metric': 'Total Identity Pools',
        'Count': total_identity_pools,
        'Details': 'Federated identity pools for AWS credential vending'
    })

    if allow_unauth > 0:
        summary.append({
            'Metric': '⚠️ Identity Pools Allow Unauthenticated',
            'Count': allow_unauth,
            'Details': 'SECURITY: Pools allowing unauthenticated access - review IAM roles'
        })

    # Clients summary
    total_clients = len(clients)
    summary.append({
        'Metric': 'Total User Pool Clients',
        'Count': total_clients,
        'Details': 'Application integrations with user pools'
    })

    # Providers summary
    total_providers = len(providers)
    saml_providers = sum(1 for p in providers if p.get('Provider Type', '') == 'SAML')
    oidc_providers = sum(1 for p in providers if p.get('Provider Type', '') == 'OIDC')
    social_providers = total_providers - saml_providers - oidc_providers

    summary.append({
        'Metric': 'Total Identity Providers',
        'Count': total_providers,
        'Details': f'SAML: {saml_providers}, OIDC: {oidc_providers}, Social: {social_providers}'
    })

    # Groups summary
    total_groups = len(groups)
    summary.append({
        'Metric': 'Total User Pool Groups',
        'Count': total_groups,
        'Details': 'Groups for user organization and role assignment'
    })

    # Regional distribution
    if user_pools:
        df = pd.DataFrame(user_pools)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'User Pools in {region}',
                'Count': count,
                'Details': 'Regional distribution'
            })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    account_id, account_name = utils.print_script_banner("AWS COGNITO EXPORT")
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({utils.mask_account_id(account_id)})")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    # Collect data
    print("\nCollecting Cognito data...")

    user_pools = collect_user_pools(regions)
    identity_pools = collect_identity_pools(regions)
    clients = collect_user_pool_clients(regions)
    providers = collect_identity_providers(regions)
    groups = collect_user_pool_groups(regions)
    summary = generate_summary(user_pools, identity_pools, clients, providers, groups)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if user_pools:
        df_user_pools = pd.DataFrame(user_pools)
        df_user_pools = utils.prepare_dataframe_for_export(df_user_pools)
        dataframes['User Pools'] = df_user_pools

    if identity_pools:
        df_identity_pools = pd.DataFrame(identity_pools)
        df_identity_pools = utils.prepare_dataframe_for_export(df_identity_pools)
        dataframes['Identity Pools'] = df_identity_pools

    if clients:
        df_clients = pd.DataFrame(clients)
        df_clients = utils.prepare_dataframe_for_export(df_clients)
        dataframes['User Pool Clients'] = df_clients

    if providers:
        df_providers = pd.DataFrame(providers)
        df_providers = utils.prepare_dataframe_for_export(df_providers)
        dataframes['Identity Providers'] = df_providers

    if groups:
        df_groups = pd.DataFrame(groups)
        df_groups = utils.prepare_dataframe_for_export(df_groups)
        dataframes['User Pool Groups'] = df_groups

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'cognito', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'User Pools': len(user_pools),
            'Identity Pools': len(identity_pools),
            'User Pool Clients': len(clients),
            'Identity Providers': len(providers),
            'User Pool Groups': len(groups)
        })
    else:
        utils.log_warning("No Cognito data found to export")

    utils.log_success("Cognito export completed successfully")


if __name__ == "__main__":
    main()

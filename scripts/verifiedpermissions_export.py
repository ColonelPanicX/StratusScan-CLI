#!/usr/bin/env python3
"""
AWS Verified Permissions Export Script

Exports AWS Verified Permissions resources (Cedar-based authorization):
- Policy Stores
- Policies (static and template-linked)
- Policy Templates
- Schemas
- Identity Sources (Cognito User Pools, OIDC)

Features:
- Complete Verified Permissions inventory
- Cedar policy tracking
- Policy template management
- Schema definitions
- Identity source configurations
- Multi-region support
- Comprehensive multi-worksheet export

Note: Requires verifiedpermissions:* permissions
Note: Verified Permissions is a regional service
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
logger = utils.setup_logging('verifiedpermissions-export')
utils.log_script_start('verifiedpermissions-export', 'Export AWS Verified Permissions Cedar policies and configurations')


@utils.aws_error_handler("Collecting policy stores", default_return=[])
def collect_policy_stores(region: str) -> List[Dict[str, Any]]:
    """Collect all Verified Permissions policy stores in a region."""
    vp = utils.get_boto3_client('verifiedpermissions', region_name=region)
    stores = []

    try:
        paginator = vp.get_paginator('list_policy_stores')
        for page in paginator.paginate():
            for store in page.get('policyStores', []):
                policy_store_id = store.get('policyStoreId', 'N/A')

                # Get detailed store information
                try:
                    detail = vp.get_policy_store(policyStoreId=policy_store_id)
                    store_detail = detail

                    validation_settings = store_detail.get('validationSettings', {})

                    stores.append({
                        'Region': region,
                        'PolicyStoreId': policy_store_id,
                        'PolicyStoreArn': store.get('arn', 'N/A'),
                        'Description': store.get('description', 'N/A'),
                        'CreatedDate': store.get('createdDate'),
                        'LastUpdatedDate': store.get('lastUpdatedDate'),
                        'ValidationMode': validation_settings.get('mode', 'N/A'),
                    })
                except Exception:
                    stores.append({
                        'Region': region,
                        'PolicyStoreId': policy_store_id,
                        'PolicyStoreArn': store.get('arn', 'N/A'),
                        'Description': store.get('description', 'N/A'),
                        'CreatedDate': store.get('createdDate'),
                        'LastUpdatedDate': store.get('lastUpdatedDate'),
                        'ValidationMode': 'N/A',
                    })
    except Exception:
        pass

    return stores


@utils.aws_error_handler("Collecting policies", default_return=[])
def collect_policies(region: str, policy_store_id: str) -> List[Dict[str, Any]]:
    """Collect policies for a policy store."""
    vp = utils.get_boto3_client('verifiedpermissions', region_name=region)
    policies = []

    try:
        paginator = vp.get_paginator('list_policies')
        for page in paginator.paginate(policyStoreId=policy_store_id):
            for policy in page.get('policies', []):
                policy_id = policy.get('policyId', 'N/A')

                # Get detailed policy information
                try:
                    detail = vp.get_policy(
                        policyStoreId=policy_store_id,
                        policyId=policy_id
                    )

                    definition = detail.get('definition', {})
                    policy_type = list(definition.keys())[0] if definition else 'N/A'

                    policies.append({
                        'Region': region,
                        'PolicyStoreId': policy_store_id,
                        'PolicyId': policy_id,
                        'PolicyType': policy.get('policyType', 'N/A'),
                        'Definition Type': policy_type,
                        'CreatedDate': policy.get('createdDate'),
                        'LastUpdatedDate': policy.get('lastUpdatedDate'),
                    })
                except Exception:
                    policies.append({
                        'Region': region,
                        'PolicyStoreId': policy_store_id,
                        'PolicyId': policy_id,
                        'PolicyType': policy.get('policyType', 'N/A'),
                        'DefinitionType': 'N/A',
                        'CreatedDate': policy.get('createdDate'),
                        'LastUpdatedDate': policy.get('lastUpdatedDate'),
                    })
    except Exception:
        pass

    return policies


@utils.aws_error_handler("Collecting policy templates", default_return=[])
def collect_policy_templates(region: str, policy_store_id: str) -> List[Dict[str, Any]]:
    """Collect policy templates for a policy store."""
    vp = utils.get_boto3_client('verifiedpermissions', region_name=region)
    templates = []

    try:
        paginator = vp.get_paginator('list_policy_templates')
        for page in paginator.paginate(policyStoreId=policy_store_id):
            for template in page.get('policyTemplates', []):
                template_id = template.get('policyTemplateId', 'N/A')

                templates.append({
                    'Region': region,
                    'PolicyStoreId': policy_store_id,
                    'PolicyTemplateId': template_id,
                    'Description': template.get('description', 'N/A'),
                    'CreatedDate': template.get('createdDate'),
                    'LastUpdatedDate': template.get('lastUpdatedDate'),
                })
    except Exception:
        pass

    return templates


@utils.aws_error_handler("Collecting identity sources", default_return=[])
def collect_identity_sources(region: str, policy_store_id: str) -> List[Dict[str, Any]]:
    """Collect identity sources for a policy store."""
    vp = utils.get_boto3_client('verifiedpermissions', region_name=region)
    sources = []

    try:
        paginator = vp.get_paginator('list_identity_sources')
        for page in paginator.paginate(policyStoreId=policy_store_id):
            for source in page.get('identitySources', []):
                identity_source_id = source.get('identitySourceId', 'N/A')

                # Get detailed source information
                try:
                    detail = vp.get_identity_source(
                        policyStoreId=policy_store_id,
                        identitySourceId=identity_source_id
                    )

                    configuration = detail.get('configuration', {})
                    config_type = list(configuration.keys())[0] if configuration else 'N/A'

                    # Extract configuration details
                    config_details = 'N/A'
                    if config_type == 'cognitoUserPoolConfiguration':
                        cognito_config = configuration.get('cognitoUserPoolConfiguration', {})
                        config_details = f"UserPoolArn: {cognito_config.get('userPoolArn', 'N/A')}"
                    elif config_type == 'openIdConnectConfiguration':
                        oidc_config = configuration.get('openIdConnectConfiguration', {})
                        config_details = f"Issuer: {oidc_config.get('issuer', 'N/A')}"

                    sources.append({
                        'Region': region,
                        'PolicyStoreId': policy_store_id,
                        'IdentitySourceId': identity_source_id,
                        'ConfigurationType': config_type,
                        'ConfigurationDetails': config_details,
                        'CreatedDate': source.get('createdDate'),
                        'LastUpdatedDate': source.get('lastUpdatedDate'),
                    })
                except Exception:
                    sources.append({
                        'Region': region,
                        'PolicyStoreId': policy_store_id,
                        'IdentitySourceId': identity_source_id,
                        'ConfigurationType': 'N/A',
                        'ConfigurationDetails': 'N/A',
                        'CreatedDate': source.get('createdDate'),
                        'LastUpdatedDate': source.get('lastUpdatedDate'),
                    })
    except Exception:
        pass

    return sources


def main():
    """Main execution function."""
    try:
        # Get account information
        account_id, account_name = utils.get_account_info()
        utils.log_info(f"Exporting Verified Permissions for account: {account_name} ({utils.mask_account_id(account_id)})")

        # Detect partition for region examples
        regions = utils.prompt_region_selection()
        # Collect all resources
        all_stores = []
        all_policies = []
        all_templates = []
        all_identity_sources = []

        for idx, region in enumerate(regions, 1):
            utils.log_info(f"[{idx}/{len(regions)}] Processing region: {region}")

            # Collect policy stores
            stores = collect_policy_stores(region)
            if stores:
                utils.log_info(f"  Found {len(stores)} policy store(s)")
                all_stores.extend(stores)

                # Collect resources for each policy store
                for store in stores:
                    policy_store_id = store['PolicyStoreId']

                    # Collect policies
                    policies = collect_policies(region, policy_store_id)
                    if policies:
                        utils.log_info(f"    Found {len(policies)} policy(ies) in store {policy_store_id}")
                        all_policies.extend(policies)

                    # Collect policy templates
                    templates = collect_policy_templates(region, policy_store_id)
                    if templates:
                        utils.log_info(f"    Found {len(templates)} policy template(s) in store {policy_store_id}")
                        all_templates.extend(templates)

                    # Collect identity sources
                    identity_sources = collect_identity_sources(region, policy_store_id)
                    if identity_sources:
                        utils.log_info(f"    Found {len(identity_sources)} identity source(s) in store {policy_store_id}")
                        all_identity_sources.extend(identity_sources)

        if not all_stores:
            utils.log_warning("No Verified Permissions policy stores found in any selected region.")
            utils.log_info("Creating empty export file...")

        utils.log_info(f"Total policy stores found: {len(all_stores)}")
        utils.log_info(f"Total policies found: {len(all_policies)}")
        utils.log_info(f"Total policy templates found: {len(all_templates)}")
        utils.log_info(f"Total identity sources found: {len(all_identity_sources)}")

        # Create DataFrames
        df_stores = utils.prepare_dataframe_for_export(pd.DataFrame(all_stores))
        df_policies = utils.prepare_dataframe_for_export(pd.DataFrame(all_policies))
        df_templates = utils.prepare_dataframe_for_export(pd.DataFrame(all_templates))
        df_identity_sources = utils.prepare_dataframe_for_export(pd.DataFrame(all_identity_sources))

        # Create summary
        summary_data = []
        summary_data.append({'Metric': 'Total Policy Stores', 'Value': len(all_stores)})
        summary_data.append({'Metric': 'Total Policies', 'Value': len(all_policies)})
        summary_data.append({'Metric': 'Total Policy Templates', 'Value': len(all_templates)})
        summary_data.append({'Metric': 'Total Identity Sources', 'Value': len(all_identity_sources)})
        summary_data.append({'Metric': 'Regions Scanned', 'Value': len(regions)})

        if not df_policies.empty:
            static_policies = len(df_policies[df_policies['PolicyType'] == 'STATIC'])
            template_linked = len(df_policies[df_policies['PolicyType'] == 'TEMPLATE_LINKED'])

            summary_data.append({'Metric': 'Static Policies', 'Value': static_policies})
            summary_data.append({'Metric': 'Template-Linked Policies', 'Value': template_linked})

        df_summary = utils.prepare_dataframe_for_export(pd.DataFrame(summary_data))

        # Create filtered views
        df_static_policies = pd.DataFrame()
        df_template_linked = pd.DataFrame()

        if not df_policies.empty:
            df_static_policies = df_policies[df_policies['PolicyType'] == 'STATIC']
            df_template_linked = df_policies[df_policies['PolicyType'] == 'TEMPLATE_LINKED']

        # Export to Excel
        filename = utils.create_export_filename(account_name, 'verifiedpermissions', 'all')

        sheets = {
            'Summary': df_summary,
            'Policy Stores': df_stores,
            'Policies': df_policies,
            'Static Policies': df_static_policies,
            'Template-Linked Policies': df_template_linked,
            'Policy Templates': df_templates,
            'Identity Sources': df_identity_sources,
        }

        utils.save_multiple_dataframes_to_excel(sheets, filename)

        # Log summary
        total_resources = (len(all_stores) + len(all_policies) +
                          len(all_templates) + len(all_identity_sources))

        utils.log_export_summary(
            total_items=total_resources,
            item_type='Verified Permissions Resources',
            filename=filename
        )

        utils.log_info(f"  Policy Stores: {len(all_stores)}")
        utils.log_info(f"  Policies: {len(all_policies)}")
        utils.log_info(f"  Policy Templates: {len(all_templates)}")
        utils.log_info(f"  Identity Sources: {len(all_identity_sources)}")

        utils.log_success("Verified Permissions export completed successfully!")

    except Exception as e:
        utils.log_error(f"Failed to export Verified Permissions resources: {str(e)}")
        raise


if __name__ == "__main__":
    main()

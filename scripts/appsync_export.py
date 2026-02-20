#!/usr/bin/env python3
"""
AWS AppSync Export Script for StratusScan

Exports comprehensive AWS AppSync GraphQL API information including APIs,
data sources, resolvers, and API keys.

Features:
- GraphQL APIs: API configurations, authentication, and endpoints
- Data Sources: DynamoDB, Lambda, HTTP, RDS, OpenSearch connections
- Resolvers: Field resolvers with request/response mappings
- API Keys: Active API keys with expiration dates
- Summary: API counts, authentication methods, and metrics

Output: Excel file with 5 worksheets
"""

import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
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

try:
    import pandas as pd
except ImportError:
    utils.log_error("pandas library is required but not installed")
    utils.log_error("Install with: pip install pandas")
    sys.exit(1)


def _scan_graphql_apis_region(region: str) -> List[Dict[str, Any]]:
    """Scan AppSync GraphQL APIs in a single region."""
    regional_apis = []

    try:
        appsync_client = utils.get_boto3_client('appsync', region_name=region)
        paginator = appsync_client.get_paginator('list_graphql_apis')
        for page in paginator.paginate():
            apis = page.get('graphqlApis', [])

            for api in apis:
                api_id = api.get('apiId', 'N/A')
                name = api.get('name', 'N/A')
                authentication_type = api.get('authenticationType', 'N/A')

                # Endpoint URLs
                uris = api.get('uris', {})
                graphql_url = uris.get('GRAPHQL', 'N/A') if uris else 'N/A'
                realtime_url = uris.get('REALTIME', 'N/A') if uris else 'N/A'

                # ARN
                arn = api.get('arn', 'N/A')

                # X-Ray tracing
                xray_enabled = api.get('xrayEnabled', False)

                # WAF Web ACL ARN
                waf_web_acl_arn = api.get('wafWebAclArn', 'N/A')

                # Additional authentication providers
                additional_auth_providers = api.get('additionalAuthenticationProviders', [])
                additional_auth_types = [provider.get('authenticationType', '')
                                        for provider in additional_auth_providers]
                additional_auth_str = ', '.join(additional_auth_types) if additional_auth_types else 'None'

                # Log config
                log_config = api.get('logConfig', {})
                logging_enabled = bool(log_config)
                field_log_level = log_config.get('fieldLogLevel', 'NONE') if log_config else 'NONE'
                cloudwatch_logs_role_arn = log_config.get('cloudWatchLogsRoleArn', 'N/A') if log_config else 'N/A'

                # Extract role name
                log_role_name = 'N/A'
                if cloudwatch_logs_role_arn != 'N/A' and '/' in cloudwatch_logs_role_arn:
                    log_role_name = cloudwatch_logs_role_arn.split('/')[-1]

                # User pool config (for Cognito auth)
                user_pool_config = api.get('userPoolConfig', {})
                user_pool_id = user_pool_config.get('userPoolId', 'N/A') if user_pool_config else 'N/A'

                # OpenID Connect config
                openid_connect_config = api.get('openIDConnectConfig', {})
                oidc_issuer = openid_connect_config.get('issuer', 'N/A') if openid_connect_config else 'N/A'

                # Tags
                tags = api.get('tags', {})
                tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'None'

                regional_apis.append({
                    'Region': region,
                    'API Name': name,
                    'API ID': api_id,
                    'Authentication Type': authentication_type,
                    'Additional Auth': additional_auth_str,
                    'GraphQL Endpoint': graphql_url,
                    'Realtime Endpoint': realtime_url,
                    'X-Ray Tracing': 'Enabled' if xray_enabled else 'Disabled',
                    'Logging': field_log_level,
                    'Log Role': log_role_name,
                    'WAF Web ACL': 'Associated' if waf_web_acl_arn != 'N/A' else 'None',
                    'Cognito User Pool': user_pool_id,
                    'OIDC Issuer': oidc_issuer,
                    'Tags': tags_str,
                    'ARN': arn,
                })

    except Exception as e:
        utils.log_error(f"Error collecting AppSync GraphQL APIs in {region}", e)

    return regional_apis


@utils.aws_error_handler("Collecting AppSync GraphQL APIs", default_return=[])
def collect_graphql_apis(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect AppSync GraphQL API information from AWS regions."""
    print("\n=== COLLECTING APPSYNC GRAPHQL APIS ===")
    results = utils.scan_regions_concurrent(regions, _scan_graphql_apis_region)
    all_apis = [api for result in results for api in result]
    utils.log_success(f"Total AppSync GraphQL APIs collected: {len(all_apis)}")
    return all_apis


@utils.aws_error_handler("Collecting AppSync data sources", default_return=[])
def collect_data_sources(regions: List[str], apis: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collect AppSync data source information from AWS regions."""
    all_data_sources = []

    for region in regions:
        utils.log_info(f"Scanning AppSync data sources in {region}...")
        appsync_client = utils.get_boto3_client('appsync', region_name=region)

        # Get data sources for each API
        region_apis = [api for api in apis if api['Region'] == region]

        for api in region_apis:
            api_id = api['API ID']
            api_name = api['API Name']

            try:
                paginator = appsync_client.get_paginator('list_data_sources')
                for page in paginator.paginate(apiId=api_id):
                    data_sources = page.get('dataSources', [])

                    for ds in data_sources:
                        ds_name = ds.get('name', 'N/A')
                        ds_type = ds.get('type', 'N/A')
                        description = ds.get('description', 'N/A')

                        # Type-specific configuration
                        type_details = 'N/A'

                        if ds_type == 'AMAZON_DYNAMODB':
                            dynamodb_config = ds.get('dynamodbConfig', {})
                            table_name = dynamodb_config.get('tableName', 'N/A')
                            type_details = f"Table: {table_name}"

                        elif ds_type == 'AWS_LAMBDA':
                            lambda_config = ds.get('lambdaConfig', {})
                            lambda_arn = lambda_config.get('lambdaFunctionArn', 'N/A')
                            if lambda_arn != 'N/A' and ':' in lambda_arn:
                                function_name = lambda_arn.split(':')[-1]
                                type_details = f"Function: {function_name}"

                        elif ds_type == 'AMAZON_ELASTICSEARCH' or ds_type == 'AMAZON_OPENSEARCH_SERVICE':
                            es_config = ds.get('elasticsearchConfig') or ds.get('openSearchServiceConfig', {})
                            endpoint = es_config.get('endpoint', 'N/A')
                            type_details = f"Endpoint: {endpoint}"

                        elif ds_type == 'HTTP':
                            http_config = ds.get('httpConfig', {})
                            endpoint = http_config.get('endpoint', 'N/A')
                            type_details = f"Endpoint: {endpoint}"

                        elif ds_type == 'RELATIONAL_DATABASE':
                            rds_config = ds.get('relationalDatabaseConfig', {})
                            rds_http_endpoint_config = rds_config.get('rdsHttpEndpointConfig', {})
                            db_cluster_identifier = rds_http_endpoint_config.get('dbClusterIdentifier', 'N/A')
                            type_details = f"Cluster: {db_cluster_identifier}"

                        # Service role ARN
                        service_role_arn = ds.get('serviceRoleArn', 'N/A')
                        role_name = 'N/A'
                        if service_role_arn != 'N/A' and '/' in service_role_arn:
                            role_name = service_role_arn.split('/')[-1]

                        all_data_sources.append({
                            'Region': region,
                            'API Name': api_name,
                            'Data Source Name': ds_name,
                            'Type': ds_type,
                            'Type Details': type_details,
                            'Service Role': role_name,
                            'Description': description,
                        })

            except Exception as e:
                utils.log_warning(f"Could not get data sources for API {api_name}: {str(e)}")
                continue

        utils.log_success(f"Collected {len([ds for ds in all_data_sources if ds['Region'] == region])} AppSync data sources from {region}")

    return all_data_sources


@utils.aws_error_handler("Collecting AppSync resolvers", default_return=[])
def collect_resolvers(regions: List[str], apis: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collect AppSync resolver information from AWS regions (limited sample)."""
    all_resolvers = []

    for region in regions:
        utils.log_info(f"Scanning AppSync resolvers in {region}...")
        appsync_client = utils.get_boto3_client('appsync', region_name=region)

        # Get resolvers for each API (limit to reduce data volume)
        region_apis = [api for api in apis if api['Region'] == region]

        for api in region_apis:
            api_id = api['API ID']
            api_name = api['API Name']

            try:
                # Get list of types first
                types_response = appsync_client.list_types(apiId=api_id, format='SDL')
                type_definitions = types_response.get('types', [])

                resolver_count = 0
                for type_def in type_definitions:
                    type_name = type_def.get('name', '')

                    # Only get resolvers for Query and Mutation types (to limit volume)
                    if type_name in ['Query', 'Mutation']:
                        try:
                            resolvers_response = appsync_client.list_resolvers(apiId=api_id, typeName=type_name)
                            resolvers = resolvers_response.get('resolvers', [])

                            for resolver in resolvers:
                                field_name = resolver.get('fieldName', 'N/A')
                                data_source_name = resolver.get('dataSourceName', 'N/A')
                                kind = resolver.get('kind', 'N/A')  # UNIT or PIPELINE

                                # Pipeline config (for PIPELINE resolvers)
                                pipeline_config = resolver.get('pipelineConfig', {})
                                functions = pipeline_config.get('functions', [])
                                function_count = len(functions)

                                # Sync config
                                sync_config = resolver.get('syncConfig', {})
                                conflict_handler = sync_config.get('conflictHandler', 'N/A') if sync_config else 'N/A'

                                # Caching config
                                caching_config = resolver.get('cachingConfig', {})
                                caching_ttl = caching_config.get('ttl', 'N/A') if caching_config else 'N/A'

                                all_resolvers.append({
                                    'Region': region,
                                    'API Name': api_name,
                                    'Type': type_name,
                                    'Field': field_name,
                                    'Kind': kind,
                                    'Data Source': data_source_name,
                                    'Pipeline Functions': function_count if kind == 'PIPELINE' else 0,
                                    'Conflict Handler': conflict_handler,
                                    'Caching TTL': caching_ttl,
                                })

                                resolver_count += 1
                                if resolver_count >= 50:  # Limit to 50 resolvers per API
                                    break

                        except Exception as e:
                            utils.log_warning(f"Could not get resolvers for type {type_name}: {str(e)}")
                            continue

                    if resolver_count >= 50:
                        break

            except Exception as e:
                utils.log_warning(f"Could not get resolvers for API {api_name}: {str(e)}")
                continue

        utils.log_success(f"Collected {len([r for r in all_resolvers if r['Region'] == region])} AppSync resolvers from {region}")

    return all_resolvers


@utils.aws_error_handler("Collecting AppSync API keys", default_return=[])
def collect_api_keys(regions: List[str], apis: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collect AppSync API key information from AWS regions."""
    all_api_keys = []

    for region in regions:
        utils.log_info(f"Scanning AppSync API keys in {region}...")
        appsync_client = utils.get_boto3_client('appsync', region_name=region)

        # Get API keys for each API
        region_apis = [api for api in apis if api['Region'] == region]

        for api in region_apis:
            api_id = api['API ID']
            api_name = api['API Name']

            try:
                paginator = appsync_client.get_paginator('list_api_keys')
                for page in paginator.paginate(apiId=api_id):
                    api_keys = page.get('apiKeys', [])

                    for key in api_keys:
                        key_id = key.get('id', 'N/A')
                        description = key.get('description', 'N/A')

                        # Expiration
                        expires = key.get('expires')
                        if expires:
                            expires_dt = datetime.fromtimestamp(expires)
                            expires_str = expires_dt.strftime('%Y-%m-%d %H:%M:%S')

                            # Check if expired
                            now = datetime.now()
                            if expires_dt < now:
                                status = 'Expired'
                            else:
                                days_until_expiry = (expires_dt - now).days
                                status = f"Active ({days_until_expiry} days remaining)"
                        else:
                            expires_str = 'N/A'
                            status = 'Active'

                        # Deletes timestamp
                        deletes = key.get('deletes')
                        if deletes:
                            deletes_dt = datetime.fromtimestamp(deletes)
                            deletes_str = deletes_dt.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            deletes_str = 'N/A'

                        all_api_keys.append({
                            'Region': region,
                            'API Name': api_name,
                            'Key ID': key_id,
                            'Description': description,
                            'Status': status,
                            'Expires': expires_str,
                            'Deletes': deletes_str,
                        })

            except Exception as e:
                utils.log_warning(f"Could not get API keys for API {api_name}: {str(e)}")
                continue

        utils.log_success(f"Collected {len([k for k in all_api_keys if k['Region'] == region])} AppSync API keys from {region}")

    return all_api_keys


def generate_summary(apis: List[Dict[str, Any]],
                     data_sources: List[Dict[str, Any]],
                     resolvers: List[Dict[str, Any]],
                     api_keys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for AppSync resources."""
    summary = []

    # Overall counts
    summary.append({
        'Metric': 'Total GraphQL APIs',
        'Count': len(apis),
        'Details': f"{len(apis)} AppSync GraphQL APIs"
    })

    summary.append({
        'Metric': 'Total Data Sources',
        'Count': len(data_sources),
        'Details': f"{len(data_sources)} data sources across all APIs"
    })

    summary.append({
        'Metric': 'Total Resolvers (Sample)',
        'Count': len(resolvers),
        'Details': f"{len(resolvers)} Query/Mutation resolvers (limited sample)"
    })

    summary.append({
        'Metric': 'Total API Keys',
        'Count': len(api_keys),
        'Details': f"{len(api_keys)} API keys across all APIs"
    })

    # Authentication types
    if apis:
        auth_types = {}
        for api in apis:
            auth_type = api['Authentication Type']
            auth_types[auth_type] = auth_types.get(auth_type, 0) + 1

        auth_details = ', '.join([f"{auth}: {count}" for auth, count in sorted(auth_types.items())])
        summary.append({
            'Metric': 'Authentication Types',
            'Count': len(auth_types),
            'Details': auth_details
        })

    # X-Ray tracing
    if apis:
        xray_enabled = len([api for api in apis if api['X-Ray Tracing'] == 'Enabled'])
        summary.append({
            'Metric': 'X-Ray Tracing Enabled',
            'Count': xray_enabled,
            'Details': f"{xray_enabled}/{len(apis)} APIs with X-Ray tracing"
        })

    # Data source types
    if data_sources:
        ds_types = {}
        for ds in data_sources:
            ds_type = ds['Type']
            ds_types[ds_type] = ds_types.get(ds_type, 0) + 1

        ds_type_details = ', '.join([f"{dstype}: {count}" for dstype, count in sorted(ds_types.items())])
        summary.append({
            'Metric': 'Data Source Types',
            'Count': len(ds_types),
            'Details': ds_type_details
        })

    # Resolver kinds
    if resolvers:
        resolver_kinds = {}
        for resolver in resolvers:
            kind = resolver['Kind']
            resolver_kinds[kind] = resolver_kinds.get(kind, 0) + 1

        kind_details = ', '.join([f"{kind}: {count}" for kind, count in sorted(resolver_kinds.items())])
        summary.append({
            'Metric': 'Resolver Kinds',
            'Count': len(resolver_kinds),
            'Details': kind_details
        })

    # APIs by region
    if apis:
        regions = {}
        for api in apis:
            region = api['Region']
            regions[region] = regions.get(region, 0) + 1

        region_details = ', '.join([f"{region}: {count}" for region, count in sorted(regions.items())])
        summary.append({
            'Metric': 'APIs by Region',
            'Count': len(regions),
            'Details': region_details
        })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    # Check dependencies
    if not utils.check_dependencies(['pandas', 'openpyxl', 'boto3']):
        utils.log_error("Required dependencies not installed")
        return

    # Get account information
    account_id, account_name = utils.get_account_info()
    utils.log_info(f"Account: {account_name} ({account_id})")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    # Collect data
    print("\n=== Collecting AppSync Data ===")
    apis = collect_graphql_apis(regions)
    data_sources = collect_data_sources(regions, apis)
    resolvers = collect_resolvers(regions, apis)
    api_keys = collect_api_keys(regions, apis)

    # Generate summary
    summary = generate_summary(apis, data_sources, resolvers, api_keys)

    # Convert to DataFrames
    apis_df = pd.DataFrame(apis) if apis else pd.DataFrame()
    data_sources_df = pd.DataFrame(data_sources) if data_sources else pd.DataFrame()
    resolvers_df = pd.DataFrame(resolvers) if resolvers else pd.DataFrame()
    api_keys_df = pd.DataFrame(api_keys) if api_keys else pd.DataFrame()
    summary_df = pd.DataFrame(summary)

    # Prepare DataFrames for export
    if not apis_df.empty:
        apis_df = utils.prepare_dataframe_for_export(apis_df)
    if not data_sources_df.empty:
        data_sources_df = utils.prepare_dataframe_for_export(data_sources_df)
    if not resolvers_df.empty:
        resolvers_df = utils.prepare_dataframe_for_export(resolvers_df)
    if not api_keys_df.empty:
        api_keys_df = utils.prepare_dataframe_for_export(api_keys_df)
    if not summary_df.empty:
        summary_df = utils.prepare_dataframe_for_export(summary_df)

    # Create export filename
    region_suffix = regions[0] if len(regions) == 1 else 'all-regions'
    filename = utils.create_export_filename(account_name, 'appsync', region_suffix)

    # Save to Excel with multiple sheets
    print("\n=== Exporting to Excel ===")
    dataframes = {
        'GraphQL APIs': apis_df,
        'Data Sources': data_sources_df,
        'Resolvers': resolvers_df,
        'API Keys': api_keys_df,
        'Summary': summary_df
    }

    if utils.save_multiple_dataframes_to_excel(dataframes, filename):
        utils.log_export_summary(
            filename=filename,
            total_items=len(apis) + len(data_sources) + len(resolvers) + len(api_keys),
            details={
                'GraphQL APIs': len(apis),
                'Data Sources': len(data_sources),
                'Resolvers': len(resolvers),
                'API Keys': len(api_keys)
            }
        )

    utils.log_script_end(script_name)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AWS Glue & Athena Export Script for StratusScan

Exports comprehensive AWS Glue (ETL) and Athena (SQL query) service information
including databases, tables, crawlers, jobs, data catalogs, and Athena workgroups.

Features:
- Glue Databases: Data catalog databases with location URIs
- Glue Tables: Schema definitions, partitions, storage formats
- Glue Crawlers: Data discovery configurations and schedules
- Glue Jobs: ETL job definitions, connections, and triggers
- Athena Workgroups: Query execution environments and settings
- Athena Data Catalogs: External catalog connections
- Summary: Resource counts and key metrics

Output: Excel file with 7 worksheets
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


def _scan_glue_databases_region(region: str) -> List[Dict[str, Any]]:
    """Scan Glue databases in a single region."""
    regional_databases = []

    try:
        glue_client = utils.get_boto3_client('glue', region_name=region)
        paginator = glue_client.get_paginator('get_databases')
        for page in paginator.paginate():
            databases = page.get('DatabaseList', [])

            for db in databases:
                db_name = db.get('Name', 'N/A')
                description = db.get('Description', 'N/A')
                location_uri = db.get('LocationUri', 'N/A')

                # Creation time
                create_time = db.get('CreateTime')
                if create_time:
                    create_time_str = create_time.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    create_time_str = 'N/A'

                # Catalog ID
                catalog_id = db.get('CatalogId', 'N/A')

                regional_databases.append({
                    'Region': region,
                    'Database Name': db_name,
                    'Description': description,
                    'Location URI': location_uri,
                    'Catalog ID': catalog_id,
                    'Created': create_time_str,
                })

    except Exception as e:
        utils.log_error(f"Error collecting Glue databases in {region}", e)

    return regional_databases


@utils.aws_error_handler("Collecting Glue databases", default_return=[])
def collect_glue_databases(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect AWS Glue database information from AWS regions."""
    print("\n=== COLLECTING GLUE DATABASES ===")
    results = utils.scan_regions_concurrent(regions, _scan_glue_databases_region)
    all_databases = [db for result in results for db in result]
    utils.log_success(f"Total Glue databases collected: {len(all_databases)}")
    return all_databases



def _scan_glue_tables_region(region: str) -> List[Dict[str, Any]]:
    """Scan Glue tables in a single region."""
    regional_tables = []
    try:
        glue_client = utils.get_boto3_client('glue', region_name=region)
        try:
            databases_response = glue_client.get_databases()
            databases = databases_response.get('DatabaseList', [])
        except Exception as e:
            utils.log_warning(f"Could not list databases in {region}: {str(e)}")
            return regional_tables
        for db in databases:
            db_name = db.get('Name', '')
            try:
                paginator = glue_client.get_paginator('get_tables')
                for page in paginator.paginate(DatabaseName=db_name):
                    tables = page.get('TableList', [])
                    for table in tables:
                        table_name = table.get('Name', 'N/A')
                        description = table.get('Description', 'N/A')
                        storage_descriptor = table.get('StorageDescriptor', {})
                        location = storage_descriptor.get('Location', 'N/A')
                        input_format = storage_descriptor.get('InputFormat', 'N/A')
                        output_format = storage_descriptor.get('OutputFormat', 'N/A')
                        serde_info = storage_descriptor.get('SerdeInfo', {})
                        serialization_library = serde_info.get('SerializationLibrary', 'N/A')
                        columns = storage_descriptor.get('Columns', [])
                        column_count = len(columns)
                        partition_keys = table.get('PartitionKeys', [])
                        partition_count = len(partition_keys)
                        partition_names = [pk.get('Name', '') for pk in partition_keys]
                        partition_names_str = ', '.join(partition_names) if partition_names else 'None'
                        table_type = table.get('TableType', 'N/A')
                        create_time = table.get('CreateTime')
                        create_time_str = create_time.strftime('%Y-%m-%d %H:%M:%S') if create_time else 'N/A'
                        update_time = table.get('UpdateTime')
                        update_time_str = update_time.strftime('%Y-%m-%d %H:%M:%S') if update_time else 'N/A'
                        regional_tables.append({'Region': region, 'Database': db_name, 'Table Name': table_name, 'Description': description, 'Table Type': table_type, 'Location': location, 'Column Count': column_count, 'Partition Keys': partition_names_str, 'Partition Count': partition_count, 'Input Format': input_format, 'Output Format': output_format, 'Serialization Library': serialization_library, 'Created': create_time_str, 'Updated': update_time_str})
            except Exception as e:
                utils.log_warning(f"Could not get tables for database {db_name}: {str(e)}")
    except Exception as e:
        utils.log_error(f"Error collecting Glue tables in {region}", e)
    return regional_tables


def _scan_glue_crawlers_region(region: str) -> List[Dict[str, Any]]:
    """Scan Glue crawlers in a single region."""
    regional_crawlers = []
    try:
        glue_client = utils.get_boto3_client('glue', region_name=region)
        paginator = glue_client.get_paginator('get_crawlers')
        for page in paginator.paginate():
            for crawler in page.get('Crawlers', []):
                role = crawler.get('Role', 'N/A')
                if role != 'N/A' and '/' in role:
                    role = role.split('/')[-1]
                targets = crawler.get('Targets', {})
                s3_targets = targets.get('S3Targets', [])
                s3_paths = [t.get('Path', '') for t in s3_targets]
                s3_paths_str = ', '.join(s3_paths[:3]) if s3_paths else 'None'
                if len(s3_paths) > 3:
                    s3_paths_str += f' (+{len(s3_paths) - 3} more)'
                schedule = crawler.get('Schedule', {})
                classifiers = crawler.get('Classifiers', [])
                schema_change_policy = crawler.get('SchemaChangePolicy', {})
                recrawl_policy = crawler.get('RecrawlPolicy', {})
                last_crawl = crawler.get('LastCrawl', {})
                creation_time = crawler.get('CreationTime')
                regional_crawlers.append({'Region': region, 'Crawler Name': crawler.get('Name', 'N/A'), 'State': crawler.get('State', 'N/A'), 'Database': crawler.get('DatabaseName', 'N/A'), 'Role': role, 'S3 Targets': len(s3_targets), 'S3 Paths': s3_paths_str, 'JDBC Targets': len(targets.get('JdbcTargets', [])), 'DynamoDB Targets': len(targets.get('DynamoDBTargets', [])), 'Schedule': schedule.get('ScheduleExpression', 'N/A') if schedule else 'N/A', 'Classifiers': ', '.join(classifiers) if classifiers else 'Default', 'Update Behavior': schema_change_policy.get('UpdateBehavior', 'N/A'), 'Delete Behavior': schema_change_policy.get('DeleteBehavior', 'N/A'), 'Recrawl Behavior': recrawl_policy.get('RecrawlBehavior', 'N/A'), 'Last Crawl Status': last_crawl.get('Status', 'Never run') if last_crawl else 'Never run', 'Created': creation_time.strftime('%Y-%m-%d %H:%M:%S') if creation_time else 'N/A'})
    except Exception as e:
        utils.log_error(f"Error collecting Glue crawlers in {region}", e)
    return regional_crawlers


def _scan_glue_jobs_region(region: str) -> List[Dict[str, Any]]:
    """Scan Glue jobs in a single region."""
    regional_jobs = []
    try:
        glue_client = utils.get_boto3_client('glue', region_name=region)
        paginator = glue_client.get_paginator('get_jobs')
        for page in paginator.paginate():
            for job in page.get('Jobs', []):
                role = job.get('Role', 'N/A')
                if role != 'N/A' and '/' in role:
                    role = role.split('/')[-1]
                command = job.get('Command', {})
                connections = job.get('Connections', {})
                connection_list = connections.get('Connections', [])
                created_on = job.get('CreatedOn')
                last_modified_on = job.get('LastModifiedOn')
                regional_jobs.append({'Region': region, 'Job Name': job.get('Name', 'N/A'), 'Description': job.get('Description', 'N/A'), 'Command': command.get('Name', 'N/A'), 'Role': role, 'Glue Version': job.get('GlueVersion', 'N/A'), 'Worker Type': job.get('WorkerType', 'N/A'), 'Number of Workers': job.get('NumberOfWorkers', 'N/A'), 'Max Capacity': job.get('MaxCapacity', 'N/A'), 'Python Version': command.get('PythonVersion', 'N/A'), 'Script Location': command.get('ScriptLocation', 'N/A'), 'Max Retries': job.get('MaxRetries', 0), 'Timeout (min)': job.get('Timeout', 0), 'Connections': ', '.join(connection_list) if connection_list else 'None', 'Created': created_on.strftime('%Y-%m-%d %H:%M:%S') if created_on else 'N/A', 'Last Modified': last_modified_on.strftime('%Y-%m-%d %H:%M:%S') if last_modified_on else 'N/A'})
    except Exception as e:
        utils.log_error(f"Error collecting Glue jobs in {region}", e)
    return regional_jobs


def _scan_athena_workgroups_region(region: str) -> List[Dict[str, Any]]:
    """Scan Athena workgroups in a single region."""
    regional_workgroups = []
    try:
        athena_client = utils.get_boto3_client('athena', region_name=region)
        paginator = athena_client.get_paginator('list_work_groups')
        for page in paginator.paginate():
            for wg_summary in page.get('WorkGroups', []):
                workgroup_name = wg_summary.get('Name', 'N/A')
                try:
                    wg_response = athena_client.get_work_group(WorkGroup=workgroup_name)
                    wg = wg_response.get('WorkGroup', {})
                    configuration = wg.get('Configuration', {})
                    result_config = configuration.get('ResultConfiguration', {})
                    encryption_config = result_config.get('EncryptionConfiguration', {})
                    encryption_option = encryption_config.get('EncryptionOption', 'None')
                    engine_version = configuration.get('EngineVersion', {})
                    creation_time = wg.get('CreationTime')
                    regional_workgroups.append({'Region': region, 'Workgroup Name': workgroup_name, 'State': wg.get('State', 'N/A'), 'Description': wg.get('Description', 'N/A'), 'Output Location': result_config.get('OutputLocation', 'N/A'), 'Encryption': encryption_option, 'KMS Key': encryption_config.get('KmsKey', 'N/A') if encryption_option != 'None' else 'N/A', 'Bytes Scanned Cutoff': configuration.get('BytesScannedCutoffPerQuery', 'N/A'), 'Enforce Config': 'Yes' if configuration.get('EnforceWorkGroupConfiguration', False) else 'No', 'CloudWatch Metrics': 'Yes' if configuration.get('PublishCloudWatchMetricsEnabled', False) else 'No', 'Requester Pays': 'Yes' if configuration.get('RequesterPaysEnabled', False) else 'No', 'Engine Version': engine_version.get('SelectedEngineVersion', 'N/A') if engine_version else 'N/A', 'Created': creation_time.strftime('%Y-%m-%d %H:%M:%S') if creation_time else 'N/A'})
                except Exception as e:
                    utils.log_warning(f"Could not get details for workgroup {workgroup_name}: {str(e)}")
    except Exception as e:
        utils.log_error(f"Error collecting Athena workgroups in {region}", e)
    return regional_workgroups


def _scan_athena_data_catalogs_region(region: str) -> List[Dict[str, Any]]:
    """Scan Athena data catalogs in a single region."""
    regional_catalogs = []
    try:
        athena_client = utils.get_boto3_client('athena', region_name=region)
        paginator = athena_client.get_paginator('list_data_catalogs')
        for page in paginator.paginate():
            for catalog_summary in page.get('DataCatalogsSummary', []):
                catalog_name = catalog_summary.get('CatalogName', 'N/A')
                try:
                    catalog_response = athena_client.get_data_catalog(Name=catalog_name)
                    catalog = catalog_response.get('DataCatalog', {})
                    parameters = catalog.get('Parameters', {})
                    regional_catalogs.append({'Region': region, 'Catalog Name': catalog_name, 'Type': catalog.get('Type', 'N/A'), 'Description': catalog.get('Description', 'N/A'), 'Parameters': ', '.join([f"{k}={v}" for k, v in parameters.items()]) if parameters else 'None'})
                except Exception as e:
                    utils.log_warning(f"Could not get details for catalog {catalog_name}: {str(e)}")
    except Exception as e:
        utils.log_error(f"Error collecting Athena data catalogs in {region}", e)
    return regional_catalogs

@utils.aws_error_handler("Collecting Glue tables", default_return=[])
def collect_glue_tables(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect AWS Glue table information from AWS regions."""
    print("\n=== COLLECTING GLUE TABLES ===")
    results = utils.scan_regions_concurrent(regions, _scan_glue_tables_region)
    all_tables = [table for result in results for table in result]
    utils.log_success(f"Total Glue tables collected: {len(all_tables)}")
    return all_tables
@utils.aws_error_handler("Collecting Glue crawlers", default_return=[])
def collect_glue_crawlers(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect AWS Glue crawler information from AWS regions."""
    print("\n=== COLLECTING GLUE CRAWLERS ===")
    results = utils.scan_regions_concurrent(regions, _scan_glue_crawlers_region)
    all_crawlers = [crawler for result in results for crawler in result]
    utils.log_success(f"Total Glue crawlers collected: {len(all_crawlers)}")
    return all_crawlers


@utils.aws_error_handler("Collecting Glue jobs", default_return=[])
def collect_glue_jobs(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect AWS Glue job information from AWS regions."""
    print("\n=== COLLECTING GLUE JOBS ===")
    results = utils.scan_regions_concurrent(regions, _scan_glue_jobs_region)
    all_jobs = [job for result in results for job in result]
    utils.log_success(f"Total Glue jobs collected: {len(all_jobs)}")
    return all_jobs


@utils.aws_error_handler("Collecting Athena workgroups", default_return=[])
def collect_athena_workgroups(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Athena workgroup information from AWS regions."""
    print("\n=== COLLECTING ATHENA WORKGROUPS ===")
    results = utils.scan_regions_concurrent(regions, _scan_athena_workgroups_region)
    all_workgroups = [wg for result in results for wg in result]
    utils.log_success(f"Total Athena workgroups collected: {len(all_workgroups)}")
    return all_workgroups


@utils.aws_error_handler("Collecting Athena data catalogs", default_return=[])
def collect_athena_data_catalogs(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Athena data catalog information from AWS regions."""
    print("\n=== COLLECTING ATHENA DATA CATALOGS ===")
    results = utils.scan_regions_concurrent(regions, _scan_athena_data_catalogs_region)
    all_catalogs = [catalog for result in results for catalog in result]
    utils.log_success(f"Total Athena data catalogs collected: {len(all_catalogs)}")
    return all_catalogs



def generate_summary(databases: List[Dict[str, Any]],
                     tables: List[Dict[str, Any]],
                     crawlers: List[Dict[str, Any]],
                     jobs: List[Dict[str, Any]],
                     workgroups: List[Dict[str, Any]],
                     catalogs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Glue and Athena resources."""
    summary = []

    # Glue resources
    summary.append({
        'Metric': 'Total Glue Databases',
        'Count': len(databases),
        'Details': f"{len(databases)} databases in Glue Data Catalog"
    })

    summary.append({
        'Metric': 'Total Glue Tables',
        'Count': len(tables),
        'Details': f"{len(tables)} tables across all databases"
    })

    summary.append({
        'Metric': 'Total Glue Crawlers',
        'Count': len(crawlers),
        'Details': f"{len([c for c in crawlers if c['State'] == 'READY'])} ready"
    })

    summary.append({
        'Metric': 'Total Glue Jobs',
        'Count': len(jobs),
        'Details': f"{len(jobs)} ETL jobs configured"
    })

    # Athena resources
    summary.append({
        'Metric': 'Total Athena Workgroups',
        'Count': len(workgroups),
        'Details': f"{len([wg for wg in workgroups if wg['State'] == 'ENABLED'])} enabled"
    })

    summary.append({
        'Metric': 'Total Athena Data Catalogs',
        'Count': len(catalogs),
        'Details': f"{len(catalogs)} data catalogs configured"
    })

    # Tables by database
    if tables:
        db_counts = {}
        for table in tables:
            db = table['Database']
            db_counts[db] = db_counts.get(db, 0) + 1

        top_dbs = sorted(db_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        db_details = ', '.join([f"{db}: {count}" for db, count in top_dbs])
        summary.append({
            'Metric': 'Top Databases by Table Count',
            'Count': len(db_counts),
            'Details': db_details
        })

    # Crawler targets
    if crawlers:
        total_s3_targets = sum(c['S3 Targets'] for c in crawlers if isinstance(c['S3 Targets'], int))
        total_jdbc_targets = sum(c['JDBC Targets'] for c in crawlers if isinstance(c['JDBC Targets'], int))
        total_dynamodb_targets = sum(c['DynamoDB Targets'] for c in crawlers if isinstance(c['DynamoDB Targets'], int))

        summary.append({
            'Metric': 'Crawler Targets',
            'Count': total_s3_targets + total_jdbc_targets + total_dynamodb_targets,
            'Details': f"S3: {total_s3_targets}, JDBC: {total_jdbc_targets}, DynamoDB: {total_dynamodb_targets}"
        })

    # Athena encryption
    if workgroups:
        encrypted_workgroups = len([wg for wg in workgroups if wg['Encryption'] != 'None'])
        summary.append({
            'Metric': 'Encrypted Athena Workgroups',
            'Count': encrypted_workgroups,
            'Details': f"{encrypted_workgroups}/{len(workgroups)} workgroups with encryption"
        })

    return summary


def _run_export(account_id: str, account_name: str, regions: List[str]) -> None:
    """Collect Glue and Athena data and write the Excel export."""
    # Collect data
    print("\n=== Collecting Glue & Athena Data ===")
    databases = collect_glue_databases(regions)
    tables = collect_glue_tables(regions)
    crawlers = collect_glue_crawlers(regions)
    jobs = collect_glue_jobs(regions)
    workgroups = collect_athena_workgroups(regions)
    catalogs = collect_athena_data_catalogs(regions)

    # Generate summary
    summary = generate_summary(databases, tables, crawlers, jobs, workgroups, catalogs)

    # Convert to DataFrames
    databases_df = pd.DataFrame(databases) if databases else pd.DataFrame()
    tables_df = pd.DataFrame(tables) if tables else pd.DataFrame()
    crawlers_df = pd.DataFrame(crawlers) if crawlers else pd.DataFrame()
    jobs_df = pd.DataFrame(jobs) if jobs else pd.DataFrame()
    workgroups_df = pd.DataFrame(workgroups) if workgroups else pd.DataFrame()
    catalogs_df = pd.DataFrame(catalogs) if catalogs else pd.DataFrame()
    summary_df = pd.DataFrame(summary)

    # Prepare DataFrames for export
    if not databases_df.empty:
        databases_df = utils.prepare_dataframe_for_export(databases_df)
    if not tables_df.empty:
        tables_df = utils.prepare_dataframe_for_export(tables_df)
    if not crawlers_df.empty:
        crawlers_df = utils.prepare_dataframe_for_export(crawlers_df)
    if not jobs_df.empty:
        jobs_df = utils.prepare_dataframe_for_export(jobs_df)
    if not workgroups_df.empty:
        workgroups_df = utils.prepare_dataframe_for_export(workgroups_df)
    if not catalogs_df.empty:
        catalogs_df = utils.prepare_dataframe_for_export(catalogs_df)
    if not summary_df.empty:
        summary_df = utils.prepare_dataframe_for_export(summary_df)

    # Create export filename
    region_suffix = regions[0] if len(regions) == 1 else 'all-regions'
    filename = utils.create_export_filename(account_name, 'glue-athena', region_suffix)

    # Save to Excel with multiple sheets
    print("\n=== Exporting to Excel ===")
    dataframes = {
        'Glue Databases': databases_df,
        'Glue Tables': tables_df,
        'Glue Crawlers': crawlers_df,
        'Glue Jobs': jobs_df,
        'Athena Workgroups': workgroups_df,
        'Athena Data Catalogs': catalogs_df,
        'Summary': summary_df
    }

    if utils.save_multiple_dataframes_to_excel(dataframes, filename):
        utils.log_export_summary(
            filename=filename,
            total_items=len(databases) + len(tables) + len(crawlers) + len(jobs) + len(workgroups) + len(catalogs),
            details={
                'Glue Databases': len(databases),
                'Glue Tables': len(tables),
                'Glue Crawlers': len(crawlers),
                'Glue Jobs': len(jobs),
                'Athena Workgroups': len(workgroups),
                'Athena Data Catalogs': len(catalogs)
            }
        )


def main():
    """Main execution function — 3-step state machine (region -> confirm -> export)."""
    utils.setup_logging("glue-athena-export")

    try:
        account_id, account_name = utils.print_script_banner("AWS GLUE AND ATHENA EXPORT")

        step = 1
        regions = None

        while True:
            if step == 1:
                result = utils.prompt_region_selection(service_name="Glue/Athena")
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                regions = result
                step = 2

            elif step == 2:
                region_str = regions[0] if len(regions) == 1 else f"{len(regions)} regions"
                msg = f"Ready to export Glue and Athena data ({region_str})."
                result = utils.prompt_confirmation(msg)
                if result == 'back':
                    step = 1
                    continue
                if result == 'exit':
                    sys.exit(11)
                step = 3

            elif step == 3:
                _run_export(account_id, account_name, regions)
                break

    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

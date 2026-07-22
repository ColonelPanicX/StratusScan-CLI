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
from typing import Any

try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils
args = utils.parse_script_args("Export AWS Glue and Athena resources to Excel")


def _scan_glue_databases_region(region: str) -> list[dict[str, Any]]:
    """
    Scan Glue databases in a single region.

    This is one of six primary scope collectors (databases, tables, crawlers,
    jobs, Athena workgroups, Athena data catalogs). It deliberately does NOT
    swallow region-level errors: an API/permission failure here must
    propagate so ``scan_regions_concurrent(..., collect_failures=True)``
    records the region as failed instead of silently reporting "no Glue
    databases" (the silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed databases are skipped (logged) rather than aborting
    the whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_databases = []
    glue_client = utils.get_boto3_client('glue', region_name=region)
    paginator = glue_client.get_paginator('get_databases')

    for page in paginator.paginate():
        databases = page.get('DatabaseList', [])

        for db in databases:
            try:
                regional_databases.append(_build_database_row(db, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed Glue database in {region}: "
                    f"{db.get('Name', '<unknown>')}",
                    e,
                )
                continue

    return regional_databases


def _build_database_row(db: dict, region: str) -> dict[str, Any]:
    """Build a single Glue database export row."""
    db_name = db.get('Name', 'N/A')
    description = db.get('Description', 'N/A')
    location_uri = db.get('LocationUri', 'N/A')

    create_time = db.get('CreateTime')
    create_time_str = create_time.strftime('%Y-%m-%d %H:%M:%S') if create_time else 'N/A'

    catalog_id = db.get('CatalogId', 'N/A')

    return {
        'Region': region,
        'Database Name': db_name,
        'Description': description,
        'Location URI': location_uri,
        'Catalog ID': catalog_id,
        'Created': create_time_str,
    }


def collect_glue_databases(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect AWS Glue database information across regions, surfacing failures.

    Returns:
        tuple: ``(databases, failed_regions)`` where ``failed_regions`` is a
        list of ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING GLUE DATABASES ===")
    results, failed_regions = utils.scan_regions_concurrent(
        regions, _scan_glue_databases_region, show_progress=True, collect_failures=True
    )
    all_databases = [db for result in results for db in result]
    utils.log_success(f"Total Glue databases collected: {len(all_databases)}")
    return all_databases, failed_regions


def _scan_glue_tables_region(region: str) -> list[dict[str, Any]]:
    """
    Scan Glue tables in a single region.

    Fetching the region's database list is the scope's top-level call and is
    NOT swallowed — its failure must propagate so the region is recorded as
    failed. Fetching tables for one specific database, and building one
    table's row, are per-item operations: they are logged and skipped so a
    single bad database/table does not discard the whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_tables = []
    glue_client = utils.get_boto3_client('glue', region_name=region)

    databases = []
    db_paginator = glue_client.get_paginator('get_databases')
    for page in db_paginator.paginate():
        databases.extend(page.get('DatabaseList', []))

    for db in databases:
        db_name = db.get('Name', '')
        try:
            paginator = glue_client.get_paginator('get_tables')
            for page in paginator.paginate(DatabaseName=db_name):
                tables = page.get('TableList', [])
                for table in tables:
                    try:
                        regional_tables.append(_build_table_row(table, region, db_name))
                    except Exception as e:
                        utils.log_error(
                            f"Skipping malformed Glue table in {region}/{db_name}: "
                            f"{table.get('Name', '<unknown>')}",
                            e,
                        )
                        continue
        except Exception as e:
            utils.log_warning(f"Could not get tables for database {db_name}: {str(e)}")

    return regional_tables


def _build_table_row(table: dict, region: str, db_name: str) -> dict[str, Any]:
    """Build a single Glue table export row."""
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

    return {
        'Region': region,
        'Database': db_name,
        'Table Name': table_name,
        'Description': description,
        'Table Type': table_type,
        'Location': location,
        'Column Count': column_count,
        'Partition Keys': partition_names_str,
        'Partition Count': partition_count,
        'Input Format': input_format,
        'Output Format': output_format,
        'Serialization Library': serialization_library,
        'Created': create_time_str,
        'Updated': update_time_str,
    }


def collect_glue_tables(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect AWS Glue table information across regions, surfacing failures.

    Returns:
        tuple: ``(tables, failed_regions)``.
    """
    print("\n=== COLLECTING GLUE TABLES ===")
    results, failed_regions = utils.scan_regions_concurrent(
        regions, _scan_glue_tables_region, show_progress=True, collect_failures=True
    )
    all_tables = [table for result in results for table in result]
    utils.log_success(f"Total Glue tables collected: {len(all_tables)}")
    return all_tables, failed_regions


def _scan_glue_crawlers_region(region: str) -> list[dict[str, Any]]:
    """Scan Glue crawlers in a single region. Region-level failures propagate."""
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_crawlers = []
    glue_client = utils.get_boto3_client('glue', region_name=region)
    paginator = glue_client.get_paginator('get_crawlers')

    for page in paginator.paginate():
        for crawler in page.get('Crawlers', []):
            try:
                regional_crawlers.append(_build_crawler_row(crawler, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed Glue crawler in {region}: "
                    f"{crawler.get('Name', '<unknown>')}",
                    e,
                )
                continue

    return regional_crawlers


def _build_crawler_row(crawler: dict, region: str) -> dict[str, Any]:
    """Build a single Glue crawler export row."""
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

    return {
        'Region': region,
        'Crawler Name': crawler.get('Name', 'N/A'),
        'State': crawler.get('State', 'N/A'),
        'Database': crawler.get('DatabaseName', 'N/A'),
        'Role': role,
        'S3 Targets': len(s3_targets),
        'S3 Paths': s3_paths_str,
        'JDBC Targets': len(targets.get('JdbcTargets', [])),
        'DynamoDB Targets': len(targets.get('DynamoDBTargets', [])),
        'Schedule': schedule.get('ScheduleExpression', 'N/A') if schedule else 'N/A',
        'Classifiers': ', '.join(classifiers) if classifiers else 'Default',
        'Update Behavior': schema_change_policy.get('UpdateBehavior', 'N/A'),
        'Delete Behavior': schema_change_policy.get('DeleteBehavior', 'N/A'),
        'Recrawl Behavior': recrawl_policy.get('RecrawlBehavior', 'N/A'),
        'Last Crawl Status': last_crawl.get('Status', 'Never run') if last_crawl else 'Never run',
        'Created': creation_time.strftime('%Y-%m-%d %H:%M:%S') if creation_time else 'N/A',
    }


def collect_glue_crawlers(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect AWS Glue crawler information across regions, surfacing failures.

    Returns:
        tuple: ``(crawlers, failed_regions)``.
    """
    print("\n=== COLLECTING GLUE CRAWLERS ===")
    results, failed_regions = utils.scan_regions_concurrent(
        regions, _scan_glue_crawlers_region, show_progress=True, collect_failures=True
    )
    all_crawlers = [crawler for result in results for crawler in result]
    utils.log_success(f"Total Glue crawlers collected: {len(all_crawlers)}")
    return all_crawlers, failed_regions


def _scan_glue_jobs_region(region: str) -> list[dict[str, Any]]:
    """Scan Glue jobs in a single region. Region-level failures propagate."""
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_jobs = []
    glue_client = utils.get_boto3_client('glue', region_name=region)
    paginator = glue_client.get_paginator('get_jobs')

    for page in paginator.paginate():
        for job in page.get('Jobs', []):
            try:
                regional_jobs.append(_build_job_row(job, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed Glue job in {region}: "
                    f"{job.get('Name', '<unknown>')}",
                    e,
                )
                continue

    return regional_jobs


def _build_job_row(job: dict, region: str) -> dict[str, Any]:
    """Build a single Glue job export row."""
    role = job.get('Role', 'N/A')
    if role != 'N/A' and '/' in role:
        role = role.split('/')[-1]
    command = job.get('Command', {})
    connections = job.get('Connections', {})
    connection_list = connections.get('Connections', [])
    created_on = job.get('CreatedOn')
    last_modified_on = job.get('LastModifiedOn')

    return {
        'Region': region,
        'Job Name': job.get('Name', 'N/A'),
        'Description': job.get('Description', 'N/A'),
        'Command': command.get('Name', 'N/A'),
        'Role': role,
        'Glue Version': job.get('GlueVersion', 'N/A'),
        'Worker Type': job.get('WorkerType', 'N/A'),
        'Number of Workers': job.get('NumberOfWorkers', 'N/A'),
        'Max Capacity': job.get('MaxCapacity', 'N/A'),
        'Python Version': command.get('PythonVersion', 'N/A'),
        'Script Location': command.get('ScriptLocation', 'N/A'),
        'Max Retries': job.get('MaxRetries', 0),
        'Timeout (min)': job.get('Timeout', 0),
        'Connections': ', '.join(connection_list) if connection_list else 'None',
        'Created': created_on.strftime('%Y-%m-%d %H:%M:%S') if created_on else 'N/A',
        'Last Modified': last_modified_on.strftime('%Y-%m-%d %H:%M:%S') if last_modified_on else 'N/A',
    }


def collect_glue_jobs(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect AWS Glue job information across regions, surfacing failures.

    Returns:
        tuple: ``(jobs, failed_regions)``.
    """
    print("\n=== COLLECTING GLUE JOBS ===")
    results, failed_regions = utils.scan_regions_concurrent(
        regions, _scan_glue_jobs_region, show_progress=True, collect_failures=True
    )
    all_jobs = [job for result in results for job in result]
    utils.log_success(f"Total Glue jobs collected: {len(all_jobs)}")
    return all_jobs, failed_regions


def _scan_athena_workgroups_region(region: str) -> list[dict[str, Any]]:
    """
    Scan Athena workgroups in a single region.

    Listing workgroups is the scope's top-level call and is NOT swallowed —
    its failure must propagate so the region is recorded as failed. Fetching
    the full details for one specific workgroup is a per-item operation: it
    is logged and skipped so a single inaccessible workgroup does not
    discard the whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_workgroups = []
    athena_client = utils.get_boto3_client('athena', region_name=region)
    next_token = None

    while True:
        params = {'MaxResults': 50}
        if next_token:
            params['NextToken'] = next_token
        page = athena_client.list_work_groups(**params)

        for wg_summary in page.get('WorkGroups', []):
            workgroup_name = wg_summary.get('Name', 'N/A')
            try:
                wg_response = athena_client.get_work_group(WorkGroup=workgroup_name)
                wg = wg_response.get('WorkGroup', {})
                regional_workgroups.append(_build_workgroup_row(wg, region, workgroup_name))
            except Exception as e:
                utils.log_warning(f"Could not get details for workgroup {workgroup_name}: {str(e)}")

        next_token = page.get('NextToken')
        if not next_token:
            break

    return regional_workgroups


def _build_workgroup_row(wg: dict, region: str, workgroup_name: str) -> dict[str, Any]:
    """Build a single Athena workgroup export row."""
    configuration = wg.get('Configuration', {})
    result_config = configuration.get('ResultConfiguration', {})
    encryption_config = result_config.get('EncryptionConfiguration', {})
    encryption_option = encryption_config.get('EncryptionOption', 'None')
    engine_version = configuration.get('EngineVersion', {})
    creation_time = wg.get('CreationTime')

    return {
        'Region': region,
        'Workgroup Name': workgroup_name,
        'State': wg.get('State', 'N/A'),
        'Description': wg.get('Description', 'N/A'),
        'Output Location': result_config.get('OutputLocation', 'N/A'),
        'Encryption': encryption_option,
        'KMS Key': encryption_config.get('KmsKey', 'N/A') if encryption_option != 'None' else 'N/A',
        'Bytes Scanned Cutoff': configuration.get('BytesScannedCutoffPerQuery', 'N/A'),
        'Enforce Config': 'Yes' if configuration.get('EnforceWorkGroupConfiguration', False) else 'No',
        'CloudWatch Metrics': 'Yes' if configuration.get('PublishCloudWatchMetricsEnabled', False) else 'No',
        'Requester Pays': 'Yes' if configuration.get('RequesterPaysEnabled', False) else 'No',
        'Engine Version': engine_version.get('SelectedEngineVersion', 'N/A') if engine_version else 'N/A',
        'Created': creation_time.strftime('%Y-%m-%d %H:%M:%S') if creation_time else 'N/A',
    }


def collect_athena_workgroups(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect Athena workgroup information across regions, surfacing failures.

    Returns:
        tuple: ``(workgroups, failed_regions)``.
    """
    print("\n=== COLLECTING ATHENA WORKGROUPS ===")
    results, failed_regions = utils.scan_regions_concurrent(
        regions, _scan_athena_workgroups_region, show_progress=True, collect_failures=True
    )
    all_workgroups = [wg for result in results for wg in result]
    utils.log_success(f"Total Athena workgroups collected: {len(all_workgroups)}")
    return all_workgroups, failed_regions


def _scan_athena_data_catalogs_region(region: str) -> list[dict[str, Any]]:
    """
    Scan Athena data catalogs in a single region.

    Listing data catalogs is the scope's top-level call and is NOT swallowed
    — its failure must propagate so the region is recorded as failed.
    Fetching the full details for one specific catalog is a per-item
    operation: it is logged and skipped so a single inaccessible catalog
    does not discard the whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_catalogs = []
    athena_client = utils.get_boto3_client('athena', region_name=region)
    paginator = athena_client.get_paginator('list_data_catalogs')

    for page in paginator.paginate():
        for catalog_summary in page.get('DataCatalogsSummary', []):
            catalog_name = catalog_summary.get('CatalogName', 'N/A')
            try:
                catalog_response = athena_client.get_data_catalog(Name=catalog_name)
                catalog = catalog_response.get('DataCatalog', {})
                regional_catalogs.append(_build_catalog_row(catalog, region, catalog_name))
            except Exception as e:
                utils.log_warning(f"Could not get details for catalog {catalog_name}: {str(e)}")

    return regional_catalogs


def _build_catalog_row(catalog: dict, region: str, catalog_name: str) -> dict[str, Any]:
    """Build a single Athena data catalog export row."""
    parameters = catalog.get('Parameters', {})

    return {
        'Region': region,
        'Catalog Name': catalog_name,
        'Type': catalog.get('Type', 'N/A'),
        'Description': catalog.get('Description', 'N/A'),
        'Parameters': ', '.join([f"{k}={v}" for k, v in parameters.items()]) if parameters else 'None',
    }


def collect_athena_data_catalogs(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect Athena data catalog information across regions, surfacing failures.

    Returns:
        tuple: ``(catalogs, failed_regions)``.
    """
    print("\n=== COLLECTING ATHENA DATA CATALOGS ===")
    results, failed_regions = utils.scan_regions_concurrent(
        regions, _scan_athena_data_catalogs_region, show_progress=True, collect_failures=True
    )
    all_catalogs = [catalog for result in results for catalog in result]
    utils.log_success(f"Total Athena data catalogs collected: {len(all_catalogs)}")
    return all_catalogs, failed_regions


def generate_summary(databases: list[dict[str, Any]],
                     tables: list[dict[str, Any]],
                     crawlers: list[dict[str, Any]],
                     jobs: list[dict[str, Any]],
                     workgroups: list[dict[str, Any]],
                     catalogs: list[dict[str, Any]]) -> list[dict[str, Any]]:
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


def _run_export(account_id: str, account_name: str, regions: list[str]) -> None:
    """Collect Glue and Athena data and write the Excel export."""
    # Collect data. Each collector below is an independent region-scanned
    # scope (databases, tables, crawlers, jobs, Athena workgroups, Athena
    # data catalogs); a region-level failure in any of them propagates via
    # scan_regions_concurrent(..., collect_failures=True) instead of being
    # silently collapsed into "empty". All six failed_regions lists are
    # merged into one combined list below (see
    # .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).
    print("\n=== Collecting Glue & Athena Data ===")
    databases, failed_databases = collect_glue_databases(regions)
    tables, failed_tables = collect_glue_tables(regions)
    crawlers, failed_crawlers = collect_glue_crawlers(regions)
    jobs, failed_jobs = collect_glue_jobs(regions)
    workgroups, failed_workgroups = collect_athena_workgroups(regions)
    catalogs, failed_catalogs = collect_athena_data_catalogs(regions)

    failed_regions = (
        failed_databases
        + failed_tables
        + failed_crawlers
        + failed_jobs
        + failed_workgroups
        + failed_catalogs
    )

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

    # Save to Excel with multiple sheets. The Summary sheet is ALWAYS
    # written (forced), so a workbook lands even when every scope failed —
    # that must not mask a real failure; see the failed_regions check below.
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

    utils.save_multiple_dataframes_to_excel(dataframes, filename)

    # If ANY scope failed in ANY region, make it loud: write a marker and
    # exit non-zero, even though the always-written Summary sheet means a
    # workbook still landed. A complete-looking workbook with silently
    # zero-row data sheets is exactly the failure mode this guards against.
    # A genuinely empty account (every scope succeeded, nothing found) has
    # an empty failed_regions list and stays exit 0 with no marker.
    if failed_regions:
        utils.report_collection_failures(account_name, 'glue-athena', failed_regions)
        print(
            "\nERROR: Glue/Athena export completed with failures — data is incomplete. "
            "See the *-glue-athena-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    """Main execution function — 3-step state machine (region -> confirm -> export)."""
    if not utils.ensure_dependencies('pandas', 'openpyxl'):
        return
    global pd
    import pandas as pd
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

#!/usr/bin/env python3
"""
Amazon Comprehend Export Script for StratusScan

Exports comprehensive Amazon Comprehend natural language processing information including:
- Document classification jobs
- Entity recognition jobs
- Sentiment analysis jobs
- Custom entity recognizers
- Custom document classifiers
- Endpoints for real-time inference

Output: Multi-worksheet Excel file with Comprehend resources
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
args = utils.parse_script_args("Export Amazon Comprehend resources to Excel")


def _build_recognizer_row(recognizer: dict, region: str) -> dict[str, Any]:
    """Build a single entity recognizer export row from a list_entity_recognizers entry."""
    recognizer_arn = recognizer.get('EntityRecognizerArn', 'N/A')
    language_code = recognizer.get('LanguageCode', 'N/A')
    status = recognizer.get('Status', 'N/A')

    submit_time = recognizer.get('SubmitTime', 'N/A')
    if submit_time != 'N/A':
        submit_time = submit_time.strftime('%Y-%m-%d %H:%M:%S')

    end_time = recognizer.get('EndTime', 'N/A')
    if end_time != 'N/A':
        end_time = end_time.strftime('%Y-%m-%d %H:%M:%S')

    # Training metrics
    recognizer_metadata = recognizer.get('RecognizerMetadata', {}) or {}
    number_of_trained_documents = recognizer_metadata.get('NumberOfTrainedDocuments', 0)
    number_of_test_documents = recognizer_metadata.get('NumberOfTestDocuments', 0)

    # Evaluation metrics
    eval_metrics = recognizer_metadata.get('EvaluationMetrics', {}) or {}
    precision = eval_metrics.get('Precision', 0)
    recall = eval_metrics.get('Recall', 0)
    f1_score = eval_metrics.get('F1Score', 0)

    # Extract recognizer name from ARN
    recognizer_name = 'N/A'
    if recognizer_arn != 'N/A' and '/' in recognizer_arn:
        recognizer_name = recognizer_arn.split('/')[-1]

    # Data access role
    data_access_role = recognizer.get('DataAccessRoleArn', 'N/A')

    # Message
    message = recognizer.get('Message', 'N/A')

    return {
        'Region': region,
        'Recognizer Name': recognizer_name,
        'ARN': recognizer_arn,
        'Language': language_code,
        'Status': status,
        'Submitted': submit_time,
        'Ended': end_time,
        'Trained Documents': number_of_trained_documents,
        'Test Documents': number_of_test_documents,
        'Precision': f"{precision:.4f}" if precision else 'N/A',
        'Recall': f"{recall:.4f}" if recall else 'N/A',
        'F1 Score': f"{f1_score:.4f}" if f1_score else 'N/A',
        'Data Access Role ARN': data_access_role,
        'Message': message
    }


def _scan_recognizers_region(region: str) -> list[dict[str, Any]]:
    """
    Collect custom entity recognizers from a single region.

    This is a primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the
    region as failed instead of silently reporting "no recognizers" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed recognizers are skipped (logged) rather than
    aborting the whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    utils.log_info(f"Collecting entity recognizers in {region}...")
    comprehend_client = utils.get_boto3_client('comprehend', region_name=region)

    region_recognizers = []
    paginator = comprehend_client.get_paginator('list_entity_recognizers')
    for page in paginator.paginate():
        recognizers = page.get('EntityRecognizerPropertiesList', [])

        for recognizer in recognizers:
            try:
                region_recognizers.append(_build_recognizer_row(recognizer, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed entity recognizer in {region}: "
                    f"{recognizer.get('EntityRecognizerArn', '<unknown>')}",
                    e,
                )
                continue

    utils.log_info(f"Collected {len(region_recognizers)} entity recognizers in {region}")
    return region_recognizers


def collect_entity_recognizers(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect custom entity recognizer information across regions, surfacing failures.

    Returns:
        tuple: ``(recognizers, failed_regions)`` where ``failed_regions`` is a
        list of ``(region, error_message)`` tuples.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_recognizers_region,
        show_progress=True,
        collect_failures=True,
    )
    all_recognizers = [r for result in region_results for r in result]
    utils.log_info(f"Collected {len(all_recognizers)} entity recognizers total")
    return all_recognizers, failed_regions


def _build_classifier_row(classifier: dict, region: str) -> dict[str, Any]:
    """Build a single document classifier export row from a list_document_classifiers entry."""
    classifier_arn = classifier.get('DocumentClassifierArn', 'N/A')
    language_code = classifier.get('LanguageCode', 'N/A')
    status = classifier.get('Status', 'N/A')
    mode = classifier.get('Mode', 'N/A')

    submit_time = classifier.get('SubmitTime', 'N/A')
    if submit_time != 'N/A':
        submit_time = submit_time.strftime('%Y-%m-%d %H:%M:%S')

    end_time = classifier.get('EndTime', 'N/A')
    if end_time != 'N/A':
        end_time = end_time.strftime('%Y-%m-%d %H:%M:%S')

    # Training metrics
    classifier_metadata = classifier.get('ClassifierMetadata', {}) or {}
    number_of_labels = classifier_metadata.get('NumberOfLabels', 0)
    number_of_trained_documents = classifier_metadata.get('NumberOfTrainedDocuments', 0)
    number_of_test_documents = classifier_metadata.get('NumberOfTestDocuments', 0)

    # Evaluation metrics
    eval_metrics = classifier_metadata.get('EvaluationMetrics', {}) or {}
    accuracy = eval_metrics.get('Accuracy', 0)
    precision = eval_metrics.get('Precision', 0)
    recall = eval_metrics.get('Recall', 0)
    f1_score = eval_metrics.get('F1Score', 0)
    micro_precision = eval_metrics.get('MicroPrecision', 0)
    micro_recall = eval_metrics.get('MicroRecall', 0)
    micro_f1 = eval_metrics.get('MicroF1Score', 0)

    # Extract classifier name from ARN
    classifier_name = 'N/A'
    if classifier_arn != 'N/A' and '/' in classifier_arn:
        classifier_name = classifier_arn.split('/')[-1]

    # Data access role
    data_access_role = classifier.get('DataAccessRoleArn', 'N/A')

    # Message
    message = classifier.get('Message', 'N/A')

    return {
        'Region': region,
        'Classifier Name': classifier_name,
        'ARN': classifier_arn,
        'Language': language_code,
        'Mode': mode,
        'Status': status,
        'Submitted': submit_time,
        'Ended': end_time,
        'Number of Labels': number_of_labels,
        'Trained Documents': number_of_trained_documents,
        'Test Documents': number_of_test_documents,
        'Accuracy': f"{accuracy:.4f}" if accuracy else 'N/A',
        'Precision': f"{precision:.4f}" if precision else 'N/A',
        'Recall': f"{recall:.4f}" if recall else 'N/A',
        'F1 Score': f"{f1_score:.4f}" if f1_score else 'N/A',
        'Micro Precision': f"{micro_precision:.4f}" if micro_precision else 'N/A',
        'Micro Recall': f"{micro_recall:.4f}" if micro_recall else 'N/A',
        'Micro F1': f"{micro_f1:.4f}" if micro_f1 else 'N/A',
        'Data Access Role ARN': data_access_role,
        'Message': message
    }


def _scan_classifiers_region(region: str) -> list[dict[str, Any]]:
    """
    Collect custom document classifiers from a single region.

    Region-level failures propagate (see ``_scan_recognizers_region`` docstring
    for the rationale); malformed individual classifiers are skipped and logged.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    utils.log_info(f"Collecting document classifiers in {region}...")
    comprehend_client = utils.get_boto3_client('comprehend', region_name=region)

    region_classifiers = []
    paginator = comprehend_client.get_paginator('list_document_classifiers')
    for page in paginator.paginate():
        classifiers = page.get('DocumentClassifierPropertiesList', [])

        for classifier in classifiers:
            try:
                region_classifiers.append(_build_classifier_row(classifier, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed document classifier in {region}: "
                    f"{classifier.get('DocumentClassifierArn', '<unknown>')}",
                    e,
                )
                continue

    utils.log_info(f"Collected {len(region_classifiers)} document classifiers in {region}")
    return region_classifiers


def collect_document_classifiers(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect custom document classifier information across regions, surfacing failures.

    Returns:
        tuple: ``(classifiers, failed_regions)`` where ``failed_regions`` is a
        list of ``(region, error_message)`` tuples.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_classifiers_region,
        show_progress=True,
        collect_failures=True,
    )
    all_classifiers = [c for result in region_results for c in result]
    utils.log_info(f"Collected {len(all_classifiers)} document classifiers total")
    return all_classifiers, failed_regions


def _build_endpoint_row(endpoint: dict, region: str) -> dict[str, Any]:
    """Build a single endpoint export row from a list_endpoints entry."""
    endpoint_arn = endpoint.get('EndpointArn', 'N/A')
    status = endpoint.get('Status', 'N/A')

    # Model ARN
    model_arn = endpoint.get('ModelArn', 'N/A')

    # Extract model type
    model_type = 'N/A'
    if 'entity-recognizer' in model_arn:
        model_type = 'Entity Recognizer'
    elif 'document-classifier' in model_arn:
        model_type = 'Document Classifier'

    # Extract endpoint name from ARN
    endpoint_name = 'N/A'
    if endpoint_arn != 'N/A' and '/' in endpoint_arn:
        endpoint_name = endpoint_arn.split('/')[-1]

    # Desired inference units
    desired_inference_units = endpoint.get('DesiredInferenceUnits', 0)
    current_inference_units = endpoint.get('CurrentInferenceUnits', 0)

    creation_time = endpoint.get('CreationTime', 'N/A')
    if creation_time != 'N/A':
        creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

    last_modified = endpoint.get('LastModifiedTime', 'N/A')
    if last_modified != 'N/A':
        last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')

    # Data access role
    data_access_role = endpoint.get('DataAccessRoleArn', 'N/A')

    # Message
    message = endpoint.get('Message', 'N/A')

    return {
        'Region': region,
        'Endpoint Name': endpoint_name,
        'ARN': endpoint_arn,
        'Status': status,
        'Model Type': model_type,
        'Model ARN': model_arn,
        'Created': creation_time,
        'Last Modified': last_modified,
        'Desired Inference Units': desired_inference_units,
        'Current Inference Units': current_inference_units,
        'Data Access Role ARN': data_access_role,
        'Message': message
    }


def _scan_endpoints_region(region: str) -> list[dict[str, Any]]:
    """
    Collect Comprehend endpoints from a single region.

    Region-level failures propagate (see ``_scan_recognizers_region`` docstring
    for the rationale); malformed individual endpoints are skipped and logged.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    utils.log_info(f"Collecting endpoints in {region}...")
    comprehend_client = utils.get_boto3_client('comprehend', region_name=region)

    region_endpoints = []
    paginator = comprehend_client.get_paginator('list_endpoints')
    for page in paginator.paginate():
        endpoints = page.get('EndpointPropertiesList', [])

        for endpoint in endpoints:
            try:
                region_endpoints.append(_build_endpoint_row(endpoint, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed endpoint in {region}: "
                    f"{endpoint.get('EndpointArn', '<unknown>')}",
                    e,
                )
                continue

    utils.log_info(f"Collected {len(region_endpoints)} endpoints in {region}")
    return region_endpoints


def collect_endpoints(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect Comprehend endpoint information across regions, surfacing failures.

    Returns:
        tuple: ``(endpoints, failed_regions)`` where ``failed_regions`` is a
        list of ``(region, error_message)`` tuples.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_endpoints_region,
        show_progress=True,
        collect_failures=True,
    )
    all_endpoints = [e for result in region_results for e in result]
    utils.log_info(f"Collected {len(all_endpoints)} endpoints total")
    return all_endpoints, failed_regions


def _build_classification_job_row(job: dict, region: str) -> dict[str, Any]:
    """Build a single document classification job export row."""
    job_id = job.get('JobId', 'N/A')
    job_name = job.get('JobName', 'N/A')
    job_status = job.get('JobStatus', 'N/A')

    submit_time = job.get('SubmitTime', 'N/A')
    if submit_time != 'N/A':
        submit_time = submit_time.strftime('%Y-%m-%d %H:%M:%S')

    end_time = job.get('EndTime', 'N/A')
    if end_time != 'N/A':
        end_time = end_time.strftime('%Y-%m-%d %H:%M:%S')

    # Document classifier ARN
    document_classifier_arn = job.get('DocumentClassifierArn', 'N/A')

    # Input config
    input_config = job.get('InputDataConfig', {}) or {}
    input_s3_uri = input_config.get('S3Uri', 'N/A')

    # Output config
    output_config = job.get('OutputDataConfig', {}) or {}
    output_s3_uri = output_config.get('S3Uri', 'N/A')

    # Data access role
    data_access_role = job.get('DataAccessRoleArn', 'N/A')

    # Message
    message = job.get('Message', 'N/A')

    return {
        'Region': region,
        'Job ID': job_id,
        'Job Name': job_name,
        'Status': job_status,
        'Submitted': submit_time,
        'Ended': end_time,
        'Document Classifier ARN': document_classifier_arn,
        'Input S3 URI': input_s3_uri,
        'Output S3 URI': output_s3_uri,
        'Data Access Role ARN': data_access_role,
        'Message': message
    }


def _scan_classification_jobs_region(region: str) -> list[dict[str, Any]]:
    """
    Collect document classification jobs (limited to 30 most recent) from a
    single region.

    Region-level failures propagate (see ``_scan_recognizers_region`` docstring
    for the rationale); malformed individual jobs are skipped and logged.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    utils.log_info(f"Collecting document classification jobs in {region}...")
    comprehend_client = utils.get_boto3_client('comprehend', region_name=region)

    region_jobs = []
    paginator = comprehend_client.get_paginator('list_document_classification_jobs')
    job_count = 0
    for page in paginator.paginate(PaginationConfig={'MaxItems': 30}):
        jobs = page.get('DocumentClassificationJobPropertiesList', [])

        for job in jobs:
            try:
                region_jobs.append(_build_classification_job_row(job, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed document classification job in {region}: "
                    f"{job.get('JobId', '<unknown>')}",
                    e,
                )
            finally:
                job_count += 1

            if job_count >= 30:
                break

    utils.log_info(f"Collected {len(region_jobs)} document classification jobs in {region}")
    return region_jobs


def collect_document_classification_jobs(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect document classification job information across regions, surfacing
    failures.

    Returns:
        tuple: ``(jobs, failed_regions)`` where ``failed_regions`` is a list of
        ``(region, error_message)`` tuples.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_classification_jobs_region,
        show_progress=True,
        collect_failures=True,
    )
    all_jobs = [j for result in region_results for j in result]
    utils.log_info(f"Collected {len(all_jobs)} document classification jobs total (limited to 30 most recent per region)")
    return all_jobs, failed_regions


def _build_entities_job_row(job: dict, region: str) -> dict[str, Any]:
    """Build a single entities detection job export row."""
    job_id = job.get('JobId', 'N/A')
    job_name = job.get('JobName', 'N/A')
    job_status = job.get('JobStatus', 'N/A')
    language_code = job.get('LanguageCode', 'N/A')

    submit_time = job.get('SubmitTime', 'N/A')
    if submit_time != 'N/A':
        submit_time = submit_time.strftime('%Y-%m-%d %H:%M:%S')

    end_time = job.get('EndTime', 'N/A')
    if end_time != 'N/A':
        end_time = end_time.strftime('%Y-%m-%d %H:%M:%S')

    # Entity recognizer ARN (if custom)
    entity_recognizer_arn = job.get('EntityRecognizerArn', 'Built-in')

    # Input config
    input_config = job.get('InputDataConfig', {}) or {}
    input_s3_uri = input_config.get('S3Uri', 'N/A')

    # Output config
    output_config = job.get('OutputDataConfig', {}) or {}
    output_s3_uri = output_config.get('S3Uri', 'N/A')

    # Data access role
    data_access_role = job.get('DataAccessRoleArn', 'N/A')

    # Message
    message = job.get('Message', 'N/A')

    return {
        'Region': region,
        'Job ID': job_id,
        'Job Name': job_name,
        'Status': job_status,
        'Language': language_code,
        'Submitted': submit_time,
        'Ended': end_time,
        'Entity Recognizer ARN': entity_recognizer_arn,
        'Input S3 URI': input_s3_uri,
        'Output S3 URI': output_s3_uri,
        'Data Access Role ARN': data_access_role,
        'Message': message
    }


def _scan_entities_jobs_region(region: str) -> list[dict[str, Any]]:
    """
    Collect entities detection jobs (limited to 30 most recent) from a single
    region.

    Region-level failures propagate (see ``_scan_recognizers_region`` docstring
    for the rationale); malformed individual jobs are skipped and logged.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    utils.log_info(f"Collecting entities detection jobs in {region}...")
    comprehend_client = utils.get_boto3_client('comprehend', region_name=region)

    region_jobs = []
    paginator = comprehend_client.get_paginator('list_entities_detection_jobs')
    job_count = 0
    for page in paginator.paginate(PaginationConfig={'MaxItems': 30}):
        jobs = page.get('EntitiesDetectionJobPropertiesList', [])

        for job in jobs:
            try:
                region_jobs.append(_build_entities_job_row(job, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed entities detection job in {region}: "
                    f"{job.get('JobId', '<unknown>')}",
                    e,
                )
            finally:
                job_count += 1

            if job_count >= 30:
                break

    utils.log_info(f"Collected {len(region_jobs)} entities detection jobs in {region}")
    return region_jobs


def collect_entities_detection_jobs(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect entities detection job information across regions, surfacing
    failures.

    Returns:
        tuple: ``(jobs, failed_regions)`` where ``failed_regions`` is a list of
        ``(region, error_message)`` tuples.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_entities_jobs_region,
        show_progress=True,
        collect_failures=True,
    )
    all_jobs = [j for result in region_results for j in result]
    utils.log_info(f"Collected {len(all_jobs)} entities detection jobs total (limited to 30 most recent per region)")
    return all_jobs, failed_regions


def generate_summary(recognizers: list[dict[str, Any]],
                     classifiers: list[dict[str, Any]],
                     endpoints: list[dict[str, Any]],
                     classification_jobs: list[dict[str, Any]],
                     entities_jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate summary statistics for Comprehend resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Entity recognizers
    total_recognizers = len(recognizers)
    trained_recognizers = sum(1 for r in recognizers if r.get('Status', '') == 'TRAINED')

    summary.append({
        'Metric': 'Total Entity Recognizers',
        'Count': total_recognizers,
        'Details': f'Trained: {trained_recognizers}'
    })

    # Document classifiers
    total_classifiers = len(classifiers)
    trained_classifiers = sum(1 for c in classifiers if c.get('Status', '') == 'TRAINED')

    summary.append({
        'Metric': 'Total Document Classifiers',
        'Count': total_classifiers,
        'Details': f'Trained: {trained_classifiers}'
    })

    # Endpoints
    total_endpoints = len(endpoints)
    in_service_endpoints = sum(1 for e in endpoints if e.get('Status', '') == 'IN_SERVICE')

    summary.append({
        'Metric': 'Total Endpoints',
        'Count': total_endpoints,
        'Details': f'In Service: {in_service_endpoints}'
    })

    # Classification jobs
    total_classification = len(classification_jobs)
    completed_classification = sum(1 for j in classification_jobs if j.get('Status', '') == 'COMPLETED')

    summary.append({
        'Metric': 'Document Classification Jobs (Sample)',
        'Count': total_classification,
        'Details': f'Completed: {completed_classification}'
    })

    # Entities detection jobs
    total_entities = len(entities_jobs)
    completed_entities = sum(1 for j in entities_jobs if j.get('Status', '') == 'COMPLETED')

    summary.append({
        'Metric': 'Entities Detection Jobs (Sample)',
        'Count': total_entities,
        'Details': f'Completed: {completed_entities}'
    })

    # Language distribution
    if recognizers:
        df = pd.DataFrame(recognizers)
        languages = df['Language'].value_counts().to_dict()
        for language, count in languages.items():
            summary.append({
                'Metric': f'Entity Recognizers - {language}',
                'Count': count,
                'Details': 'Language distribution'
            })

    return summary


def main():
    """Main execution function."""
    if not utils.ensure_dependencies('pandas', 'openpyxl'):
        return
    global pd
    import pandas as pd
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    partition = utils.detect_partition()
    if not utils.is_service_available_in_partition("comprehend", partition):
        utils.log_warning("Amazon Comprehend is not available in AWS GovCloud. Skipping.")
        sys.exit(0)

    account_id, account_name = utils.print_script_banner("AWS AMAZON COMPREHEND EXPORT")
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({utils.mask_account_id(account_id)})")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    # Collect data
    print("\nCollecting Amazon Comprehend data...")

    # Each scope is a region-scanned collector that raises on region-level
    # failure; failures accumulate into one combined list that drives a
    # single failure marker + exit code below (see
    # .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).
    recognizers, failed_recognizers = collect_entity_recognizers(regions)
    classifiers, failed_classifiers = collect_document_classifiers(regions)
    endpoints, failed_endpoints = collect_endpoints(regions)
    classification_jobs, failed_classification_jobs = collect_document_classification_jobs(regions)
    entities_jobs, failed_entities_jobs = collect_entities_detection_jobs(regions)

    failed_regions = (
        failed_recognizers
        + failed_classifiers
        + failed_endpoints
        + failed_classification_jobs
        + failed_entities_jobs
    )

    summary = generate_summary(recognizers, classifiers, endpoints,
                                classification_jobs, entities_jobs)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if recognizers:
        df_recognizers = pd.DataFrame(recognizers)
        df_recognizers = utils.prepare_dataframe_for_export(df_recognizers)
        dataframes['Entity Recognizers'] = df_recognizers

    if classifiers:
        df_classifiers = pd.DataFrame(classifiers)
        df_classifiers = utils.prepare_dataframe_for_export(df_classifiers)
        dataframes['Document Classifiers'] = df_classifiers

    if endpoints:
        df_endpoints = pd.DataFrame(endpoints)
        df_endpoints = utils.prepare_dataframe_for_export(df_endpoints)
        dataframes['Endpoints'] = df_endpoints

    if classification_jobs:
        df_classification = pd.DataFrame(classification_jobs)
        df_classification = utils.prepare_dataframe_for_export(df_classification)
        dataframes['Classification Jobs'] = df_classification

    if entities_jobs:
        df_entities = pd.DataFrame(entities_jobs)
        df_entities = utils.prepare_dataframe_for_export(df_entities)
        dataframes['Entities Detection Jobs'] = df_entities

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export whatever succeeded first — a partial export is required even
    # when some regions failed (see the silent-collection-failure blast-radius audit).
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'comprehend', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
    elif not failed_regions:
        # Genuinely empty account: every region succeeded and returned nothing.
        utils.log_warning("No Amazon Comprehend data found to export")

    # If ANY region failed ANY scope collection, make it loud: write a marker
    # and exit non-zero, even if some data was exported. A partial export
    # that looks complete is exactly the failure mode this guards against.
    if failed_regions:
        utils.report_collection_failures(account_name, 'comprehend', failed_regions)
        print(
            "\nERROR: Amazon Comprehend export completed with failures — data is incomplete. "
            "See the *-comprehend-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)

    utils.log_success("Amazon Comprehend export completed successfully")


if __name__ == "__main__":
    main()

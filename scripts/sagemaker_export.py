#!/usr/bin/env python3
"""
SageMaker Export Script for StratusScan

Exports comprehensive Amazon SageMaker machine learning information including:
- Notebook instances for ML development
- Training jobs and model training configurations
- Models and model packages
- Endpoints and endpoint configurations for inference
- Processing jobs for data processing
- Transform jobs for batch inference

Output: Multi-worksheet Excel file with SageMaker resources
"""

import json
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
args = utils.parse_script_args("Export Amazon SageMaker resources to Excel")



def _load_sagemaker_pricing_data(region: str) -> dict[str, dict[str, float]]:
    """Load SageMaker on-demand pricing for ml.* instance types.

    Returns dict: {instance_type: {'hourly': float, 'monthly': float}}
    Training cost = (billable_seconds / 3600) x instances x hourly.
    Notebooks/endpoints use monthly for 730 hr/mo estimates.
    """
    pricing_file = Path(__file__).parent.parent / 'reference' / 'sagemaker-pricing.json'
    try:
        with open(pricing_file, encoding='utf-8') as fh:
            data = json.load(fh)
        records = data.get('records', {})
        partition = utils.detect_partition(region)
        price_region = 'us-gov-west-1' if partition == 'aws-us-gov' else 'us-east-1'
        pricing = {}
        for instance_type, info in records.items():
            region_pricing = (info.get('pricing') or {}).get(price_region)
            if region_pricing:
                hourly = region_pricing.get('on_demand_hourly_usd')
                monthly = region_pricing.get('on_demand_monthly_usd')
                if hourly is not None:
                    pricing[instance_type] = {
                        'hourly': float(hourly),
                        'monthly': float(monthly) if monthly is not None else round(float(hourly) * 730, 2),
                    }
        return pricing
    except Exception:
        return {}


def _build_notebook_row(notebook: dict, region: str, sagemaker_client, sm_pricing_data: dict) -> dict[str, Any]:
    """
    Build the export row for a single SageMaker notebook instance.

    Extracted so per-notebook processing can be wrapped in try/except by the
    caller: a malformed/unreachable notebook is logged and skipped rather
    than discarding the whole region's results.
    """
    notebook_name = notebook.get('NotebookInstanceName', 'N/A')

    notebook_response = sagemaker_client.describe_notebook_instance(
        NotebookInstanceName=notebook_name
    )

    instance_type = notebook_response.get('InstanceType', 'N/A')
    status = notebook_response.get('NotebookInstanceStatus', 'N/A')
    arn = notebook_response.get('NotebookInstanceArn', 'N/A')

    creation_time = notebook_response.get('CreationTime', 'N/A')
    if creation_time != 'N/A':
        creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

    last_modified = notebook_response.get('LastModifiedTime', 'N/A')
    if last_modified != 'N/A':
        last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')

    # Network configuration
    subnet_id = notebook_response.get('SubnetId', 'N/A')
    security_groups = notebook_response.get('SecurityGroups', [])
    security_groups_str = ', '.join(security_groups) if security_groups else 'None'

    # Access settings
    direct_internet_access = notebook_response.get('DirectInternetAccess', 'Enabled')
    root_access = notebook_response.get('RootAccess', 'Enabled')

    # IAM role
    role_arn = notebook_response.get('RoleArn', 'N/A')

    # Volume settings
    volume_size_gb = notebook_response.get('VolumeSizeInGB', 'N/A')

    # Platform identifier
    platform_identifier = notebook_response.get('PlatformIdentifier', 'N/A')

    # URL
    url = notebook_response.get('Url', 'N/A')

    # Lifecycle config
    lifecycle_config = notebook_response.get('NotebookInstanceLifecycleConfigName', 'None')

    # KMS key
    kms_key = notebook_response.get('KmsKeyId', 'None')

    # Failure reason
    failure_reason = notebook_response.get('FailureReason', 'N/A')

    # Cost estimation — monthly if always running; $0 when stopped
    nb_pricing = sm_pricing_data.get(instance_type, {})
    if status == 'InService' and nb_pricing:
        monthly_cost = nb_pricing['monthly']
        cost_note = 'Estimate: monthly if running 24/7; $0 when stopped'
    elif status == 'Stopped':
        monthly_cost = 0.0
        cost_note = 'No compute charge while stopped'
    elif nb_pricing:
        monthly_cost = 'N/A'
        cost_note = f'Status={status}; cost not estimated'
    else:
        monthly_cost = 'N/A'
        cost_note = 'Instance type not in pricing data'

    return {
        'Region': region,
        'Notebook Name': notebook_name,
        'ARN': arn,
        'Status': status,
        'Instance Type': instance_type,
        'Platform': platform_identifier,
        'Created': creation_time,
        'Last Modified': last_modified,
        'Volume Size (GB)': volume_size_gb,
        'Direct Internet Access': direct_internet_access,
        'Root Access': root_access,
        'Subnet ID': subnet_id,
        'Security Groups': security_groups_str,
        'IAM Role ARN': role_arn,
        'Lifecycle Config': lifecycle_config,
        'KMS Key': kms_key,
        'URL': url,
        'Failure Reason': failure_reason,
        'Monthly Cost (On-Demand)': monthly_cost,
        'Cost Note': cost_note,
    }


def _scan_notebook_instances_region(region: str) -> list[dict[str, Any]]:
    """
    Scan SageMaker notebook instances in a single region.

    This is the primary scope collector. It deliberately does NOT swallow
    errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the
    region as failed instead of silently reporting "no notebook instances"
    (the silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed/unreachable notebook instances are skipped (logged)
    rather than aborting the whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_notebooks = []
    sagemaker_client = utils.get_boto3_client('sagemaker', region_name=region)
    sm_pricing_data = _load_sagemaker_pricing_data(region)

    paginator = sagemaker_client.get_paginator('list_notebook_instances')
    for page in paginator.paginate():
        notebooks = page.get('NotebookInstances', [])

        for notebook in notebooks:
            notebook_name = notebook.get('NotebookInstanceName', '<unknown>')
            try:
                regional_notebooks.append(
                    _build_notebook_row(notebook, region, sagemaker_client, sm_pricing_data)
                )
            except Exception as e:
                utils.log_warning(f"Could not get details for notebook {notebook_name} in {region}: {str(e)}")
                continue

    return regional_notebooks


def collect_notebook_instances(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect SageMaker notebook instance information across regions, surfacing
    failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Returns:
        tuple: ``(notebooks, failed_regions)`` where ``failed_regions`` is a
        list of ``(region, error_message)`` tuples.
    """
    print("\n=== COLLECTING SAGEMAKER NOTEBOOK INSTANCES ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_notebook_instances_region,
        show_progress=True,
        collect_failures=True,
    )
    all_notebooks = [nb for result in region_results for nb in result]
    utils.log_success(f"Total notebook instances collected: {len(all_notebooks)}")
    return all_notebooks, failed_regions


def _build_training_job_row(job: dict, region: str, sagemaker_client, sm_pricing_data: dict) -> dict[str, Any]:
    """Build the export row for a single SageMaker training job."""
    job_name = job.get('TrainingJobName', 'N/A')

    job_response = sagemaker_client.describe_training_job(TrainingJobName=job_name)

    status = job_response.get('TrainingJobStatus', 'N/A')
    arn = job_response.get('TrainingJobArn', 'N/A')

    creation_time = job_response.get('CreationTime', 'N/A')
    if creation_time != 'N/A':
        creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

    training_start = job_response.get('TrainingStartTime', 'N/A')
    if training_start != 'N/A':
        training_start = training_start.strftime('%Y-%m-%d %H:%M:%S')

    training_end = job_response.get('TrainingEndTime', 'N/A')
    if training_end != 'N/A':
        training_end = training_end.strftime('%Y-%m-%d %H:%M:%S')

    # Training duration
    training_time_seconds = job_response.get('TrainingTimeInSeconds', 0)
    training_time_str = f"{training_time_seconds / 60:.1f} minutes" if training_time_seconds else 'N/A'

    # Billable time
    billable_seconds = job_response.get('BillableTimeInSeconds', 0)
    billable_time_str = f"{billable_seconds / 60:.1f} minutes" if billable_seconds else 'N/A'

    # Algorithm
    algorithm_spec = job_response.get('AlgorithmSpecification', {})
    training_image = algorithm_spec.get('TrainingImage', 'N/A')
    algorithm_name = algorithm_spec.get('AlgorithmName', 'N/A')

    # Extract algorithm type from image
    algorithm_type = 'Custom'
    if 'xgboost' in training_image.lower():
        algorithm_type = 'XGBoost'
    elif 'blazingtext' in training_image.lower():
        algorithm_type = 'BlazingText'
    elif 'linear-learner' in training_image.lower():
        algorithm_type = 'Linear Learner'
    elif algorithm_name != 'N/A':
        algorithm_type = algorithm_name

    # Resource config
    resource_config = job_response.get('ResourceConfig', {})
    instance_type = resource_config.get('InstanceType', 'N/A')
    instance_count = resource_config.get('InstanceCount', 0)
    volume_size_gb = resource_config.get('VolumeSizeInGB', 'N/A')

    # Hyperparameters
    hyperparameters = job_response.get('HyperParameters', {})
    hyperparam_count = len(hyperparameters)

    # Metrics
    final_metrics = job_response.get('FinalMetricDataList', [])
    metric_count = len(final_metrics)

    # Output
    model_artifacts = job_response.get('ModelArtifacts', {})
    s3_model_artifacts = model_artifacts.get('S3ModelArtifacts', 'N/A')

    # Failure reason
    failure_reason = job_response.get('FailureReason', 'N/A')

    # Actual job cost from billable seconds (only meaningful for Completed)
    tj_pricing = sm_pricing_data.get(instance_type, {})
    if status == 'Completed' and billable_seconds and instance_count and tj_pricing:
        actual_cost = round((billable_seconds / 3600) * instance_count * tj_pricing['hourly'], 4)
        cost_note = 'Actual: (billable_sec / 3600) x instances x on-demand rate'
    elif status == 'Completed' and not tj_pricing:
        actual_cost = 'N/A'
        cost_note = 'Instance type not in pricing data'
    else:
        actual_cost = 'N/A'
        cost_note = f'Status={status}; actual cost unavailable'

    return {
        'Region': region,
        'Job Name': job_name,
        'ARN': arn,
        'Status': status,
        'Algorithm Type': algorithm_type,
        'Instance Type': instance_type,
        'Instance Count': instance_count,
        'Volume Size (GB)': volume_size_gb,
        'Created': creation_time,
        'Training Start': training_start,
        'Training End': training_end,
        'Training Time': training_time_str,
        'Billable Time': billable_time_str,
        'Hyperparameters': hyperparam_count,
        'Final Metrics': metric_count,
        'Model Artifacts': s3_model_artifacts,
        'Failure Reason': failure_reason,
        'Job Cost (On-Demand)': actual_cost,
        'Cost Note': cost_note,
    }


def _scan_training_jobs_region(region: str) -> list[dict[str, Any]]:
    """
    Scan SageMaker training jobs in a single region (limited to 50 most
    recent). Raises on scope-level failure; per-job failures are skipped.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_jobs = []
    sagemaker_client = utils.get_boto3_client('sagemaker', region_name=region)
    sm_pricing_data = _load_sagemaker_pricing_data(region)

    paginator = sagemaker_client.get_paginator('list_training_jobs')
    job_count = 0
    for page in paginator.paginate(
        SortBy='CreationTime',
        SortOrder='Descending',
        PaginationConfig={'MaxItems': 50}
    ):
        jobs = page.get('TrainingJobSummaries', [])

        for job in jobs:
            job_name = job.get('TrainingJobName', '<unknown>')
            try:
                regional_jobs.append(
                    _build_training_job_row(job, region, sagemaker_client, sm_pricing_data)
                )
            except Exception as e:
                utils.log_warning(f"Could not get details for training job {job_name}: {str(e)}")
                continue

            job_count += 1

        if job_count >= 50:
            break

    return regional_jobs


def collect_training_jobs(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """Collect SageMaker training job information (limited to recent 50 per region), surfacing failures."""
    print("\n=== COLLECTING SAGEMAKER TRAINING JOBS ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_training_jobs_region,
        show_progress=True,
        collect_failures=True,
    )
    all_jobs = [job for result in region_results for job in result]
    utils.log_success(f"Total training jobs collected: {len(all_jobs)} (limited to 50 per region)")
    return all_jobs, failed_regions


def _build_model_row(model: dict, region: str, sagemaker_client) -> dict[str, Any]:
    """Build the export row for a single SageMaker model."""
    model_name = model.get('ModelName', 'N/A')

    model_response = sagemaker_client.describe_model(ModelName=model_name)

    arn = model_response.get('ModelArn', 'N/A')
    role_arn = model_response.get('ExecutionRoleArn', 'N/A')

    creation_time = model_response.get('CreationTime', 'N/A')
    if creation_time != 'N/A':
        creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

    # Primary container
    primary_container = model_response.get('PrimaryContainer', {})
    container_image = primary_container.get('Image', 'N/A')
    model_data_url = primary_container.get('ModelDataUrl', 'N/A')
    container_mode = primary_container.get('Mode', 'N/A')

    # VPC config
    vpc_config = model_response.get('VpcConfig', {})
    subnets = vpc_config.get('Subnets', [])
    vpc_enabled = 'Yes' if subnets else 'No'

    # Network isolation
    enable_network_isolation = model_response.get('EnableNetworkIsolation', False)

    # Containers
    containers = model_response.get('Containers', [])
    container_count = len(containers) if containers else (1 if primary_container else 0)

    return {
        'Region': region,
        'Model Name': model_name,
        'ARN': arn,
        'Created': creation_time,
        'Execution Role ARN': role_arn,
        'Container Image': container_image,
        'Model Data URL': model_data_url,
        'Container Mode': container_mode,
        'Container Count': container_count,
        'VPC Enabled': vpc_enabled,
        'Network Isolation': enable_network_isolation
    }


def _scan_models_region(region: str) -> list[dict[str, Any]]:
    """
    Scan SageMaker models in a single region. Raises on scope-level failure;
    per-model failures are skipped.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_models = []
    sagemaker_client = utils.get_boto3_client('sagemaker', region_name=region)

    paginator = sagemaker_client.get_paginator('list_models')
    for page in paginator.paginate():
        models = page.get('Models', [])

        for model in models:
            model_name = model.get('ModelName', '<unknown>')
            try:
                regional_models.append(_build_model_row(model, region, sagemaker_client))
            except Exception as e:
                utils.log_warning(f"Could not get details for model {model_name}: {str(e)}")
                continue

    return regional_models


def collect_models(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """Collect SageMaker model information, surfacing failures."""
    print("\n=== COLLECTING SAGEMAKER MODELS ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_models_region,
        show_progress=True,
        collect_failures=True,
    )
    all_models = [model for result in region_results for model in result]
    utils.log_success(f"Total models collected: {len(all_models)}")
    return all_models, failed_regions


def _build_endpoint_row(endpoint: dict, region: str, sagemaker_client, sm_pricing_data: dict) -> dict[str, Any]:
    """Build the export row for a single SageMaker endpoint."""
    endpoint_name = endpoint.get('EndpointName', 'N/A')

    endpoint_response = sagemaker_client.describe_endpoint(EndpointName=endpoint_name)

    status = endpoint_response.get('EndpointStatus', 'N/A')
    arn = endpoint_response.get('EndpointArn', 'N/A')
    config_name = endpoint_response.get('EndpointConfigName', 'N/A')

    creation_time = endpoint_response.get('CreationTime', 'N/A')
    if creation_time != 'N/A':
        creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

    last_modified = endpoint_response.get('LastModifiedTime', 'N/A')
    if last_modified != 'N/A':
        last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')

    # Production variants
    production_variants = endpoint_response.get('ProductionVariants', [])
    variant_count = len(production_variants)

    # Get instance info from first variant
    instance_type = 'N/A'
    current_instance_count = 0
    desired_instance_count = 0

    if production_variants:
        first_variant = production_variants[0]
        instance_type = first_variant.get('InstanceType', 'N/A')
        current_instance_count = first_variant.get('CurrentInstanceCount', 0)
        desired_instance_count = first_variant.get('DesiredInstanceCount', 0)

    # Data capture config
    data_capture_config = endpoint_response.get('DataCaptureConfig', {})
    data_capture_enabled = data_capture_config.get('EnableCapture', False)

    # Failure reason
    failure_reason = endpoint_response.get('FailureReason', 'N/A')

    # Monthly cost for InService endpoints (first variant × current count)
    ep_pricing = sm_pricing_data.get(instance_type, {})
    instance_count_for_cost = current_instance_count or desired_instance_count
    if status == 'InService' and ep_pricing and instance_count_for_cost:
        monthly_cost = round(ep_pricing['monthly'] * instance_count_for_cost, 2)
        cost_note = 'Estimate: first variant × instance count × 730 hr/mo; multi-variant may be higher'
    elif status == 'InService' and not ep_pricing:
        monthly_cost = 'N/A'
        cost_note = 'Instance type not in pricing data'
    else:
        monthly_cost = 'N/A'
        cost_note = f'Status={status}; cost not estimated'

    return {
        'Region': region,
        'Endpoint Name': endpoint_name,
        'ARN': arn,
        'Status': status,
        'Config Name': config_name,
        'Created': creation_time,
        'Last Modified': last_modified,
        'Instance Type': instance_type,
        'Current Instances': current_instance_count,
        'Desired Instances': desired_instance_count,
        'Production Variants': variant_count,
        'Data Capture Enabled': data_capture_enabled,
        'Failure Reason': failure_reason,
        'Monthly Cost (On-Demand)': monthly_cost,
        'Cost Note': cost_note,
    }


def _scan_endpoints_region(region: str) -> list[dict[str, Any]]:
    """
    Scan SageMaker endpoints in a single region. Raises on scope-level
    failure; per-endpoint failures are skipped.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_endpoints = []
    sagemaker_client = utils.get_boto3_client('sagemaker', region_name=region)
    sm_pricing_data = _load_sagemaker_pricing_data(region)

    paginator = sagemaker_client.get_paginator('list_endpoints')
    for page in paginator.paginate():
        endpoints = page.get('Endpoints', [])

        for endpoint in endpoints:
            endpoint_name = endpoint.get('EndpointName', '<unknown>')
            try:
                regional_endpoints.append(
                    _build_endpoint_row(endpoint, region, sagemaker_client, sm_pricing_data)
                )
            except Exception as e:
                utils.log_warning(f"Could not get details for endpoint {endpoint_name}: {str(e)}")
                continue

    return regional_endpoints


def collect_endpoints(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """Collect SageMaker endpoint information, surfacing failures."""
    print("\n=== COLLECTING SAGEMAKER ENDPOINTS ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_endpoints_region,
        show_progress=True,
        collect_failures=True,
    )
    all_endpoints = [ep for result in region_results for ep in result]
    utils.log_success(f"Total endpoints collected: {len(all_endpoints)}")
    return all_endpoints, failed_regions


def _build_processing_job_row(job: dict, region: str) -> dict[str, Any]:
    """Build the export row for a single SageMaker processing job summary."""
    job_name = job.get('ProcessingJobName', 'N/A')
    status = job.get('ProcessingJobStatus', 'N/A')
    arn = job.get('ProcessingJobArn', 'N/A')

    creation_time = job.get('CreationTime', 'N/A')
    if creation_time != 'N/A':
        creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

    processing_end = job.get('ProcessingEndTime', 'N/A')
    if processing_end != 'N/A':
        processing_end = processing_end.strftime('%Y-%m-%d %H:%M:%S')

    failure_reason = job.get('FailureReason', 'N/A')

    return {
        'Region': region,
        'Job Name': job_name,
        'ARN': arn,
        'Status': status,
        'Created': creation_time,
        'Processing End': processing_end,
        'Failure Reason': failure_reason
    }


def _scan_processing_jobs_region(region: str) -> list[dict[str, Any]]:
    """
    Scan SageMaker processing jobs in a single region (limited to 30 most
    recent). Raises on scope-level failure; per-job failures are skipped.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    regional_jobs = []
    sagemaker_client = utils.get_boto3_client('sagemaker', region_name=region)

    paginator = sagemaker_client.get_paginator('list_processing_jobs')
    job_count = 0
    for page in paginator.paginate(
        SortBy='CreationTime',
        SortOrder='Descending',
        PaginationConfig={'MaxItems': 30}
    ):
        jobs = page.get('ProcessingJobSummaries', [])

        for job in jobs:
            job_name = job.get('ProcessingJobName', '<unknown>')
            try:
                regional_jobs.append(_build_processing_job_row(job, region))
            except Exception as e:
                utils.log_warning(f"Skipping malformed processing job {job_name} in {region}: {str(e)}")
                continue

            job_count += 1
            if job_count >= 30:
                break

    return regional_jobs


def collect_processing_jobs(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """Collect SageMaker processing job information (limited to recent 30 per region), surfacing failures."""
    print("\n=== COLLECTING SAGEMAKER PROCESSING JOBS ===")
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_processing_jobs_region,
        show_progress=True,
        collect_failures=True,
    )
    all_jobs = [job for result in region_results for job in result]
    utils.log_success(f"Total processing jobs collected: {len(all_jobs)} (limited to 30 per region)")
    return all_jobs, failed_regions


def generate_summary(notebooks: list[dict[str, Any]],
                     training_jobs: list[dict[str, Any]],
                     models: list[dict[str, Any]],
                     endpoints: list[dict[str, Any]],
                     processing_jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate summary statistics for SageMaker resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Notebooks summary
    total_notebooks = len(notebooks)
    running_notebooks = sum(1 for n in notebooks if n.get('Status', '') == 'InService')

    summary.append({
        'Metric': 'Total Notebook Instances',
        'Count': total_notebooks,
        'Details': f'Running: {running_notebooks}'
    })

    # Internet access warning
    direct_internet = sum(1 for n in notebooks if n.get('Direct Internet Access', '') == 'Enabled')
    if direct_internet > 0:
        summary.append({
            'Metric': '⚠️ Notebooks with Direct Internet',
            'Count': direct_internet,
            'Details': 'SECURITY: Consider VPC-only access for production notebooks'
        })

    # Training jobs summary
    total_training = len(training_jobs)
    completed_training = sum(1 for j in training_jobs if j.get('Status', '') == 'Completed')
    failed_training = sum(1 for j in training_jobs if j.get('Status', '') == 'Failed')

    summary.append({
        'Metric': 'Total Training Jobs (Sample)',
        'Count': total_training,
        'Details': f'Completed: {completed_training}, Failed: {failed_training}'
    })

    # Models summary
    total_models = len(models)
    summary.append({
        'Metric': 'Total Models',
        'Count': total_models,
        'Details': 'Trained ML models ready for deployment'
    })

    # Endpoints summary
    total_endpoints = len(endpoints)
    in_service_endpoints = sum(1 for e in endpoints if e.get('Status', '') == 'InService')

    summary.append({
        'Metric': 'Total Endpoints',
        'Count': total_endpoints,
        'Details': f'InService: {in_service_endpoints}'
    })

    # Processing jobs summary
    total_processing = len(processing_jobs)
    summary.append({
        'Metric': 'Total Processing Jobs (Sample)',
        'Count': total_processing,
        'Details': 'Data processing and feature engineering jobs'
    })

    # Regional distribution
    if notebooks:
        df = pd.DataFrame(notebooks)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Notebook Instances in {region}',
                'Count': count,
                'Details': 'Regional distribution'
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

    account_id, account_name = utils.print_script_banner("AWS SAGEMAKER EXPORT")
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({utils.mask_account_id(account_id)})")

    # Detect partition for region examples
    regions = utils.prompt_region_selection()
    # Collect data. Each scope collector surfaces its own failed regions
    # (rather than swallowing collection errors into an empty result — see
    # .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md);
    # all scopes' failures are merged below into one combined list.
    print("\nCollecting SageMaker data...")

    notebooks, failed_notebooks = collect_notebook_instances(regions)
    training_jobs, failed_training = collect_training_jobs(regions)
    models, failed_models = collect_models(regions)
    endpoints, failed_endpoints = collect_endpoints(regions)
    processing_jobs, failed_processing = collect_processing_jobs(regions)

    failed_regions = failed_notebooks + failed_training + failed_models + failed_endpoints + failed_processing

    summary = generate_summary(notebooks, training_jobs, models, endpoints, processing_jobs)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if notebooks:
        df_notebooks = pd.DataFrame(notebooks)
        df_notebooks = utils.prepare_dataframe_for_export(df_notebooks)
        dataframes['Notebook Instances'] = df_notebooks

    if training_jobs:
        df_training = pd.DataFrame(training_jobs)
        df_training = utils.prepare_dataframe_for_export(df_training)
        dataframes['Training Jobs'] = df_training

    if models:
        df_models = pd.DataFrame(models)
        df_models = utils.prepare_dataframe_for_export(df_models)
        dataframes['Models'] = df_models

    if endpoints:
        df_endpoints = pd.DataFrame(endpoints)
        df_endpoints = utils.prepare_dataframe_for_export(df_endpoints)
        dataframes['Endpoints'] = df_endpoints

    if processing_jobs:
        df_processing = pd.DataFrame(processing_jobs)
        df_processing = utils.prepare_dataframe_for_export(df_processing)
        dataframes['Processing Jobs'] = df_processing

    # The Summary sheet is always built (even when every scope is empty), so
    # a workbook always lands. Preserve that: it is what keeps this exporter
    # a PARTIAL rather than a VULNERABLE case in the audit.
    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'sagemaker', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
    else:
        utils.log_warning("No SageMaker data found to export")

    # If ANY scope failed to collect in ANY region, make it loud: write a
    # failure marker and exit non-zero, even though the Summary sheet made
    # the workbook look complete. A zero-row sheet that is actually a failed
    # collection (not a genuinely empty account) is exactly the failure mode
    # this guards against.
    if failed_regions:
        utils.report_collection_failures(account_name, 'sagemaker', failed_regions)
        print(
            "\nERROR: SageMaker export completed with failures — data is incomplete. "
            "See the *-sagemaker-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)

    utils.log_success("SageMaker export completed successfully")


if __name__ == "__main__":
    main()

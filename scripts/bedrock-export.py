#!/usr/bin/env python3
"""
Amazon Bedrock Export Script for StratusScan

Exports comprehensive Amazon Bedrock generative AI information including:
- Foundation models available in the region
- Custom models (fine-tuned models)
- Model invocation logging configurations
- Guardrails for responsible AI
- Knowledge bases for RAG applications
- Agents for task automation

Output: Multi-worksheet Excel file with Bedrock resources
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


def check_dependencies():
    """Check if required dependencies are installed."""
    utils.log_info("Checking dependencies...")

    missing = []

    try:
        import pandas
        utils.log_info("✓ pandas is installed")
    except ImportError:
        missing.append("pandas")

    try:
        import openpyxl
        utils.log_info("✓ openpyxl is installed")
    except ImportError:
        missing.append("openpyxl")

    try:
        import boto3
        utils.log_info("✓ boto3 is installed")
    except ImportError:
        missing.append("boto3")

    if missing:
        utils.log_error(f"Missing dependencies: {', '.join(missing)}")
        utils.log_error("Please install using: pip install " + " ".join(missing))
        sys.exit(1)

    utils.log_success("All dependencies are installed")


@utils.aws_error_handler("Collecting Bedrock foundation models", default_return=[])
def collect_foundation_models(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect available Bedrock foundation models from AWS regions."""
    all_models = []

    for region in regions:
        utils.log_info(f"Collecting foundation models in {region}...")
        bedrock_client = utils.get_boto3_client('bedrock', region_name=region)

        try:
            paginator = bedrock_client.get_paginator('list_foundation_models')
            for page in paginator.paginate():
                models = page.get('modelSummaries', [])

                for model in models:
                    model_id = model.get('modelId', 'N/A')
                    model_arn = model.get('modelArn', 'N/A')
                    model_name = model.get('modelName', 'N/A')
                    provider_name = model.get('providerName', 'N/A')

                    # Input/output modalities
                    input_modalities = model.get('inputModalities', [])
                    output_modalities = model.get('outputModalities', [])
                    input_str = ', '.join(input_modalities) if input_modalities else 'N/A'
                    output_str = ', '.join(output_modalities) if output_modalities else 'N/A'

                    # Response streaming
                    response_streaming = model.get('responseStreamingSupported', False)

                    # Customization supported
                    customization_supported = model.get('customizationsSupported', [])
                    customization_str = ', '.join(customization_supported) if customization_supported else 'None'

                    # Inference types
                    inference_types = model.get('inferenceTypesSupported', [])
                    inference_str = ', '.join(inference_types) if inference_types else 'N/A'

                    # Model lifecycle status
                    model_lifecycle = model.get('modelLifecycle', {})
                    lifecycle_status = model_lifecycle.get('status', 'N/A')

                    all_models.append({
                        'Region': region,
                        'Model ID': model_id,
                        'Model Name': model_name,
                        'Provider': provider_name,
                        'ARN': model_arn,
                        'Lifecycle Status': lifecycle_status,
                        'Input Modalities': input_str,
                        'Output Modalities': output_str,
                        'Response Streaming': response_streaming,
                        'Customization Supported': customization_str,
                        'Inference Types': inference_str
                    })

        except Exception as e:
            utils.log_warning(f"Error listing foundation models in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_models)} foundation models")
    return all_models


@utils.aws_error_handler("Collecting Bedrock custom models", default_return=[])
def collect_custom_models(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Bedrock custom (fine-tuned) models."""
    all_custom_models = []

    for region in regions:
        utils.log_info(f"Collecting custom models in {region}...")
        bedrock_client = utils.get_boto3_client('bedrock', region_name=region)

        try:
            paginator = bedrock_client.get_paginator('list_custom_models')
            for page in paginator.paginate():
                models = page.get('modelSummaries', [])

                for model in models:
                    model_arn = model.get('modelArn', 'N/A')
                    model_name = model.get('modelName', 'N/A')
                    base_model_arn = model.get('baseModelArn', 'N/A')

                    creation_time = model.get('creationTime', 'N/A')
                    if creation_time != 'N/A':
                        creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')

                    # Extract base model name from ARN
                    base_model_name = 'N/A'
                    if base_model_arn != 'N/A' and '/' in base_model_arn:
                        base_model_name = base_model_arn.split('/')[-1]

                    # Customization type
                    customization_type = model.get('customizationType', 'N/A')

                    all_custom_models.append({
                        'Region': region,
                        'Model Name': model_name,
                        'Model ARN': model_arn,
                        'Base Model': base_model_name,
                        'Base Model ARN': base_model_arn,
                        'Customization Type': customization_type,
                        'Created': creation_time
                    })

        except Exception as e:
            utils.log_warning(f"Error listing custom models in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_custom_models)} custom models")
    return all_custom_models


@utils.aws_error_handler("Collecting Bedrock model invocation logging", default_return=[])
def collect_model_invocation_logging(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Bedrock model invocation logging configurations."""
    all_logging_configs = []

    for region in regions:
        utils.log_info(f"Collecting model invocation logging config in {region}...")
        bedrock_client = utils.get_boto3_client('bedrock', region_name=region)

        try:
            response = bedrock_client.get_model_invocation_logging_configuration()
            logging_config = response.get('loggingConfig', {})

            if logging_config:
                # CloudWatch Logs
                cloudwatch_config = logging_config.get('cloudWatchConfig', {})
                cloudwatch_enabled = cloudwatch_config.get('logGroupName') is not None
                cloudwatch_log_group = cloudwatch_config.get('logGroupName', 'N/A')
                cloudwatch_role = cloudwatch_config.get('roleArn', 'N/A')

                # S3
                s3_config = logging_config.get('s3Config', {})
                s3_enabled = s3_config.get('bucketName') is not None
                s3_bucket = s3_config.get('bucketName', 'N/A')
                s3_prefix = s3_config.get('keyPrefix', 'N/A')

                # Text data delivery
                text_data_delivery = logging_config.get('textDataDeliveryEnabled', False)
                image_data_delivery = logging_config.get('imageDataDeliveryEnabled', False)
                embedding_data_delivery = logging_config.get('embeddingDataDeliveryEnabled', False)

                all_logging_configs.append({
                    'Region': region,
                    'CloudWatch Enabled': cloudwatch_enabled,
                    'CloudWatch Log Group': cloudwatch_log_group,
                    'CloudWatch Role ARN': cloudwatch_role,
                    'S3 Enabled': s3_enabled,
                    'S3 Bucket': s3_bucket,
                    'S3 Key Prefix': s3_prefix,
                    'Text Data Delivery': text_data_delivery,
                    'Image Data Delivery': image_data_delivery,
                    'Embedding Data Delivery': embedding_data_delivery
                })

        except Exception as e:
            utils.log_warning(f"Error getting model invocation logging config in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_logging_configs)} logging configurations")
    return all_logging_configs


@utils.aws_error_handler("Collecting Bedrock guardrails", default_return=[])
def collect_guardrails(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Bedrock guardrails for responsible AI."""
    all_guardrails = []

    for region in regions:
        utils.log_info(f"Collecting guardrails in {region}...")
        bedrock_client = utils.get_boto3_client('bedrock', region_name=region)

        try:
            paginator = bedrock_client.get_paginator('list_guardrails')
            for page in paginator.paginate():
                guardrails = page.get('guardrails', [])

                for guardrail in guardrails:
                    guardrail_id = guardrail.get('id', 'N/A')
                    guardrail_arn = guardrail.get('arn', 'N/A')
                    guardrail_name = guardrail.get('name', 'N/A')
                    description = guardrail.get('description', 'N/A')
                    version = guardrail.get('version', 'N/A')
                    status = guardrail.get('status', 'N/A')

                    created_at = guardrail.get('createdAt', 'N/A')
                    if created_at != 'N/A':
                        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')

                    updated_at = guardrail.get('updatedAt', 'N/A')
                    if updated_at != 'N/A':
                        updated_at = updated_at.strftime('%Y-%m-%d %H:%M:%S')

                    all_guardrails.append({
                        'Region': region,
                        'Guardrail Name': guardrail_name,
                        'Guardrail ID': guardrail_id,
                        'ARN': guardrail_arn,
                        'Version': version,
                        'Status': status,
                        'Description': description,
                        'Created': created_at,
                        'Updated': updated_at
                    })

        except Exception as e:
            utils.log_warning(f"Error listing guardrails in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_guardrails)} guardrails")
    return all_guardrails


@utils.aws_error_handler("Collecting Bedrock knowledge bases", default_return=[])
def collect_knowledge_bases(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Bedrock knowledge bases for RAG applications."""
    all_knowledge_bases = []

    for region in regions:
        utils.log_info(f"Collecting knowledge bases in {region}...")
        bedrock_agent_client = utils.get_boto3_client('bedrock-agent', region_name=region)

        try:
            paginator = bedrock_agent_client.get_paginator('list_knowledge_bases')
            for page in paginator.paginate():
                knowledge_bases = page.get('knowledgeBaseSummaries', [])

                for kb in knowledge_bases:
                    kb_id = kb.get('knowledgeBaseId', 'N/A')
                    kb_name = kb.get('name', 'N/A')
                    description = kb.get('description', 'N/A')
                    status = kb.get('status', 'N/A')

                    created_at = kb.get('createdAt', 'N/A')
                    if created_at != 'N/A':
                        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')

                    updated_at = kb.get('updatedAt', 'N/A')
                    if updated_at != 'N/A':
                        updated_at = updated_at.strftime('%Y-%m-%d %H:%M:%S')

                    # Get additional details
                    try:
                        kb_details = bedrock_agent_client.get_knowledge_base(
                            knowledgeBaseId=kb_id
                        )
                        kb_data = kb_details.get('knowledgeBase', {})

                        kb_arn = kb_data.get('knowledgeBaseArn', 'N/A')
                        role_arn = kb_data.get('roleArn', 'N/A')

                        # Storage configuration
                        storage_config = kb_data.get('storageConfiguration', {})
                        storage_type = storage_config.get('type', 'N/A')

                        all_knowledge_bases.append({
                            'Region': region,
                            'Knowledge Base Name': kb_name,
                            'Knowledge Base ID': kb_id,
                            'ARN': kb_arn,
                            'Status': status,
                            'Description': description,
                            'Storage Type': storage_type,
                            'Role ARN': role_arn,
                            'Created': created_at,
                            'Updated': updated_at
                        })

                    except Exception as e:
                        utils.log_warning(f"Could not get details for knowledge base {kb_id}: {str(e)}")
                        # Add basic info
                        all_knowledge_bases.append({
                            'Region': region,
                            'Knowledge Base Name': kb_name,
                            'Knowledge Base ID': kb_id,
                            'ARN': 'N/A',
                            'Status': status,
                            'Description': description,
                            'Storage Type': 'N/A',
                            'Role ARN': 'N/A',
                            'Created': created_at,
                            'Updated': updated_at
                        })

        except Exception as e:
            utils.log_warning(f"Error listing knowledge bases in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_knowledge_bases)} knowledge bases")
    return all_knowledge_bases


@utils.aws_error_handler("Collecting Bedrock agents", default_return=[])
def collect_agents(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect Bedrock agents for task automation."""
    all_agents = []

    for region in regions:
        utils.log_info(f"Collecting agents in {region}...")
        bedrock_agent_client = utils.get_boto3_client('bedrock-agent', region_name=region)

        try:
            paginator = bedrock_agent_client.get_paginator('list_agents')
            for page in paginator.paginate():
                agents = page.get('agentSummaries', [])

                for agent in agents:
                    agent_id = agent.get('agentId', 'N/A')
                    agent_name = agent.get('agentName', 'N/A')
                    agent_status = agent.get('agentStatus', 'N/A')
                    description = agent.get('description', 'N/A')
                    latest_agent_version = agent.get('latestAgentVersion', 'N/A')

                    created_at = agent.get('createdAt', 'N/A')
                    if created_at != 'N/A':
                        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')

                    updated_at = agent.get('updatedAt', 'N/A')
                    if updated_at != 'N/A':
                        updated_at = updated_at.strftime('%Y-%m-%d %H:%M:%S')

                    # Get additional details
                    try:
                        agent_details = bedrock_agent_client.get_agent(agentId=agent_id)
                        agent_data = agent_details.get('agent', {})

                        agent_arn = agent_data.get('agentArn', 'N/A')
                        agent_resource_role_arn = agent_data.get('agentResourceRoleArn', 'N/A')
                        foundation_model = agent_data.get('foundationModel', 'N/A')
                        idle_session_ttl = agent_data.get('idleSessionTTLInSeconds', 'N/A')

                        all_agents.append({
                            'Region': region,
                            'Agent Name': agent_name,
                            'Agent ID': agent_id,
                            'ARN': agent_arn,
                            'Status': agent_status,
                            'Latest Version': latest_agent_version,
                            'Foundation Model': foundation_model,
                            'Description': description,
                            'Role ARN': agent_resource_role_arn,
                            'Idle Session TTL (seconds)': idle_session_ttl,
                            'Created': created_at,
                            'Updated': updated_at
                        })

                    except Exception as e:
                        utils.log_warning(f"Could not get details for agent {agent_id}: {str(e)}")
                        # Add basic info
                        all_agents.append({
                            'Region': region,
                            'Agent Name': agent_name,
                            'Agent ID': agent_id,
                            'ARN': 'N/A',
                            'Status': agent_status,
                            'Latest Version': latest_agent_version,
                            'Foundation Model': 'N/A',
                            'Description': description,
                            'Role ARN': 'N/A',
                            'Idle Session TTL (seconds)': 'N/A',
                            'Created': created_at,
                            'Updated': updated_at
                        })

        except Exception as e:
            utils.log_warning(f"Error listing agents in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_agents)} agents")
    return all_agents


def generate_summary(foundation_models: List[Dict[str, Any]],
                     custom_models: List[Dict[str, Any]],
                     logging_configs: List[Dict[str, Any]],
                     guardrails: List[Dict[str, Any]],
                     knowledge_bases: List[Dict[str, Any]],
                     agents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Bedrock resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Foundation models summary
    total_foundation = len(foundation_models)
    summary.append({
        'Metric': 'Total Foundation Models',
        'Count': total_foundation,
        'Details': 'Available pre-trained models from various providers'
    })

    # Model providers
    if foundation_models:
        df = pd.DataFrame(foundation_models)
        providers = df['Provider'].value_counts().to_dict()
        for provider, count in providers.items():
            summary.append({
                'Metric': f'Models from {provider}',
                'Count': count,
                'Details': 'Foundation model provider'
            })

    # Custom models
    total_custom = len(custom_models)
    summary.append({
        'Metric': 'Total Custom Models',
        'Count': total_custom,
        'Details': 'Fine-tuned models based on foundation models'
    })

    # Logging configs
    total_logging = len(logging_configs)
    cloudwatch_enabled = sum(1 for c in logging_configs if c.get('CloudWatch Enabled', False))
    s3_enabled = sum(1 for c in logging_configs if c.get('S3 Enabled', False))

    summary.append({
        'Metric': 'Regions with Logging Configured',
        'Count': total_logging,
        'Details': f'CloudWatch: {cloudwatch_enabled}, S3: {s3_enabled}'
    })

    # Guardrails
    total_guardrails = len(guardrails)
    summary.append({
        'Metric': 'Total Guardrails',
        'Count': total_guardrails,
        'Details': 'Responsible AI guardrails for content filtering'
    })

    # Knowledge bases
    total_kb = len(knowledge_bases)
    summary.append({
        'Metric': 'Total Knowledge Bases',
        'Count': total_kb,
        'Details': 'Knowledge bases for RAG (Retrieval Augmented Generation)'
    })

    # Agents
    total_agents = len(agents)
    summary.append({
        'Metric': 'Total Agents',
        'Count': total_agents,
        'Details': 'Bedrock agents for autonomous task execution'
    })

    # Regional distribution
    if foundation_models:
        df = pd.DataFrame(foundation_models)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Foundation Models in {region}',
                'Count': count,
                'Details': 'Regional model availability'
            })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    print("\n" + "="*60)
    print("Amazon Bedrock Export Tool")
    print("="*60)

    # Check dependencies
    check_dependencies()

    # Get AWS account information
    account_id, account_name = utils.get_account_info()
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({account_id})")

    # Detect partition for region examples
    partition = utils.detect_partition()
    if partition == 'aws-us-gov':
        example_regions = "us-gov-west-1, us-gov-east-1"
    else:
        example_regions = "us-east-1, us-west-1, us-west-2, eu-west-1"

    # Display standardized region selection menu
    print("\n" + "=" * 68)
    print("REGION SELECTION")
    print("=" * 68)
    print("\nAmazon Bedrock is a regional service.")
    print("\nPlease select an option for region selection:")
    print("\n  1. Default Regions")
    print(f"     ({example_regions})")
    print("\n  2. All Available Regions")
    print("     (Scan all regions where Bedrock is available)")
    print("\n  3. Specific Region")
    print("     (Enter a specific AWS region code)")
    print("\n" + "-" * 68)

    # Get and validate region choice
    regions = []
    while not regions:
        try:
            region_choice = input("\nEnter your choice (1, 2, or 3): ").strip()

            if region_choice == '1':
                regions = utils.get_partition_default_regions()
                print(f"\nUsing default regions: {', '.join(regions)}")
            elif region_choice == '2':
                regions = utils.get_partition_regions()
                print(f"\nScanning all {len(regions)} available regions")
            elif region_choice == '3':
                available_regions = utils.get_partition_regions()
                print("\n" + "=" * 68)
                print("AVAILABLE REGIONS")
                print("=" * 68)
                for idx, region in enumerate(available_regions, 1):
                    print(f"  {idx:2d}. {region}")
                print("=" * 68)

                region_input = input("\nEnter region number or region code: ").strip()

                if region_input.isdigit():
                    region_idx = int(region_input)
                    if 1 <= region_idx <= len(available_regions):
                        regions = [available_regions[region_idx - 1]]
                        print(f"\nUsing region: {regions[0]}")
                    else:
                        print(f"\nInvalid region number. Please enter a number between 1 and {len(available_regions)}.")
                else:
                    if region_input in available_regions:
                        regions = [region_input]
                        print(f"\nUsing region: {regions[0]}")
                    else:
                        print(f"\nInvalid region code: {region_input}")
                        print("Please enter a valid region code from the list above.")
            else:
                print("\nInvalid choice. Please enter 1, 2, or 3.")
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            sys.exit(0)
        except Exception as e:
            utils.log_error(f"Error getting region selection: {str(e)}")
            print("Please try again.")

    if not regions:
        utils.log_error("No regions selected. Exiting.")
        return

    # Collect data
    print("\nCollecting Amazon Bedrock data...")

    foundation_models = collect_foundation_models(regions)
    custom_models = collect_custom_models(regions)
    logging_configs = collect_model_invocation_logging(regions)
    guardrails = collect_guardrails(regions)
    knowledge_bases = collect_knowledge_bases(regions)
    agents = collect_agents(regions)
    summary = generate_summary(foundation_models, custom_models, logging_configs,
                                guardrails, knowledge_bases, agents)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if foundation_models:
        df_foundation = pd.DataFrame(foundation_models)
        df_foundation = utils.prepare_dataframe_for_export(df_foundation)
        dataframes['Foundation Models'] = df_foundation

    if custom_models:
        df_custom = pd.DataFrame(custom_models)
        df_custom = utils.prepare_dataframe_for_export(df_custom)
        dataframes['Custom Models'] = df_custom

    if logging_configs:
        df_logging = pd.DataFrame(logging_configs)
        df_logging = utils.prepare_dataframe_for_export(df_logging)
        dataframes['Invocation Logging'] = df_logging

    if guardrails:
        df_guardrails = pd.DataFrame(guardrails)
        df_guardrails = utils.prepare_dataframe_for_export(df_guardrails)
        dataframes['Guardrails'] = df_guardrails

    if knowledge_bases:
        df_kb = pd.DataFrame(knowledge_bases)
        df_kb = utils.prepare_dataframe_for_export(df_kb)
        dataframes['Knowledge Bases'] = df_kb

    if agents:
        df_agents = pd.DataFrame(agents)
        df_agents = utils.prepare_dataframe_for_export(df_agents)
        dataframes['Agents'] = df_agents

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'bedrock', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Foundation Models': len(foundation_models),
            'Custom Models': len(custom_models),
            'Logging Configurations': len(logging_configs),
            'Guardrails': len(guardrails),
            'Knowledge Bases': len(knowledge_bases),
            'Agents': len(agents)
        })
    else:
        utils.log_warning("No Amazon Bedrock data found to export")

    utils.log_success("Amazon Bedrock export completed successfully")


if __name__ == "__main__":
    main()

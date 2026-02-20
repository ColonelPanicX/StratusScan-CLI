#!/usr/bin/env python3
"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS EC2 Image Builder Export Tool
Version: v0.1.0
Date: NOV-09-2025

Description:
This script exports AWS EC2 Image Builder information from all regions into an Excel file with
multiple worksheets. The output includes image pipelines, image recipes, components,
infrastructure configurations, distribution settings, and build execution history.

Features:
- Image pipelines with schedules and status
- Image recipes with base images and component lists
- Build and test components
- Infrastructure configurations for build environments
- Distribution settings (regions and accounts)
- Image build execution history
- Container recipes (for container images)
"""

import sys
import datetime
from pathlib import Path
from typing import List, Dict, Any

# Add path to import utils module
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()

    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))

    try:
        import utils
    except ImportError:
        print("ERROR: Could not import the utils module. Make sure utils.py is in the StratusScan directory.")
        sys.exit(1)


def print_title():
    """Print the title and header of the script to the console."""
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                    ")
    print("====================================================================")
    print("           AWS EC2 IMAGE BUILDER EXPORT TOOL")
    print("====================================================================")
    print("Version: v0.1.0                        Date: NOV-09-2025")
    # Detect partition and set environment name
    partition = utils.detect_partition()
    partition_name = "AWS GovCloud (US)" if partition == 'aws-us-gov' else "AWS Commercial"
    
    print(f"Environment: {partition_name}")
    print("====================================================================")

    # Get the current AWS account ID
    try:
        sts_client = utils.get_boto3_client('sts')
        account_id = sts_client.get_caller_identity().get('Account')
        account_name = utils.get_account_name(account_id, default=account_id)

        print(f"Account ID: {account_id}")
        print(f"Account Name: {account_name}")
    except Exception as e:
        print("Could not determine account information.")
        utils.log_error("Error getting account information", e)
        account_id = "unknown"
        account_name = "unknown"

    print("====================================================================")
    return account_id, account_name
@utils.aws_error_handler("Collecting Image Builder pipelines", default_return=[])
def collect_image_pipelines(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Image Builder pipeline information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with pipeline information
    """
    print("\n=== COLLECTING IMAGE BUILDER PIPELINES ===")
    all_pipelines = []

    for region in regions:
        if not utils.validate_aws_region(region):
            utils.log_error(f"Skipping invalid AWS region: {region}")
            continue

        print(f"\nProcessing region: {region}")

        try:
            imagebuilder = utils.get_boto3_client('imagebuilder', region_name=region)

            # Get image pipelines
            response = imagebuilder.list_image_pipelines()
            pipeline_arns = [p['arn'] for p in response.get('imagePipelineList', [])]

            print(f"  Found {len(pipeline_arns)} pipelines")

            for pipeline_arn in pipeline_arns:
                try:
                    # Get pipeline details
                    pipeline_response = imagebuilder.get_image_pipeline(imagePipelineArn=pipeline_arn)
                    pipeline = pipeline_response.get('imagePipeline', {})

                    name = pipeline.get('name', '')
                    description = pipeline.get('description', 'N/A')
                    status = pipeline.get('status', '')

                    # Image recipe or container recipe
                    image_recipe_arn = pipeline.get('imageRecipeArn', 'N/A')
                    container_recipe_arn = pipeline.get('containerRecipeArn', 'N/A')

                    recipe_type = 'AMI' if image_recipe_arn != 'N/A' else 'Container'
                    recipe_arn = image_recipe_arn if recipe_type == 'AMI' else container_recipe_arn

                    # Infrastructure configuration
                    infrastructure_config_arn = pipeline.get('infrastructureConfigurationArn', 'N/A')

                    # Distribution configuration
                    distribution_config_arn = pipeline.get('distributionConfigurationArn', 'N/A')

                    # Schedule
                    schedule = pipeline.get('schedule', {})
                    schedule_expression = schedule.get('scheduleExpression', 'N/A')
                    pipeline_execution_start_condition = schedule.get('pipelineExecutionStartCondition', 'N/A')

                    # Enhanced image metadata
                    enhanced_metadata_enabled = pipeline.get('enhancedImageMetadataEnabled', False)

                    # Image tests
                    image_tests_config = pipeline.get('imageTestsConfiguration', {})
                    tests_enabled = image_tests_config.get('imageTestsEnabled', False)
                    timeout_minutes = image_tests_config.get('timeoutMinutes', 0)

                    # Date created
                    date_created = pipeline.get('dateCreated', 'N/A')

                    # Tags
                    tags = pipeline.get('tags', {})
                    tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'N/A'

                    all_pipelines.append({
                        'Region': region,
                        'Pipeline Name': name,
                        'Status': status,
                        'Recipe Type': recipe_type,
                        'Schedule Expression': schedule_expression,
                        'Start Condition': pipeline_execution_start_condition,
                        'Tests Enabled': tests_enabled,
                        'Test Timeout (min)': timeout_minutes,
                        'Enhanced Metadata': enhanced_metadata_enabled,
                        'Infrastructure Config ARN': infrastructure_config_arn,
                        'Distribution Config ARN': distribution_config_arn,
                        'Recipe ARN': recipe_arn,
                        'Date Created': date_created,
                        'Description': description,
                        'Tags': tags_str,
                        'Pipeline ARN': pipeline_arn
                    })

                except Exception as e:
                    utils.log_error(f"Error getting pipeline details for {pipeline_arn}", e)

        except Exception as e:
            utils.log_error(f"Error processing region {region} for pipelines", e)

    utils.log_success(f"Total pipelines collected: {len(all_pipelines)}")
    return all_pipelines


@utils.aws_error_handler("Collecting image recipes", default_return=[])
def collect_image_recipes(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Image Builder image recipe information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with image recipe information
    """
    print("\n=== COLLECTING IMAGE RECIPES ===")
    all_recipes = []

    for region in regions:
        if not utils.validate_aws_region(region):
            continue

        print(f"\nProcessing region: {region}")

        try:
            imagebuilder = utils.get_boto3_client('imagebuilder', region_name=region)

            # Get image recipes
            response = imagebuilder.list_image_recipes()
            recipe_arns = [r['arn'] for r in response.get('imageRecipeSummaryList', [])]

            for recipe_arn in recipe_arns:
                try:
                    # Get recipe details
                    recipe_response = imagebuilder.get_image_recipe(imageRecipeArn=recipe_arn)
                    recipe = recipe_response.get('imageRecipe', {})

                    name = recipe.get('name', '')
                    version = recipe.get('version', '')
                    description = recipe.get('description', 'N/A')
                    platform = recipe.get('platform', '')

                    # Parent image
                    parent_image = recipe.get('parentImage', 'N/A')

                    # Block device mappings
                    block_device_mappings = recipe.get('blockDeviceMappings', [])
                    volume_count = len(block_device_mappings)

                    # Components
                    components = recipe.get('components', [])
                    component_count = len(components)
                    component_arns = [c.get('componentArn', '') for c in components]

                    # Working directory
                    working_directory = recipe.get('workingDirectory', 'N/A')

                    # Date created
                    date_created = recipe.get('dateCreated', 'N/A')

                    # Tags
                    tags = recipe.get('tags', {})
                    tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'N/A'

                    all_recipes.append({
                        'Region': region,
                        'Recipe Name': name,
                        'Version': version,
                        'Platform': platform,
                        'Parent Image': parent_image,
                        'Component Count': component_count,
                        'Volume Count': volume_count,
                        'Working Directory': working_directory,
                        'Date Created': date_created,
                        'Description': description,
                        'Tags': tags_str,
                        'Recipe ARN': recipe_arn
                    })

                except Exception as e:
                    utils.log_error(f"Error getting recipe details for {recipe_arn}", e)

        except Exception as e:
            utils.log_error(f"Error collecting recipes in region {region}", e)

    utils.log_success(f"Total image recipes collected: {len(all_recipes)}")
    return all_recipes


@utils.aws_error_handler("Collecting components", default_return=[])
def collect_components(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Image Builder component information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with component information
    """
    print("\n=== COLLECTING COMPONENTS ===")
    all_components = []

    for region in regions:
        if not utils.validate_aws_region(region):
            continue

        print(f"\nProcessing region: {region}")

        try:
            imagebuilder = utils.get_boto3_client('imagebuilder', region_name=region)

            # Get components (owned by account)
            response = imagebuilder.list_components(owner='Self')
            component_arns = [c['arn'] for c in response.get('componentVersionList', [])]

            for component_arn in component_arns:
                try:
                    # Get component details
                    component_response = imagebuilder.get_component(componentBuildVersionArn=component_arn)
                    component = component_response.get('component', {})

                    name = component.get('name', '')
                    version = component.get('version', '')
                    description = component.get('description', 'N/A')
                    component_type = component.get('type', '')
                    platform = component.get('platform', '')

                    # Supported OS versions
                    supported_os_versions = component.get('supportedOsVersions', [])
                    os_versions_str = ', '.join(supported_os_versions) if supported_os_versions else 'All'

                    # Change description
                    change_description = component.get('changeDescription', 'N/A')

                    # Date created
                    date_created = component.get('dateCreated', 'N/A')

                    # Tags
                    tags = component.get('tags', {})
                    tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'N/A'

                    all_components.append({
                        'Region': region,
                        'Component Name': name,
                        'Version': version,
                        'Type': component_type,
                        'Platform': platform,
                        'Supported OS Versions': os_versions_str,
                        'Date Created': date_created,
                        'Change Description': change_description,
                        'Description': description,
                        'Tags': tags_str,
                        'Component ARN': component_arn
                    })

                except Exception as e:
                    utils.log_error(f"Error getting component details for {component_arn}", e)

        except Exception as e:
            utils.log_error(f"Error collecting components in region {region}", e)

    utils.log_success(f"Total components collected: {len(all_components)}")
    return all_components


@utils.aws_error_handler("Collecting infrastructure configurations", default_return=[])
def collect_infrastructure_configurations(regions: List[str]) -> List[Dict[str, Any]]:
    """
    Collect Image Builder infrastructure configuration information from AWS regions.

    Args:
        regions: List of AWS regions to scan

    Returns:
        list: List of dictionaries with infrastructure configuration information
    """
    print("\n=== COLLECTING INFRASTRUCTURE CONFIGURATIONS ===")
    all_configs = []

    for region in regions:
        if not utils.validate_aws_region(region):
            continue

        print(f"\nProcessing region: {region}")

        try:
            imagebuilder = utils.get_boto3_client('imagebuilder', region_name=region)

            # Get infrastructure configurations
            response = imagebuilder.list_infrastructure_configurations()
            config_arns = [c['arn'] for c in response.get('infrastructureConfigurationSummaryList', [])]

            for config_arn in config_arns:
                try:
                    # Get configuration details
                    config_response = imagebuilder.get_infrastructure_configuration(
                        infrastructureConfigurationArn=config_arn
                    )
                    config = config_response.get('infrastructureConfiguration', {})

                    name = config.get('name', '')
                    description = config.get('description', 'N/A')

                    # Instance types
                    instance_types = config.get('instanceTypes', [])
                    instance_types_str = ', '.join(instance_types) if instance_types else 'N/A'

                    # Instance profile name
                    instance_profile_name = config.get('instanceProfileName', 'N/A')

                    # Security group IDs
                    security_group_ids = config.get('securityGroupIds', [])
                    sg_count = len(security_group_ids)

                    # Subnet ID
                    subnet_id = config.get('subnetId', 'N/A')

                    # Terminate on failure
                    terminate_on_failure = config.get('terminateInstanceOnFailure', False)

                    # SNS topic ARN
                    sns_topic_arn = config.get('snsTopicArn', 'N/A')

                    # Key pair
                    key_pair = config.get('keyPair', 'N/A')

                    # Resource tags
                    resource_tags = config.get('resourceTags', {})
                    resource_tags_str = ', '.join([f"{k}={v}" for k, v in resource_tags.items()]) if resource_tags else 'N/A'

                    # Date created
                    date_created = config.get('dateCreated', 'N/A')

                    # Tags
                    tags = config.get('tags', {})
                    tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'N/A'

                    all_configs.append({
                        'Region': region,
                        'Config Name': name,
                        'Instance Types': instance_types_str,
                        'Instance Profile': instance_profile_name,
                        'Subnet ID': subnet_id,
                        'Security Group Count': sg_count,
                        'Key Pair': key_pair,
                        'Terminate on Failure': terminate_on_failure,
                        'SNS Topic ARN': sns_topic_arn,
                        'Resource Tags': resource_tags_str,
                        'Date Created': date_created,
                        'Description': description,
                        'Tags': tags_str,
                        'Config ARN': config_arn
                    })

                except Exception as e:
                    utils.log_error(f"Error getting infrastructure config details for {config_arn}", e)

        except Exception as e:
            utils.log_error(f"Error collecting infrastructure configs in region {region}", e)

    utils.log_success(f"Total infrastructure configurations collected: {len(all_configs)}")
    return all_configs


def export_image_builder_data(account_id: str, account_name: str):
    """
    Export EC2 Image Builder information to an Excel file.

    Args:
        account_id: The AWS account ID
        account_name: The AWS account name
    """
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
    print()
    print("Please select which AWS regions to scan:")
    print()
    print("1. Default Regions (recommended for most use cases)")
    print(f"   └─ {example_regions}")
    print()
    print("2. All Available Regions")
    print("   └─ Scans all regions (slower, more comprehensive)")
    print()
    print("3. Specific Region")
    print("   └─ Choose a single region to scan")
    print()

    # Get user selection with validation
    while True:
        try:
            selection = input("Enter your selection (1-3): ").strip()
            selection_int = int(selection)
            if 1 <= selection_int <= 3:
                break
            else:
                print("Please enter a number between 1 and 3.")
        except ValueError:
            print("Please enter a valid number (1-3).")

    # Get regions based on selection
    all_available_regions = utils.get_aws_regions()
    default_regions = utils.get_partition_regions(partition, all_regions=False)

    # Process selection
    if selection_int == 1:
        regions = default_regions
        region_text = f"default AWS regions ({len(regions)} regions)"
        region_suffix = ""
    elif selection_int == 2:
        regions = all_available_regions
        region_text = f"all AWS regions ({len(regions)} regions)"
        region_suffix = ""
    else:  # selection_int == 3
        # Display numbered list of regions
        print("\n" + "=" * 68)
        print("AVAILABLE AWS REGIONS")
        print("=" * 68)
        print()
        for idx, region in enumerate(all_available_regions, 1):
            print(f"{idx:2}. {region}")
        print()

        # Get region selection with validation
        while True:
            try:
                region_num = input(f"Enter region number (1-{len(all_available_regions)}): ").strip()
                region_idx = int(region_num) - 1
                if 0 <= region_idx < len(all_available_regions):
                    selected_region = all_available_regions[region_idx]
                    regions = [selected_region]
                    region_text = f"AWS region \"{selected_region}\""
                    region_suffix = f"-{selected_region}"
                    break
                else:
                    print(f"Please enter a number between 1 and {len(all_available_regions)}.")
            except ValueError:
                print(f"Please enter a valid number (1-{len(all_available_regions)}).")

    print(f"\nStarting EC2 Image Builder export process for {region_text}...")
    print("=" * 68)
    print("This may take some time depending on the number of regions and resources...")

    utils.log_info(f"Processing {len(regions)} AWS regions: {', '.join(regions)}")

    # Import pandas for DataFrame handling
    import pandas as pd

    # Dictionary to hold all DataFrames for export
    data_frames = {}

    # STEP 1: Collect pipelines
    pipelines = collect_image_pipelines(regions)
    if pipelines:
        data_frames['Image Pipelines'] = pd.DataFrame(pipelines)

    # STEP 2: Collect image recipes
    recipes = collect_image_recipes(regions)
    if recipes:
        data_frames['Image Recipes'] = pd.DataFrame(recipes)

    # STEP 3: Collect components
    components = collect_components(regions)
    if components:
        data_frames['Components'] = pd.DataFrame(components)

    # STEP 4: Collect infrastructure configurations
    infra_configs = collect_infrastructure_configurations(regions)
    if infra_configs:
        data_frames['Infrastructure Configurations'] = pd.DataFrame(infra_configs)

    # Check if we have any data
    if not data_frames:
        utils.log_warning("No EC2 Image Builder data was collected. Nothing to export.")
        print("\nNo EC2 Image Builder resources found in the selected region(s).")
        return

    # STEP 5: Prepare all DataFrames for export
    for sheet_name in data_frames:
        data_frames[sheet_name] = utils.prepare_dataframe_for_export(data_frames[sheet_name])

    # STEP 6: Create filename and export
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    final_excel_file = utils.create_export_filename(
        account_name,
        'image-builder',
        region_suffix,
        current_date
    )

    # Save using utils module for consistent formatting
    try:
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, final_excel_file)

        if output_path:
            utils.log_success("EC2 Image Builder data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")

            # Summary of exported data
            for sheet_name, df in data_frames.items():
                utils.log_info(f"  - {sheet_name}: {len(df)} records")
                print(f"  - {sheet_name}: {len(df)} records")
        else:
            utils.log_error("Error creating Excel file. Please check the logs.")

    except Exception as e:
        utils.log_error("Error creating Excel file", e)


def main():
    # Initialize logging
    utils.setup_logging("image-builder-export")
    SCRIPT_START_TIME = datetime.datetime.now()
    utils.log_script_start("image-builder-export.py", "AWS EC2 Image Builder Export Tool")

    try:
        # Print title and get account information
        account_id, account_name = print_title()

        # Check and install dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Check if account name is unknown
        if account_name == "unknown":
            proceed = input("Unable to determine account name. Proceed anyway? (y/n): ").lower()
            if proceed != 'y':
                print("Exiting script...")
                sys.exit(0)

        # Export EC2 Image Builder data
        export_image_builder_data(account_id, account_name)

        print("\nEC2 Image Builder export script execution completed.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        utils.log_info("Script cancelled by user")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
    finally:
        utils.log_script_end("image-builder-export.py", SCRIPT_START_TIME)


if __name__ == "__main__":
    main()

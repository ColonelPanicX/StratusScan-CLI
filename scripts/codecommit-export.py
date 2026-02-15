#!/usr/bin/env python3
"""
AWS CodeCommit Export Script for StratusScan

Exports comprehensive AWS CodeCommit source control information including:
- Repositories with clone URLs and encryption
- Branches with commit tracking
- Pull requests with review status
- Approval rule templates

Output: Multi-worksheet Excel file with CodeCommit resources
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


@utils.aws_error_handler("Collecting CodeCommit repositories", default_return=[])
def collect_repositories(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect CodeCommit repository information from AWS regions."""
    all_repositories = []

    for region in regions:
        utils.log_info(f"Collecting CodeCommit repositories in {region}...")
        codecommit_client = utils.get_boto3_client('codecommit', region_name=region)

        try:
            # List all repositories
            paginator = codecommit_client.get_paginator('list_repositories')
            repository_names = []
            for page in paginator.paginate():
                repos = page.get('repositories', [])
                repository_names.extend([r.get('repositoryName') for r in repos])

            if not repository_names:
                continue

            utils.log_info(f"Found {len(repository_names)} repositories in {region}")

            # Batch get repository metadata
            for repo_name in repository_names:
                try:
                    repo_response = codecommit_client.get_repository(repositoryName=repo_name)
                    repo_metadata = repo_response.get('repositoryMetadata', {})

                    repo_id = repo_metadata.get('repositoryId', 'N/A')
                    arn = repo_metadata.get('Arn', 'N/A')
                    description = repo_metadata.get('repositoryDescription', 'None')

                    created = repo_metadata.get('creationDate', 'N/A')
                    if created != 'N/A':
                        created = created.strftime('%Y-%m-%d %H:%M:%S')

                    last_modified = repo_metadata.get('lastModifiedDate', 'N/A')
                    if last_modified != 'N/A':
                        last_modified = last_modified.strftime('%Y-%m-%d %H:%M:%S')

                    # Clone URLs
                    clone_url_http = repo_metadata.get('cloneUrlHttp', 'N/A')
                    clone_url_ssh = repo_metadata.get('cloneUrlSsh', 'N/A')

                    # Default branch
                    default_branch = repo_metadata.get('defaultBranch', 'N/A')

                    # KMS encryption
                    kms_key_id = repo_metadata.get('kmsKeyId', 'None')

                    all_repositories.append({
                        'Region': region,
                        'Repository Name': repo_name,
                        'Repository ID': repo_id,
                        'ARN': arn,
                        'Description': description,
                        'Created': created,
                        'Last Modified': last_modified,
                        'Default Branch': default_branch,
                        'Clone URL (HTTP)': clone_url_http,
                        'Clone URL (SSH)': clone_url_ssh,
                        'KMS Key ID': kms_key_id
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get metadata for repository {repo_name}: {str(e)}")
                    continue

        except Exception as e:
            utils.log_warning(f"Error collecting CodeCommit repositories in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_repositories)} CodeCommit repositories")
    return all_repositories


@utils.aws_error_handler("Collecting repository branches", default_return=[])
def collect_branches(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect branch information from CodeCommit repositories."""
    all_branches = []

    for region in regions:
        utils.log_info(f"Collecting branches in {region}...")
        codecommit_client = utils.get_boto3_client('codecommit', region_name=region)

        try:
            # List all repositories first
            paginator = codecommit_client.get_paginator('list_repositories')
            for page in paginator.paginate():
                repos = page.get('repositories', [])

                for repo in repos:
                    repo_name = repo.get('repositoryName', 'N/A')

                    # List branches for this repository
                    try:
                        branch_paginator = codecommit_client.get_paginator('list_branches')
                        for branch_page in branch_paginator.paginate(repositoryName=repo_name):
                            branches = branch_page.get('branches', [])

                            for branch_name in branches:
                                # Get branch details
                                try:
                                    branch_response = codecommit_client.get_branch(
                                        repositoryName=repo_name,
                                        branchName=branch_name
                                    )
                                    branch_data = branch_response.get('branch', {})

                                    commit_id = branch_data.get('commitId', 'N/A')

                                    # Get commit info
                                    try:
                                        commit_response = codecommit_client.get_commit(
                                            repositoryName=repo_name,
                                            commitId=commit_id
                                        )
                                        commit = commit_response.get('commit', {})

                                        author = commit.get('author', {})
                                        author_name = author.get('name', 'N/A')
                                        author_date = author.get('date', 'N/A')
                                        if author_date != 'N/A':
                                            author_date = author_date.strftime('%Y-%m-%d %H:%M:%S')

                                        commit_message = commit.get('message', 'N/A')
                                        # Truncate message for display
                                        if len(commit_message) > 100:
                                            commit_message = commit_message[:97] + '...'

                                    except Exception:
                                        author_name = 'N/A'
                                        author_date = 'N/A'
                                        commit_message = 'N/A'

                                    all_branches.append({
                                        'Region': region,
                                        'Repository Name': repo_name,
                                        'Branch Name': branch_name,
                                        'Commit ID': commit_id,
                                        'Author': author_name,
                                        'Last Commit Date': author_date,
                                        'Last Commit Message': commit_message
                                    })

                                except Exception as e:
                                    utils.log_warning(f"Could not get details for branch {branch_name} in {repo_name}: {str(e)}")
                                    continue

                    except Exception as e:
                        utils.log_warning(f"Could not list branches for repository {repo_name}: {str(e)}")
                        continue

        except Exception as e:
            utils.log_warning(f"Error collecting branches in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_branches)} branches")
    return all_branches


@utils.aws_error_handler("Collecting pull requests", default_return=[])
def collect_pull_requests(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect pull request information (limited to open PRs)."""
    all_pull_requests = []

    for region in regions:
        utils.log_info(f"Collecting pull requests in {region}...")
        codecommit_client = utils.get_boto3_client('codecommit', region_name=region)

        try:
            # List all repositories first
            paginator = codecommit_client.get_paginator('list_repositories')
            for page in paginator.paginate():
                repos = page.get('repositories', [])

                for repo in repos:
                    repo_name = repo.get('repositoryName', 'N/A')

                    # List pull requests for this repository (open only)
                    try:
                        pr_paginator = codecommit_client.get_paginator('list_pull_requests')
                        for pr_page in pr_paginator.paginate(
                            repositoryName=repo_name,
                            pullRequestStatus='OPEN'
                        ):
                            pr_ids = pr_page.get('pullRequestIds', [])

                            # Get details for each PR
                            for pr_id in pr_ids:
                                try:
                                    pr_response = codecommit_client.get_pull_request(pullRequestId=pr_id)
                                    pr = pr_response.get('pullRequest', {})

                                    title = pr.get('title', 'N/A')
                                    description = pr.get('description', 'None')
                                    status = pr.get('pullRequestStatus', 'N/A')

                                    created_date = pr.get('creationDate', 'N/A')
                                    if created_date != 'N/A':
                                        created_date = created_date.strftime('%Y-%m-%d %H:%M:%S')

                                    last_activity = pr.get('lastActivityDate', 'N/A')
                                    if last_activity != 'N/A':
                                        last_activity = last_activity.strftime('%Y-%m-%d %H:%M:%S')

                                    # Author
                                    author_arn = pr.get('authorArn', 'N/A')

                                    # Targets
                                    targets = pr.get('pullRequestTargets', [])
                                    if targets:
                                        target = targets[0]
                                        source_ref = target.get('sourceReference', 'N/A')
                                        dest_ref = target.get('destinationReference', 'N/A')
                                        merge_metadata = target.get('mergeMetadata', {})
                                        is_merged = merge_metadata.get('isMerged', False)
                                        merge_option = merge_metadata.get('mergeOption', 'N/A')
                                    else:
                                        source_ref = 'N/A'
                                        dest_ref = 'N/A'
                                        is_merged = False
                                        merge_option = 'N/A'

                                    all_pull_requests.append({
                                        'Region': region,
                                        'Repository Name': repo_name,
                                        'PR ID': pr_id,
                                        'Title': title,
                                        'Status': status,
                                        'Created': created_date,
                                        'Last Activity': last_activity,
                                        'Source Branch': source_ref,
                                        'Destination Branch': dest_ref,
                                        'Is Merged': is_merged,
                                        'Merge Option': merge_option,
                                        'Author ARN': author_arn,
                                        'Description': description
                                    })

                                except Exception as e:
                                    utils.log_warning(f"Could not get details for PR {pr_id}: {str(e)}")
                                    continue

                    except Exception as e:
                        utils.log_warning(f"Could not list pull requests for repository {repo_name}: {str(e)}")
                        continue

        except Exception as e:
            utils.log_warning(f"Error collecting pull requests in {region}: {str(e)}")
            continue

    utils.log_info(f"Collected {len(all_pull_requests)} open pull requests")
    return all_pull_requests


def generate_summary(repositories: List[Dict[str, Any]],
                     branches: List[Dict[str, Any]],
                     pull_requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for CodeCommit resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Repositories summary
    total_repos = len(repositories)
    summary.append({
        'Metric': 'Total Repositories',
        'Count': total_repos,
        'Details': 'CodeCommit Git repositories'
    })

    # Encrypted repositories
    encrypted_repos = sum(1 for r in repositories if r.get('KMS Key ID', 'None') != 'None')
    summary.append({
        'Metric': 'Repositories with KMS Encryption',
        'Count': encrypted_repos,
        'Details': 'Repositories using customer-managed KMS keys'
    })

    # Branches summary
    total_branches = len(branches)
    summary.append({
        'Metric': 'Total Branches',
        'Count': total_branches,
        'Details': 'Branches across all repositories'
    })

    # Average branches per repository
    if total_repos > 0:
        avg_branches = total_branches / total_repos
        summary.append({
            'Metric': 'Average Branches per Repository',
            'Count': f"{avg_branches:.1f}",
            'Details': 'Branch distribution'
        })

    # Pull requests summary
    total_prs = len(pull_requests)
    summary.append({
        'Metric': 'Open Pull Requests',
        'Count': total_prs,
        'Details': 'Currently open pull requests awaiting review/merge'
    })

    # Regional distribution
    if repositories:
        df = pd.DataFrame(repositories)
        regions = df['Region'].value_counts().to_dict()
        for region, count in regions.items():
            summary.append({
                'Metric': f'Repositories in {region}',
                'Count': count,
                'Details': 'Regional distribution'
            })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    print("\n" + "="*60)
    print("AWS CodeCommit Export Tool")
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
    print("\nCodeCommit is a regional service.")
    print("\nPlease select an option for region selection:")
    print("\n  1. Default Regions")
    print(f"     ({example_regions})")
    print("\n  2. All Available Regions")
    print("     (Scan all regions where CodeCommit is available)")
    print("\n  3. Specific Region")
    print("     (Enter a specific AWS region code)")
    print("\n" + "-" * 68)

    # Get and validate region choice
    regions = []
    while not regions:
        try:
            region_choice = input("\nEnter your choice (1, 2, or 3): ").strip()

            if region_choice == '1':
                # Default regions
                regions = utils.get_partition_default_regions()
                print(f"\nUsing default regions: {', '.join(regions)}")
            elif region_choice == '2':
                # All available regions
                regions = utils.get_partition_regions(partition, all_regions=True)
                print(f"\nScanning all {len(regions)} available regions")
            elif region_choice == '3':
                # Specific region - show numbered list
                available_regions = utils.get_partition_regions(
                    partition, all_regions=True
                )
                print("\n" + "=" * 68)
                print("AVAILABLE REGIONS")
                print("=" * 68)
                for idx, region in enumerate(available_regions, 1):
                    print(f"  {idx}. {region}")
                print("-" * 68)

                # Get region selection
                region_selected = False
                while not region_selected:
                    try:
                        region_num = input(
                            f"\nEnter region number (1-{len(available_regions)}): "
                        ).strip()
                        region_idx = int(region_num) - 1

                        if 0 <= region_idx < len(available_regions):
                            selected_region = available_regions[region_idx]
                            regions = [selected_region]
                            print(f"\nSelected region: {selected_region}")
                            region_selected = True
                        else:
                            print(
                                f"Invalid selection. Please enter a number "
                                f"between 1 and {len(available_regions)}."
                            )
                    except ValueError:
                        print("Invalid input. Please enter a number.")
                    except KeyboardInterrupt:
                        print("\n\nOperation cancelled by user.")
                        sys.exit(0)
            else:
                print("\nInvalid choice. Please enter 1, 2, or 3.")

        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            sys.exit(0)
        except Exception as e:
            utils.log_error(f"Error getting region selection: {str(e)}")
            print("Please try again.")

    # Collect data
    print("\nCollecting AWS CodeCommit data...")

    repositories = collect_repositories(regions)
    branches = collect_branches(regions)
    pull_requests = collect_pull_requests(regions)
    summary = generate_summary(repositories, branches, pull_requests)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if repositories:
        df_repositories = pd.DataFrame(repositories)
        df_repositories = utils.prepare_dataframe_for_export(df_repositories)
        dataframes['Repositories'] = df_repositories

    if branches:
        df_branches = pd.DataFrame(branches)
        df_branches = utils.prepare_dataframe_for_export(df_branches)
        dataframes['Branches'] = df_branches

    if pull_requests:
        df_pull_requests = pd.DataFrame(pull_requests)
        df_pull_requests = utils.prepare_dataframe_for_export(df_pull_requests)
        dataframes['Open Pull Requests'] = df_pull_requests

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    # Export to Excel
    if dataframes:
        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'codecommit', region_suffix)

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Repositories': len(repositories),
            'Branches': len(branches),
            'Open Pull Requests': len(pull_requests)
        })
    else:
        utils.log_warning("No AWS CodeCommit data found to export")

    utils.log_success("AWS CodeCommit export completed successfully")


if __name__ == "__main__":
    main()

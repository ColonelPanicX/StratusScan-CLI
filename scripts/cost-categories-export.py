#!/usr/bin/env python3
"""
Cost Categories Export Script

Exports AWS Cost Categories configuration and structure:
- Cost Category definitions and metadata
- Category rules and expressions
- Inherited value rules
- Split charge rules
- Default values and processing status
- Rule versioning and effective dates
- Category hierarchy analysis

Features:
- Complete cost category inventory
- Rule breakdown and analysis
- Expression parsing and display
- Active vs. historical categories
- Multi-level hierarchy support
- Rule type classification
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
import json
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
logger = utils.setup_logging('cost-categories-export')
utils.log_script_start('cost-categories-export', 'Export AWS Cost Categories configuration')


def parse_expression(expression: Dict, prefix: str = "") -> str:
    """Parse Cost Category expression into human-readable format."""
    if not expression:
        return "N/A"

    # Handle different expression types
    if 'Dimensions' in expression:
        dim = expression['Dimensions']
        key = dim.get('Key', 'Unknown')
        values = ', '.join(dim.get('Values', []))
        match_options = ', '.join(dim.get('MatchOptions', []))
        return f"{prefix}Dimension: {key} = [{values}] (Match: {match_options})"

    elif 'Tags' in expression:
        tag = expression['Tags']
        key = tag.get('Key', 'Unknown')
        values = ', '.join(tag.get('Values', []))
        match_options = ', '.join(tag.get('MatchOptions', []))
        return f"{prefix}Tag: {key} = [{values}] (Match: {match_options})"

    elif 'CostCategories' in expression:
        cc = expression['CostCategories']
        key = cc.get('Key', 'Unknown')
        values = ', '.join(cc.get('Values', []))
        match_options = ', '.join(cc.get('MatchOptions', []))
        return f"{prefix}CostCategory: {key} = [{values}] (Match: {match_options})"

    elif 'And' in expression:
        sub_expressions = [parse_expression(e, prefix + "  ") for e in expression['And']]
        return f"{prefix}AND:\n" + "\n".join(sub_expressions)

    elif 'Or' in expression:
        sub_expressions = [parse_expression(e, prefix + "  ") for e in expression['Or']]
        return f"{prefix}OR:\n" + "\n".join(sub_expressions)

    elif 'Not' in expression:
        sub_expr = parse_expression(expression['Not'], prefix + "  ")
        return f"{prefix}NOT:\n{sub_expr}"

    else:
        return f"{prefix}Complex Expression (see JSON)"


@utils.aws_error_handler("Listing Cost Category Definitions", default_return=[])
def list_cost_category_definitions() -> List[Dict[str, Any]]:
    """List all Cost Category definitions."""
    # Cost Explorer is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    ce = utils.get_boto3_client('ce', region_name=home_region)

    cost_categories = []
    next_token = None

    while True:
        params = {'MaxResults': 100}
        if next_token:
            params['NextToken'] = next_token

        response = ce.list_cost_category_definitions(**params)

        for cc_ref in response.get('CostCategoryReferences', []):
            cost_categories.append(cc_ref)

        next_token = response.get('NextToken')
        if not next_token:
            break

    return cost_categories


@utils.aws_error_handler("Describing Cost Category Definition", default_return=None)
def describe_cost_category(cost_category_arn: str) -> Dict[str, Any]:
    """Get detailed Cost Category definition."""
    # Cost Explorer is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    ce = utils.get_boto3_client('ce', region_name=home_region)

    response = ce.describe_cost_category_definition(
        CostCategoryArn=cost_category_arn
    )

    return response.get('CostCategory')


def main():
    """Main execution function."""
    try:
        # Get account information
        account_id, account_name = utils.get_account_info()
        utils.log_info(f"Exporting Cost Categories for account: {account_name} ({account_id})")

        utils.log_info("Cost Categories are global (accessed via us-east-1)...")

        # List all cost categories
        utils.log_info("Retrieving Cost Category definitions...")
        cost_category_refs = list_cost_category_definitions()

        if not cost_category_refs:
            utils.log_warning("No Cost Categories found.")
            utils.log_info("Creating empty export file...")
        else:
            utils.log_info(f"Found {len(cost_category_refs)} Cost Category definition(s)")

        # Collect detailed information for each category
        all_categories = []
        all_rules = []
        all_inherited_rules = []
        all_split_rules = []

        for idx, cc_ref in enumerate(cost_category_refs, 1):
            cc_name = cc_ref.get('Name', 'Unknown')
            cc_arn = cc_ref.get('CostCategoryArn', 'N/A')

            utils.log_info(f"[{idx}/{len(cost_category_refs)}] Processing: {cc_name}")

            # Get detailed definition
            cc_detail = describe_cost_category(cc_arn)

            if not cc_detail:
                utils.log_warning(f"  Could not retrieve details for {cc_name}")
                continue

            # Main category info
            all_categories.append({
                'Name': cc_detail.get('Name', 'N/A'),
                'ARN': cc_detail.get('CostCategoryArn', 'N/A'),
                'EffectiveStart': cc_detail.get('EffectiveStart'),
                'EffectiveEnd': cc_detail.get('EffectiveEnd', 'N/A'),
                'DefaultValue': cc_detail.get('DefaultValue', 'N/A'),
                'RuleVersion': cc_detail.get('RuleVersion', 'N/A'),
                'ProcessingStatus': cc_ref.get('ProcessingStatus', [{'Status': 'N/A'}])[0].get('Status', 'N/A'),
                'NumberOfRules': cc_ref.get('NumberOfRules', 0),
                'Values': ', '.join(cc_ref.get('Values', [])) if cc_ref.get('Values') else 'N/A',
            })

            # Extract rules
            rules = cc_detail.get('Rules', [])
            for rule_idx, rule in enumerate(rules, 1):
                rule_value = rule.get('Value', 'N/A')
                rule_expr = rule.get('Rule', {})

                all_rules.append({
                    'CategoryName': cc_name,
                    'RuleNumber': rule_idx,
                    'Value': rule_value,
                    'Type': rule.get('Type', 'REGULAR'),
                    'Expression': parse_expression(rule_expr),
                    'ExpressionJSON': json.dumps(rule_expr, indent=2),
                })

            # Extract inherited value rules
            inherited_rules = cc_detail.get('Rules', [])
            for rule in inherited_rules:
                if rule.get('Type') == 'INHERITED_VALUE':
                    inherited = rule.get('InheritedValue', {})
                    all_inherited_rules.append({
                        'CategoryName': cc_name,
                        'DimensionName': inherited.get('DimensionName', 'N/A'),
                        'DimensionKey': inherited.get('DimensionKey', 'N/A'),
                    })

            # Extract split charge rules
            split_rules = cc_detail.get('SplitChargeRules', [])
            for split_idx, split in enumerate(split_rules, 1):
                all_split_rules.append({
                    'CategoryName': cc_name,
                    'SplitRuleNumber': split_idx,
                    'Source': split.get('Source', 'N/A'),
                    'Targets': ', '.join(split.get('Targets', [])),
                    'Method': split.get('Method', 'N/A'),
                    'Parameters': ', '.join([f"{p.get('Type')}={', '.join(p.get('Values', []))}"
                                            for p in split.get('Parameters', [])]),
                })

        # Create DataFrames
        df_categories = utils.prepare_dataframe_for_export(pd.DataFrame(all_categories))
        df_rules = utils.prepare_dataframe_for_export(pd.DataFrame(all_rules))
        df_inherited = utils.prepare_dataframe_for_export(pd.DataFrame(all_inherited_rules))
        df_splits = utils.prepare_dataframe_for_export(pd.DataFrame(all_split_rules))

        # Create summary
        summary_data = []
        if not df_categories.empty:
            summary_data.append({
                'Metric': 'Total Cost Categories',
                'Value': len(df_categories),
            })
            summary_data.append({
                'Metric': 'Total Rules',
                'Value': len(df_rules),
            })
            summary_data.append({
                'Metric': 'Inherited Value Rules',
                'Value': len(df_inherited),
            })
            summary_data.append({
                'Metric': 'Split Charge Rules',
                'Value': len(df_splits),
            })
            summary_data.append({
                'Metric': 'Categories with Default Values',
                'Value': len(df_categories[df_categories['DefaultValue'] != 'N/A']),
            })
            summary_data.append({
                'Metric': 'Active Categories',
                'Value': len(df_categories[df_categories['EffectiveEnd'] == 'N/A']),
            })

        df_summary = utils.prepare_dataframe_for_export(pd.DataFrame(summary_data))

        # Export to Excel
        filename = utils.create_export_filename(account_name, 'cost-categories', 'all')

        sheets = {
            'Summary': df_summary,
            'Cost Categories': df_categories,
            'Category Rules': df_rules,
            'Inherited Value Rules': df_inherited,
            'Split Charge Rules': df_splits,
        }

        utils.save_multiple_dataframes_to_excel(sheets, filename)

        # Log summary
        utils.log_export_summary(
            total_items=len(cost_category_refs),
            item_type='Cost Categories',
            filename=filename
        )

        if not df_categories.empty:
            utils.log_info(f"  Total Rules: {len(df_rules)}")
            if not df_inherited.empty:
                utils.log_info(f"  Inherited Value Rules: {len(df_inherited)}")
            if not df_splits.empty:
                utils.log_info(f"  Split Charge Rules: {len(df_splits)}")

        utils.log_success("Cost Categories export completed successfully!")

    except Exception as e:
        utils.log_error(f"Failed to export Cost Categories: {str(e)}")
        raise


if __name__ == "__main__":
    main()

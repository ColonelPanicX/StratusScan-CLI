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

import json
import sys
from pathlib import Path
from typing import Any

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
args = utils.parse_script_args("Export AWS Cost Categories to Excel")

utils.setup_logging('cost-categories-export')


def parse_expression(expression: dict, prefix: str = "") -> str:
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


def _build_cost_category_row(cc_ref: dict) -> dict[str, Any]:
    """
    Build the primary-scope inventory row for a single Cost Category
    reference returned by ``list_cost_category_definitions``.

    Extracted so per-item processing can be wrapped in try/except by the
    caller: a malformed reference must not sink the whole primary-scope
    collection. Every field is read with ``.get()`` and a safe default for
    the same reason (see
    .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).

    Args:
        cc_ref: A single CostCategoryReferences entry from
            list_cost_category_definitions.

    Returns:
        dict: The assembled primary-scope row.
    """
    processing_status_list = cc_ref.get('ProcessingStatus') or [{'Status': 'N/A'}]
    processing_status = (
        processing_status_list[0].get('Status', 'N/A') if processing_status_list else 'N/A'
    )

    return {
        'Name': cc_ref.get('Name', 'Unknown'),
        'CostCategoryArn': cc_ref.get('CostCategoryArn', 'N/A'),
        'ProcessingStatus': processing_status,
        'NumberOfRules': cc_ref.get('NumberOfRules', 0),
        'Values': ', '.join(cc_ref.get('Values', [])) if cc_ref.get('Values') else 'N/A',
    }


def list_cost_category_definitions() -> list[dict[str, Any]]:
    """
    PRIMARY scope collector: list all Cost Category definitions
    (top-level inventory).

    Not wrapped in ``aws_error_handler`` and does not swallow errors to an
    empty list: a swallowed error here would be indistinguishable from an
    account with no Cost Categories configured, producing silent data loss
    (see the 07.15.2026 / 07.16.2026 silent-collection-failure audits).
    Cost Categories (Cost Explorer) is a global, account-scope service (not
    multi-region — see scripts/shield_export.py for the account-scope
    reference pattern this follows). Account-scope failures (client
    creation, pagination) are allowed to raise so the caller can record this
    scope as *failed* rather than *empty*. Per-item errors are contained
    internally via ``_build_cost_category_row`` (logged and skipped).

    Returns:
        list: Primary-scope inventory rows (see ``_build_cost_category_row``).

    Raises:
        Exception: Any AWS/pagination error for the account scope (caller
            records it as a failed scope; it is never masked as empty).
    """
    # Cost Explorer is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    ce = utils.get_boto3_client('ce', region_name=home_region)

    raw_refs = []
    next_token = None

    while True:
        params = {'MaxResults': 100}
        if next_token:
            params['NextToken'] = next_token

        response = ce.list_cost_category_definitions(**params)
        raw_refs.extend(response.get('CostCategoryReferences', []))

        next_token = response.get('NextToken')
        if not next_token:
            break

    cost_categories = []
    skipped = 0

    for cc_ref in raw_refs:
        try:
            cost_categories.append(_build_cost_category_row(cc_ref))
        except Exception as e:
            skipped += 1
            name = cc_ref.get('Name', 'Unknown') if isinstance(cc_ref, dict) else 'Unknown'
            utils.log_error(f"Skipping Cost Category reference '{name}' due to a processing error", e)
            continue

    if skipped:
        utils.log_warning(
            f"{skipped} of {len(raw_refs)} Cost Category reference(s) were skipped due to "
            "processing errors (see log above); the remaining references were still collected."
        )

    return cost_categories


@utils.aws_error_handler("Describing Cost Category Definition", default_return=None)
def describe_cost_category(cost_category_arn: str) -> dict[str, Any]:
    """Get detailed Cost Category definition."""
    # Cost Explorer is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    ce = utils.get_boto3_client('ce', region_name=home_region)

    response = ce.describe_cost_category_definition(
        CostCategoryArn=cost_category_arn
    )

    return response.get('CostCategory')


def _run_export(account_id: str, account_name: str) -> None:
    """
    Collect Cost Categories data and write the Excel export.

    Cost Categories (Cost Explorer) is a global, account-scope service (not
    multi-region), so failure tracking follows the account-scope pattern
    (see scripts/shield_export.py) rather than
    ``utils.scan_regions_concurrent``. ``list_cost_category_definitions()``
    is the PRIMARY scope: a real API error there must propagate to
    ``failed_scopes``, never collapse into "no Cost Categories configured"
    (see .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).
    ``describe_cost_category()`` is per-item enrichment and continues to
    degrade gracefully — a single category's detail failing does not fail
    the whole export.

    An Excel workbook (with a forced ``Summary`` sheet) is always written,
    even when the primary scope failed, so a partial export never looks
    like a missing file. If the primary scope failed, a failure marker is
    written and the process exits non-zero; a genuinely empty account
    (primary scope succeeded, nothing configured) exits 0 with no marker.
    """
    utils.log_info(f"Exporting Cost Categories for account: {account_name} ({utils.mask_account_id(account_id)})")
    utils.log_info("Cost Categories are global (accessed via us-east-1)...")

    # Account-scope failure tracking (see scripts/shield_export.py).
    failed_scopes = []

    # STEP 1: List all cost categories (PRIMARY scope — a real API error
    # here must propagate to failed_scopes, never collapse into an empty
    # list that reads as "no Cost Categories configured").
    utils.log_info("Retrieving Cost Category definitions...")
    try:
        cost_category_refs = list_cost_category_definitions()
    except Exception as e:
        failed_scopes.append(('cost_categories', str(e)))
        utils.log_error(f"Cost Category definitions collection failed: {e}")
        cost_category_refs = []

    if not cost_category_refs and not failed_scopes:
        # Genuinely empty: the primary scope succeeded and there is simply
        # nothing configured.
        utils.log_warning("No Cost Categories found.")
        utils.log_info("Creating empty export file...")
    elif cost_category_refs:
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
            # ProcessingStatus/Values are already resolved to display strings by
            # _build_cost_category_row() — read directly rather than re-deriving
            # from the raw AWS shape.
            'ProcessingStatus': cc_ref.get('ProcessingStatus', 'N/A'),
            'NumberOfRules': cc_ref.get('NumberOfRules', 0),
            'Values': cc_ref.get('Values', 'N/A'),
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

    # The Summary sheet (and the rest of the workbook) is always written,
    # even when the primary scope failed — PRESERVE this: a partial export
    # that looks complete is exactly the failure mode this guards against,
    # so it must always be paired with the marker + non-zero exit below
    # when failed_scopes is non-empty.
    utils.save_multiple_dataframes_to_excel(sheets, filename)

    # Log summary
    if not df_categories.empty:
        utils.log_info(f"  Total Rules: {len(df_rules)}")
        if not df_inherited.empty:
            utils.log_info(f"  Inherited Value Rules: {len(df_inherited)}")
        if not df_splits.empty:
            utils.log_info(f"  Split Charge Rules: {len(df_splits)}")

    utils.log_success("Cost Categories export completed successfully!")

    # If the primary scope failed, make it loud: write a marker and exit
    # non-zero, even though the workbook (with its forced Summary sheet)
    # was still written. A partial export that looks complete is exactly
    # the failure mode this guards against.
    if failed_scopes:
        utils.report_collection_failures(account_name, 'cost-categories', failed_scopes)
        print(
            "\nERROR: Cost Categories export completed with failures — data is "
            "incomplete. See the *-cost-categories-FAILED-*.txt marker in the "
            "output directory."
        )
        sys.exit(1)


def main():
    """Main execution function — 2-step state machine (confirm -> export) for global service."""
    try:
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return
        global pd
        import pandas as pd
        account_id, account_name = utils.print_script_banner("AWS COST CATEGORIES EXPORT")

        # GovCloud availability guard — Cost Explorer is not available in GovCloud
        partition = utils.detect_partition()
        if not utils.is_service_available_in_partition("ce", partition):
            utils.log_warning("Cost Categories (Cost Explorer) is not available in AWS GovCloud. Skipping.")
            sys.exit(0)

        step = 1

        while True:
            if step == 1:
                msg = "Ready to export Cost Categories data (global service, us-east-1)."
                result = utils.prompt_confirmation(msg)
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                step = 2

            elif step == 2:
                _run_export(account_id, account_name)
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

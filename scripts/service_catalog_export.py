#!/usr/bin/env python3
"""
Service Catalog Export Script

Exports AWS Service Catalog portfolio and product information:
- Portfolios (collections of products)
- Products (catalog items)
- Provisioned products (deployed instances)
- Provisioning artifacts (product versions)
- Portfolio access (principal associations)
- Product launch paths
- Constraints (launch and template constraints)
- Tag options

Features:
- Complete portfolio inventory
- Product catalog with versions
- Provisioned product tracking
- Access control visibility
- Constraint analysis
- Multi-region support
- Comprehensive multi-worksheet export
"""

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
args = utils.parse_script_args("Export AWS Service Catalog portfolios and products to Excel")


def _build_portfolio_row(portfolio: dict, region: str) -> dict[str, Any]:
    """Build a single portfolio export row from a list_portfolios item."""
    return {
        'Region': region,
        'PortfolioId': portfolio.get('Id', 'N/A'),
        'PortfolioARN': portfolio.get('ARN', 'N/A'),
        'DisplayName': portfolio.get('DisplayName', 'N/A'),
        'Description': portfolio.get('Description', 'N/A'),
        'ProviderName': portfolio.get('ProviderName', 'N/A'),
        'CreatedTime': portfolio.get('CreatedTime'),
    }


def _scan_portfolios_region(region: str) -> list[dict[str, Any]]:
    """
    Collect Service Catalog portfolios from a single region.

    This is one of the primary scope collectors. It deliberately does NOT
    swallow errors: an API/permission failure here must propagate so
    ``scan_regions_concurrent(..., collect_failures=True)`` records the
    region as failed instead of silently reporting "no portfolios" (the
    silent-collection-loss bug — see
    ``.collab/audit/07.16.2026-silent-collection-failure-blast-radius.md``).

    Individual malformed portfolios are skipped (logged) rather than
    aborting the whole region.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    sc = utils.get_boto3_client('servicecatalog', region_name=region)
    portfolios = []

    paginator = sc.get_paginator('list_portfolios')
    for page in paginator.paginate():
        for portfolio in page.get('PortfolioDetails', []):
            try:
                portfolios.append(_build_portfolio_row(portfolio, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed portfolio in {region}: "
                    f"{portfolio.get('Id', '<unknown>')}",
                    e,
                )
                continue

    return portfolios


def collect_portfolios(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect Service Catalog portfolios across regions, surfacing failures.

    Uses ``collect_failures=True`` so a region whose collection errors is
    reported as a failed scope rather than silently collapsed into an empty
    result.

    Returns:
        tuple: ``(portfolios, failed_regions)`` where ``failed_regions`` is a
        list of ``(region, error_message)`` tuples.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_portfolios_region,
        show_progress=True,
        collect_failures=True,
    )
    all_portfolios = [p for result in region_results for p in result]
    return all_portfolios, failed_regions


def _build_product_row(product: dict, region: str) -> dict[str, Any]:
    """Build a single product export row from a search_products_as_admin item."""
    product_view = product.get('ProductViewSummary', {})
    product_arn = product.get('ProductARN', 'N/A')

    return {
        'Region': region,
        'ProductId': product_view.get('ProductId', 'N/A'),
        'ProductARN': product_arn,
        'Name': product_view.get('Name', 'N/A'),
        'ShortDescription': product_view.get('ShortDescription', 'N/A'),
        'Type': product_view.get('Type', 'N/A'),
        'Owner': product_view.get('Owner', 'N/A'),
        'Distributor': product_view.get('Distributor', 'N/A'),
        'SupportDescription': product_view.get('SupportDescription', 'N/A'),
        'SupportEmail': product_view.get('SupportEmail', 'N/A'),
        'SupportUrl': product_view.get('SupportUrl', 'N/A'),
    }


def _scan_products_region(region: str) -> list[dict[str, Any]]:
    """
    Collect Service Catalog products (as admin) from a single region.

    Primary scope collector — see ``_scan_portfolios_region`` docstring for
    the no-swallow contract this follows.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    sc = utils.get_boto3_client('servicecatalog', region_name=region)
    products = []

    paginator = sc.get_paginator('search_products_as_admin')
    for page in paginator.paginate():
        for product in page.get('ProductViewDetails', []):
            try:
                products.append(_build_product_row(product, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed product in {region}: "
                    f"{product.get('ProductARN', '<unknown>')}",
                    e,
                )
                continue

    return products


def collect_products(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect Service Catalog products across regions, surfacing failures.

    Returns:
        tuple: ``(products, failed_regions)`` — see ``collect_portfolios``.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_products_region,
        show_progress=True,
        collect_failures=True,
    )
    all_products = [p for result in region_results for p in result]
    return all_products, failed_regions


def _build_provisioned_product_row(product: dict, region: str) -> dict[str, Any]:
    """Build a single provisioned-product export row from a scan_provisioned_products item."""
    return {
        'Region': region,
        'ProvisionedProductId': product.get('Id', 'N/A'),
        'ProvisionedProductARN': product.get('Arn', 'N/A'),
        'Name': product.get('Name', 'N/A'),
        'Type': product.get('Type', 'N/A'),
        'Status': product.get('Status', 'N/A'),
        'StatusMessage': product.get('StatusMessage', 'N/A'),
        'CreatedTime': product.get('CreatedTime'),
        'LastRecordId': product.get('LastRecordId', 'N/A'),
        'ProductId': product.get('ProductId', 'N/A'),
        'ProductName': product.get('ProductName', 'N/A'),
        'ProvisioningArtifactId': product.get('ProvisioningArtifactId', 'N/A'),
        'ProvisioningArtifactName': product.get('ProvisioningArtifactName', 'N/A'),
        'UserArn': product.get('UserArn', 'N/A'),
        'UserArnSession': product.get('UserArnSession', 'N/A'),
    }


def _scan_provisioned_products_region(region: str) -> list[dict[str, Any]]:
    """
    Collect Service Catalog provisioned products from a single region.

    Primary scope collector — see ``_scan_portfolios_region`` docstring for
    the no-swallow contract this follows.
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Skipping invalid AWS region: {region}")
        return []

    sc = utils.get_boto3_client('servicecatalog', region_name=region)
    provisioned = []

    paginator = sc.get_paginator('scan_provisioned_products')
    for page in paginator.paginate():
        for product in page.get('ProvisionedProducts', []):
            try:
                provisioned.append(_build_provisioned_product_row(product, region))
            except Exception as e:
                utils.log_error(
                    f"Skipping malformed provisioned product in {region}: "
                    f"{product.get('Id', '<unknown>')}",
                    e,
                )
                continue

    return provisioned


def collect_provisioned_products(regions: list[str]) -> tuple[list[dict[str, Any]], list]:
    """
    Collect Service Catalog provisioned products across regions, surfacing failures.

    Returns:
        tuple: ``(provisioned_products, failed_regions)`` — see ``collect_portfolios``.
    """
    region_results, failed_regions = utils.scan_regions_concurrent(
        regions=regions,
        scan_function=_scan_provisioned_products_region,
        show_progress=True,
        collect_failures=True,
    )
    all_provisioned = [p for result in region_results for p in result]
    return all_provisioned, failed_regions


@utils.aws_error_handler("Listing provisioning artifacts", default_return=[])
def list_provisioning_artifacts(region: str, product_id: str) -> list[dict[str, Any]]:
    """List provisioning artifacts (versions) for a product."""
    sc = utils.get_boto3_client('servicecatalog', region_name=region)
    artifacts = []

    try:
        response = sc.list_provisioning_artifacts(ProductId=product_id)

        for artifact in response.get('ProvisioningArtifactDetails', []):
            artifacts.append({
                'Region': region,
                'ProductId': product_id,
                'ArtifactId': artifact.get('Id', 'N/A'),
                'Name': artifact.get('Name', 'N/A'),
                'Description': artifact.get('Description', 'N/A'),
                'Type': artifact.get('Type', 'N/A'),
                'CreatedTime': artifact.get('CreatedTime'),
                'Active': artifact.get('Active', False),
                'Guidance': artifact.get('Guidance', 'N/A'),
            })
    except Exception:
        # Product might not have artifacts or might be inaccessible
        pass

    return artifacts


@utils.aws_error_handler("Listing portfolio access", default_return=[])
def list_portfolio_principals(region: str, portfolio_id: str) -> list[dict[str, Any]]:
    """List principals with access to a portfolio."""
    sc = utils.get_boto3_client('servicecatalog', region_name=region)
    principals = []

    try:
        paginator = sc.get_paginator('list_principals_for_portfolio')
        for page in paginator.paginate(PortfolioId=portfolio_id):
            for principal in page.get('Principals', []):
                principals.append({
                    'Region': region,
                    'PortfolioId': portfolio_id,
                    'PrincipalARN': principal.get('PrincipalARN', 'N/A'),
                    'PrincipalType': principal.get('PrincipalType', 'N/A'),
                })
    except Exception:
        # Portfolio might not have any principals
        pass

    return principals


def _run_export(account_id: str, account_name: str, regions: list) -> None:
    """Collect Service Catalog data and write the Excel export."""
    # STEP 1: Collect the primary scopes (portfolios, products, provisioned
    # products). Each is routed through scan_regions_concurrent with
    # collect_failures=True so a region that errors is recorded as failed
    # rather than silently collapsed into "empty" — see
    # .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md.
    failed_regions: list = []

    utils.log_info("=== COLLECTING PORTFOLIOS ===")
    all_portfolios, portfolio_failures = collect_portfolios(regions)
    utils.log_success(f"Total portfolios collected: {len(all_portfolios)}")
    failed_regions.extend(portfolio_failures)

    utils.log_info("=== COLLECTING PRODUCTS ===")
    all_products, product_failures = collect_products(regions)
    utils.log_success(f"Total products collected: {len(all_products)}")
    failed_regions.extend(product_failures)

    utils.log_info("=== COLLECTING PROVISIONED PRODUCTS ===")
    all_provisioned, provisioned_failures = collect_provisioned_products(regions)
    utils.log_success(f"Total provisioned products collected: {len(all_provisioned)}")
    failed_regions.extend(provisioned_failures)

    # STEP 2: Secondary, best-effort detail (per-portfolio/per-product lookups).
    # These are not primary scopes — a failure here is logged and skipped
    # rather than tracked as a failed region.
    all_principals: list[dict[str, Any]] = []
    for portfolio in all_portfolios:
        portfolio_id = portfolio.get('PortfolioId')
        portfolio_region = portfolio.get('Region')
        if not portfolio_id or portfolio_id == 'N/A' or not portfolio_region:
            continue
        principals = list_portfolio_principals(portfolio_region, portfolio_id)
        all_principals.extend(principals)

    all_artifacts: list[dict[str, Any]] = []
    for product in all_products[:10]:
        product_id = product.get('ProductId')
        product_region = product.get('Region')
        if not product_id or product_id == 'N/A' or not product_region:
            continue
        artifacts = list_provisioning_artifacts(product_region, product_id)
        all_artifacts.extend(artifacts)

    if not all_portfolios and not all_products:
        utils.log_warning("No Service Catalog portfolios or products found in any selected region.")
        utils.log_info("Creating empty export file...")

    utils.log_info(f"Total portfolios found: {len(all_portfolios)}")
    utils.log_info(f"Total products found: {len(all_products)}")
    utils.log_info(f"Total provisioned products found: {len(all_provisioned)}")

    # Create DataFrames
    df_portfolios = utils.prepare_dataframe_for_export(pd.DataFrame(all_portfolios))
    df_products = utils.prepare_dataframe_for_export(pd.DataFrame(all_products))
    df_provisioned = utils.prepare_dataframe_for_export(pd.DataFrame(all_provisioned))
    df_artifacts = utils.prepare_dataframe_for_export(pd.DataFrame(all_artifacts))
    df_principals = utils.prepare_dataframe_for_export(pd.DataFrame(all_principals))

    # Create summary — this sheet is ALWAYS written, even when collection
    # partially failed, so a workbook always lands. Failure signaling is
    # handled separately via the FAILED marker + non-zero exit below.
    summary_data = []
    summary_data.append({'Metric': 'Total Portfolios', 'Value': len(all_portfolios)})
    summary_data.append({'Metric': 'Total Products', 'Value': len(all_products)})
    summary_data.append({'Metric': 'Total Provisioned Products', 'Value': len(all_provisioned)})
    summary_data.append({'Metric': 'Total Provisioning Artifacts', 'Value': len(all_artifacts)})
    summary_data.append({'Metric': 'Total Portfolio Principals', 'Value': len(all_principals)})
    summary_data.append({'Metric': 'Regions Scanned', 'Value': len(regions)})

    if not df_provisioned.empty:
        active_provisioned = len(df_provisioned[df_provisioned['Status'] == 'AVAILABLE'])
        error_provisioned = len(df_provisioned[df_provisioned['Status'] == 'ERROR'])

        summary_data.append({'Metric': 'Active Provisioned Products', 'Value': active_provisioned})
        summary_data.append({'Metric': 'Error Provisioned Products', 'Value': error_provisioned})

    df_summary = utils.prepare_dataframe_for_export(pd.DataFrame(summary_data))

    # Create active provisioned products view
    df_active_provisioned = pd.DataFrame()
    if not df_provisioned.empty:
        df_active_provisioned = df_provisioned[df_provisioned['Status'] == 'AVAILABLE']

    # Export to Excel
    filename = utils.create_export_filename(account_name, 'service-catalog', 'all')

    sheets = {
        'Summary': df_summary,
        'Portfolios': df_portfolios,
        'Products': df_products,
        'Provisioned Products': df_provisioned,
        'Active Provisioned': df_active_provisioned,
        'Provisioning Artifacts': df_artifacts,
        'Portfolio Access': df_principals,
    }

    utils.save_multiple_dataframes_to_excel(sheets, filename)

    # Log summary
    utils.log_info(f"  Portfolios: {len(all_portfolios)}")
    utils.log_info(f"  Products: {len(all_products)}")
    utils.log_info(f"  Provisioned Products: {len(all_provisioned)}")

    utils.log_success("Service Catalog export completed successfully!")

    # If ANY primary scope failed collection in any region, make it loud: a
    # workbook always landed above (Summary sheet is always written), but a
    # partial export that looks complete is exactly the failure mode this
    # guards against. Write a marker and exit non-zero. A genuinely empty
    # account (no failures, no data) stays exit 0 with no marker.
    if failed_regions:
        utils.report_collection_failures(account_name, 'service-catalog', failed_regions)
        print(
            "\nERROR: Service Catalog export completed with failures — data is incomplete. "
            "See the *-service-catalog-FAILED-*.txt marker in the output directory."
        )
        sys.exit(1)


def main():
    """Main function — 3-step state machine with b/x navigation."""
    try:
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            return
        global pd
        import pandas as pd
        utils.setup_logging("service-catalog-export")
        account_id, account_name = utils.print_script_banner("AWS SERVICE CATALOG EXPORT")

        step = 1
        regions = None

        while True:
            if step == 1:
                result = utils.prompt_region_selection(service_name="Service Catalog")
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                regions = result
                step = 2

            elif step == 2:
                region_str = ', '.join(regions) if len(regions) <= 3 else f"{len(regions)} regions"
                msg = f"Ready to export Service Catalog data ({region_str})."
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

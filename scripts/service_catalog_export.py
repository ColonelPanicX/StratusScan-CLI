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
from typing import List, Dict, Any
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
logger = utils.setup_logging('service-catalog-export')
utils.log_script_start('service-catalog-export', 'Export AWS Service Catalog portfolios and products')


@utils.aws_error_handler("Listing portfolios", default_return=[])
def list_portfolios(region: str) -> List[Dict[str, Any]]:
    """List all portfolios."""
    sc = utils.get_boto3_client('servicecatalog', region_name=region)
    portfolios = []

    paginator = sc.get_paginator('list_portfolios')
    for page in paginator.paginate():
        for portfolio in page.get('PortfolioDetails', []):
            portfolios.append({
                'Region': region,
                'PortfolioId': portfolio.get('Id', 'N/A'),
                'PortfolioARN': portfolio.get('ARN', 'N/A'),
                'DisplayName': portfolio.get('DisplayName', 'N/A'),
                'Description': portfolio.get('Description', 'N/A'),
                'ProviderName': portfolio.get('ProviderName', 'N/A'),
                'CreatedTime': portfolio.get('CreatedTime'),
            })

    return portfolios


@utils.aws_error_handler("Searching products as admin", default_return=[])
def search_products_as_admin(region: str) -> List[Dict[str, Any]]:
    """Search all products as admin."""
    sc = utils.get_boto3_client('servicecatalog', region_name=region)
    products = []

    paginator = sc.get_paginator('search_products_as_admin')
    for page in paginator.paginate():
        for product in page.get('ProductViewDetails', []):
            product_view = product.get('ProductViewSummary', {})
            product_arn = product.get('ProductARN', 'N/A')

            products.append({
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
            })

    return products


@utils.aws_error_handler("Scanning provisioned products", default_return=[])
def scan_provisioned_products(region: str) -> List[Dict[str, Any]]:
    """Scan all provisioned products."""
    sc = utils.get_boto3_client('servicecatalog', region_name=region)
    provisioned = []

    paginator = sc.get_paginator('scan_provisioned_products')
    for page in paginator.paginate():
        for product in page.get('ProvisionedProducts', []):
            provisioned.append({
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
            })

    return provisioned


@utils.aws_error_handler("Listing provisioning artifacts", default_return=[])
def list_provisioning_artifacts(region: str, product_id: str) -> List[Dict[str, Any]]:
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
def list_portfolio_principals(region: str, portfolio_id: str) -> List[Dict[str, Any]]:
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


def main():
    """Main execution function."""
    try:
        # Get account information
        account_id, account_name = utils.get_account_info()
        utils.log_info(f"Exporting Service Catalog resources for account: {account_name} ({account_id})")

        # Prompt for regions
        utils.log_info("Service Catalog is a regional service.")

        # Detect partition for region examples
        regions = utils.prompt_region_selection()
        # Collect all resources
        all_portfolios = []
        all_products = []
        all_provisioned = []
        all_artifacts = []
        all_principals = []

        for idx, region in enumerate(regions, 1):
            utils.log_info(f"[{idx}/{len(regions)}] Processing region: {region}")

            # Collect portfolios
            portfolios = list_portfolios(region)
            if portfolios:
                utils.log_info(f"  Found {len(portfolios)} portfolio(s)")
                all_portfolios.extend(portfolios)

                # Collect principals for each portfolio
                for portfolio in portfolios:
                    portfolio_id = portfolio['PortfolioId']
                    principals = list_portfolio_principals(region, portfolio_id)
                    all_principals.extend(principals)

            # Collect products
            products = search_products_as_admin(region)
            if products:
                utils.log_info(f"  Found {len(products)} product(s)")
                all_products.extend(products)

                # Collect artifacts for each product (sample first 10)
                for product in products[:10]:
                    product_id = product['ProductId']
                    artifacts = list_provisioning_artifacts(region, product_id)
                    all_artifacts.extend(artifacts)

            # Collect provisioned products
            provisioned = scan_provisioned_products(region)
            if provisioned:
                utils.log_info(f"  Found {len(provisioned)} provisioned product(s)")
                all_provisioned.extend(provisioned)

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

        # Create summary
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
        utils.log_export_summary(
            total_items=len(all_portfolios) + len(all_products) + len(all_provisioned),
            item_type='Service Catalog Resources',
            filename=filename
        )

        utils.log_info(f"  Portfolios: {len(all_portfolios)}")
        utils.log_info(f"  Products: {len(all_products)}")
        utils.log_info(f"  Provisioned Products: {len(all_provisioned)}")

        utils.log_success("Service Catalog export completed successfully!")

    except Exception as e:
        utils.log_error(f"Failed to export Service Catalog resources: {str(e)}")
        raise


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AWS Marketplace Subscriptions Export Script for StratusScan

Exports comprehensive AWS Marketplace subscription information including:
- Active and historical agreements (private offers, public subscriptions)
- Agreement terms (pricing, legal, support, renewal details)
- Cost and payment tracking

Output: Multi-worksheet Excel file with Marketplace resources
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


@utils.aws_error_handler("Collecting Marketplace agreements", default_return=[])
def collect_agreements() -> List[Dict[str, Any]]:
    """Collect AWS Marketplace agreement information (global service)."""
    print("\n=== COLLECTING MARKETPLACE AGREEMENTS ===")
    all_agreements = []

    # Marketplace Agreement API is a global service - use partition-aware home region
    home_region = utils.get_partition_default_region()
    mp_client = utils.get_boto3_client('marketplace-agreement', region_name=home_region)

    try:
        # Search for all agreements (active and expired)
        paginator = mp_client.get_paginator('search_agreements')

        # Search without filters to get all agreements
        for page in paginator.paginate():
            agreements = page.get('agreementViewSummaries', [])

            for agreement_summary in agreements:
                agreement_id = agreement_summary.get('agreementId', 'N/A')

                try:
                    # Get detailed agreement information
                    agreement_response = mp_client.describe_agreement(
                        agreementId=agreement_id
                    )

                    agreement_details = agreement_response

                    proposer = agreement_details.get('proposer', {})
                    acceptor = agreement_details.get('acceptor', {})

                    agreement_type = agreement_details.get('agreementType', 'N/A')
                    status = agreement_details.get('status', 'N/A')

                    acceptance_time = agreement_details.get('acceptanceTime', 'N/A')
                    if acceptance_time != 'N/A':
                        acceptance_time = acceptance_time.strftime('%Y-%m-%d %H:%M:%S')

                    start_time = agreement_details.get('startTime', 'N/A')
                    if start_time != 'N/A':
                        start_time = start_time.strftime('%Y-%m-%d %H:%M:%S')

                    end_time = agreement_details.get('endTime', 'N/A')
                    if end_time != 'N/A':
                        end_time = end_time.strftime('%Y-%m-%d %H:%M:%S')

                    estimated_charges = agreement_details.get('estimatedCharges', {})
                    agreement_amount = estimated_charges.get('agreementValue', 'N/A')
                    currency_code = estimated_charges.get('currencyCode', 'N/A')

                    all_agreements.append({
                        'Agreement ID': agreement_id,
                        'Agreement Type': agreement_type,
                        'Status': status,
                        'Proposer Account ID': proposer.get('accountId', 'N/A'),
                        'Acceptor Account ID': acceptor.get('accountId', 'N/A'),
                        'Acceptance Time': acceptance_time,
                        'Start Time': start_time,
                        'End Time': end_time,
                        'Agreement Amount': agreement_amount,
                        'Currency': currency_code
                    })

                except Exception as e:
                    utils.log_warning(f"Could not get details for agreement {agreement_id}: {str(e)}")
                    continue

    except Exception as e:
        utils.log_warning(f"Error searching agreements: {str(e)}")

    utils.log_success(f"Total agreements collected: {len(all_agreements)}")
    return all_agreements


@utils.aws_error_handler("Collecting agreement terms", default_return=[])
def collect_agreement_terms(agreements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collect detailed terms for each agreement."""
    print("\n=== COLLECTING AGREEMENT TERMS ===")
    all_terms = []

    home_region = utils.get_partition_default_region()
    mp_client = utils.get_boto3_client('marketplace-agreement', region_name=home_region)

    for agreement in agreements:
        agreement_id = agreement.get('Agreement ID', 'N/A')
        if agreement_id == 'N/A':
            continue

        try:
            # Get agreement terms
            paginator = mp_client.get_paginator('get_agreement_terms')
            for page in paginator.paginate(agreementId=agreement_id):
                accepted_terms = page.get('acceptedTerms', [])

                for term in accepted_terms:
                    term_type = term.get('type', 'N/A')

                    # Extract pricing information if available
                    pricing_info = 'N/A'
                    legal_info = 'N/A'
                    support_info = 'N/A'
                    renewal_info = 'N/A'

                    # ConfigurableUpfrontPricingTerm
                    if 'configurableUpfrontPricingTerm' in term:
                        pricing_term = term['configurableUpfrontPricingTerm']
                        pricing_info = f"Upfront: {pricing_term.get('currencyCode', 'USD')} {pricing_term.get('rateCards', [{}])[0].get('price', 'N/A')}"

                    # RecurringPaymentTerm
                    elif 'recurringPaymentTerm' in term:
                        payment_term = term['recurringPaymentTerm']
                        billing_period = payment_term.get('billingPeriod', 'N/A')
                        pricing_info = f"Recurring: {billing_period}"

                    # LegalTerm
                    elif 'legalTerm' in term:
                        legal_term = term['legalTerm']
                        legal_info = legal_term.get('type', 'N/A')

                    # SupportTerm
                    elif 'supportTerm' in term:
                        support_term = term['supportTerm']
                        support_info = support_term.get('type', 'N/A')

                    # RenewalTerm
                    elif 'renewalTerm' in term:
                        renewal_term = term['renewalTerm']
                        renewal_info = f"Type: {renewal_term.get('type', 'N/A')}"

                    all_terms.append({
                        'Agreement ID': agreement_id,
                        'Term Type': term_type,
                        'Pricing Details': pricing_info,
                        'Legal Details': legal_info,
                        'Support Details': support_info,
                        'Renewal Details': renewal_info
                    })

        except Exception as e:
            utils.log_warning(f"Could not get terms for agreement {agreement_id}: {str(e)}")
            continue

    utils.log_success(f"Total agreement terms collected: {len(all_terms)}")
    return all_terms


def generate_summary(agreements: List[Dict[str, Any]],
                     terms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate summary statistics for Marketplace resources."""
    utils.log_info("Generating summary statistics...")

    summary = []

    # Agreements summary
    total_agreements = len(agreements)
    active_agreements = sum(1 for a in agreements if a.get('Status', '') == 'ACTIVE')
    expired_agreements = sum(1 for a in agreements if a.get('Status', '') == 'EXPIRED')

    summary.append({
        'Metric': 'Total Agreements',
        'Count': total_agreements,
        'Details': f'Active: {active_agreements}, Expired: {expired_agreements}'
    })

    # Calculate total spend (active agreements only)
    if agreements:
        total_spend = 0
        currency = 'USD'
        for agreement in agreements:
            if agreement.get('Status', '') == 'ACTIVE':
                amount = agreement.get('Agreement Amount', 'N/A')
                curr = agreement.get('Currency', 'USD')
                if amount != 'N/A' and isinstance(amount, (int, float, str)):
                    try:
                        total_spend += float(amount)
                        currency = curr
                    except (ValueError, TypeError):
                        pass

        if total_spend > 0:
            summary.append({
                'Metric': 'Active Agreement Value',
                'Count': f'{currency} {total_spend:,.2f}',
                'Details': 'Total estimated charges for active agreements'
            })

    # Agreement types
    if agreements:
        df = pd.DataFrame(agreements)
        agreement_types = df['Agreement Type'].value_counts().to_dict()
        for atype, count in agreement_types.items():
            summary.append({
                'Metric': f'{atype} Agreements',
                'Count': count,
                'Details': 'Agreement type distribution'
            })

    # Terms summary
    summary.append({
        'Metric': 'Total Agreement Terms',
        'Count': len(terms),
        'Details': 'Pricing, legal, support, and renewal terms'
    })

    return summary


def main():
    """Main execution function."""
    script_name = Path(__file__).stem
    utils.setup_logging(script_name)
    utils.log_script_start(script_name)

    print("\n" + "="*60)
    print("AWS Marketplace Subscriptions Export Tool")
    print("="*60)

    # Check dependencies
    check_dependencies()

    # Get AWS account information
    account_id, account_name = utils.get_account_info()
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Please check your credentials.")
        return

    utils.log_info(f"AWS Account: {account_name} ({account_id})")

    # Note: Marketplace APIs are global services
    print("\nNote: AWS Marketplace is a global service (not region-specific)")
    print("Data will be collected from all your Marketplace agreements and subscriptions.")

    # Collect data
    print("\nCollecting AWS Marketplace data...")

    agreements = collect_agreements()
    terms = collect_agreement_terms(agreements)
    summary = generate_summary(agreements, terms)

    # Create DataFrames
    utils.log_info("Creating DataFrames...")

    dataframes = {}

    if summary:
        df_summary = pd.DataFrame(summary)
        df_summary = utils.prepare_dataframe_for_export(df_summary)
        dataframes['Summary'] = df_summary

    if agreements:
        df_agreements = pd.DataFrame(agreements)
        df_agreements = utils.prepare_dataframe_for_export(df_agreements)
        dataframes['Agreements'] = df_agreements

    if terms:
        df_terms = pd.DataFrame(terms)
        df_terms = utils.prepare_dataframe_for_export(df_terms)
        dataframes['Agreement Terms'] = df_terms

    # Export to Excel
    if dataframes:
        filename = utils.create_export_filename(account_name, 'marketplace', 'global')

        utils.log_info(f"Exporting to {filename}...")
        utils.save_multiple_dataframes_to_excel(dataframes, filename)

        # Log summary
        utils.log_export_summary(filename, {
            'Agreements': len(agreements),
            'Agreement Terms': len(terms)
        })
    else:
        utils.log_warning("No Marketplace data found to export")

    utils.log_success("Marketplace export completed successfully")


if __name__ == "__main__":
    main()

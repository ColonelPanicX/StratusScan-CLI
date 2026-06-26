#!/usr/bin/env python3
"""
Cost Management & Optimization All-in-One Export Script

Thin wrapper over _resource_bundle.run_bundle().  Bundles the exporters under
the main-menu "Cost Management & Optimization" category and delegates all
orchestration to the shared engine.

Covered services (multi-select at runtime):
  Billing, Cost Optimization Hub, Trusted Advisor, Compute Optimizer,
  Savings Plans, AWS Budgets, Reserved Instances, Cost Categories,
  Cost Anomaly Detection
"""

import sys
from pathlib import Path

try:
    from _resource_bundle import run_bundle
except ImportError:
    sys.path.append(str(Path(__file__).parent))
    from _resource_bundle import run_bundle

CATEGORY = "Cost Management & Optimization"
SLUG = "cost-management"
SCRIPTS = [
    ("Billing Export",         "billing_export.py"),
    ("Cost Optimization Hub",  "cost_optimization_hub_export.py"),
    ("Trusted Advisor",        "trusted_advisor_cost_optimization_export.py"),
    ("Compute Optimizer",      "compute_optimizer_export.py"),
    ("Savings Plans",          "savings_plans_export.py"),
    ("AWS Budgets",            "budgets_export.py"),
    ("Reserved Instances",     "reserved_instances_export.py"),
    ("Cost Categories",        "cost_categories_export.py"),
    ("Cost Anomaly Detection", "cost_anomaly_detection_export.py"),
]

GOVCLOUD_NOTE = (
    "Most cost services (Cost Explorer, Trusted Advisor, Compute Optimizer, "
    "Savings Plans, Cost Optimization Hub) are unavailable in GovCloud and "
    "will be reported as skipped when run in an aws-us-gov account."
)


def main() -> None:
    run_bundle(
        CATEGORY,
        SLUG,
        SCRIPTS,
        description="Export all cost management & optimization data to Excel",
        note=GOVCLOUD_NOTE,
    )


if __name__ == "__main__":
    main()

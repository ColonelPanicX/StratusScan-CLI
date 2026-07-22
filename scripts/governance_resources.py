#!/usr/bin/env python3
"""
Management & Governance All-in-One Export Script

Thin wrapper over _resource_bundle.run_bundle().  Bundles the exporters under
the main-menu "Management & Governance" category and delegates all
orchestration to the shared engine.

Covered services (multi-select at runtime):
  CloudFormation, Service Catalog, AWS Health, License Manager,
  AWS Marketplace, AWS Control Tower, Systems Manager Fleet
"""

import sys
from pathlib import Path

try:
    from _resource_bundle import run_bundle
except ImportError:
    sys.path.append(str(Path(__file__).parent))
    from _resource_bundle import run_bundle

CATEGORY = "Management & Governance"
SLUG = "management-governance"
SCRIPTS = [
    ("CloudFormation",        "cloudformation_export.py"),
    ("Service Catalog",       "service_catalog_export.py"),
    ("AWS Health",            "health_export.py"),
    ("License Manager",       "license_manager_export.py"),
    ("AWS Marketplace",       "marketplace_export.py"),
    ("AWS Control Tower",     "controltower_export.py"),
    ("Systems Manager Fleet", "ssm_fleet_export.py"),
]

GOVCLOUD_NOTE = (
    "AWS Health (Business/Enterprise Support) and Marketplace are unavailable "
    "in GovCloud and will be reported as skipped when run in an aws-us-gov "
    "account."
)


def main() -> None:
    run_bundle(
        CATEGORY,
        SLUG,
        SCRIPTS,
        description="Export all management & governance resources to Excel",
        note=GOVCLOUD_NOTE,
    )


if __name__ == "__main__":
    main()

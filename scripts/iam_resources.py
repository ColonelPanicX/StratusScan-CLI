#!/usr/bin/env python3
"""
Identity & Access Management All-in-One Export Script

Thin wrapper over _resource_bundle.run_bundle().  Bundles the exporters under
the main-menu "Identity & Access Management" category and delegates all
orchestration to the shared engine.

Covered services (multi-select at runtime):
  IAM, IAM Identity Center
"""

import sys
from pathlib import Path

try:
    from _resource_bundle import run_bundle
except ImportError:
    sys.path.append(str(Path(__file__).parent))
    from _resource_bundle import run_bundle

CATEGORY = "Identity & Access Management"
SLUG = "iam"
SCRIPTS = [
    ("IAM",                 "iam_export.py"),
    ("IAM Identity Center", "iam_identity_center_export.py"),
]


def main() -> None:
    run_bundle(
        CATEGORY,
        SLUG,
        SCRIPTS,
        description="Export all IAM resources (users, roles, Identity Center) to Excel",
    )


if __name__ == "__main__":
    main()

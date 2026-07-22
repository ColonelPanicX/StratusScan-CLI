#!/usr/bin/env python3
"""
Security & Compliance All-in-One Export Script

Thin wrapper over _resource_bundle.run_bundle().  Bundles every exporter under
the main-menu "Security & Compliance" category (Security Monitoring +
Identity, Certs & Config) and delegates all orchestration to the shared engine.

Covered services (multi-select at runtime):
  Security Hub, GuardDuty, Detective, Macie, AWS WAF, Shield Advanced,
  IAM Access Analyzer, KMS, ACM, ACM Private CA, Secrets Manager, Cognito,
  Verified Access, Verified Permissions, IAM Roles Anywhere,
  IAM Identity Providers, CloudTrail, AWS Config
"""

import sys
from pathlib import Path

try:
    from _resource_bundle import run_bundle
except ImportError:
    sys.path.append(str(Path(__file__).parent))
    from _resource_bundle import run_bundle

CATEGORY = "Security & Compliance"
SLUG = "security-compliance"
SCRIPTS = [
    ("Security Hub",            "security_hub_export.py"),
    ("GuardDuty",              "guardduty_export.py"),
    ("Detective",              "detective_export.py"),
    ("Macie",                  "macie_export.py"),
    ("AWS WAF",                "waf_export.py"),
    ("Shield Advanced",        "shield_export.py"),
    ("IAM Access Analyzer",    "access_analyzer_export.py"),
    ("KMS",                    "kms_export.py"),
    ("ACM",                    "acm_export.py"),
    ("ACM Private CA",         "acm_privateca_export.py"),
    ("Secrets Manager",        "secrets_manager_export.py"),
    ("Cognito",                "cognito_export.py"),
    ("Verified Access",        "verifiedaccess_export.py"),
    ("Verified Permissions",   "verifiedpermissions_export.py"),
    ("IAM Roles Anywhere",     "iam_rolesanywhere_export.py"),
    ("IAM Identity Providers", "iam_identity_providers_export.py"),
    ("CloudTrail",             "cloudtrail_export.py"),
    ("AWS Config",             "config_export.py"),
]

GOVCLOUD_NOTE = (
    "Several services (Detective, Macie, Shield Advanced) are unavailable in "
    "GovCloud and will be reported as skipped when run in an aws-us-gov account."
)


def main() -> None:
    run_bundle(
        CATEGORY,
        SLUG,
        SCRIPTS,
        description="Export all security & compliance resources to Excel",
        note=GOVCLOUD_NOTE,
    )


if __name__ == "__main__":
    main()

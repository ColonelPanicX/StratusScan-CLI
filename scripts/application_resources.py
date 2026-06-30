#!/usr/bin/env python3
"""
Application Services All-in-One Export Script

Thin wrapper over _resource_bundle.run_bundle().  Bundles the exporters under
the main-menu "Application Services" category and delegates all orchestration
to the shared engine.

Covered services (multi-select at runtime):
  Step Functions, App Runner, Elastic Beanstalk, AppSync, AWS Connect,
  API Gateway, EventBridge, SQS/SNS, Cloud Map, SES, SES & Pinpoint
"""

import sys
from pathlib import Path

try:
    from _resource_bundle import run_bundle
except ImportError:
    sys.path.append(str(Path(__file__).parent))
    from _resource_bundle import run_bundle

CATEGORY = "Application Services"
SLUG = "application-services"
SCRIPTS = [
    ("Step Functions",    "stepfunctions_export.py"),
    ("App Runner",        "apprunner_export.py"),
    ("Elastic Beanstalk", "elasticbeanstalk_export.py"),
    ("AppSync",           "appsync_export.py"),
    ("AWS Connect",       "connect_export.py"),
    ("API Gateway",       "api_gateway_export.py"),
    ("EventBridge",       "eventbridge_export.py"),
    ("SQS/SNS",           "sqs_sns_export.py"),
    ("Cloud Map",         "cloudmap_export.py"),
    ("SES",               "ses_export.py"),
    ("SES & Pinpoint",    "ses_pinpoint_export.py"),
]


def main() -> None:
    run_bundle(
        CATEGORY,
        SLUG,
        SCRIPTS,
        description="Export all application services resources to Excel",
    )


if __name__ == "__main__":
    main()

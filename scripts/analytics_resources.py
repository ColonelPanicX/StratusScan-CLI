#!/usr/bin/env python3
"""
Data & Analytics All-in-One Export Script

Thin wrapper over _resource_bundle.run_bundle().  Bundles the exporters under
the main-menu "Data & Analytics" category and delegates all orchestration to
the shared engine.

Covered services (multi-select at runtime):
  OpenSearch Service, Redshift, Glue & Athena, Lake Formation, SageMaker,
  Bedrock, Comprehend, Rekognition, CloudWatch, X-Ray
"""

import sys
from pathlib import Path

try:
    from _resource_bundle import run_bundle
except ImportError:
    sys.path.append(str(Path(__file__).parent))
    from _resource_bundle import run_bundle

CATEGORY = "Data & Analytics"
SLUG = "data-analytics"
SCRIPTS = [
    ("OpenSearch Service", "opensearch_export.py"),
    ("Redshift",           "redshift_export.py"),
    ("Glue & Athena",      "glue_athena_export.py"),
    ("Lake Formation",     "lakeformation_export.py"),
    ("SageMaker",          "sagemaker_export.py"),
    ("Bedrock",            "bedrock_export.py"),
    ("Comprehend",         "comprehend_export.py"),
    ("Rekognition",        "rekognition_export.py"),
    ("CloudWatch",         "cloudwatch_export.py"),
    ("X-Ray",              "xray_export.py"),
]


def main() -> None:
    run_bundle(
        CATEGORY,
        SLUG,
        SCRIPTS,
        description="Export all data & analytics resources to Excel",
    )


if __name__ == "__main__":
    main()

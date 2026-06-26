#!/usr/bin/env python3
"""
Database Resources All-in-One Export Script

Thin wrapper over _resource_bundle.run_bundle().  Defines the database exporter
registry and delegates all orchestration (region/script selection, subprocess
execution, zip archiving, summary) to the shared engine.

Covered services (multi-select at runtime):
  RDS, DynamoDB, ElastiCache, DocumentDB, Neptune
"""

import sys
from pathlib import Path

try:
    from _resource_bundle import run_bundle
except ImportError:
    sys.path.append(str(Path(__file__).parent))
    from _resource_bundle import run_bundle

CATEGORY = "Database Resources"
SLUG = "database-resources"
SCRIPTS = [
    ("RDS",         "rds_export.py"),
    ("DynamoDB",    "dynamodb_export.py"),
    ("ElastiCache", "elasticache_export.py"),
    ("DocumentDB",  "documentdb_export.py"),
    ("Neptune",     "neptune_export.py"),
]


def main() -> None:
    run_bundle(
        CATEGORY,
        SLUG,
        SCRIPTS,
        description="Export all database resources (RDS, DynamoDB, etc.) to Excel",
    )


if __name__ == "__main__":
    main()

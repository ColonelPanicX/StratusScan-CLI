#!/usr/bin/env python3
"""
Storage Resources All-in-One Export Script

Thin wrapper over _resource_bundle.run_bundle().  Defines the storage exporter
registry and delegates all orchestration (region/script selection, subprocess
execution, zip archiving, summary) to the shared engine.

Covered services (multi-select at runtime):
  EBS Volumes, EBS Snapshots, S3, EFS, FSx, AWS Backup, S3 Access Points,
  DataSync, Transfer Family, Storage Gateway, Glacier Vaults
"""

import sys
from pathlib import Path

try:
    from _resource_bundle import run_bundle
except ImportError:
    sys.path.append(str(Path(__file__).parent))
    from _resource_bundle import run_bundle

CATEGORY = "Storage Resources"
SLUG = "storage-resources"
SCRIPTS = [
    ("EBS Volumes",       "ebs_volumes_export.py"),
    ("EBS Snapshots",     "ebs_snapshots_export.py"),
    ("S3",                "s3_export.py"),
    ("EFS",               "efs_export.py"),
    ("FSx",               "fsx_export.py"),
    ("AWS Backup",        "backup_export.py"),
    ("S3 Access Points",  "s3_accesspoints_export.py"),
    ("DataSync",          "datasync_export.py"),
    ("Transfer Family",   "transfer_family_export.py"),
    ("Storage Gateway",   "storagegateway_export.py"),
    ("Glacier Vaults",    "glacier_export.py"),
]


def main() -> None:
    run_bundle(
        CATEGORY,
        SLUG,
        SCRIPTS,
        description="Export all storage resources (S3, EFS, EBS, etc.) to Excel",
    )


if __name__ == "__main__":
    main()

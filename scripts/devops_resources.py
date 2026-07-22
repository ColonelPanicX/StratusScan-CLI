#!/usr/bin/env python3
"""
DevOps Services All-in-One Export Script

Thin wrapper over _resource_bundle.run_bundle().  Bundles the exporters under
the main-menu "DevOps Services" category and delegates all orchestration to
the shared engine.

Covered services (multi-select at runtime):
  CodeBuild, CodePipeline, CodeCommit, CodeDeploy
"""

import sys
from pathlib import Path

try:
    from _resource_bundle import run_bundle
except ImportError:
    sys.path.append(str(Path(__file__).parent))
    from _resource_bundle import run_bundle

CATEGORY = "DevOps Services"
SLUG = "devops"
SCRIPTS = [
    ("CodeBuild",    "codebuild_export.py"),
    ("CodePipeline", "codepipeline_export.py"),
    ("CodeCommit",   "codecommit_export.py"),
    ("CodeDeploy",   "codedeploy_export.py"),
]


def main() -> None:
    run_bundle(
        CATEGORY,
        SLUG,
        SCRIPTS,
        description="Export all DevOps services resources to Excel",
    )


if __name__ == "__main__":
    main()

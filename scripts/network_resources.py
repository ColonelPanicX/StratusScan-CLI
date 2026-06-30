#!/usr/bin/env python3
"""
Network Resources All-in-One Export Script

Thin wrapper over _resource_bundle.run_bundle().  Defines the network exporter
registry and delegates all orchestration (region/script selection, subprocess
execution, zip archiving, summary) to the shared engine.

Covered services (multi-select at runtime):
  VPC/Subnet, ELB, Network ACLs, Security Groups, Route Tables, CloudFront,
  Route 53, VPN, Direct Connect, Global Accelerator, Transit Gateway,
  Network Firewall, Network Manager

Note: CloudFront, Route 53, and Global Accelerator are not available in
GovCloud.  Their exporters exit cleanly with code 0 when the partition is
aws-us-gov, so they may be selected safely — they will simply produce no
output file and be reported as skipped in the summary.
"""

import sys
from pathlib import Path

try:
    from _resource_bundle import run_bundle
except ImportError:
    sys.path.append(str(Path(__file__).parent))
    from _resource_bundle import run_bundle

CATEGORY = "Network Resources"
SLUG = "network-resources"
SCRIPTS = [
    ("VPC/Subnet",          "vpc_data_export.py"),
    ("ELB",                 "elb_export.py"),
    ("Network ACLs",        "nacl_export.py"),
    ("Security Groups",     "security_groups_export.py"),
    ("Route Tables",        "route_tables_export.py"),
    ("CloudFront",          "cloudfront_export.py"),
    ("Route 53",            "route53_export.py"),
    ("VPN",                 "vpn_export.py"),
    ("Direct Connect",      "directconnect_export.py"),
    ("Global Accelerator",  "globalaccelerator_export.py"),
    ("Transit Gateway",     "transit_gateway_export.py"),
    ("Network Firewall",    "network_firewall_export.py"),
    ("Network Manager",     "network_manager_export.py"),
]

GOVCLOUD_NOTE = (
    "CloudFront, Route 53, and Global Accelerator are unavailable in GovCloud "
    "and will be reported as skipped when run in an aws-us-gov account."
)


def main() -> None:
    run_bundle(
        CATEGORY,
        SLUG,
        SCRIPTS,
        description="Export all network resources (VPC, subnets, NACLs, etc.) to Excel",
        note=GOVCLOUD_NOTE,
    )


if __name__ == "__main__":
    main()

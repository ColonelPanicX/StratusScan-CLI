# StratusScan-CLI

[![Version: 0.3.0](https://img.shields.io/badge/version-0.3.0-blue.svg)](https://github.com/ColonelPanicX/StratusScan-CLI/releases)
[![Status: Beta](https://img.shields.io/badge/status-beta-yellow.svg)](#project-status)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![AWS Commercial](https://img.shields.io/badge/AWS-Commercial-orange.svg)](https://aws.amazon.com/)
[![AWS GovCloud](https://img.shields.io/badge/AWS-GovCloud%20(US)-blue.svg)](https://aws.amazon.com/govcloud-us/)

A Python CLI tool for exporting AWS resource inventories to Excel workbooks. Supports 100+ AWS services across Commercial and GovCloud partitions, targeting infrastructure audits, FedRAMP evidence collection, and cost analysis.

[Quick Start](#quick-start) • [Features](#features) • [Installation](#installation) • [Usage](#usage) • [Permissions](#aws-permissions)

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/ColonelPanicX/StratusScan-CLI.git
cd StratusScan-CLI

# Install dependencies
pip install boto3 pandas openpyxl

# Configure AWS credentials
aws configure

# Run the configuration wizard (recommended)
python configure.py

# Launch StratusScan
python stratusscan.py
```

Select a resource category from the menu and follow the prompts. Exports are saved to the `output/` directory as `.xlsx` files.

---

## Features

### Core Capabilities

- **Hierarchical menu interface**: Organized by resource category with consistent navigation
- **Multi-region scanning**: Scan specific regions or all regions; concurrent execution for performance
- **Dual-partition support**: Full AWS Commercial and AWS GovCloud (US) support with automatic FIPS endpoint injection
- **Account mapping**: Translate AWS account IDs to friendly names via `config.json`
- **Standardized Excel output**: Consistent multi-sheet workbooks with timestamp-based filenames
- **Read-only operations**: No write permissions required; safe for production environments

### Smart Scan

**Smart Scan** automates the discovery-to-export workflow. Launch it from the StratusScan main menu:

1. **Service Discovery**: Scans your AWS account to identify which services are actively in use
2. **Script Recommendations**: Maps discovered services to relevant export scripts
3. **Scope Selection**: Choose Quick Scan (all recommended scripts) or Deep Scan (full catalog)
4. **Batch Execution**: Runs selected scripts sequentially with real-time progress output and a Markdown summary report

### Cost Estimation

Built-in cost reference data for EC2 and RDS, sourced from AWS pricing and stored as static CSVs in `reference/`. No live pricing API calls at runtime.

### GovCloud Support

- Automatic partition detection from caller ARN or region
- FIPS endpoints injected automatically for `us-gov-west-1` and `us-gov-east-1`
- Service availability checks guard against calling services unavailable in GovCloud (Cost Explorer, Global Accelerator, Rekognition, Cognito, Comprehend, Connect, Bedrock, and others)
- Four IAM policy files covering Commercial/GovCloud × required/optional permission sets

---

## Installation

### Requirements

- Python 3.9 or higher
- AWS credentials configured (CLI, environment variables, or IAM instance profile)
- Read-only AWS permissions ([see details](#aws-permissions))

### Runtime Dependencies

```bash
pip install boto3 pandas openpyxl
```

Missing packages are detected at script startup with an install prompt, but pre-installing is recommended.

### Developer Installation

```bash
pip install -e ".[dev]"
```

Includes pytest, moto, ruff, black, and mypy.

### AWS Authentication

**AWS CLI (recommended)**
```bash
aws configure
```

**Environment variables**
```bash
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_DEFAULT_REGION="us-east-1"
```

**IAM instance profile**: Credentials are picked up automatically when running on EC2.

---

## Configuration

StratusScan reads `config.json` for account mappings and default regions. The file is created automatically from `config-template.json` on first run.

### Configuration Wizard

```bash
python configure.py            # Interactive setup
python configure.py --validate  # Full validation (non-interactive)
python configure.py --perms     # Permissions check only
```

The wizard covers account ID-to-name mappings, default region selection (with presets for common setups), and AWS permission validation.

### Manual Configuration

```json
{
  "account_mappings": {
    "123456789012": "PROD-ACCOUNT",
    "234567890123": "DEV-ACCOUNT"
  },
  "organization_name": "YOUR-ORGANIZATION",
  "default_regions": ["us-east-1", "us-west-2"],
  "enabled_services": {
    "trusted_advisor": {
      "enabled": true,
      "note": "Requires Business or Enterprise support plan"
    }
  }
}
```

### CI / Unattended Execution

```bash
STRATUSSCAN_AUTO_RUN=1 STRATUSSCAN_REGIONS=us-east-1,us-west-2 python scripts/ec2_export.py
```

---

## Usage

### Main Menu

```bash
python stratusscan.py
```

Navigate the hierarchical menu by category (Compute, Storage, Network, IAM, Security, Cost, Smart Scan). Each exporter prompts for region selection and saves its output to `output/`.

### Direct Script Execution

Individual exporters can be run standalone:

```bash
python scripts/ec2_export.py
python scripts/iam_export.py
python scripts/s3_export.py
```

Each script self-contains its region prompting and output logic.

### Smart Scan

Access Smart Scan from the main menu. The workflow:

1. **Discovery phase**: StratusScan scans the account and identifies active AWS services
2. **Analysis**: Discovered services are mapped to relevant export scripts
3. **Selection**: Choose Quick Scan (all recommended) or Deep Scan (full catalog), with optional manual deselection
4. **Execution**: Scripts run sequentially; a Markdown summary report is written on completion

### Region Selection

When prompted for regions:
- Enter a specific region code: `us-east-1`, `eu-west-1`, `ap-southeast-2`
- Enter `all` to scan all opted-in regions for the current partition
- GovCloud sessions default to `us-gov-west-1` and `us-gov-east-1`

### Output Archives

From the main menu, **Output Management > Create Output Archive** zips all files in `output/` to `ACCOUNT-NAME-export-MM.DD.YYYY.zip`.

---

## AWS Permissions

StratusScan requires read-only access. Four purpose-built IAM policies are provided in `policies/`:

### AWS Commercial

| Policy file | Purpose |
|---|---|
| `commercial-required-permissions.json` | Core StratusScan functionality (~230 actions) |
| `commercial-optional-permissions.json` | ML/AI, CloudFront, Global Accelerator (~38 additional actions) |

### AWS GovCloud (US)

| Policy file | Purpose |
|---|---|
| `govcloud-required-permissions.json` | Core functionality, FedRAMP-compatible |
| `govcloud-optional-permissions.json` | Available ML/AI services in GovCloud |

**GovCloud service availability notes:**
- Global Accelerator, Cost Explorer, Trusted Advisor, Rekognition, Cognito, Comprehend, Connect, and Bedrock are not available in GovCloud — StratusScan skips these automatically
- CloudFront operates outside the ITAR boundary and is excluded from GovCloud policy files

All policies are compatible with both IAM (attach to users/roles) and IAM Identity Center (use as Permission Set inline policies).

See [`policies/README.md`](policies/README.md) for full details.

---

## Supported AWS Resources

StratusScan ships with **100+ export scripts** across these categories:

<details>
<summary><b>Compute</b></summary>

- EC2 Instances — instance details, OS, network config, cost estimates
- ECS — clusters, services, tasks, container instances
- EKS — clusters, node groups, configurations
- RDS — engines, storage, connection details
- Lambda — functions, runtimes, configurations
- Auto Scaling Groups — ASGs, instances, scaling policies, lifecycle hooks
- Elastic Beanstalk, App Runner, Batch, Lightsail

</details>

<details>
<summary><b>Storage</b></summary>

- S3 — buckets, encryption, versioning, object counts via CloudWatch metrics
- EBS — volumes, snapshots, encryption status
- EFS — file systems, mount targets, access points
- FSx, Glacier/Archive, Storage Gateway

</details>

<details>
<summary><b>Network</b></summary>

- VPC — VPCs, subnets, NAT gateways, peering, Elastic IPs
- Elastic Load Balancers — Classic, ALB, NLB, target groups, listeners
- Route 53 — hosted zones, records, resolver endpoints
- Security Groups, Network ACLs, Route Tables
- VPN, Direct Connect, Global Accelerator (Commercial only), Transit Gateway

</details>

<details>
<summary><b>IAM and Identity</b></summary>

- IAM — users, roles, policies, MFA devices, access keys, group memberships
- IAM Identity Center — users, groups, permission sets, assignments
- AWS Organizations — structure, accounts, OUs, SCPs
- AWS Access Analyzer — findings (external access + unused access analyzers)

</details>

<details>
<summary><b>Security</b></summary>

- Security Hub — findings, standards, compliance status
- GuardDuty — detectors, findings
- CloudTrail — trails, event selectors
- Config — rules, compliance status
- KMS — keys, key policies
- WAF — Web ACLs, rules, IP sets, rule groups
- Certificate Manager, Secrets Manager, Macie

</details>

<details>
<summary><b>Data and Analytics</b></summary>

- DynamoDB, Redshift, ElastiCache, MemoryDB
- Kinesis, MSK (Kafka), OpenSearch
- Glue, Athena
- Neptune — clusters, instances, snapshots, Neptune Analytics graphs

</details>

<details>
<summary><b>Cost and Governance</b></summary>

- AWS Backup — vaults, plans, selections, jobs
- Cost Optimization Hub (Commercial only)
- Compute Optimizer (Commercial only)
- Trusted Advisor (Commercial only; requires Business+ support)
- Reserved Instances, Savings Plans

</details>

---

## Output Files

All exports use a consistent naming convention:

```
{ACCOUNT-NAME}-{resource-type}-{suffix}-export-{MM.DD.YYYY}.xlsx
```

Examples:
```
PROD-ACCOUNT-ec2-all-export-03.03.2026.xlsx
DEV-ACCOUNT-iam-all-export-03.03.2026.xlsx
PROD-ACCOUNT-waf-all-export-03.03.2026.xlsx
```

Most exports produce multi-sheet workbooks — one sheet per resource type (e.g., the ELB export has Load Balancers, Target Groups, and Listeners sheets).

---

## Troubleshooting

**Missing dependencies**
```bash
pip install boto3 pandas openpyxl
```

**AWS credentials not found**
```bash
aws configure
# or
export AWS_ACCESS_KEY_ID="..." AWS_SECRET_ACCESS_KEY="..."
```

**Permission denied errors**
- Verify read-only policies are attached ([see permissions](#aws-permissions))
- Trusted Advisor requires AWS Business or Enterprise Support
- Cost Explorer requires opt-in and appropriate permissions

**GovCloud connection issues**
- StratusScan auto-injects FIPS endpoints; no manual configuration needed
- Verify credentials are for a GovCloud partition (`aws-us-gov`) profile

**Getting help**
1. Check `logs/` for detailed error messages
2. Validate credentials: `aws sts get-caller-identity`
3. Validate permissions: `python configure.py --perms`
4. Open an issue on GitHub with the relevant log excerpt

---

## Contributing

```bash
# Fork, clone, and install dev deps
git clone https://github.com/yourusername/StratusScan-CLI.git
cd StratusScan-CLI
pip install -e ".[dev]"

# Run tests
pytest
pytest -m "not slow"   # Skip slow integration tests

# Code quality
ruff check .
black .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the exporter script template and contribution guidelines.

---

## Project Status

**Current version: 0.3.0-beta**

StratusScan-CLI is in active beta development. The API and output format may change before the 1.0.0 stable release. All active development occurs on the `dev` branch; `main` is release snapshots only.

### What's in v0.3.0

- **Smart Scan redesign**: Fully integrated orchestrator in the main menu. Replaces the old `services_in_use_export.py` flow. Supports Quick Scan and Deep Scan modes with Markdown execution reports.
- **API correctness audit**: 6-PR remediation pass across all 107 exporter scripts covering runtime crashes, pagination gaps, GovCloud guard improvements, inaccurate field mappings, and missing API coverage (lifecycle hooks, target groups, listeners, rule groups, backup jobs, Neptune Analytics, and more).
- **Configure.py refactor**: Preset-based region selection, streamlined 4-step flow, improved GovCloud detection.
- **Main menu styling**: Box-drawing UI consistent with configure.py design standard applied throughout.

### Roadmap

| Version | Target | Notes |
|---|---|---|
| `0.3.x` | Patch releases | S3 large-account performance, coverage gaps |
| `1.0.0` | Planned | Full Textual-based TUI; subprocess output streamed live |

---

## Versioning

StratusScan-CLI uses [Semantic Versioning](https://semver.org/).

| Series | Status | Notes |
|---|---|---|
| `3.x.x` | Deprecated | Superseded by governance reset at `0.1.0` |
| `0.1.x` | Superseded | Initial relaunch |
| `0.2.x` | Superseded | Backend stabilization, pricing data v2 |
| `0.3.x` | Current (Beta) | Smart Scan orchestrator, full API correctness audit |
| `1.0.0` | Planned | Textual TUI, stable API |

---

## Branch Workflow

| Branch | Purpose |
|---|---|
| `dev` | Primary development — all PRs target `dev` first |
| `main` | Release snapshots only — no direct commits |
| `feat/*`, `fix/*` | Short-lived topic branches targeting `dev` |

All work originates from a GitHub Issue. PRs must reference issues using closing keywords (`Closes #N`, `Fixes #N`).

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built with assistance from [Claude Code](https://claude.ai/code). Powered by [AWS SDK for Python (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html). Excel export via [pandas](https://pandas.pydata.org/) and [openpyxl](https://openpyxl.readthedocs.io/). AWS mocking in tests via [moto](https://github.com/getmoto/moto).

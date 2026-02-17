# StratusScan-CLI

[![Version: 0.1.0](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/ColonelPanicX/StratusScan-CLI/releases)
[![Status: Beta](https://img.shields.io/badge/status-beta-yellow.svg)](#-project-status)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![AWS Commercial](https://img.shields.io/badge/AWS-Commercial-orange.svg)](https://aws.amazon.com/)
[![AWS GovCloud](https://img.shields.io/badge/AWS-GovCloud%20(US)-blue.svg)](https://aws.amazon.com/govcloud-us/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> A professional AWS resource export tool for multi-account, multi-region environments. Export detailed AWS infrastructure data to Excel with built-in cost estimation and intelligent optimization recommendations.

[Quick Start](#-quick-start) • [Features](#-features) • [Installation](#-installation) • [Documentation](#-documentation) • [Contributing](#-contributing)

---

## 🚀 Quick Start

Get up and running in 5 minutes:

```bash
# 1. Clone the repository
git clone https://github.com/ColonelPanicX/StratusScan-CLI.git
cd StratusScan-CLI

# 2. Install dependencies
pip install boto3 pandas openpyxl

# 3. Configure AWS credentials (choose one)
aws configure  # Interactive setup
# OR set environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"

# 4. Run configuration (recommended but optional)
python configure.py

# 5. Launch StratusScan
python stratusscan.py
```

That's it! Select a resource to export from the menu and follow the prompts. Exports are saved to the `output/` directory.

---

## ✨ Features

### Core Capabilities
- **🎯 Centralized Menu Interface**: Easy-to-use hierarchical menu for all export tools
- **🌍 Multi-Region Support**: Scan resources across specific regions or all AWS regions
- **🏢 Account Mapping**: Translate AWS account IDs to friendly organization names
- **📊 Standardized Exports**: Consistent Excel output with timestamp-based filenames
- **🔐 Read-Only Operations**: Safe, non-destructive AWS resource scanning

### Advanced Features
- **🧠 Smart Scan**: Intelligent script recommendations based on discovered AWS services with batch execution
- **💰 Cost Estimation**: Built-in cost calculators for RDS, S3, NAT Gateway, and EC2 with pricing data
- **🎯 Optimization Engine**: Intelligent recommendations for cost savings and resource optimization
- **🔄 Progress Checkpointing**: Resume interrupted long-running operations automatically
- **✅ Dry-Run Mode**: Validate exports before execution with built-in validation
- **🔒 Data Sanitization**: Automatic detection and masking of sensitive data in exports
- **📋 Comprehensive Reports**: All-in-one reports for Compute, Storage, and Network resources

### Quality & Reliability
- **✅ 75+ Automated Tests**: Comprehensive test coverage with pytest and CI/CD pipeline
- **🔧 Error Handling**: Standardized error handling with automatic retry and exponential backoff
- **📝 Detailed Logging**: Complete audit trails with console and file output
- **🔍 Type Safety**: Full type hints for improved IDE support and static analysis
- **🛡️ Security Scanning**: Pre-commit hooks with Bandit and credential detection

---

## 📋 Installation

### Requirements

- **Python**: 3.9 or higher
- **AWS Access**: Configured credentials (CLI, environment variables, or IAM role)
- **Permissions**: Read-only access to AWS resources ([see details](#-aws-permissions))

### Install Dependencies

The scripts will prompt to install missing packages automatically, or you can install them manually:

```bash
pip install boto3 pandas openpyxl
```

### Developer Installation

For contributors (includes testing and development tools):

```bash
pip install -e ".[dev]"
pre-commit install  # Optional: Enable automated quality checks
```

### AWS Authentication

Configure your AWS credentials using one of these methods:

**Option 1: AWS CLI (Recommended)**
```bash
aws configure
AWS Access Key ID: [Your AWS Access Key]
AWS Secret Access Key: [Your AWS Secret Key]
Default region name: us-east-1
Default output format: json
```

**Option 2: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID="your-aws-access-key"
export AWS_SECRET_ACCESS_KEY="your-aws-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

**Option 3: IAM Instance Profile**
If running on EC2, credentials are automatically provided via the instance profile.

---

## ⚙️ Configuration

StratusScan uses a `config.json` file for account mappings and preferences.

### Interactive Setup (Recommended)

Run the configuration wizard:

```bash
python configure.py
```

This interactive tool will guide you through:
- Setting up account ID to name mappings
- Configuring default AWS regions
- Validating AWS permissions
- Checking dependencies

### Manual Configuration

Alternatively, create `config.json` manually:

```json
{
  "account_mappings": {
    "123456789012": "PROD-ACCOUNT",
    "234567890123": "DEV-ACCOUNT",
    "345678901234": "TEST-ACCOUNT"
  },
  "organization_name": "YOUR-ORGANIZATION",
  "default_regions": ["us-east-1", "us-west-2"],
  "resource_preferences": {
    "ec2": {
      "default_region": "us-east-1"
    }
  },
  "enabled_services": {
    "trusted_advisor": {
      "enabled": true,
      "note": "Available in AWS Commercial"
    }
  }
}
```

---

## 📖 Usage

### Main Menu Interface (Recommended)

```bash
python stratusscan.py
```

Navigate through the hierarchical menu to select resources:

1. Choose a category (Compute, Storage, Network, IAM, Security, Cost)
2. Select specific resource type or comprehensive report
3. Choose region(s) to scan
4. Wait for export to complete
5. Find your Excel file in `output/` directory

### Direct Script Execution

Run individual export scripts directly:

```bash
python scripts/ec2-export.py
python scripts/route53-export.py
python scripts/iam-comprehensive-export.py
```

Each script will prompt for required information and save output to `output/`.

### Smart Scan - Intelligent Export Automation

**Smart Scan** analyzes your AWS environment and recommends the most relevant export scripts to run based on discovered services. This feature saves time by automating the workflow of discovering services and exporting their data.

#### How It Works

1. **Service Discovery**: Run `services-in-use-export.py` to scan your AWS account
2. **Automatic Analysis**: Smart Scan analyzes the export to identify which services you're using
3. **Script Recommendations**: Get a curated list of export scripts matching your active services
4. **Interactive Selection**: Choose which exports to run (or run all with Quick Scan)
5. **Batch Execution**: Selected scripts run sequentially with real-time progress tracking

#### Usage Examples

**Interactive Mode (Recommended)**:
```bash
python scripts/services-in-use-export.py
# After service discovery completes, you'll be prompted:
# "Launch Smart Scan analyzer? (y/n):"
```

**Automatic Smart Scan**:
```bash
python scripts/services-in-use-export.py --smart-scan
# Automatically launches Smart Scan after service discovery
```

**Quick Scan (Full Automation)**:
```bash
python scripts/services-in-use-export.py --smart-scan --quick-scan
# Discovers services AND runs all recommended scripts automatically
```

**Skip Smart Scan**:
```bash
python scripts/services-in-use-export.py --no-smart-scan
# Only run service discovery, skip Smart Scan prompt
```

#### Interactive Smart Scan Menu

When Smart Scan launches, you'll see a menu with these options:

1. **Quick Scan** - Run all recommended scripts immediately (fastest)
2. **Custom Selection** - Choose specific scripts by category or service
3. **View Checklist** - See complete list of recommendations
4. **Save & Exit** - Save checklist to file for later review
5. **Exit** - Skip batch execution

#### Features

- **Intelligent Mapping**: 160+ AWS services mapped to 166 export scripts
- **Service Aliases**: Recognizes service name variations (e.g., "EC2", "Amazon EC2")
- **Always-Run Scripts**: Core security/compliance scripts (GuardDuty, CloudTrail, IAM, etc.)
- **Category Grouping**: Scripts organized by function (Compute, Storage, Network, etc.)
- **Progress Tracking**: Real-time execution status with `[X/Total] (percent%)` display
- **Execution Summary**: Success/failure stats with duration for each script
- **Execution Logs**: Detailed logs saved automatically for audit trails

#### Example Workflow

```bash
# 1. Discover active services
$ python scripts/services-in-use-export.py --smart-scan

# Smart Scan analyzes your environment...
# Found 23 active services

# 2. Choose what to run
Smart Scan Menu:
  1. Quick Scan (run all 31 recommended scripts)
  2. Custom Selection
  3. View Checklist
  4. Save & Exit
  5. Exit

# 3. Watch batch execution
Executing Scripts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[1/31] (3%) ec2-export.py ✓ Success (2m 15s)
[2/31] (6%) s3-export.py ✓ Success (1m 45s)
[3/31] (10%) rds-export.py ✓ Success (3m 30s)
...

# 4. Review summary
Execution Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Scripts: 31
Successful: 29
Failed: 2
Total Time: 42m 15s
```

#### Execution Logs

All batch executions are automatically logged to:
```
smart-scan-execution-YYYY-MM-DD-HHMMSS.log
```

The log includes script names, success/failure status, duration, output files, and error messages.

### Region Selection

When prompted, choose:
- **`all`**: Scan all AWS commercial regions
- **Specific region**: e.g., `us-east-1`, `eu-west-1`, `ap-southeast-1`

The tool validates regions and provides helpful error messages for invalid selections.

### Creating Export Archives

After running multiple exports, create a zip archive:

1. Select **Output Management** from the main menu
2. Choose **Create Output Archive**
3. Find the zip file in the root directory with format: `ACCOUNT-NAME-export-MM.DD.YYYY.zip`

---

## 🔐 AWS Permissions

StratusScan requires **read-only** access to AWS resources. We provide purpose-built IAM policies for both **AWS Commercial** and **AWS GovCloud (US)** environments.

### Recommended Approach: Custom StratusScan Policies

Choose the policy combination that matches your environment and requirements:

#### AWS Commercial

**Minimum Required:**
- [`policies/commercial-required-permissions.json`](policies/commercial-required-permissions.json) - Core StratusScan functionality (230 actions)

**Full Featured (Recommended):**
- [`policies/commercial-required-permissions.json`](policies/commercial-required-permissions.json) - Core functionality
- [`policies/commercial-optional-permissions.json`](policies/commercial-optional-permissions.json) - ML/AI, CloudFront, Global Accelerator (38 actions)

#### AWS GovCloud (US)

**Minimum Required:**
- [`policies/govcloud-required-permissions.json`](policies/govcloud-required-permissions.json) - Core functionality (FedRAMP High compliant)

**Full Featured (Recommended):**
- [`policies/govcloud-required-permissions.json`](policies/govcloud-required-permissions.json) - Core functionality
- [`policies/govcloud-optional-permissions.json`](policies/govcloud-optional-permissions.json) - ML/AI including Bedrock (34 actions)

**Key Differences for GovCloud:**
- ❌ Global Accelerator not available (use Route53 latency-based routing)
- ⚠️ CloudFront operates outside ITAR boundary (not included for compliance)
- ✅ All core services fully supported including Bedrock (as of November 2024)
- 🔐 FedRAMP High, DoD SRG IL-2/4/5, FIPS 140-3 compliant

### IAM vs IAM Identity Center

All policies work in **both IAM and IAM Identity Center** with no modifications needed. They have been validated for compatibility with both systems.

**For IAM:** Attach policies to IAM users, roles, or groups
**For IAM Identity Center:** Use as inline policies in Permission Sets

### Alternative: AWS Managed Policies

For quick setup, you can use AWS managed policies (less granular control):

- `ReadOnlyAccess` - General resource access
- `IAMReadOnlyAccess` - IAM resources
- `AWSSupportAccess` - Trusted Advisor (requires Business/Enterprise support)
- `ComputeOptimizerReadOnlyAccess` - Compute Optimizer recommendations
- `CostOptimizationHubReadOnlyAccess` - Cost recommendations

### Documentation

For detailed policy information, implementation guides, and service limitations:
- **[Policies README](policies/README.md)** - Complete policy documentation
- **[Quick Start Guide](policies/QUICK-START.md)** - Fast implementation instructions

---

## 📦 Supported AWS Resources

StratusScan supports **40+ AWS resource exporters** across multiple categories:

<details>
<summary><b>Compute Resources (5 exporters)</b></summary>

- **EC2 Instances**: Detailed instance info including OS, size, cost calculations, network config
- **ECS Clusters**: ECS cluster information, services, tasks, container instances
- **EKS Clusters**: Kubernetes cluster information, node groups, configurations
- **RDS Databases**: Database engine, size, storage, connection information
- **Compute Resources (All-in-One)**: Combined report of all compute resources

</details>

<details>
<summary><b>Storage Resources (4 exporters)</b></summary>

- **EBS Volumes**: Volume IDs, size, state, attachment info, pricing
- **EBS Snapshots**: Snapshot IDs, size, encryption status, creation dates
- **S3 Buckets**: Bucket information including size, object count, region, configuration
- **Storage Resources (All-in-One)**: Combined report of all storage resources

</details>

<details>
<summary><b>Network Resources (7 exporters)</b></summary>

- **VPC Resources**: VPCs, subnets, NAT gateways, peering connections, Elastic IPs
- **Route 53**: Hosted zones, DNS records, resolver endpoints/rules, query logging
- **Elastic Load Balancers**: Classic, Application, and Network load balancers
- **Security Groups**: Group details, inbound/outbound rules, resource associations
- **Network ACLs**: NACL rules, subnet associations, configurations
- **Route Tables**: Route table information, routes, subnet associations
- **Network Resources (All-in-One)**: Combined report of all network resources

</details>

<details>
<summary><b>IAM & Identity Resources (9 exporters)</b></summary>

- **IAM Comprehensive**: Complete IAM analysis (users, roles, policies, permissions)
- **IAM Users**: Basic user information and access keys
- **IAM Roles**: Role details, trust policies, attached permissions
- **IAM Policies**: Detailed policy analysis with risk assessment
- **IAM Identity Center Users**: AWS SSO/Identity Center users and assignments
- **IAM Identity Center Groups**: Group memberships and assignments
- **IAM Identity Center Permission Sets**: Permission set configurations
- **IAM Identity Center Comprehensive**: Complete Identity Center analysis
- **AWS Organizations**: Organizations structure, accounts, organizational units

</details>

<details>
<summary><b>Security Resources (2 exporters)</b></summary>

- **Security Hub**: Security findings, compliance status, remediation guidance
- **Services in Use**: Analysis of AWS services currently in use

</details>

<details>
<summary><b>Cost Optimization Resources (4 exporters)</b></summary>

- **Billing Export**: AWS billing and cost data
- **Cost Optimization Hub**: Recommendations and savings opportunities
- **Compute Optimizer**: Recommendations for EC2, Auto Scaling, EBS, Lambda
- **Trusted Advisor**: Cost optimization checks and recommendations (requires Business+ support)

</details>

---

## 📂 Output Files

### File Naming Convention

All exports follow a consistent naming pattern:

```
{ACCOUNT-NAME}-{RESOURCE-TYPE}-{SUFFIX}-export-{MM.DD.YYYY}.xlsx
```

**Examples:**
- `PROD-ACCOUNT-ec2-running-export-10.27.2025.xlsx`
- `DEV-ACCOUNT-route53-all-export-10.27.2025.xlsx`
- `PROD-ACCOUNT-iam-comprehensive-export-10.27.2025.xlsx`

**Archive:**
- `ACCOUNT-NAME-export-MM.DD.YYYY.zip`

---

## 📚 Documentation

- **[API Reference](API_REFERENCE.md)** - Complete API documentation with examples
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute with script templates
- **[Testing Guide](TESTING.md)** - Running tests and writing new tests
- **[Wiki](https://github.com/ColonelPanicX/StratusScan-CLI/wiki)** - Detailed guides and tutorials

---

## 🐛 Troubleshooting

### Common Issues

**Missing Dependencies**
```bash
# Install required packages
pip install boto3 pandas openpyxl
```

**AWS Credentials Not Found**
```bash
# Configure AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
```

**Permission Denied Errors**
- Ensure your IAM user/role has read-only access to AWS resources
- Verify you have the necessary policies attached ([see permissions](#-aws-permissions))
- For Trusted Advisor: Requires AWS Business or Enterprise Support plan

**Invalid Region Errors**
- Use valid AWS commercial region codes (e.g., `us-east-1`, not `us-east-1a`)
- Type `all` to scan all regions
- The tool validates regions and provides helpful error messages

### Getting Help

1. Check the log files in `logs/` directory for detailed error messages
2. Verify your AWS credentials: `aws sts get-caller-identity`
3. Run `python configure.py --perms` to validate AWS permissions
4. Review our [Wiki](https://github.com/ColonelPanicX/StratusScan-CLI/wiki) for detailed guides
5. Open an issue on GitHub with logs and error details

---

## 🤝 Contributing

Contributions are welcome! We've made it easy to get started:

- **⚡ 30-Minute Onboarding**: Complete [contributor guide](CONTRIBUTING.md) with script templates
- **🧪 Automated Testing**: 75+ tests with pytest and CI/CD pipeline
- **✨ Code Quality**: Pre-commit hooks with Black, Ruff, and Bandit
- **📚 API Documentation**: Full [API reference](API_REFERENCE.md) with examples
- **🔒 Security First**: Automated credential detection and security scanning

### Quick Start for Contributors

```bash
# 1. Fork and clone
git clone https://github.com/yourusername/StratusScan-CLI.git
cd StratusScan-CLI

# 2. Install development dependencies
pip install -e ".[dev]"

# 3. Set up pre-commit hooks (optional)
pre-commit install

# 4. Run tests
pytest

# 5. Make your changes and submit a PR
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines and script templates.

---

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Built with assistance from [Claude Code](https://claude.ai/code)
- Powered by [AWS SDK for Python (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- Excel export using [pandas](https://pandas.pydata.org/) and [openpyxl](https://openpyxl.readthedocs.io/)
- Testing with [pytest](https://pytest.org/) and [moto](https://github.com/getmoto/moto)

---

## 📊 Project Status

**Current Version**: 0.1.0 — **Beta**

> ⚠️ StratusScan-CLI is currently in **Beta**. The API and output format may change
> before the 1.0.0 stable release. Breaking changes will be documented in the changelog.
> All development happens on the `dev` branch.

- ✅ **75+ Automated Tests** - Comprehensive test coverage
- ✅ **CI/CD Pipeline** - GitHub Actions testing Python 3.9-3.12
- ✅ **Cost Estimation** - Built-in AWS cost calculators
- ✅ **Type Safety** - Full type hints throughout codebase
- ✅ **Security Scanning** - Pre-commit hooks with Bandit
- ✅ **40+ Exporters** - Comprehensive AWS resource coverage

---

## 🔖 Versioning Strategy

StratusScan-CLI uses [Semantic Versioning (SemVer)](https://semver.org/).

- **Current series**: `0.x.x` — pre-release, active development
- **Stable release**: `1.0.0` — planned once core API and export format stabilize
- **Breaking changes**: may occur in any `0.x` release; documented in the changelog
- **Previous versions**: the `3.x.x` series is deprecated and superseded by `0.1.0`

| Version Range | Status | Notes |
|---|---|---|
| `3.x.x` | Deprecated | Superseded by governance reset at `0.1.0` |
| `0.1.x` | Active (Beta) | Current development line |
| `1.0.0` | Planned | Stable release target |

---

## 🌿 Branch Workflow

| Branch | Purpose | Target |
|---|---|---|
| `dev` | Primary development — all feature work merges here first | `main` (release only) |
| `main` | Stable release snapshots only — no direct commits | — |
| `feature/*` | Short-lived feature branches | `dev` via PR |

**All work must originate from a GitHub Issue.** PRs must reference issues using GitHub
closing keywords (`Closes #N`, `Fixes #N`, `Resolves #N`).

```
feature/* → dev → main (release merge only)
```

---

## 📞 Support

For questions, issues, or feature requests, please open an issue on GitHub.

**Note**: StratusScan supports both **AWS Commercial** and **AWS GovCloud (US)** environments with 96.8% service compatibility. Always verify compliance with your organization's security policies and applicable regulations (FedRAMP, ITAR, etc.) before use.

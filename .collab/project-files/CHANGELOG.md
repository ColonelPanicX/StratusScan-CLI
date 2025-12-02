# Changelog

All notable changes to StratusScan-CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2025-11-10

### Added - Phase 3D: Advanced Security & Identity (4 scripts)

#### Macie Export (macie-export.py)
- Amazon Macie data security service export with 6 worksheets
- Classification job tracking with schedules and statistics
- Security findings export with severity levels
- S3 bucket classification status monitoring
- Custom data identifier patterns and regex
- Supports both AWS Commercial and sensitive data discovery

#### Cognito Export (cognito-export.py)
- User pool export with MFA and password policy configurations
- Identity pool export with federated identity settings
- App client configurations with OAuth flows and scopes
- Identity provider integrations (SAML, OIDC, social providers)
- User group memberships with role mappings
- Security configuration analysis (MFA, email/SMS verification)

#### ACM Private CA Export (acm-privateca-export.py)
- Private Certificate Authority configurations
- Certificate lifecycle management and expiration tracking
- Certificate templates with usage extensions
- CA resource-based permissions
- Revocation configuration (CRL and OCSP)
- FIPS 140-2 compliance tracking

#### IAM Identity Providers Export (iam-identity-providers-export.py)
- SAML identity provider export with metadata documents
- OIDC identity provider export with client IDs and thumbprints
- Automatic provider type detection (EKS, GitHub Actions, Google, Azure AD, Apple)
- IAM role trust relationship analysis
- Federated authentication configuration tracking

### Added - Phase 3E: AI & Machine Learning (4 scripts)

#### SageMaker Export (sagemaker-export.py)
- Notebook instance export with lifecycle configurations
- Training job export (limited to 50 most recent) with billable time tracking
- Model artifact and container configurations
- Model endpoint export with instance counts and autoscaling
- Processing job configurations with input/output tracking
- Security warnings for direct internet access and VPC isolation

#### Bedrock Export (bedrock-export.py)
- Foundation model availability tracking (Claude, Titan, Jurassic, etc.)
- Custom model fine-tuning status and job details
- Model invocation logging configurations
- Guardrails with content filter settings and blocked topics
- RAG knowledge base integration with data source URIs
- Bedrock agent export with instruction sets and action groups

#### Comprehend Export (comprehend-export.py)
- Custom entity recognizer export with evaluation metrics
- Document classifier export with training status
- Real-time endpoint monitoring with throughput tracking
- Classification job export (limited to 50 most recent)
- Entity detection job tracking with entity types
- Model accuracy metrics (F1, precision, recall)

#### Rekognition Export (rekognition-export.py)
- Custom vision project export
- Project version export with training metrics and billable hours
- Face collection management with face counts
- Stream processor configurations for video analysis
- Model deployment status tracking
- Performance metrics (F1 score, precision, recall)

### Added - Phase 3F: Developer Tools & CI/CD (4 scripts)

#### CodeBuild Export (codebuild-export.py)
- Build project export with environment configurations
- Recent build export (limited to 50 most recent) with status and duration
- Report group export for test results and code coverage
- VPC configuration monitoring
- Security warnings for privileged mode usage
- Build cache configurations (S3, local)

#### CodePipeline Export (codepipeline-export.py)
- Pipeline definition export with stage flow visualization
- Recent execution export (limited to 10 per pipeline) with status
- Webhook configuration for automated triggers
- Artifact store and encryption tracking
- Stage transition and action provider details

#### CodeCommit Export (codecommit-export.py)
- Git repository export with clone URLs (HTTP and SSH)
- Branch export with latest commit tracking
- Open pull request export with review status
- KMS encryption monitoring
- Repository default branch tracking
- Commit message and author information

#### CodeDeploy Export (codedeploy-export.py)
- Application and deployment group export
- Recent deployment export (limited to 30 most recent) with status
- Blue/green deployment configuration tracking
- Auto-rollback settings monitoring
- Load balancer and target group associations
- Deployment strategy configurations

### Changed

- **Menu Structure**: Added 3 new main menu categories
  - Option 14: Advanced Security & Identity
  - Option 15: AI & Machine Learning
  - Option 16: Developer Tools & CI/CD
  - Renumbered Output Management from 14 → 17
- **Total Scripts**: Increased from 60 to 84 export scripts (+40% coverage)
- **Version Numbers**: Updated across all documentation files
  - stratusscan.py: v2.2.0
  - pyproject.toml: v2.2.0
  - README.md: v2.2.0
  - API_REFERENCE.md: v2.2.0

### Technical Details

- All new scripts follow established StratusScan patterns:
  - `@aws_error_handler` decorator for standardized error handling
  - Type hints from `typing` module for all functions
  - Multi-region support with region selection
  - DateTime formatting for Excel compatibility
  - `prepare_dataframe_for_export()` for data standardization
  - `save_multiple_dataframes_to_excel()` for multi-worksheet exports
  - Boto3 pagination for large result sets
  - Summary statistics generation

### Performance Optimizations

- Data sampling implemented for large datasets:
  - Training jobs: 50 most recent per region
  - Builds: 50 most recent per region
  - Pipeline executions: 10 per pipeline
  - Deployments: 30 most recent per region
  - Classification jobs: Limited to prevent overwhelming exports
  - Entity detection jobs: Limited to 50 most recent

### Security Enhancements

- Security warnings added for:
  - SageMaker notebooks with direct internet access
  - CodeBuild projects using privileged mode
  - Cognito identity pools allowing unauthenticated access
  - Resources without VPC isolation
  - Resources without KMS encryption

---

## [2.1.4] - 2025-11-07

### Added - Phase 3A, 3B, 3C (12 scripts)

#### Database Resources (Phase 3A)
- DynamoDB export with GSIs, backups, and configuration details
- ElastiCache export for Redis/Memcached clusters
- DocumentDB export (MongoDB-compatible)
- Neptune export (Graph Database)

#### Analytics & Data (Phase 3B)
- OpenSearch Service export with VPC configs and encryption
- Redshift data warehouse export with snapshots
- Glue & Athena export for data catalog and queries
- Lake Formation export with permissions and LF-Tags

#### Application Services (Phase 3C)
- Step Functions export with state machines and executions
- App Runner export with auto scaling and VPC connectors
- Elastic Beanstalk export with applications and environments
- AppSync export for GraphQL APIs and resolvers

### Added - Phase 2A, 2B, 2C, 2D (16 scripts)

#### Security & Compliance (Phase 2A)
- GuardDuty export with threat detection findings
- AWS WAF export with web ACLs and rules
- CloudTrail export with audit logging
- AWS Config export with compliance rules

#### Cost Management (Phase 2B)
- Savings Plans export with commitment tracking
- AWS Budgets export with alerts and thresholds

#### Integration & Messaging (Phase 2C)
- API Gateway export (REST and HTTP APIs)
- EventBridge export with event buses and rules
- SQS/SNS export with queues and topics

#### Monitoring & Operations (Phase 2D)
- CloudWatch export with alarms and log groups
- Systems Manager Fleet export with patch compliance

### Added - Phase 1 Enhancements (8 scripts)

#### Security & Identity
- KMS export with key management
- Secrets Manager export (metadata only, no secret values)
- ACM export with SSL/TLS certificates
- IAM Access Analyzer export

#### Storage Resources
- EFS export with file systems and mount targets
- FSx export (Windows, Lustre, ONTAP, OpenZFS)
- AWS Backup export with vaults and plans

#### Compute Resources
- Lambda function export
- ECR repository export with vulnerability scans
- AMI export with architecture details
- EC2 Image Builder export

#### Network Resources
- CloudFront distribution export
- Transit Gateway export
- Network Firewall export

### Added - Infrastructure & Quality

- **Progress Checkpointing**: Resume interrupted long-running operations
- **Dry-Run Validation**: Validate exports before execution
- **Cost Estimation**: Built-in calculators for RDS, S3, NAT Gateway, EC2
- **Data Sanitization**: Automatic detection and masking of sensitive data
- **Comprehensive Testing**: 75+ automated tests with pytest
- **CI/CD Pipeline**: GitHub Actions testing Python 3.9-3.12
- **Type Safety**: Full type hints throughout codebase
- **Security Scanning**: Pre-commit hooks with Bandit
- **API Documentation**: Complete API reference with examples

### Changed

- Migrated from AWS GovCloud to AWS Commercial optimization
- Default regions: us-east-1, us-west-2, us-west-1, eu-west-1
- Partition handling for standard AWS
- License updated from MIT to GPL-3.0

---

## [1.4.0] - 2025-08-19

### Added
- Session management with automatic retry logic
- Standardized error handling with `@aws_error_handler` decorator
- Context manager for multi-step AWS operations
- ARN building with partition awareness

### Changed
- Improved boto3 client creation with retry configuration
- Enhanced logging infrastructure
- Better error messages for credential issues

---

## [1.3.3] - 2025-08-15

### Fixed
- Region validation for edge cases
- Excel export column width calculations
- Timezone handling in datetime exports

---

## [1.3.2] - 2025-08-12

### Added
- VPC data export improvements
- Security group rule export enhancements

### Fixed
- Pagination issues with large EC2 fleets
- Memory optimization for multi-region scans

---

## [1.3.1] - 2025-08-08

### Fixed
- IAM comprehensive export pagination
- Route table export formatting
- EBS snapshot date handling

---

## [1.3.0] - 2025-08-05

### Added
- IAM comprehensive export (all-in-one report)
- Route table export script
- Network ACL export enhancements

### Changed
- Improved menu structure with submenus
- Better account mapping configuration

---

## [1.0.0] - 2025-08-01

### Added - Initial Release
- Core export scripts:
  - EC2 instances with cost calculations
  - RDS databases
  - EKS clusters
  - ECS clusters
  - EBS volumes and snapshots
  - S3 buckets
  - VPC resources (subnets, NAT gateways, peering)
  - Security groups
  - Network ACLs
  - Load balancers (CLB, ALB, NLB)
  - IAM users, roles, policies
  - IAM Identity Center (AWS SSO)
  - AWS Organizations
  - Security Hub
  - Services in Use
  - Billing export
  - Cost Optimization Hub
  - Trusted Advisor
  - Compute Optimizer

- Core Infrastructure:
  - Main menu interface (stratusscan.py)
  - Utility module (utils.py)
  - Configuration wizard (configure.py)
  - Account ID to name mapping
  - Multi-region support
  - Standardized Excel output
  - Logging infrastructure
  - Error handling

---

## Release Statistics

### Version 2.2.0
- **Total Scripts**: 84 (+24 from v2.1.4)
- **New Categories**: 3 (Advanced Security, AI/ML, Developer Tools)
- **Commits**: 28 since v1.4.0
- **Lines of Code**: ~25,000+ (Python)
- **Documentation**: 4 major docs (README, API, CONTRIBUTING, TESTING)

### Version 2.1.4
- **Total Scripts**: 60 (+40 from v1.4.0)
- **New Categories**: 6 (Database, Analytics, Application, Integration, Monitoring, Cost)
- **Infrastructure**: Testing, CI/CD, Type hints
- **Quality**: 75+ automated tests

### Version 1.4.0
- **Total Scripts**: 20
- **Core Categories**: Compute, Storage, Network, IAM, Security, Billing
- **Foundation**: Menu system, utilities, configuration

---

## Upgrade Guide

### From 2.1.4 to 2.2.0

No breaking changes. New scripts and menu options are added automatically.

**What's New:**
- 24 new export scripts across 3 categories
- 3 new main menu options (14, 15, 16)
- Output Management moved from option 14 to 17

**Action Required:**
- None - all existing functionality preserved
- Optionally explore new menu categories for Advanced Security, AI/ML, and Developer Tools

### From 1.4.0 to 2.1.4

**Major Updates:**
- 40 new export scripts added
- New infrastructure: testing, CI/CD, progress checkpointing
- Configuration file format unchanged

**Action Required:**
- Run `python configure.py` to validate updated configuration
- Update IAM permissions if using new services (see README)
- Install dev dependencies if contributing: `pip install -e ".[dev]"`

---

## Future Roadmap

### Planned for v2.3.0
- Container & Orchestration: ECS Anywhere, EKS Anywhere, App Mesh
- Media Services: MediaConvert, MediaLive, Kinesis Video Streams
- IoT Services: IoT Core, IoT Analytics, Greengrass

### Planned for v2.4.0
- Multi-account aggregation support
- Cost trend analysis and forecasting
- Resource relationship mapping
- Compliance benchmark validation

### Planned for v3.0.0
- Interactive dashboard for exported data
- Real-time resource monitoring
- Automated remediation recommendations
- Integration with third-party tools

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Adding new export scripts
- Writing tests
- Submitting pull requests
- Code style and quality standards

---

## Support

For questions, issues, or feature requests:
- Open an issue on GitHub
- Review existing documentation in [README.md](README.md)
- Check [API_REFERENCE.md](API_REFERENCE.md) for technical details

---

**Note**: This tool is designed for AWS Commercial environments. Always verify compliance with your organization's security policies before use.

---

*Changelog maintained according to [Keep a Changelog](https://keepachangelog.com/)*

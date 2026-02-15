# AWS Managed Policies for StratusScan

This document lists the **AWS Managed Policies** required for StratusScan to function properly with **read-only access**.

## Recommended Approach: Use AWS Managed Policies

Instead of creating custom inline policies, attach these AWS Managed Policies to your IAM users, roles, or Identity Center permission sets. AWS Managed Policies are maintained by AWS and automatically updated when new services or permissions are added.

## Required Managed Policies

### Core Required Policies

| Policy Name | ARN | Purpose | Services Covered |
|------------|-----|---------|------------------|
| **ReadOnlyAccess** | `arn:aws:iam::aws:policy/ReadOnlyAccess` | Provides read-only access to all AWS services | EC2, S3, RDS, Lambda, VPC, ELB, CloudWatch, CloudTrail, Config, GuardDuty, KMS, Secrets Manager, and 80+ more |
| **IAMReadOnlyAccess** | `arn:aws:iam::aws:policy/IAMReadOnlyAccess` | Read-only access to IAM resources | IAM users, roles, policies, Identity Center (SSO) |
| **SecurityAudit** | `arn:aws:iam::aws:policy/SecurityAudit` | Security audit permissions | Enhanced security service access including Security Hub findings |
| **AWSSupportAccess** | `arn:aws:iam::aws:policy/AWSSupportAccess` | Access to AWS Support and Trusted Advisor | Support cases, Trusted Advisor checks |

### Optional Policies (Recommended)

| Policy Name | ARN | Purpose |
|------------|-----|---------|
| **ComputeOptimizerReadOnlyAccess** | `arn:aws:iam::aws:policy/ComputeOptimizerReadOnlyAccess` | Access to Compute Optimizer recommendations |

## Policy Coverage by Service Category

### Compute Resources
- **Covered by**: ReadOnlyAccess
- **Services**: EC2, Auto Scaling, ECS, EKS, Lambda, Elastic Beanstalk, App Runner

### Storage Resources
- **Covered by**: ReadOnlyAccess
- **Services**: S3, EBS, EFS, FSx, Glacier, Backup, Storage Gateway

### Database Resources
- **Covered by**: ReadOnlyAccess
- **Services**: RDS, DynamoDB, ElastiCache, Redshift, Neptune, DocumentDB, MemoryDB

### Network Resources
- **Covered by**: ReadOnlyAccess
- **Services**: VPC, Subnets, Route Tables, Security Groups, NACLs, ELB, ALB, NLB, Route 53, CloudFront, Direct Connect, Transit Gateway, Network Firewall

### Security & Identity
- **Covered by**: ReadOnlyAccess + IAMReadOnlyAccess + SecurityAudit
- **Services**: IAM, Identity Center (SSO), Organizations, KMS, Secrets Manager, ACM, GuardDuty, Macie, Security Hub, Detective, Access Analyzer, WAF, Shield, CloudTrail, Config

### Monitoring & Logging
- **Covered by**: ReadOnlyAccess
- **Services**: CloudWatch, CloudWatch Logs, X-Ray

### Application Services
- **Covered by**: ReadOnlyAccess
- **Services**: API Gateway, AppSync, Cognito, SNS, SQS, EventBridge, Step Functions

### Developer Tools
- **Covered by**: ReadOnlyAccess
- **Services**: CodeCommit, CodeBuild, CodeDeploy, CodePipeline

### Data Analytics
- **Covered by**: ReadOnlyAccess
- **Services**: Athena, Glue, Lake Formation, OpenSearch, EMR

### Management & Governance
- **Covered by**: ReadOnlyAccess
- **Services**: CloudFormation, Systems Manager, Service Catalog, License Manager

### Cost Management
- **Covered by**: ReadOnlyAccess + ComputeOptimizerReadOnlyAccess
- **Services**: Cost Explorer, Budgets, Cost Optimization Hub, Savings Plans, Compute Optimizer

### Support & Health
- **Covered by**: AWSSupportAccess + ReadOnlyAccess
- **Services**: AWS Support, Trusted Advisor, AWS Health

## Implementation Instructions

### For IAM Users or Roles

1. Navigate to **IAM** → **Users** (or **Roles**)
2. Select your user/role
3. Click **Add permissions** → **Attach policies directly**
4. Search for and attach these policies:
   - ✓ ReadOnlyAccess
   - ✓ IAMReadOnlyAccess
   - ✓ SecurityAudit
   - ✓ AWSSupportAccess
   - ✓ ComputeOptimizerReadOnlyAccess (optional but recommended)

### For AWS IAM Identity Center (SSO)

1. Navigate to **IAM Identity Center** → **Permission sets**
2. Create a new permission set or edit existing
3. Under **Permissions**, choose **Attach AWS managed policies**
4. Search for and attach the same policies listed above

### For AWS GovCloud

All listed AWS Managed Policies are available in GovCloud **except**:
- Services operating outside GovCloud boundary (CloudFront, Global Accelerator) are excluded from ReadOnlyAccess in GovCloud

The same policy set works for both Commercial and GovCloud regions.

## Advantages of AWS Managed Policies

1. **Automatic Updates**: AWS maintains and updates these policies as new services are added
2. **No Size Limits**: No 6,144 character limit like inline policies
3. **Best Practices**: Policies follow AWS security best practices
4. **Easy Management**: Attach/detach without editing JSON
5. **Compliance**: Pre-approved policies that meet security standards
6. **Version Control**: AWS tracks policy versions automatically

## When to Use Custom Policies

Only create custom policies if you need to:
- **Restrict access** beyond read-only (e.g., limit to specific regions or resource tags)
- **Deny specific actions** that managed policies allow
- **Meet compliance requirements** that require more restrictive permissions

For most use cases, the AWS Managed Policies listed above provide the correct level of access for StratusScan.

## Verification

To verify the managed policies are attached correctly:

```bash
# For IAM user
aws iam list-attached-user-policies --user-name YOUR_USERNAME

# For IAM role
aws iam list-attached-role-policies --role-name YOUR_ROLE_NAME

# Check effective permissions
aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::ACCOUNT_ID:user/YOUR_USERNAME \
    --action-names ec2:DescribeInstances s3:ListAllMyBuckets iam:ListUsers \
    --resource-arns "*"
```

## Summary

**Minimal Required Setup** (4 policies):
```
✓ ReadOnlyAccess
✓ IAMReadOnlyAccess
✓ SecurityAudit
✓ AWSSupportAccess
```

**Recommended Setup** (5 policies - includes cost optimization):
```
✓ ReadOnlyAccess
✓ IAMReadOnlyAccess
✓ SecurityAudit
✓ AWSSupportAccess
✓ ComputeOptimizerReadOnlyAccess
```

This approach is **simpler, more maintainable, and more secure** than custom inline policies.

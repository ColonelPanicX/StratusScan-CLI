# Region Selection Partition Awareness Audit

**Status:** In Progress
**Priority:** High
**Category:** Multi-Partition Compliance
**Created:** 2025-12-03
**Target Completion:** TBD

## Overview

Audit and fix all 111 export scripts to ensure proper partition-aware region selection. Many scripts have custom region selection logic that may attempt to access Commercial regions when running in GovCloud (or vice versa), causing authentication failures.

## Problem Statement

During testing in GovCloud, the vpc-data-export.py script attempted to validate Commercial AWS regions (us-east-1, us-west-2, etc.) when the user selected a specific GovCloud region. This resulted in multiple AuthFailure warnings and degraded user experience.

**Root Causes:**
1. Scripts using local `get_aws_regions()` functions that weren't partition-aware
2. Utils functions (`get_aws_regions()`, `get_available_aws_regions()`) returning hardcoded Commercial regions
3. No consistent pattern for region selection across all export scripts
4. Scripts querying EC2 DescribeRegions without partition context

## Solution Implemented (vpc-data-export.py)

### Fixed Functions in utils.py

1. **`get_aws_regions()` (line 251-260)**
   ```python
   def get_aws_regions() -> List[str]:
       """
       Get list of default AWS regions for the current partition.
       Partition-aware: Returns GovCloud regions when in GovCloud, Commercial regions otherwise.
       """
       partition = detect_partition()
       return get_partition_regions(partition)
   ```

2. **`get_available_aws_regions()` (line 973-993)**
   ```python
   def get_available_aws_regions() -> List[str]:
       """
       Get list of AWS regions that are currently accessible.
       Partition-aware: Returns GovCloud regions when in GovCloud, Commercial regions otherwise.
       """
       partition = detect_partition()
       partition_regions = get_partition_regions(partition)

       available_regions = []
       for region in partition_regions:
           if check_aws_region_access(region):
               available_regions.append(region)
           else:
               log_warning(f"AWS region {region} is not accessible")

       return available_regions
   ```

3. **Enhanced `get_partition_regions()` (line 534-564)**
   ```python
   def get_partition_regions(partition: str = 'aws', all_regions: bool = False) -> List[str]:
       """
       Get available regions for a specific AWS partition.

       Args:
           partition: AWS partition ('aws' or 'aws-us-gov')
           all_regions: If True, query EC2 for all regions; if False, return default subset
       """
       if partition == 'aws-us-gov':
           # GovCloud only has 2 regions
           return ['us-gov-west-1', 'us-gov-east-1']
       elif partition == 'aws':
           if all_regions:
               # Query EC2 for all Commercial regions
               try:
                   ec2 = get_boto3_client('ec2', region_name='us-east-1')
                   response = ec2.describe_regions(AllRegions=True)
                   regions = [region['RegionName'] for region in response['Regions']]
                   return sorted(regions)
               except Exception as e:
                   log_warning(f"Could not query all regions from EC2, using default list: {e}")
                   return DEFAULT_REGIONS
           else:
               # Return default subset of commercial regions
               return DEFAULT_REGIONS
       else:
           log_warning(f"Unknown partition: {partition}, returning commercial regions")
           return DEFAULT_REGIONS
   ```

### Fixed Script Pattern (vpc-data-export.py)

**Before:**
```python
def get_aws_regions():
    """Get a list of available AWS regions."""
    try:
        regions = utils.get_available_aws_regions()
        if not regions:
            utils.log_warning("No accessible AWS regions found. Using default list.")
            regions = utils.get_aws_regions()
        return regions
    except Exception as e:
        utils.log_error("Error getting AWS regions", e)
        return utils.get_aws_regions()
```

**After:**
```python
def get_aws_regions():
    """Get a list of all available AWS regions for the current partition."""
    try:
        # Detect partition and get ALL regions for that partition
        partition = utils.detect_partition()
        regions = utils.get_partition_regions(partition, all_regions=True)
        utils.log_info(f"Retrieved {len(regions)} regions for partition {partition}")
        return regions
    except Exception as e:
        utils.log_error("Error getting AWS regions", e)
        # Fallback to default regions for the partition
        partition = utils.detect_partition()
        return utils.get_partition_regions(partition, all_regions=False)
```

## Audit Checklist

### Phase 1: Identify Scripts with Region Selection

- [ ] Scan all 111 scripts for region selection patterns
- [ ] Categorize by region selection method:
  - [ ] Scripts with custom `get_aws_regions()` functions
  - [ ] Scripts using `utils.get_aws_regions()`
  - [ ] Scripts using `utils.get_available_aws_regions()`
  - [ ] Scripts with hardcoded region lists
  - [ ] Scripts querying EC2 DescribeRegions directly
  - [ ] Scripts using user input for region selection

### Phase 2: Fix Scripts by Category

#### Category 1: Scripts with Custom Region Functions
**Pattern to Fix:**
- Look for local `get_aws_regions()` or similar functions
- Update to use `utils.get_partition_regions(partition, all_regions=True)`
- Remove hardcoded region lists

**Scripts to Check:**
- [x] vpc-data-export.py (FIXED)
- [ ] All other scripts with custom region functions

#### Category 2: Scripts Using Hardcoded Regions
**Pattern to Fix:**
- Replace hardcoded region lists with `utils.get_partition_regions()`
- Ensure partition detection occurs before region selection

**Common Patterns to Find:**
```python
regions = ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1']
DEFAULT_REGIONS = ['us-east-1', 'us-west-2']
```

#### Category 3: Scripts with User Input Region Selection
**Pattern to Fix:**
- Update region examples in prompts based on partition
- Validate user input against partition-appropriate regions
- Update help text to show correct regions for current partition

**Example Fix:**
```python
# Detect partition and set partition-appropriate region examples
partition = utils.detect_partition()
if partition == 'aws-us-gov':
    example_regions = "us-gov-west-1, us-gov-east-1"
else:
    example_regions = "us-east-1, us-west-1, us-west-2, eu-west-1"
```

### Phase 3: Testing

- [ ] Test in AWS Commercial environment
  - [ ] "All regions" selection returns ~20+ regions
  - [ ] Specific region selection works
  - [ ] No GovCloud regions attempted

- [ ] Test in AWS GovCloud environment
  - [ ] "All regions" selection returns 2 regions (us-gov-west-1, us-gov-east-1)
  - [ ] Specific region selection works (us-gov-west-1 or us-gov-east-1)
  - [ ] No Commercial regions attempted
  - [ ] No AuthFailure errors

## Scripts to Audit (111 Total)

### Infrastructure Scripts (40)
- [ ] ec2-export.py
- [ ] rds-export.py
- [ ] lambda-export.py
- [ ] ecs-export.py
- [ ] eks-export.py
- [ ] autoscaling-export.py
- [ ] ecr-export.py
- [ ] ami-export.py
- [ ] ec2-capacity-reservations-export.py
- [ ] ec2-dedicated-hosts-export.py
- [ ] image-builder-export.py
- [ ] compute-resources.py
- [ ] ebs-volumes-export.py
- [ ] ebs-snapshots-export.py
- [ ] s3-export.py
- [ ] efs-export.py
- [ ] fsx-export.py
- [ ] backup-export.py
- [ ] datasync-export.py
- [ ] transfer-family-export.py
- [ ] storagegateway-export.py
- [ ] glacier-export.py
- [ ] s3-accesspoints-export.py
- [ ] storage-resources.py
- [x] vpc-data-export.py (FIXED)
- [ ] elb-export.py
- [ ] nacl-export.py
- [ ] security-groups-export.py
- [ ] route-tables-export.py
- [ ] vpn-export.py
- [ ] directconnect-export.py
- [ ] transit-gateway-export.py
- [ ] network-firewall-export.py
- [ ] network-resources.py
- [ ] dynamodb-export.py
- [ ] elasticache-export.py
- [ ] documentdb-export.py
- [ ] neptune-export.py
- [ ] cloudfront-export.py
- [ ] route53-export.py
- [ ] globalaccelerator-export.py
- [ ] network-manager-export.py

### Security & Compliance Scripts (20)
- [ ] security-hub-export.py
- [ ] guardduty-export.py
- [ ] waf-export.py
- [ ] cloudtrail-export.py
- [ ] config-export.py
- [ ] kms-export.py
- [ ] secrets-manager-export.py
- [ ] acm-export.py
- [ ] access-analyzer-export.py
- [ ] detective-export.py
- [ ] shield-export.py
- [ ] macie-export.py
- [ ] cognito-export.py
- [ ] acm-privateca-export.py
- [ ] verifiedaccess-export.py
- [ ] iam-rolesanywhere-export.py
- [ ] iam-identity-providers-export.py
- [ ] verifiedpermissions-export.py

### IAM & Identity Scripts (10)
- [ ] iam-export.py
- [ ] iam-roles-export.py
- [ ] iam-policies-export.py
- [ ] iam-comprehensive-export.py
- [ ] organizations-export.py
- [ ] iam-identity-center-export.py
- [ ] iam-identity-center-groups-export.py
- [ ] iam-identity-center-permission-sets-export.py
- [ ] iam-identity-center-comprehensive-export.py

### Cost Management Scripts (9)
- [ ] billing-export.py
- [ ] cost-optimization-hub-export.py
- [ ] trusted-advisor-cost-optimization-export.py
- [ ] compute-optimizer-export.py
- [ ] savings-plans-export.py
- [ ] budgets-export.py
- [ ] reserved-instances-export.py
- [ ] cost-categories-export.py
- [ ] cost-anomaly-detection-export.py

### Application Services Scripts (12)
- [ ] stepfunctions-export.py
- [ ] apprunner-export.py
- [ ] elasticbeanstalk-export.py
- [ ] appsync-export.py
- [ ] connect-export.py
- [ ] api-gateway-export.py
- [ ] eventbridge-export.py
- [ ] sqs-sns-export.py
- [ ] cloudmap-export.py
- [ ] ses-export.py
- [ ] ses-pinpoint-export.py

### Data & Analytics Scripts (10)
- [ ] opensearch-export.py
- [ ] redshift-export.py
- [ ] glue-athena-export.py
- [ ] lakeformation-export.py
- [ ] sagemaker-export.py
- [ ] bedrock-export.py
- [ ] comprehend-export.py
- [ ] rekognition-export.py
- [ ] cloudwatch-export.py
- [ ] xray-export.py

### Developer Tools Scripts (4)
- [ ] codebuild-export.py
- [ ] codepipeline-export.py
- [ ] codecommit-export.py
- [ ] codedeploy-export.py

### Management & Governance Scripts (7)
- [ ] cloudformation-export.py
- [ ] service-catalog-export.py
- [ ] health-export.py
- [ ] license-manager-export.py
- [ ] marketplace-export.py
- [ ] controltower-export.py
- [ ] ssm-fleet-export.py

### Special Scripts (2)
- [x] services-in-use-export.py (FIXED - different issue)

## Implementation Strategy

### Approach 1: Automated Search & Replace
**Pros:**
- Fast for simple patterns
- Consistent changes

**Cons:**
- May miss edge cases
- Could break custom logic

### Approach 2: Manual Review & Fix (RECOMMENDED)
**Pros:**
- Careful review of each script's logic
- Can optimize while fixing
- Ensures no regressions

**Cons:**
- Time-consuming (111 scripts)
- Requires testing each fix

### Hybrid Approach (RECOMMENDED)
1. **Automated Detection**: Script to identify all region selection patterns
2. **Categorize**: Group scripts by pattern type
3. **Batch Fix**: Fix common patterns in batches
4. **Manual Review**: Review and test each fix
5. **Integration Test**: Test all scripts in both partitions

## Search Patterns for Automated Detection

```bash
# Find scripts with custom get_aws_regions functions
grep -l "def get_aws_regions" scripts/*.py

# Find scripts with hardcoded region lists
grep -l "us-east-1.*us-west-2" scripts/*.py

# Find scripts using utils.get_available_aws_regions()
grep -l "utils.get_available_aws_regions" scripts/*.py

# Find scripts with EC2 describe_regions calls
grep -l "describe_regions" scripts/*.py

# Find scripts with region user input
grep -l "input.*region" scripts/*.py
```

## Success Criteria

- [ ] All 111 scripts tested in Commercial AWS
- [ ] All 111 scripts tested in GovCloud
- [ ] No AuthFailure errors when selecting appropriate regions
- [ ] "All regions" returns correct partition regions
- [ ] Specific region selection works in both partitions
- [ ] Documentation updated with region selection best practices
- [ ] Template/pattern established for future scripts

## Related Issues

- Multi-partition compliance audit (completed)
- VPC export script region selection (FIXED - this document)
- Services-in-use script function call error (FIXED - different issue)

## Notes

- This audit is critical for true multi-partition support
- May discover other partition-related issues during review
- Should establish coding standards for region selection going forward
- Consider creating a `utils.get_user_region_selection()` helper function to standardize this across all scripts

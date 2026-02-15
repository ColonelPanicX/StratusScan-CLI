# S3 Access Points Export - Quick Start Guide

## What This Script Does

Exports all S3 Access Points configurations from your AWS account:
- **Standard Access Points**: VPC-restricted or Internet-accessible per-bucket endpoints
- **Multi-Region Access Points (MRAP)**: Global endpoints spanning multiple regions
- **Object Lambda Access Points**: Data transformation endpoints using Lambda

## Quick Start

```bash
# Navigate to StratusScan directory
cd /path/to/stratusscan-cli

# Run the script
python scripts/s3-accesspoints-export.py

# When prompted, select regions:
# - Type 'all' for all AWS regions
# - Or specify a region like 'us-east-1'
```

## Output

**File Location**: `output/{account-name}-s3-accesspoints-all-export-{MM.DD.YYYY}.xlsx`

**Excel Sheets**:
1. **Summary**: Counts and statistics
2. **Standard Access Points**: Regional access points with VPC/Internet config
3. **Multi-Region APs**: Global MRAP endpoints
4. **Object Lambda APs**: Lambda transformation endpoints
5. **VPC Access Points**: Filtered VPC-only access points
6. **Public Access Points**: Filtered Internet-accessible access points

## Minimum IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAccessPoints",
        "s3:GetAccessPoint",
        "s3:ListMultiRegionAccessPoints",
        "s3:GetMultiRegionAccessPoint",
        "s3:ListAccessPointsForObjectLambda",
        "s3:GetAccessPointConfigurationForObjectLambda",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Common Scenarios

### Scenario 1: No Access Points Found
```
No S3 Access Points found in the selected regions
This is normal if Access Points are not configured in your account
```
**This is normal!** Access Points are optional and may not be configured.

### Scenario 2: Multi-Region Access Points Only
If you only have MRAPs, you'll see:
- Summary shows counts
- Multi-Region APs sheet has data
- Other sheets may be empty

### Scenario 3: VPC-Restricted Access Points
Check the "VPC Access Points" sheet to see which access points are VPC-only.

## Key Data Points Exported

### Standard Access Points
- Name, ARN, Alias
- Bucket name and account
- Network origin (VPC or Internet)
- VPC ID (if restricted)
- Block public access settings
- Creation date

### Multi-Region Access Points
- Name, ARN, Status
- Associated regions and buckets
- Block public access settings
- Replication configuration

### Object Lambda Access Points
- Name, ARN
- Lambda function ARNs
- Supporting access point
- Allowed features

## Troubleshooting

| Issue | Solution |
|-------|----------|
| AccessDenied error | Add required IAM permissions (see above) |
| No data in Object Lambda sheet | Normal - Object Lambda may not be enabled |
| Script timeout | Reduce regions or check network connectivity |
| Empty output | Normal if no Access Points are configured |

## Performance

- **Fast**: 1-3 regions with <10 access points: 10-30 seconds
- **Medium**: All regions with 10-50 access points: 1-3 minutes
- **Large**: All regions with 100+ access points: 3-10 minutes

## Next Steps

After running the script:
1. Open the Excel file in `output/` directory
2. Review the Summary sheet for counts
3. Check VPC Access Points sheet for network restrictions
4. Review Public Access Points sheet for security audit
5. Verify MRAP configurations in Multi-Region APs sheet

## Related Documentation

- Full README: `scripts/README-s3-accesspoints-export.md`
- AWS S3 Access Points: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points.html
- Multi-Region Access Points: https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiRegionAccessPoints.html
- Object Lambda: https://docs.aws.amazon.com/AmazonS3/latest/userguide/transforming-objects.html

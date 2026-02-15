# S3 Access Points Export Script

## Overview

The `s3-accesspoints-export.py` script provides comprehensive export of all S3 Access Points configurations across your AWS account, including Standard Access Points, Multi-Region Access Points (MRAP), and Object Lambda Access Points.

## Features

### Access Point Types Supported

1. **Standard Access Points**
   - Per-bucket access points with simplified permissions management
   - VPC-restricted or Internet-accessible configurations
   - Custom block public access settings
   - Access point policies

2. **Multi-Region Access Points (MRAP)**
   - Global endpoints spanning multiple AWS regions
   - Automatic failover and routing
   - Cross-region bucket associations
   - Replication status and configuration

3. **Object Lambda Access Points**
   - Data transformation on retrieval using Lambda functions
   - Supporting access point configurations
   - Allowed features and actions
   - CloudWatch metrics integration

## Output Structure

The script generates a multi-sheet Excel workbook with the following sheets:

### Sheet 1: Summary
- Total counts by access point type
- VPC vs. Internet accessibility breakdown
- MRAP status distribution
- Regional distribution statistics

### Sheet 2: Standard Access Points
- Access Point name, ARN, and alias
- Associated bucket name and account
- Network origin (VPC or Internet)
- VPC ID (if VPC-restricted)
- Block public access settings (4 flags)
- Creation date
- Custom policy indicator

### Sheet 3: Multi-Region Access Points
- MRAP name, ARN, and alias
- Status (READY, CREATING, etc.)
- Associated regions and buckets
- Region count
- Block public access settings
- Creation date

### Sheet 4: Object Lambda Access Points
- Object Lambda access point name and ARN
- Supporting access point ARN
- Lambda function ARNs (transformation functions)
- Allowed features/actions
- CloudWatch metrics status
- Region and alias

### Sheet 5: VPC Access Points
- Filtered view of Standard Access Points with NetworkOrigin = VPC
- Same columns as Standard Access Points sheet

### Sheet 6: Public Access Points
- Filtered view of Standard Access Points with NetworkOrigin = Internet
- Same columns as Standard Access Points sheet

## Usage

### Basic Usage

```bash
python scripts/s3-accesspoints-export.py
```

The script will:
1. Display account information
2. Prompt for region selection (all regions or specific region)
3. Collect Standard and Object Lambda Access Points from selected regions
4. Collect Multi-Region Access Points globally (always from us-west-2)
5. Export to Excel with filename: `{account-name}-s3-accesspoints-all-export-{MM.DD.YYYY}.xlsx`

### Region Selection

**Option 1: All Regions**
```
Select region(s) to scan for Standard and Object Lambda Access Points:
Available AWS regions: us-east-1, us-west-2, us-west-1, eu-west-1, ap-southeast-1
Enter region or 'all' for all regions: all
```

**Option 2: Specific Region**
```
Enter region or 'all' for all regions: us-east-1
```

## IAM Permissions Required

The script requires the following IAM permissions:

### Standard Access Points
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAccessPoints",
        "s3:GetAccessPoint",
        "s3:GetAccessPointPolicy",
        "s3:GetAccessPointPolicyStatus",
        "s3:GetPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}
```

### Multi-Region Access Points
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListMultiRegionAccessPoints",
        "s3:GetMultiRegionAccessPoint",
        "s3:DescribeMultiRegionAccessPointOperation"
      ],
      "Resource": "*"
    }
  ]
}
```

### Object Lambda Access Points
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAccessPointsForObjectLambda",
        "s3:GetAccessPointConfigurationForObjectLambda"
      ],
      "Resource": "*"
    }
  ]
}
```

### Complete Policy (All Features)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAccessPoints",
        "s3:GetAccessPoint",
        "s3:GetAccessPointPolicy",
        "s3:GetAccessPointPolicyStatus",
        "s3:GetPublicAccessBlock",
        "s3:ListMultiRegionAccessPoints",
        "s3:GetMultiRegionAccessPoint",
        "s3:DescribeMultiRegionAccessPointOperation",
        "s3:ListAccessPointsForObjectLambda",
        "s3:GetAccessPointConfigurationForObjectLambda",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## AWS API Details

### Standard Access Points
- **Service**: `s3control`
- **Regional**: Yes (scanned per region)
- **Key APIs**:
  - `list_access_points()`
  - `get_access_point()`
  - `get_access_point_policy_status()`

### Multi-Region Access Points
- **Service**: `s3control`
- **Regional**: No (always queried from us-west-2)
- **Key APIs**:
  - `list_multi_region_access_points()`
  - `get_multi_region_access_point()`

### Object Lambda Access Points
- **Service**: `s3control`
- **Regional**: Yes (scanned per region)
- **Key APIs**:
  - `list_access_points_for_object_lambda()`
  - `get_access_point_configuration_for_object_lambda()`

## Important Notes

### Account ID Requirement
All S3 Control API operations require an `AccountId` parameter. The script automatically retrieves this using STS `get_caller_identity()`.

### Multi-Region Access Points
- MRAPs are **global resources** but must be queried from `us-west-2` region
- The script automatically handles this regardless of your selected regions
- MRAP data is collected only once per execution

### Object Lambda Availability
- Object Lambda Access Points may not be available in all regions
- The script gracefully handles regions where the service is unavailable
- No error is raised if Object Lambda is not supported in a region

### VPC Access Points
- VPC-restricted access points can only be accessed from the specified VPC
- The script identifies these by `NetworkOrigin = VPC`
- VPC ID is included in the export for network troubleshooting

### Block Public Access Settings
The script exports four Block Public Access settings for each access point:
1. **BlockPublicAcls**: Block public ACLs
2. **IgnorePublicAcls**: Ignore public ACLs
3. **BlockPublicPolicy**: Block public bucket policies
4. **RestrictPublicBuckets**: Restrict public bucket policies

## Troubleshooting

### No Access Points Found
```
No S3 Access Points found in the selected regions
This is normal if Access Points are not configured in your account
```
**Resolution**: This is normal. S3 Access Points are optional features and may not be configured in your environment.

### AccessDenied Errors
```
AWS error [AccessDenied]: User is not authorized to perform: s3:ListAccessPoints
```
**Resolution**: Ensure your IAM user/role has the required permissions listed above.

### Object Lambda Not Available
```
Object Lambda not available in {region}: ...
```
**Resolution**: This is expected behavior. Object Lambda is not available in all regions. The script continues with other regions.

### MRAP Query Timeout
```
Could not get details for MRAP {name}: ...
```
**Resolution**: Multi-Region Access Points queries can be slow. The script includes retry logic via `utils.get_boto3_client()`. If timeouts persist, check network connectivity to us-west-2.

## Output File Location

```
/home/asimov/code/github/public/stratusscan-cli/output/{account-name}-s3-accesspoints-all-export-{MM.DD.YYYY}.xlsx
```

## Dependencies

- **boto3**: AWS SDK for Python
- **pandas**: Data manipulation and DataFrame creation
- **openpyxl**: Excel file generation

Install with:
```bash
pip install boto3 pandas openpyxl
```

## Performance Considerations

- **Standard Access Points**: O(n) where n = number of regions × access points per region
- **Multi-Region Access Points**: O(1) - single query to us-west-2
- **Object Lambda Access Points**: O(n) where n = number of regions × OL access points per region

Typical execution time:
- 1-3 regions, <10 access points: 10-30 seconds
- All regions, 10-50 access points: 1-3 minutes
- All regions, 100+ access points: 3-10 minutes

## Integration with StratusScan

This script follows all StratusScan patterns:
- Uses `utils.get_boto3_client()` for automatic retry logic
- Uses `@utils.aws_error_handler` decorator for consistent error handling
- Uses `utils.prepare_dataframe_for_export()` for DataFrame preparation
- Uses `utils.save_multiple_dataframes_to_excel()` for multi-sheet exports
- Follows standard naming convention for output files
- Includes comprehensive logging to both console and log files

## Security Notes

- All operations are **read-only**
- No access point configurations are modified
- Access point policies are not exported (only existence is indicated)
- The script uses least-privilege API calls
- All credentials are handled by AWS SDK (boto3)

## Cost Implications

- **API Calls**: Standard AWS API pricing applies
- **Data Transfer**: Negligible (only metadata is retrieved)
- **Storage**: No additional storage costs (read-only operations)

Estimated cost per execution: **$0.00 - $0.01** (based on API call volume)

## Examples

### Example 1: Scan All Regions
```bash
$ python scripts/s3-accesspoints-export.py

====================================================================
                  AWS RESOURCE SCANNER
====================================================================
AWS S3 ACCESS POINTS COMPREHENSIVE EXPORT SCRIPT
====================================================================
Version: v1.0.0                       Date: NOV-13-2025
Environment: AWS Commercial
====================================================================
Account ID: 123456789012
Account Name: PROD-ACCOUNT
====================================================================

Select region(s) to scan for Standard and Object Lambda Access Points:
Available AWS regions: us-east-1, us-west-2, us-west-1, eu-west-1, ap-southeast-1
Enter region or 'all' for all regions: all

Scanning 4 region(s) for Access Points...
[25.0%] Processing region 1/4: us-east-1
Collecting standard access points in us-east-1...
Found 3 standard access points in us-east-1
Collecting Object Lambda Access Points in us-east-1...
Found 1 Object Lambda Access Points in us-east-1

[50.0%] Processing region 2/4: us-west-2
...

Collecting Multi-Region Access Points (from us-west-2)...
Found 2 Multi-Region Access Points

============================================================
Collection Summary:
  Standard Access Points: 8
  Multi-Region Access Points: 2
  Object Lambda Access Points: 1
  Total Access Points: 11
============================================================

Exporting data to Excel...
Data successfully exported to: /path/to/output/PROD-ACCOUNT-s3-accesspoints-all-export-11.13.2025.xlsx

Script execution completed successfully.
```

### Example 2: Scan Specific Region
```bash
$ python scripts/s3-accesspoints-export.py

...
Enter region or 'all' for all regions: us-east-1

Scanning 1 region(s) for Access Points...
[100.0%] Processing region 1/1: us-east-1
...
```

## Related Scripts

- `s3-export.py`: Standard S3 bucket inventory
- `vpc-data-export.py`: VPC configurations (useful for VPC Access Points)
- `lambda-export.py`: Lambda functions (useful for Object Lambda Access Points)

## Version History

- **v1.0.0** (NOV-13-2025): Initial release
  - Standard Access Points support
  - Multi-Region Access Points support
  - Object Lambda Access Points support
  - Multi-sheet Excel export
  - VPC and Public access point filtering
  - Comprehensive summary statistics

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the log file in `logs/logs-s3-accesspoints-export-{timestamp}.log`
3. Verify IAM permissions are correctly configured
4. Ensure boto3 is up to date: `pip install --upgrade boto3`

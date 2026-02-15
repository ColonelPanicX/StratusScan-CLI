# AWS DataSync Export Script

## Overview

The `datasync-export.py` script provides comprehensive AWS DataSync resource export across all selected regions. It collects data about DataSync tasks, locations, agents, and execution history, exporting everything to a multi-sheet Excel workbook for analysis.

## Features

### Data Collection
- **Tasks**: All DataSync tasks with configuration details, schedule, options, and filter rules
- **Locations**: All location types (S3, EFS, FSx, NFS, SMB, HDFS, Object Storage) with type-specific configuration
- **Agents**: Agent status, connectivity, platform information, and VPC endpoint details
- **Executions**: Recent task execution history (last 30 days) with transfer statistics

### Export Capabilities
- Multi-region scanning with progress tracking
- Comprehensive multi-sheet Excel export
- Summary analytics with status breakdowns
- Active tasks and failed executions filtering
- Human-readable byte formatting (GB/TB)
- Timezone-aware datetime handling

### Technical Implementation
- Uses `utils.get_boto3_client()` with automatic retry logic
- Proper pagination for all list operations
- Type hints for code clarity
- `@aws_error_handler` decorator for error handling
- DataFrame preparation and sanitization
- StratusScan standard file naming

## Prerequisites

### Required Dependencies
- Python 3.7+
- boto3
- pandas
- openpyxl

The script will automatically prompt to install missing dependencies.

### AWS Permissions

The script requires the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DataSyncReadOnly",
      "Effect": "Allow",
      "Action": [
        "datasync:ListTasks",
        "datasync:ListLocations",
        "datasync:ListAgents",
        "datasync:ListTaskExecutions",
        "datasync:DescribeTask",
        "datasync:DescribeLocationS3",
        "datasync:DescribeLocationEfs",
        "datasync:DescribeLocationFsxWindows",
        "datasync:DescribeLocationFsxLustre",
        "datasync:DescribeLocationFsxOpenZfs",
        "datasync:DescribeLocationFsxOntap",
        "datasync:DescribeLocationNfs",
        "datasync:DescribeLocationSmb",
        "datasync:DescribeLocationHdfs",
        "datasync:DescribeLocationObjectStorage",
        "datasync:DescribeAgent",
        "datasync:DescribeTaskExecution"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSGetCallerIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Alternatively, use the AWS managed policy: **ReadOnlyAccess**

## Usage

### Basic Execution

```bash
# From the scripts directory
python datasync-export.py

# From the StratusScan root directory
python scripts/datasync-export.py
```

### Region Selection

When prompted, you can:
- Enter `all` to scan all default regions (us-east-1, us-west-2, us-west-1, eu-west-1)
- Enter a specific region (e.g., `us-east-1`)

### Example Output

```
====================================================================
                   AWS RESOURCE SCANNER
====================================================================
            AWS DATASYNC COMPREHENSIVE EXPORT
====================================================================
Account ID: 123456789012
Account Name: PROD-ACCOUNT
Environment: AWS Commercial
====================================================================

Select AWS region(s) for DataSync export:
Available AWS regions: us-east-1, us-west-2, us-west-1, eu-west-1, ap-southeast-1
Enter region or 'all' for all regions: all

Scanning 4 region(s): us-east-1, us-west-2, us-west-1, eu-west-1

Processing region: us-east-1
Found 5 DataSync tasks in us-east-1
[20.0%] Processing task 1/5 in us-east-1
...
Collection complete:
  Tasks: 12
  Locations: 24
  Agents: 3
  Executions (30 days): 156

AWS DataSync data exported successfully!
File location: /path/to/output/PROD-ACCOUNT-datasync-all-export-11.13.2025.xlsx
```

## Output File Structure

### File Naming Convention
```
{account-name}-datasync-all-export-{MM.DD.YYYY}.xlsx
```

Example: `PROD-ACCOUNT-datasync-all-export-11.13.2025.xlsx`

### Excel Sheets

#### Sheet 1: Summary
Overall statistics and counts:
- Total Tasks (by status)
- Total Locations (by type: S3, EFS, FSx, NFS, SMB, HDFS, Object Storage)
- Total Agents (by status: ONLINE, OFFLINE)
- Total Executions (last 30 days, by status: SUCCESS, ERROR, In Progress)

#### Sheet 2: Tasks
All DataSync tasks with:
- Task Name, ARN, Status
- Source Location ARN
- Destination Location ARN
- Schedule Expression
- CloudWatch Log Group
- Creation Time
- Options (VerifyMode, OverwriteMode, Atime, Mtime, UID, GID, PreserveDeletedFiles)
- Filter Rules (Include/Exclude counts)
- Region

#### Sheet 3: Locations
All DataSync locations with:
- Location ARN
- Location Type (S3, EFS, FSx-Windows, FSx-Lustre, FSx-OpenZFS, FSx-ONTAP, NFS, SMB, HDFS, Object Storage)
- Location URI
- Region
- Type-specific configuration:
  - **S3**: Bucket ARN, Storage Class, Subdirectory
  - **EFS**: EFS ARN, Subnet ARN, Subdirectory
  - **FSx**: FSx ARN, Subdirectory
  - **NFS**: Server Hostname, Subdirectory, Agent ARNs
  - **SMB**: Server Hostname, Subdirectory, User
  - **HDFS**: Authentication Type, NameNode count
  - **Object Storage**: Server Hostname, Server Port

#### Sheet 4: Agents
All DataSync agents with:
- Agent Name, ARN, Status
- Endpoint Type (PUBLIC, VPC, FIPS)
- Last Heartbeat
- Creation Time
- Platform Version
- VPC Endpoint ID
- Private Link Subnet ARN
- Region

#### Sheet 5: Recent Executions
Task executions from last 30 days:
- Task Execution ARN
- Task ARN
- Status (QUEUED, LAUNCHING, PREPARING, TRANSFERRING, VERIFYING, SUCCESS, ERROR)
- Start Time
- Duration (formatted: Xh Ym)
- Files Transferred
- Bytes Transferred (human-readable: GB/TB)
- Files Failed
- Error Code, Error Detail
- Region

#### Sheet 6: Active Tasks
Filtered view of tasks with `Status = AVAILABLE`
(Same columns as Tasks sheet)

#### Sheet 7: Failed Executions
Filtered view of executions with `Status = ERROR`
(Same columns as Recent Executions sheet)

## Data Collection Details

### Location Type Detection

The script attempts to describe each location using all supported location types:
1. S3 (describe_location_s3)
2. EFS (describe_location_efs)
3. FSx Windows (describe_location_fsx_windows)
4. FSx Lustre (describe_location_fsx_lustre)
5. FSx OpenZFS (describe_location_fsx_open_zfs)
6. FSx ONTAP (describe_location_fsx_ontap)
7. NFS (describe_location_nfs)
8. SMB (describe_location_smb)
9. HDFS (describe_location_hdfs)
10. Object Storage (describe_location_object_storage)

This approach is necessary because location type is not directly available in the location ARN.

### Execution History Filtering

- Only executions from the last 30 days are collected
- Date filtering uses `StartTime` field
- Calculates duration from execution metadata
- Formats transfer sizes in human-readable format (GB, TB)

### Progress Tracking

The script provides detailed progress logging:
- Per-region processing
- Per-resource-type processing
- Percentage completion for tasks, locations, and agents
- Total resource counts

## Error Handling

The script implements comprehensive error handling:

### Credentials
```
NoCredentialsError: No AWS credentials found.
Please configure credentials using 'aws configure' or environment variables.
```

### Access Denied
```
AWS error [AccessDenied]: User is not authorized to perform: datasync:ListTasks
```

### Region Issues
```
Invalid AWS region: invalid-region
Valid AWS regions include: us-east-1, us-west-1, us-west-2, eu-west-1
```

### Location Type Detection
If a location type cannot be determined (all describe operations fail), it is marked as `Location Type: Unknown`.

## Performance Considerations

### API Call Optimization
- Uses paginators for all list operations
- Automatic retry logic via `utils.get_boto3_client()`
- Efficient batch processing of task executions

### Execution History Scope
- Limited to last 30 days to prevent excessive API calls
- Date filtering applied before detailed describe calls
- Configurable via code modification if needed

### Multi-Region Scanning
- Sequential region processing
- Progress tracking per region
- Graceful degradation on regional failures

## Integration with StratusScan

### File Naming
Follows StratusScan standard: `{account-name}-datasync-all-export-{MM.DD.YYYY}.xlsx`

### Output Directory
Saves to `output/` directory via `utils.get_output_filepath()`

### Logging
- Console and file logging via `utils.setup_logging()`
- Saved to `logs/logs-datasync-export-{MM.DD.YYYY-HHMM}.log`

### Configuration
- Uses `config.json` for account mappings
- Respects default regions from configuration
- Account name displayed in filename

## Troubleshooting

### No DataSync Resources Found
```
No DataSync resources found in any region. Exiting...
```
**Solution**: Verify DataSync is being used in the selected regions, or try `all` regions.

### Missing Dependencies
```
The following packages are required but not installed: pandas, openpyxl
Would you like to install these packages now? (y/n):
```
**Solution**: Enter `y` to auto-install, or manually run `pip install pandas openpyxl boto3`

### Timeout Issues
If the script times out with many executions:
- The script uses `utils.get_boto3_client()` which has automatic retry with adaptive backoff
- No manual throttling needed
- If issues persist, reduce execution history scope by modifying `thirty_days_ago` variable

### Empty Sheets
Some sheets may not appear if no resources of that type exist:
- Active Tasks: Only if tasks with Status=AVAILABLE exist
- Failed Executions: Only if ERROR executions exist in last 30 days

## Advanced Usage

### Custom Execution History Period

To change from 30 days to 7 days, modify in `collect_task_executions()`:

```python
# Change this line:
thirty_days_ago = datetime.datetime.now() - datetime.timedelta(days=30)

# To:
seven_days_ago = datetime.datetime.now() - datetime.timedelta(days=7)
```

### Custom Byte Formatting

To change from GB/TB to MB/GB, modify `format_bytes_human_readable()`:

```python
def format_bytes_human_readable(bytes_value: int) -> str:
    if bytes_value == 0:
        return "0 B"

    mb_value = bytes_value / (1024 ** 2)  # Convert to MB instead of GB

    if mb_value < 1024:
        return f"{mb_value:.2f} MB"
    else:
        gb_value = mb_value / 1024
        return f"{gb_value:.2f} GB"
```

### Include Only Specific Location Types

To filter to only S3 locations, modify `collect_datasync_locations()`:

```python
# After successfully identifying location type:
if location_type == 'S3':
    locations_data.append(location_data)
# Skip all other types
```

## Related Scripts

- **vpc-data-export.py**: Network infrastructure (VPCs, subnets, VPC endpoints)
- **s3-export.py**: S3 bucket inventory (may be used as DataSync endpoints)
- **efs-export.py**: EFS file systems (may be used as DataSync endpoints)

## Support

For issues, questions, or contributions:
1. Check the StratusScan main README
2. Review the utils.py module documentation
3. Consult AWS DataSync documentation: https://docs.aws.amazon.com/datasync/

## Version History

- **v1.0.0** (NOV-13-2025): Initial release
  - Multi-region DataSync task export
  - All location types supported
  - Agent monitoring
  - 30-day execution history
  - Multi-sheet Excel export with summary analytics

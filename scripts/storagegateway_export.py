#!/usr/bin/env python3
"""
StratusScan - AWS Storage Gateway Export Script

Exports comprehensive Storage Gateway information including:
- Gateways (File, Volume, Tape)
- File Shares (NFS and SMB)
- Volumes (Cached and Stored)
- Tapes (Virtual Tapes)
- Tape Pools
- Local Disks

Output: Multi-sheet Excel file with all Storage Gateway resources
"""

import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

# Import utils with fallback for running from scripts directory
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

# Third-party imports (will be checked by dependency_check)
import pandas as pd
from botocore.exceptions import ClientError


# ============================================================================
# DATA COLLECTION FUNCTIONS
# ============================================================================

@utils.aws_error_handler("Listing Storage Gateways", default_return=[])
def list_gateways(region: str) -> List[str]:
    """List all Storage Gateway ARNs in a region."""
    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    gateway_arns = []

    paginator = sgw.get_paginator('list_gateways')
    for page in paginator.paginate():
        gateway_arns.extend([gw['GatewayARN'] for gw in page.get('Gateways', [])])

    return gateway_arns


@utils.aws_error_handler("Describing gateway", default_return=None)
def describe_gateway(gateway_arn: str, region: str) -> Optional[Dict[str, Any]]:
    """Get detailed information about a gateway."""
    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    response = sgw.describe_gateway_information(GatewayARN=gateway_arn)
    return response


@utils.aws_error_handler("Listing file shares", default_return=[])
def list_file_shares(gateway_arn: str, region: str) -> List[str]:
    """List all file share ARNs for a gateway."""
    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    file_share_arns = []

    paginator = sgw.get_paginator('list_file_shares')
    for page in paginator.paginate(GatewayARN=gateway_arn):
        file_share_arns.extend([fs['FileShareARN'] for fs in page.get('FileShareInfoList', [])])

    return file_share_arns


@utils.aws_error_handler("Describing NFS file shares", default_return=[])
def describe_nfs_file_shares(file_share_arns: List[str], region: str) -> List[Dict[str, Any]]:
    """Get detailed information about NFS file shares."""
    if not file_share_arns:
        return []

    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    response = sgw.describe_nfs_file_shares(FileShareARNList=file_share_arns)
    return response.get('NFSFileShareInfoList', [])


@utils.aws_error_handler("Describing SMB file shares", default_return=[])
def describe_smb_file_shares(file_share_arns: List[str], region: str) -> List[Dict[str, Any]]:
    """Get detailed information about SMB file shares."""
    if not file_share_arns:
        return []

    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    response = sgw.describe_smb_file_shares(FileShareARNList=file_share_arns)
    return response.get('SMBFileShareInfoList', [])


@utils.aws_error_handler("Listing volumes", default_return=[])
def list_volumes(gateway_arn: str, region: str) -> List[str]:
    """List all volume ARNs for a gateway."""
    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    volume_arns = []

    paginator = sgw.get_paginator('list_volumes')
    for page in paginator.paginate(GatewayARN=gateway_arn):
        volume_arns.extend([vol['VolumeARN'] for vol in page.get('VolumeInfos', [])])

    return volume_arns


@utils.aws_error_handler("Describing cached volumes", default_return=[])
def describe_cached_volumes(volume_arns: List[str], region: str) -> List[Dict[str, Any]]:
    """Get detailed information about cached iSCSI volumes."""
    if not volume_arns:
        return []

    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    response = sgw.describe_cachedi_scsi_volumes(VolumeARNs=volume_arns)
    return response.get('CachediSCSIVolumes', [])


@utils.aws_error_handler("Describing stored volumes", default_return=[])
def describe_stored_volumes(volume_arns: List[str], region: str) -> List[Dict[str, Any]]:
    """Get detailed information about stored iSCSI volumes."""
    if not volume_arns:
        return []

    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    response = sgw.describe_storedi_scsi_volumes(VolumeARNs=volume_arns)
    return response.get('StorediSCSIVolumes', [])


@utils.aws_error_handler("Listing tapes", default_return=[])
def list_tapes(region: str) -> List[str]:
    """List all tape ARNs in a region."""
    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    tape_arns = []

    paginator = sgw.get_paginator('list_tapes')
    for page in paginator.paginate():
        tape_arns.extend([tape['TapeARN'] for tape in page.get('TapeInfos', [])])

    return tape_arns


@utils.aws_error_handler("Describing tapes", default_return=[])
def describe_tapes(tape_arns: List[str], region: str) -> List[Dict[str, Any]]:
    """Get detailed information about tapes (batch operation)."""
    if not tape_arns:
        return []

    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    all_tapes = []

    # Process in batches of 100 (API limit)
    batch_size = 100
    for i in range(0, len(tape_arns), batch_size):
        batch = tape_arns[i:i + batch_size]
        response = sgw.describe_tapes(TapeARNs=batch)
        all_tapes.extend(response.get('Tapes', []))

    return all_tapes


@utils.aws_error_handler("Listing tape pools", default_return=[])
def list_tape_pools(region: str) -> List[Dict[str, Any]]:
    """List all tape pools in a region."""
    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    pools = []

    paginator = sgw.get_paginator('list_tape_pools')
    for page in paginator.paginate():
        pools.extend(page.get('PoolInfos', []))

    return pools


@utils.aws_error_handler("Listing local disks", default_return=[])
def list_local_disks(gateway_arn: str, region: str) -> List[Dict[str, Any]]:
    """List local disks for a gateway."""
    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    response = sgw.list_local_disks(GatewayARN=gateway_arn)
    return response.get('Disks', [])


@utils.aws_error_handler("Listing tags", default_return=[])
def list_tags_for_resource(resource_arn: str, region: str) -> List[Dict[str, str]]:
    """List tags for a Storage Gateway resource."""
    sgw = utils.get_boto3_client('storagegateway', region_name=region)
    response = sgw.list_tags_for_resource(ResourceARN=resource_arn)
    return response.get('Tags', [])


# ============================================================================
# DATA PROCESSING FUNCTIONS
# ============================================================================

def format_tags(tags: List[Dict[str, str]]) -> str:
    """Format tags list as 'Key=Value' pairs."""
    if not tags:
        return 'N/A'
    return ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags])


def bytes_to_gb(bytes_value: Optional[int]) -> str:
    """Convert bytes to GB with 2 decimal places."""
    if bytes_value is None or bytes_value == 0:
        return '0 GB'
    gb = bytes_value / (1024 ** 3)
    return f"{gb:.2f} GB"


def bytes_to_tb(bytes_value: Optional[int]) -> str:
    """Convert bytes to TB with 2 decimal places."""
    if bytes_value is None or bytes_value == 0:
        return '0 TB'
    tb = bytes_value / (1024 ** 4)
    return f"{tb:.2f} TB"


def extract_gateway_id(gateway_arn: str) -> str:
    """Extract gateway ID from ARN."""
    # ARN format: arn:aws:storagegateway:region:account-id:gateway/gateway-id
    try:
        return gateway_arn.split('/')[-1]
    except Exception:
        return gateway_arn


def extract_file_share_id(file_share_arn: str) -> str:
    """Extract file share ID from ARN."""
    # ARN format: arn:aws:storagegateway:region:account-id:share/share-id
    try:
        return file_share_arn.split('/')[-1]
    except Exception:
        return file_share_arn


def extract_volume_id(volume_arn: str) -> str:
    """Extract volume ID from ARN."""
    # ARN format: arn:aws:storagegateway:region:account-id:gateway/gateway-id/volume/volume-id
    try:
        return volume_arn.split('/')[-1]
    except Exception:
        return volume_arn


def collect_all_gateways(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect all Storage Gateways across specified regions."""
    all_gateways = []

    for region in regions:
        utils.log_info(f"Scanning Storage Gateways in {region}...")

        gateway_arns = list_gateways(region)

        if not gateway_arns:
            utils.log_info(f"  No gateways found in {region}")
            continue

        utils.log_info(f"  Found {len(gateway_arns)} gateway(s) in {region}")

        for idx, gateway_arn in enumerate(gateway_arns, 1):
            utils.log_info(f"  Processing gateway {idx}/{len(gateway_arns)}: {extract_gateway_id(gateway_arn)}")

            gateway_info = describe_gateway(gateway_arn, region)
            if not gateway_info:
                continue

            # Get tags
            tags = list_tags_for_resource(gateway_arn, region)

            gateway_data = {
                'Region': region,
                'GatewayARN': gateway_info.get('GatewayARN', 'N/A'),
                'GatewayId': gateway_info.get('GatewayId', 'N/A'),
                'GatewayName': gateway_info.get('GatewayName', 'N/A'),
                'GatewayType': gateway_info.get('GatewayType', 'N/A'),
                'GatewayState': gateway_info.get('GatewayState', 'N/A'),
                'GatewayTimezone': gateway_info.get('GatewayTimezone', 'N/A'),
                'SoftwareVersion': gateway_info.get('SoftwareUpdatesEndDate', 'N/A'),
                'Ec2InstanceId': gateway_info.get('Ec2InstanceId', 'N/A'),
                'Ec2InstanceRegion': gateway_info.get('Ec2InstanceRegion', 'N/A'),
                'GatewayIpAddress': gateway_info.get('NextUpdateAvailabilityDate', 'N/A'),
                'HostEnvironment': gateway_info.get('HostEnvironment', 'N/A'),
                'EndpointType': gateway_info.get('EndpointType', 'N/A'),
                'VPCEndpoint': gateway_info.get('VPCEndpoint', 'N/A'),
                'CloudWatchLogGroupARN': gateway_info.get('CloudWatchLogGroupARN', 'N/A'),
                'DeprecationDate': gateway_info.get('DeprecationDate', 'N/A'),
                'SoftwareUpdatesEndDate': gateway_info.get('SoftwareUpdatesEndDate', 'N/A'),
                'SupportedGatewayCapacities': ', '.join(gateway_info.get('SupportedGatewayCapacities', [])) or 'N/A',
                'Tags': format_tags(tags)
            }

            # Get gateway network interfaces if available
            network_interfaces = gateway_info.get('GatewayNetworkInterfaces', [])
            if network_interfaces:
                gateway_data['GatewayIpAddress'] = network_interfaces[0].get('Ipv4Address', 'N/A')

            all_gateways.append(gateway_data)

    return all_gateways


def collect_all_file_shares(regions: List[str], gateway_arns_by_region: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """Collect all file shares across specified regions."""
    all_file_shares = []

    for region in regions:
        if region not in gateway_arns_by_region:
            continue

        utils.log_info(f"Scanning file shares in {region}...")

        for gateway_arn in gateway_arns_by_region[region]:
            file_share_arns = list_file_shares(gateway_arn, region)

            if not file_share_arns:
                continue

            utils.log_info(f"  Found {len(file_share_arns)} file share(s) for gateway {extract_gateway_id(gateway_arn)}")

            # Separate NFS and SMB file shares by ARN pattern
            nfs_arns = []
            smb_arns = []

            for arn in file_share_arns:
                # Try to determine type - we'll handle errors in describe operations
                nfs_arns.append(arn)  # Start with NFS, fallback to SMB if it fails

            # Try NFS first
            nfs_shares = describe_nfs_file_shares(nfs_arns, region)
            for share in nfs_shares:
                file_share_data = {
                    'Region': region,
                    'FileShareARN': share.get('FileShareARN', 'N/A'),
                    'FileShareId': share.get('FileShareId', 'N/A'),
                    'FileShareName': share.get('FileShareName', 'N/A'),
                    'FileShareType': 'NFS',
                    'FileShareStatus': share.get('FileShareStatus', 'N/A'),
                    'GatewayARN': share.get('GatewayARN', 'N/A'),
                    'LocationARN': share.get('LocationARN', 'N/A'),
                    'Path': share.get('Path', 'N/A'),
                    'Role': share.get('Role', 'N/A'),
                    'DefaultStorageClass': share.get('DefaultStorageClass', 'N/A'),
                    'ObjectACL': share.get('ObjectACL', 'N/A'),
                    'ReadOnly': share.get('ReadOnly', False),
                    'RequesterPays': share.get('RequesterPays', False),
                    'Squash': share.get('Squash', 'N/A'),
                    'ValidUserList': ', '.join(share.get('ClientList', [])) or 'N/A',
                    'Authentication': 'N/A',
                    'CaseSensitivity': 'N/A',
                    'Tags': format_tags(share.get('Tags', []))
                }
                all_file_shares.append(file_share_data)

            # Identify SMB shares (those that failed NFS describe)
            nfs_arns_set = {share.get('FileShareARN') for share in nfs_shares}
            smb_arns = [arn for arn in file_share_arns if arn not in nfs_arns_set]

            # Try SMB
            smb_shares = describe_smb_file_shares(smb_arns, region)
            for share in smb_shares:
                file_share_data = {
                    'Region': region,
                    'FileShareARN': share.get('FileShareARN', 'N/A'),
                    'FileShareId': share.get('FileShareId', 'N/A'),
                    'FileShareName': share.get('FileShareName', 'N/A'),
                    'FileShareType': 'SMB',
                    'FileShareStatus': share.get('FileShareStatus', 'N/A'),
                    'GatewayARN': share.get('GatewayARN', 'N/A'),
                    'LocationARN': share.get('LocationARN', 'N/A'),
                    'Path': share.get('Path', 'N/A'),
                    'Role': share.get('Role', 'N/A'),
                    'DefaultStorageClass': share.get('DefaultStorageClass', 'N/A'),
                    'ObjectACL': share.get('ObjectACL', 'N/A'),
                    'ReadOnly': share.get('ReadOnly', False),
                    'RequesterPays': share.get('RequesterPays', False),
                    'Squash': 'N/A',
                    'ValidUserList': ', '.join(share.get('ValidUserList', [])) or 'N/A',
                    'Authentication': share.get('Authentication', 'N/A'),
                    'CaseSensitivity': share.get('CaseSensitivity', 'N/A'),
                    'Tags': format_tags(share.get('Tags', []))
                }
                all_file_shares.append(file_share_data)

    return all_file_shares


def collect_all_volumes(regions: List[str], gateway_arns_by_region: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """Collect all volumes across specified regions."""
    all_volumes = []

    for region in regions:
        if region not in gateway_arns_by_region:
            continue

        utils.log_info(f"Scanning volumes in {region}...")

        for gateway_arn in gateway_arns_by_region[region]:
            volume_arns = list_volumes(gateway_arn, region)

            if not volume_arns:
                continue

            utils.log_info(f"  Found {len(volume_arns)} volume(s) for gateway {extract_gateway_id(gateway_arn)}")

            # Try cached volumes first
            cached_volumes = describe_cached_volumes(volume_arns, region)
            for volume in cached_volumes:
                volume_data = {
                    'Region': region,
                    'VolumeARN': volume.get('VolumeARN', 'N/A'),
                    'VolumeId': volume.get('VolumeId', 'N/A'),
                    'VolumeType': volume.get('VolumeType', 'CACHED'),
                    'VolumeStatus': volume.get('VolumeStatus', 'N/A'),
                    'VolumeAttachmentStatus': volume.get('VolumeAttachmentStatus', 'N/A'),
                    'VolumeSizeInBytes': volume.get('VolumeSizeInBytes', 0),
                    'VolumeSizeGB': bytes_to_gb(volume.get('VolumeSizeInBytes', 0)),
                    'VolumeUsedInBytes': volume.get('VolumeUsedInBytes', 0),
                    'VolumeUsedGB': bytes_to_gb(volume.get('VolumeUsedInBytes', 0)),
                    'GatewayARN': gateway_arn,
                    'VolumeiSCSIAttributes': volume.get('VolumeiSCSIAttributes', {}).get('TargetARN', 'N/A'),
                    'SourceSnapshotId': volume.get('SourceSnapshotId', 'N/A'),
                    'KMSKey': volume.get('KMSKey', 'N/A'),
                    'CreatedDate': volume.get('CreatedDate', 'N/A')
                }
                all_volumes.append(volume_data)

            # Identify stored volumes (those that failed cached describe)
            cached_arns_set = {vol.get('VolumeARN') for vol in cached_volumes}
            stored_arns = [arn for arn in volume_arns if arn not in cached_arns_set]

            # Try stored volumes
            stored_volumes = describe_stored_volumes(stored_arns, region)
            for volume in stored_volumes:
                volume_data = {
                    'Region': region,
                    'VolumeARN': volume.get('VolumeARN', 'N/A'),
                    'VolumeId': volume.get('VolumeId', 'N/A'),
                    'VolumeType': volume.get('VolumeType', 'STORED'),
                    'VolumeStatus': volume.get('VolumeStatus', 'N/A'),
                    'VolumeAttachmentStatus': 'N/A',
                    'VolumeSizeInBytes': volume.get('VolumeSizeInBytes', 0),
                    'VolumeSizeGB': bytes_to_gb(volume.get('VolumeSizeInBytes', 0)),
                    'VolumeUsedInBytes': volume.get('VolumeUsedInBytes', 0),
                    'VolumeUsedGB': bytes_to_gb(volume.get('VolumeUsedInBytes', 0)),
                    'GatewayARN': gateway_arn,
                    'VolumeiSCSIAttributes': volume.get('VolumeiSCSIAttributes', {}).get('TargetARN', 'N/A'),
                    'SourceSnapshotId': volume.get('SourceSnapshotId', 'N/A'),
                    'KMSKey': volume.get('KMSKey', 'N/A'),
                    'CreatedDate': volume.get('CreatedDate', 'N/A')
                }
                all_volumes.append(volume_data)

    return all_volumes


def collect_all_tapes(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect all tapes across specified regions."""
    all_tapes = []

    for region in regions:
        utils.log_info(f"Scanning tapes in {region}...")

        tape_arns = list_tapes(region)

        if not tape_arns:
            utils.log_info(f"  No tapes found in {region}")
            continue

        utils.log_info(f"  Found {len(tape_arns)} tape(s) in {region}")

        tapes = describe_tapes(tape_arns, region)

        for tape in tapes:
            tape_data = {
                'Region': region,
                'TapeARN': tape.get('TapeARN', 'N/A'),
                'TapeBarcode': tape.get('TapeBarcode', 'N/A'),
                'TapeStatus': tape.get('TapeStatus', 'N/A'),
                'TapeSizeInBytes': tape.get('TapeSizeInBytes', 0),
                'TapeSizeGB': bytes_to_gb(tape.get('TapeSizeInBytes', 0)),
                'TapeUsedInBytes': tape.get('TapeUsedInBytes', 0),
                'TapeUsedGB': bytes_to_gb(tape.get('TapeUsedInBytes', 0)),
                'Progress': f"{tape.get('Progress', 0):.1f}%" if tape.get('Progress') else 'N/A',
                'PoolId': tape.get('PoolId', 'N/A'),
                'PoolEntryDate': tape.get('PoolEntryDate', 'N/A'),
                'RetentionStartDate': tape.get('RetentionStartDate', 'N/A'),
                'Worm': tape.get('Worm', False),
                'TapeCreatedDate': tape.get('TapeCreatedDate', 'N/A')
            }
            all_tapes.append(tape_data)

    return all_tapes


def collect_all_tape_pools(regions: List[str]) -> List[Dict[str, Any]]:
    """Collect all tape pools across specified regions."""
    all_pools = []

    for region in regions:
        utils.log_info(f"Scanning tape pools in {region}...")

        pools = list_tape_pools(region)

        if not pools:
            utils.log_info(f"  No tape pools found in {region}")
            continue

        utils.log_info(f"  Found {len(pools)} tape pool(s) in {region}")

        for pool in pools:
            pool_data = {
                'Region': region,
                'PoolARN': pool.get('PoolARN', 'N/A'),
                'PoolName': pool.get('PoolName', 'N/A'),
                'StorageClass': pool.get('StorageClass', 'N/A'),
                'RetentionLockType': pool.get('RetentionLockType', 'N/A'),
                'RetentionLockTimeInDays': pool.get('RetentionLockTimeInDays', 'N/A'),
                'PoolStatus': pool.get('PoolStatus', 'N/A')
            }
            all_pools.append(pool_data)

    return all_pools


def collect_all_local_disks(regions: List[str], gateway_arns_by_region: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """Collect all local disks across specified regions."""
    all_disks = []

    for region in regions:
        if region not in gateway_arns_by_region:
            continue

        utils.log_info(f"Scanning local disks in {region}...")

        for gateway_arn in gateway_arns_by_region[region]:
            disks = list_local_disks(gateway_arn, region)

            if not disks:
                continue

            utils.log_info(f"  Found {len(disks)} local disk(s) for gateway {extract_gateway_id(gateway_arn)}")

            for disk in disks:
                disk_data = {
                    'Region': region,
                    'GatewayARN': gateway_arn,
                    'GatewayId': extract_gateway_id(gateway_arn),
                    'DiskId': disk.get('DiskId', 'N/A'),
                    'DiskPath': disk.get('DiskPath', 'N/A'),
                    'DiskNode': disk.get('DiskNode', 'N/A'),
                    'DiskStatus': disk.get('DiskStatus', 'N/A'),
                    'DiskAllocationType': disk.get('DiskAllocationType', 'N/A'),
                    'DiskAllocationResource': disk.get('DiskAllocationResource', 'N/A'),
                    'DiskSizeInBytes': disk.get('DiskSizeInBytes', 0),
                    'DiskSizeGB': bytes_to_gb(disk.get('DiskSizeInBytes', 0)),
                    'DiskAttributeValues': ', '.join(disk.get('DiskAttributeValues', [])) or 'N/A'
                }
                all_disks.append(disk_data)

    return all_disks


def create_summary_sheet(gateways: List[Dict[str, Any]], file_shares: List[Dict[str, Any]],
                         volumes: List[Dict[str, Any]], tapes: List[Dict[str, Any]],
                         pools: List[Dict[str, Any]], disks: List[Dict[str, Any]]) -> pd.DataFrame:
    """Create summary sheet with counts and statistics."""
    summary_data = []

    # Gateway counts by type
    gateway_types = {}
    gateway_states = {}
    for gw in gateways:
        gw_type = gw.get('GatewayType', 'Unknown')
        gateway_types[gw_type] = gateway_types.get(gw_type, 0) + 1

        gw_state = gw.get('GatewayState', 'Unknown')
        gateway_states[gw_state] = gateway_states.get(gw_state, 0) + 1

    summary_data.append({'Category': 'Total Gateways', 'Count': len(gateways), 'Details': ''})
    for gw_type, count in sorted(gateway_types.items()):
        summary_data.append({'Category': f'  - {gw_type}', 'Count': count, 'Details': ''})

    summary_data.append({'Category': 'Gateway States', 'Count': '', 'Details': ''})
    for state, count in sorted(gateway_states.items()):
        summary_data.append({'Category': f'  - {state}', 'Count': count, 'Details': ''})

    # File share counts
    file_share_types = {}
    for fs in file_shares:
        fs_type = fs.get('FileShareType', 'Unknown')
        file_share_types[fs_type] = file_share_types.get(fs_type, 0) + 1

    summary_data.append({'Category': '', 'Count': '', 'Details': ''})
    summary_data.append({'Category': 'Total File Shares', 'Count': len(file_shares), 'Details': ''})
    for fs_type, count in sorted(file_share_types.items()):
        summary_data.append({'Category': f'  - {fs_type}', 'Count': count, 'Details': ''})

    # Volume counts
    volume_types = {}
    total_volume_size = 0
    for vol in volumes:
        vol_type = vol.get('VolumeType', 'Unknown')
        volume_types[vol_type] = volume_types.get(vol_type, 0) + 1
        total_volume_size += vol.get('VolumeSizeInBytes', 0)

    summary_data.append({'Category': '', 'Count': '', 'Details': ''})
    summary_data.append({'Category': 'Total Volumes', 'Count': len(volumes), 'Details': bytes_to_tb(total_volume_size)})
    for vol_type, count in sorted(volume_types.items()):
        summary_data.append({'Category': f'  - {vol_type}', 'Count': count, 'Details': ''})

    # Tape counts
    tape_statuses = {}
    total_tape_size = 0
    for tape in tapes:
        tape_status = tape.get('TapeStatus', 'Unknown')
        tape_statuses[tape_status] = tape_statuses.get(tape_status, 0) + 1
        total_tape_size += tape.get('TapeSizeInBytes', 0)

    summary_data.append({'Category': '', 'Count': '', 'Details': ''})
    summary_data.append({'Category': 'Total Tapes', 'Count': len(tapes), 'Details': bytes_to_tb(total_tape_size)})
    for status, count in sorted(tape_statuses.items()):
        summary_data.append({'Category': f'  - {status}', 'Count': count, 'Details': ''})

    # Tape pools
    summary_data.append({'Category': '', 'Count': '', 'Details': ''})
    summary_data.append({'Category': 'Total Tape Pools', 'Count': len(pools), 'Details': ''})

    # Local disks
    disk_types = {}
    total_disk_size = 0
    for disk in disks:
        disk_type = disk.get('DiskAllocationType', 'Unknown')
        disk_types[disk_type] = disk_types.get(disk_type, 0) + 1
        total_disk_size += disk.get('DiskSizeInBytes', 0)

    summary_data.append({'Category': '', 'Count': '', 'Details': ''})
    summary_data.append({'Category': 'Total Local Disks', 'Count': len(disks), 'Details': bytes_to_tb(total_disk_size)})
    for disk_type, count in sorted(disk_types.items()):
        summary_data.append({'Category': f'  - {disk_type}', 'Count': count, 'Details': ''})

    return pd.DataFrame(summary_data)


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def _run_export(account_id: str, account_name: str, regions: List[str]) -> None:
    """Collect Storage Gateway data and write the Excel export."""
    utils.log_info("\n" + "=" * 80)
    utils.log_info("Collecting Storage Gateway Data")
    utils.log_info("=" * 80)

    # Collect gateways
    gateways = collect_all_gateways(regions)
    utils.log_info(f"\nTotal gateways found: {len(gateways)}")

    # Build gateway ARN mapping by region for subsequent operations
    gateway_arns_by_region = {}
    for gw in gateways:
        region = gw['Region']
        if region not in gateway_arns_by_region:
            gateway_arns_by_region[region] = []
        gateway_arns_by_region[region].append(gw['GatewayARN'])

    # Collect file shares
    file_shares = collect_all_file_shares(regions, gateway_arns_by_region)
    utils.log_info(f"Total file shares found: {len(file_shares)}")

    # Collect volumes
    volumes = collect_all_volumes(regions, gateway_arns_by_region)
    utils.log_info(f"Total volumes found: {len(volumes)}")

    # Collect tapes
    tapes = collect_all_tapes(regions)
    utils.log_info(f"Total tapes found: {len(tapes)}")

    # Collect tape pools
    tape_pools = collect_all_tape_pools(regions)
    utils.log_info(f"Total tape pools found: {len(tape_pools)}")

    # Collect local disks
    local_disks = collect_all_local_disks(regions, gateway_arns_by_region)
    utils.log_info(f"Total local disks found: {len(local_disks)}")

    # Create DataFrames
    utils.log_info("\n" + "=" * 80)
    utils.log_info("Preparing Excel Export")
    utils.log_info("=" * 80)

    summary_df = create_summary_sheet(gateways, file_shares, volumes, tapes, tape_pools, local_disks)
    gateways_df = pd.DataFrame(gateways) if gateways else pd.DataFrame()
    file_shares_df = pd.DataFrame(file_shares) if file_shares else pd.DataFrame()
    volumes_df = pd.DataFrame(volumes) if volumes else pd.DataFrame()
    tapes_df = pd.DataFrame(tapes) if tapes else pd.DataFrame()
    tape_pools_df = pd.DataFrame(tape_pools) if tape_pools else pd.DataFrame()
    local_disks_df = pd.DataFrame(local_disks) if local_disks else pd.DataFrame()

    # Filter active gateways for separate sheet
    active_gateways_df = gateways_df[gateways_df['GatewayState'] == 'RUNNING'].copy() if not gateways_df.empty else pd.DataFrame()

    # Prepare DataFrames for export
    summary_df = utils.prepare_dataframe_for_export(summary_df)
    gateways_df = utils.prepare_dataframe_for_export(gateways_df)
    file_shares_df = utils.prepare_dataframe_for_export(file_shares_df)
    volumes_df = utils.prepare_dataframe_for_export(volumes_df)
    tapes_df = utils.prepare_dataframe_for_export(tapes_df)
    tape_pools_df = utils.prepare_dataframe_for_export(tape_pools_df)
    local_disks_df = utils.prepare_dataframe_for_export(local_disks_df)
    active_gateways_df = utils.prepare_dataframe_for_export(active_gateways_df)

    # Create multi-sheet Excel file
    filename = utils.create_export_filename(account_name, 'storagegateway', 'all')

    sheets = {
        'Summary': summary_df,
        'Gateways': gateways_df,
        'File Shares': file_shares_df,
        'Volumes': volumes_df,
        'Tapes': tapes_df,
        'Tape Pools': tape_pools_df,
        'Local Disks': local_disks_df,
        'Active Gateways': active_gateways_df
    }

    success = utils.save_multiple_dataframes_to_excel(sheets, filename)

    if success:
        utils.log_success(f"\nExport completed successfully!")
        utils.log_success(f"File saved to: {utils.get_output_filepath(filename)}")
        utils.log_info(f"\nExport Summary:")
        utils.log_info(f"  - Total Gateways: {len(gateways)}")
        utils.log_info(f"  - Active Gateways: {len(active_gateways_df)}")
        utils.log_info(f"  - File Shares: {len(file_shares)}")
        utils.log_info(f"  - Volumes: {len(volumes)}")
        utils.log_info(f"  - Tapes: {len(tapes)}")
        utils.log_info(f"  - Tape Pools: {len(tape_pools)}")
        utils.log_info(f"  - Local Disks: {len(local_disks)}")
    else:
        utils.log_error("Export failed. Check the log file for details.")
        sys.exit(1)


def main():
    """Main execution function — 3-step state machine (region -> confirm -> export)."""
    try:
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            utils.log_error("Missing required dependencies. Please install them and try again.")
            sys.exit(1)

        utils.setup_logging('storagegateway-export')
        account_id, account_name = utils.print_script_banner("AWS STORAGE GATEWAY EXPORT")

        utils.log_info(f"AWS Account: {account_name} ({utils.mask_account_id(account_id)})")

        step = 1
        regions = None

        while True:
            if step == 1:
                result = utils.prompt_region_selection(service_name="Storage Gateway")
                if result == 'back':
                    sys.exit(10)
                if result == 'exit':
                    sys.exit(11)
                regions = result
                step = 2

            elif step == 2:
                region_str = regions[0] if len(regions) == 1 else f"{len(regions)} regions"
                msg = f"Ready to export Storage Gateway data ({region_str})."
                result = utils.prompt_confirmation(msg)
                if result == 'back':
                    step = 1
                    continue
                if result == 'exit':
                    sys.exit(11)
                step = 3

            elif step == 3:
                _run_export(account_id, account_name, regions)
                break

    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)


if __name__ == '__main__':
    main()

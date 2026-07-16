#!/usr/bin/env python3

"""
===========================
= AWS RESOURCE SCANNER =
===========================

Title: AWS Security Groups Export Script
Date: NOV-15-2025

Description:
This script exports security group information from AWS regions including group name, ID,
VPC, inbound rules, outbound rules, and associated resources. Each security group rule is listed
on its own line for better analysis and filtering. The data is exported to an Excel file with
AWS-specific naming convention and compliance markers.

Phase 4B Update:
- Concurrent region scanning (4x-10x performance improvement)
- Automatic fallback to sequential on errors
"""

import datetime
import sys
from pathlib import Path

# Add path to import utils module
try:
    # Try to import directly (if utils.py is in Python path)
    import utils
except ImportError:
    # If import fails, try to find the module relative to this script
    script_dir = Path(__file__).parent.absolute()

    # Check if we're in the scripts directory
    if script_dir.name.lower() == 'scripts':
        # Add the parent directory (StratusScan root) to the path
        sys.path.append(str(script_dir.parent))
    else:
        # Add the current directory to the path
        sys.path.append(str(script_dir))

    # Try import again
    try:
        import utils
    except ImportError:
        print("ERROR: Could not import the utils module. Make sure utils.py is in the StratusScan directory.")
        sys.exit(1)
args = utils.parse_script_args("Export EC2 security groups and rules to Excel")

def is_valid_aws_region(region_name):
    """
    Check if a region name is a valid AWS region.

    Args:
        region_name (str): The region name to validate

    Returns:
        bool: True if valid, False otherwise
    """
    return utils.is_aws_region(region_name)

def build_vpc_name_map(ec2_client):
    """
    Fetch all VPCs in a region and return a {vpc_id: display_name} map.
    """
    vpc_map = {}
    try:
        paginator = ec2_client.get_paginator('describe_vpcs')
        for page in paginator.paginate():
            for vpc in page.get('Vpcs', []):
                vpc_id = vpc['VpcId']
                name = vpc_id
                for tag in vpc.get('Tags', []):
                    if tag['Key'] == 'Name':
                        name = f"{tag['Value']} ({vpc_id})"
                        break
                vpc_map[vpc_id] = name
    except Exception:
        pass
    return vpc_map


def build_sg_resource_map(ec2_client, region):
    """
    Fetch EC2, RDS, ELB, ALBv2, and Lambda resources once per region
    and return a {sg_id: [resource_strings]} map.
    """
    sg_resources = {}

    def _append(sg_id, label):
        sg_resources.setdefault(sg_id, []).append(label)

    # EC2 instances
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for res in page.get('Reservations', []):
                for inst in res.get('Instances', []):
                    inst_name = 'Unnamed'
                    for tag in inst.get('Tags', []):
                        if tag['Key'] == 'Name':
                            inst_name = tag['Value']
                            break
                    label = f"EC2:{inst_name} ({inst['InstanceId']})"
                    for sg in inst.get('SecurityGroups', []):
                        _append(sg['GroupId'], label)
    except Exception as e:
        utils.log_warning(f"Could not fetch EC2 instances for resource map: {e}")

    # RDS instances
    try:
        rds_client = utils.get_boto3_client('rds', region_name=region)
        paginator = rds_client.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for inst in page.get('DBInstances', []):
                label = f"RDS:{inst['DBInstanceIdentifier']}"
                for sg in inst.get('VpcSecurityGroups', []):
                    _append(sg.get('VpcSecurityGroupId', ''), label)
    except Exception as e:
        utils.log_warning(f"Could not fetch RDS instances for resource map: {e}")

    # Classic ELBs
    try:
        elb_client = utils.get_boto3_client('elb', region_name=region)
        paginator = elb_client.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            for lb in page.get('LoadBalancerDescriptions', []):
                label = f"ELB:{lb['LoadBalancerName']}"
                for sg_id in lb.get('SecurityGroups', []):
                    _append(sg_id, label)
    except Exception as e:
        utils.log_warning(f"Could not fetch ELBs for resource map: {e}")

    # ALBv2 / NLB
    try:
        elbv2_client = utils.get_boto3_client('elbv2', region_name=region)
        paginator = elbv2_client.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            for lb in page.get('LoadBalancers', []):
                label = f"ALB/NLB:{lb['LoadBalancerName']}"
                for sg_id in lb.get('SecurityGroups', []):
                    _append(sg_id, label)
    except Exception as e:
        utils.log_warning(f"Could not fetch ALBs/NLBs for resource map: {e}")

    # Lambda functions
    try:
        lambda_client = utils.get_boto3_client('lambda', region_name=region)
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for fn in page.get('Functions', []):
                vpc_cfg = fn.get('VpcConfig', {})
                label = f"Lambda:{fn['FunctionName']}"
                for sg_id in vpc_cfg.get('SecurityGroupIds', []):
                    _append(sg_id, label)
    except Exception as e:
        utils.log_warning(f"Could not fetch Lambda functions for resource map: {e}")

    return sg_resources

def format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=True):
    """
    Format IP range rule details.

    Args:
        ip_range: The IP range dictionary
        protocol: The protocol
        from_port: The from port
        to_port: The to port
        is_inbound: Whether this is an inbound rule

    Returns:
        str: Formatted rule string
    """
    if protocol == '-1':
        protocol = 'All'

    # Format port range
    port_range = ''
    if from_port is not None and to_port is not None:
        port_range = str(from_port) if from_port == to_port else f"{from_port}-{to_port}"
    else:
        port_range = 'All'

    # Format CIDR
    cidr = ip_range.get('CidrIp', ip_range.get('CidrIpv6', 'Unknown'))

    if is_inbound:
        return f"{cidr} → {protocol}:{port_range}"
    else:
        return f"{protocol}:{port_range} → {cidr}"

def format_security_group_reference(sg_ref, protocol, from_port, to_port, is_inbound=True):
    """
    Format security group reference rule details.

    Args:
        sg_ref: The security group reference dictionary
        protocol: The protocol
        from_port: The from port
        to_port: The to port
        is_inbound: Whether this is an inbound rule

    Returns:
        str: Formatted rule string
    """
    if protocol == '-1':
        protocol = 'All'

    # Format port range
    port_range = ''
    if from_port is not None and to_port is not None:
        port_range = str(from_port) if from_port == to_port else f"{from_port}-{to_port}"
    else:
        port_range = 'All'

    # Format security group reference
    sg_identifier = ""
    if 'GroupId' in sg_ref:
        sg_identifier = f"sg:{sg_ref['GroupId']}"
    elif 'GroupName' in sg_ref:
        sg_identifier = f"sg:{sg_ref['GroupName']}"
    else:
        sg_identifier = "sg:Unknown"

    if is_inbound:
        return f"{sg_identifier} → {protocol}:{port_range}"
    else:
        return f"{protocol}:{port_range} → {sg_identifier}"


def _build_sg_rule_rows(sg, region, vpc_map, sg_resource_map, rules_map):
    """
    Build all export rows (inbound, outbound, and the no-rules placeholder) for
    a single security group.

    Extracted so the per-security-group processing in ``get_security_group_rules``
    can be wrapped in try/except by the caller: a malformed security group must
    not discard the whole region's results. Every required field is read with
    ``.get()`` and a safe default for the same reason.

    Args:
        sg (dict): A single SecurityGroups entry from describe_security_groups.
        region (str): AWS region name.
        vpc_map (dict): {vpc_id: display_name} lookup.
        sg_resource_map (dict): {sg_id: [resource_strings]} lookup.
        rules_map (dict): {sg_id: [rule dicts]} lookup from describe_security_group_rules.

    Returns:
        list: The assembled row dict(s) for this security group.
    """
    rows = []

    sg_id = sg.get('GroupId', 'N/A')
    sg_name = sg.get('GroupName', 'Unnamed')

    vpc_id = sg.get('VpcId', '')
    vpc_name = vpc_map.get(vpc_id, vpc_id) if vpc_id else "No VPC (EC2-Classic)"

    resources = sg_resource_map.get(sg_id, [])
    resources_str = '; '.join(resources) if resources else 'None'

    # Get description
    description = sg.get('Description', '')

    # Get owner information
    owner_id = sg.get('OwnerId', 'N/A')
    owner_formatted = utils.get_account_name_formatted(owner_id)

    # Process inbound rules (IpPermissions)
    for permission in sg.get('IpPermissions', []):
        protocol = permission.get('IpProtocol', 'All')
        from_port = permission.get('FromPort', None)
        to_port = permission.get('ToPort', None)

        # Process IPv4 ranges
        for ip_range in permission.get('IpRanges', []):
            # Find matching rule in the rules map
            rule_id = sg_id  # Default to using the security group ID
            if sg_id in rules_map:
                for rule in rules_map[sg_id]:
                    if (rule.get('IpProtocol') == protocol and
                        rule.get('FromPort', None) == from_port and
                        rule.get('ToPort', None) == to_port and
                        rule.get('CidrIpv4', '') == ip_range.get('CidrIp', '') and
                        not rule.get('IsEgress', True)):
                        rule_id = rule.get('SecurityGroupRuleId', sg_id)
                        break

            rule_desc = ip_range.get('Description', '')
            rule_text = format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=True)

            rows.append({
                'Rule ID': rule_id,
                'SG Name': sg_name,
                'SG ID': sg_id,
                'VPC': vpc_name,
                'SG Description': description,
                'Direction': 'Inbound',
                'Rule': rule_text,
                'Rule Description': rule_desc,
                'Protocol': protocol if protocol != '-1' else 'All',
                'From Port': from_port if from_port is not None else 'All',
                'To Port': to_port if to_port is not None else 'All',
                'CIDR': ip_range.get('CidrIp', ''),
                'Owner ID': owner_formatted,
                'Used By': resources_str,
                'Region': region
            })

        # Process IPv6 ranges
        for ip_range in permission.get('Ipv6Ranges', []):
            # Find matching rule in the rules map
            rule_id = sg_id  # Default to using the security group ID
            if sg_id in rules_map:
                for rule in rules_map[sg_id]:
                    if (rule.get('IpProtocol') == protocol and
                        rule.get('FromPort', None) == from_port and
                        rule.get('ToPort', None) == to_port and
                        rule.get('CidrIpv6', '') == ip_range.get('CidrIpv6', '') and
                        not rule.get('IsEgress', True)):
                        rule_id = rule.get('SecurityGroupRuleId', sg_id)
                        break

            rule_desc = ip_range.get('Description', '')
            rule_text = format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=True)

            rows.append({
                'Rule ID': rule_id,
                'SG Name': sg_name,
                'SG ID': sg_id,
                'VPC': vpc_name,
                'SG Description': description,
                'Direction': 'Inbound',
                'Rule': rule_text,
                'Rule Description': rule_desc,
                'Protocol': protocol if protocol != '-1' else 'All',
                'From Port': from_port if from_port is not None else 'All',
                'To Port': to_port if to_port is not None else 'All',
                'CIDR': ip_range.get('CidrIpv6', ''),
                'Owner ID': owner_formatted,
                'Used By': resources_str,
                'Region': region
            })

        # Process security group references
        for sg_ref in permission.get('UserIdGroupPairs', []):
            # Find matching rule in the rules map
            rule_id = sg_id  # Default to using the security group ID
            ref_group_id = sg_ref.get('GroupId', '')
            if sg_id in rules_map:
                for rule in rules_map[sg_id]:
                    referenced_group = rule.get('ReferencedGroupInfo', {}).get('GroupId', '')
                    if (rule.get('IpProtocol') == protocol and
                        rule.get('FromPort', None) == from_port and
                        rule.get('ToPort', None) == to_port and
                        referenced_group == ref_group_id and
                        not rule.get('IsEgress', True)):
                        rule_id = rule.get('SecurityGroupRuleId', sg_id)
                        break

            rule_desc = sg_ref.get('Description', '')
            rule_text = format_security_group_reference(sg_ref, protocol, from_port, to_port, is_inbound=True)

            rows.append({
                'Rule ID': rule_id,
                'SG Name': sg_name,
                'SG ID': sg_id,
                'VPC': vpc_name,
                'SG Description': description,
                'Direction': 'Inbound',
                'Rule': rule_text,
                'Rule Description': rule_desc,
                'Protocol': protocol if protocol != '-1' else 'All',
                'From Port': from_port if from_port is not None else 'All',
                'To Port': to_port if to_port is not None else 'All',
                'Referenced SG': sg_ref.get('GroupId', ''),
                'Owner ID': owner_formatted,
                'Used By': resources_str,
                'Region': region
            })

    # Process outbound rules (IpPermissionsEgress)
    for permission in sg.get('IpPermissionsEgress', []):
        protocol = permission.get('IpProtocol', 'All')
        from_port = permission.get('FromPort', None)
        to_port = permission.get('ToPort', None)

        # Process IPv4 ranges
        for ip_range in permission.get('IpRanges', []):
            # Find matching rule in the rules map
            rule_id = sg_id  # Default to using the security group ID
            if sg_id in rules_map:
                for rule in rules_map[sg_id]:
                    if (rule.get('IpProtocol') == protocol and
                        rule.get('FromPort', None) == from_port and
                        rule.get('ToPort', None) == to_port and
                        rule.get('CidrIpv4', '') == ip_range.get('CidrIp', '') and
                        rule.get('IsEgress', False)):
                        rule_id = rule.get('SecurityGroupRuleId', sg_id)
                        break

            rule_desc = ip_range.get('Description', '')
            rule_text = format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=False)

            rows.append({
                'Rule ID': rule_id,
                'SG Name': sg_name,
                'SG ID': sg_id,
                'VPC': vpc_name,
                'SG Description': description,
                'Direction': 'Outbound',
                'Rule': rule_text,
                'Rule Description': rule_desc,
                'Protocol': protocol if protocol != '-1' else 'All',
                'From Port': from_port if from_port is not None else 'All',
                'To Port': to_port if to_port is not None else 'All',
                'CIDR': ip_range.get('CidrIp', ''),
                'Owner ID': owner_formatted,
                'Used By': resources_str,
                'Region': region
            })

        # Process IPv6 ranges
        for ip_range in permission.get('Ipv6Ranges', []):
            # Find matching rule in the rules map
            rule_id = sg_id  # Default to using the security group ID
            if sg_id in rules_map:
                for rule in rules_map[sg_id]:
                    if (rule.get('IpProtocol') == protocol and
                        rule.get('FromPort', None) == from_port and
                        rule.get('ToPort', None) == to_port and
                        rule.get('CidrIpv6', '') == ip_range.get('CidrIpv6', '') and
                        rule.get('IsEgress', False)):
                        rule_id = rule.get('SecurityGroupRuleId', sg_id)
                        break

            rule_desc = ip_range.get('Description', '')
            rule_text = format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=False)

            rows.append({
                'Rule ID': rule_id,
                'SG Name': sg_name,
                'SG ID': sg_id,
                'VPC': vpc_name,
                'SG Description': description,
                'Direction': 'Outbound',
                'Rule': rule_text,
                'Rule Description': rule_desc,
                'Protocol': protocol if protocol != '-1' else 'All',
                'From Port': from_port if from_port is not None else 'All',
                'To Port': to_port if to_port is not None else 'All',
                'CIDR': ip_range.get('CidrIpv6', ''),
                'Owner ID': owner_formatted,
                'Used By': resources_str,
                'Region': region
            })

        # Process security group references
        for sg_ref in permission.get('UserIdGroupPairs', []):
            # Find matching rule in the rules map
            rule_id = sg_id  # Default to using the security group ID
            ref_group_id = sg_ref.get('GroupId', '')
            if sg_id in rules_map:
                for rule in rules_map[sg_id]:
                    referenced_group = rule.get('ReferencedGroupInfo', {}).get('GroupId', '')
                    if (rule.get('IpProtocol') == protocol and
                        rule.get('FromPort', None) == from_port and
                        rule.get('ToPort', None) == to_port and
                        referenced_group == ref_group_id and
                        rule.get('IsEgress', False)):
                        rule_id = rule.get('SecurityGroupRuleId', sg_id)
                        break

            rule_desc = sg_ref.get('Description', '')
            rule_text = format_security_group_reference(sg_ref, protocol, from_port, to_port, is_inbound=False)

            rows.append({
                'Rule ID': rule_id,
                'SG Name': sg_name,
                'SG ID': sg_id,
                'VPC': vpc_name,
                'SG Description': description,
                'Direction': 'Outbound',
                'Rule': rule_text,
                'Rule Description': rule_desc,
                'Protocol': protocol if protocol != '-1' else 'All',
                'From Port': from_port if from_port is not None else 'All',
                'To Port': to_port if to_port is not None else 'All',
                'Referenced SG': sg_ref.get('GroupId', ''),
                'Owner ID': owner_formatted,
                'Used By': resources_str,
                'Region': region
            })

    # If no rules found, add a placeholder entry
    if not sg.get('IpPermissions', []) and not sg.get('IpPermissionsEgress', []):
        rows.append({
            'Rule ID': sg_id,
            'SG Name': sg_name,
            'SG ID': sg_id,
            'VPC': vpc_name,
            'SG Description': description,
            'Direction': 'N/A',
            'Rule': 'No rules defined',
            'Rule Description': '',
            'Protocol': 'N/A',
            'From Port': 'N/A',
            'To Port': 'N/A',
            'CIDR': '',
            'Owner ID': owner_formatted,
            'Used By': resources_str,
            'Region': region
        })

    return rows


def get_security_group_rules(region):
    """
    Get all security groups and their rules from a specific AWS region.

    Not wrapped in ``aws_error_handler``: a swallowed error here would return an
    empty list that ``main()`` cannot distinguish from a genuinely empty region,
    producing silent data loss (see .collab/audit/07.16.2026-silent-collection-failure-blast-radius.md).
    Region-level failures are allowed to raise so the caller can record the
    region as *failed* rather than *empty*. Per-security-group errors are
    contained internally (logged and skipped).

    Args:
        region: AWS region name

    Returns:
        list: List of dictionaries with security group rule information

    Raises:
        Exception: Any AWS/pagination error for the region (caller records it as
            a failed region and surfaces it; it is never masked as empty).
    """
    if not utils.is_aws_region(region):
        utils.log_error(f"Invalid AWS region: {region}")
        return []

    security_group_rules = []

    ec2_client = utils.get_boto3_client('ec2', region_name=region)

    # Batch-fetch lookup maps (one pass each instead of per-SG)
    vpc_map = build_vpc_name_map(ec2_client)
    sg_resource_map = build_sg_resource_map(ec2_client, region)

    # Get all security groups
    sg_paginator = ec2_client.get_paginator('describe_security_groups')
    security_groups = []
    for page in sg_paginator.paginate():
        security_groups.extend(page.get('SecurityGroups', []))

    # Get all security group rules
    rules_paginator = ec2_client.get_paginator('describe_security_group_rules')
    all_rules = []
    for page in rules_paginator.paginate():
        all_rules.extend(page.get('SecurityGroupRules', []))

    # Build rules lookup by SG ID
    rules_map = {}
    for rule in all_rules:
        sg_id = rule.get('GroupId', '')
        if sg_id not in rules_map:
            rules_map[sg_id] = []
        rules_map[sg_id].append(rule)

    total_sgs = len(security_groups)

    if total_sgs > 0:
        utils.log_info(f"Found {total_sgs} security groups in {region} to process")

    # Process each security group. One malformed SG must not sink the region, so
    # each is built inside try/except; failures are logged and skipped.
    skipped = 0
    for sg_index, sg in enumerate(security_groups, 1):
        sg_id = sg.get('GroupId', 'N/A')
        sg_name = sg.get('GroupName', 'Unnamed')
        progress = (sg_index / total_sgs) * 100 if total_sgs > 0 else 0

        utils.log_info(f"[{progress:.1f}%] Processing security group {sg_index}/{total_sgs}: {sg_id} ({sg_name})")

        try:
            sg_rows = _build_sg_rule_rows(sg, region, vpc_map, sg_resource_map, rules_map)
        except Exception as e:
            skipped += 1
            utils.log_error(
                f"Skipping security group '{sg_id}' in {region} due to a processing error", e
            )
            continue

        security_group_rules.extend(sg_rows)

    if skipped:
        utils.log_warning(
            f"{skipped} of {total_sgs} security group(s) in {region} were skipped due to "
            "processing errors (see log above); the remaining security groups were still collected."
        )

    return security_group_rules

def export_to_excel(security_group_rules, account_name, region_suffix=""):
    """
    Export security group rules data to Excel with AWS identifier.

    Args:
        security_group_rules: List of security group rules
        account_name: AWS account name
        region_suffix: Region suffix for filename

    Returns:
        str: Path to the exported file or None if failed
    """
    import pandas as pd

    if not security_group_rules:
        utils.log_warning("No security group rules found to export.")
        return None

    # Create a DataFrame
    df = pd.DataFrame(security_group_rules)

    # Prepare and sanitize DataFrame for export (security groups may have sensitive descriptions/tags)
    df = utils.sanitize_for_export(
        utils.prepare_dataframe_for_export(df)
    )

    # Get current date for filename
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")

    # Use utils to create output filename with AWS identifier
    filename = utils.create_export_filename(
        account_name,
        "sg-rules",
        region_suffix,
        current_date
    )

    # Save using utils function
    output_path = utils.save_dataframe_to_excel(df, filename, sheet_name='Security Group Rules')

    if output_path:
        utils.log_success("AWS Security Group data exported successfully!")
        utils.log_success(f"File location: {output_path}")
        return output_path
    else:
        utils.log_error("Error exporting data. Please check the logs.")
        return None

def main():
    """
    Main function to run the script.
    """
    try:
        # Print title and get account information
        utils.setup_logging("security-groups-export")
        account_id, account_name = utils.print_script_banner("AWS SECURITY GROUPS EXPORT")

        # Check dependencies
        if not utils.ensure_dependencies('pandas', 'openpyxl'):
            sys.exit(1)

        # Import pandas after dependency check

        if account_name.startswith("UNKNOWN"):
            proceed = utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False)
            if not proceed:
                utils.log_info("Exiting script...")
                sys.exit(0)

        regions = utils.prompt_region_selection()
        region_suffix = 'all'

        # Collect security group rules from selected AWS regions (Phase 4B: concurrent)
        utils.log_info("This may take some time depending on the number of regions and security groups.")

        # Define region scan function
        def scan_region_security_groups(region):
            utils.log_info(f"Processing AWS region: {region}")
            region_rules = get_security_group_rules(region)
            utils.log_info(f"Found {len(region_rules)} security group rules in {region}")
            return region_rules

        # Use concurrent region scanning (with automatic fallback to sequential on
        # errors). collect_failures=True returns the regions that raised so a
        # failed collection is distinguishable from a genuinely empty account.
        region_results, failed_regions = utils.scan_regions_concurrent(
            regions=regions,
            scan_function=scan_region_security_groups,
            max_workers=2,
            show_progress=True,
            collect_failures=True,
        )

        # Flatten results
        all_security_group_rules = []
        for rules in region_results:
            all_security_group_rules.extend(rules)

        # Print summary
        total_rules = len(all_security_group_rules)
        utils.log_success(f"Total security group rules found across all AWS regions: {total_rules}")

        # Export whatever succeeded, then decide on exit status based on failures.
        if total_rules > 0:
            # Export to Excel
            utils.log_info("Exporting security group rules to Excel format...")
            output_file = export_to_excel(all_security_group_rules, account_name, region_suffix)

            if output_file:
                utils.log_info(f"Export contains data from {len(regions)} AWS region(s)")
                utils.log_info(f"Total security group rules exported: {total_rules}")
                print("\nScript execution completed.")
            else:
                utils.log_error("Failed to export data. Please check the logs.")
                sys.exit(1)
        elif not failed_regions:
            # Genuinely empty account: every region succeeded and returned nothing.
            utils.log_warning("No security group rules found. Nothing to export.")

        # If ANY region failed, make it loud: write a marker and exit non-zero,
        # even if some data was exported. A partial export that looks complete is
        # exactly the failure mode this guards against.
        if failed_regions:
            utils.report_collection_failures(account_name, "sg-rules", failed_regions)
            print(
                "\nERROR: Security Groups export completed with failures — data is incomplete. "
                "See the *-sg-rules-FAILED-*.txt marker in the output directory."
            )
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()

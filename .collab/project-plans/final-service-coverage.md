# Final Service Coverage - 8 Remaining Services

**Status:** Backlog
**Priority:** MEDIUM
**Owner:** Claude
**Estimated Effort:** 8-12 hours (1-1.5 hours per service)
**Created:** 12.01.2025
**Target Completion:** TBD

---

## Overview

Complete the final 8 AWS service exporters to reach ~99% coverage of useful AWS services. Currently at 97 services (111 scripts), target is 105 services (119 scripts).

## Background

StratusScan has achieved 92% coverage of useful AWS services through Phases 1-4. Eight services remain to reach the ~99% coverage target, after which focus shifts to Phase 5 cross-cutting features.

## Goal

Implement exporters for the remaining 8 useful AWS services:
1. SES/Pinpoint (Email & Messaging)
2. Cloud Map (Service Discovery)
3. X-Ray (Application Tracing)
4. Connect (Contact Center)
5. Network Manager (Global Networks)
6. Marketplace Subscriptions (Licenses & Usage)
7. Glacier Vaults (Archive Storage)
8. Verified Permissions (Cedar Policies)

## Services Breakdown

### Batch 1: Communication & Analytics (3 services)

#### 1. SES / Pinpoint Export
**Service:** Amazon Simple Email Service + Amazon Pinpoint
**Category:** Integration & Messaging
**Effort:** 1.5 hours

**Resources to Export:**
- SES: Email identities, sending quotas, bounce/complaint metrics, configuration sets
- Pinpoint: Email campaigns, journey analytics, application configurations
- Combined export showing email infrastructure

**Worksheets:**
- Email Identities (SES)
- Sending Quotas & Limits
- Configuration Sets
- Pinpoint Campaigns
- Summary

**Key APIs:**
- `ses.list_identities()`, `ses.get_send_quota()`
- `pinpoint.get_apps()`, `pinpoint.get_campaigns()`

**Cost Data:** Usage-based (emails sent, campaigns active)

---

#### 2. Cloud Map Export
**Service:** AWS Cloud Map (Service Discovery)
**Category:** Network Resources
**Effort:** 1 hour

**Resources to Export:**
- Namespaces (HTTP, DNS public, DNS private)
- Services and instances
- Service discovery configurations
- Health check settings

**Worksheets:**
- Namespaces
- Services
- Service Instances
- Health Checks
- Summary

**Key APIs:**
- `servicediscovery.list_namespaces()`
- `servicediscovery.list_services()`
- `servicediscovery.list_instances()`

**Multi-Region:** Yes (regional service)

---

#### 3. X-Ray Export
**Service:** AWS X-Ray
**Category:** Developer Tools
**Effort:** 1 hour

**Resources to Export:**
- Tracing configurations
- Sampling rules
- Groups and filters
- Encryption configs

**Worksheets:**
- Sampling Rules
- Groups
- Encryption Config
- Summary

**Key APIs:**
- `xray.get_sampling_rules()`
- `xray.get_groups()`
- `xray.get_encryption_config()`

**Multi-Region:** Yes (regional service)

---

### Batch 2: Enterprise & Network (3 services)

#### 4. Connect Export
**Service:** Amazon Connect
**Category:** Customer Engagement
**Effort:** 1.5 hours

**Resources to Export:**
- Contact center instances
- Hours of operation
- Queues and routing profiles
- Contact flows
- User configurations

**Worksheets:**
- Instances
- Hours of Operation
- Queues
- Routing Profiles
- Users
- Summary

**Key APIs:**
- `connect.list_instances()`
- `connect.list_hours_of_operations()`
- `connect.list_queues()`
- `connect.list_routing_profiles()`

**Multi-Region:** Yes (regional service)

---

#### 5. Network Manager Export
**Service:** AWS Network Manager
**Category:** Network Resources
**Effort:** 1.5 hours

**Resources to Export:**
- Global networks
- Devices and links
- Sites and connections
- Transit gateway registrations
- Attachments

**Worksheets:**
- Global Networks
- Devices
- Links
- Sites
- Connections
- TGW Registrations
- Summary

**Key APIs:**
- `networkmanager.describe_global_networks()`
- `networkmanager.get_devices()`
- `networkmanager.get_links()`
- `networkmanager.get_sites()`

**Multi-Region:** Global service (use partition default region)

---

#### 6. Marketplace Subscriptions Export
**Service:** AWS Marketplace
**Category:** Cost & Licensing
**Effort:** 1 hour

**Resources to Export:**
- Active subscriptions
- License entitlements
- Usage tracking
- Costs and billing

**Worksheets:**
- Active Subscriptions
- License Entitlements
- Usage Summary
- Costs

**Key APIs:**
- `marketplace-entitlement.get_entitlements()`
- `marketplace-catalog.list_entities()`

**Multi-Region:** Global service (use partition default region)

---

### Batch 3: Storage & Security (2 services)

#### 7. Glacier Vaults Export
**Service:** Amazon S3 Glacier
**Category:** Storage Resources
**Effort:** 1 hour

**Resources to Export:**
- Vaults and their configurations
- Vault access policies
- Vault notifications
- Inventory retrieval configs

**Worksheets:**
- Vaults
- Access Policies
- Notifications
- Summary

**Key APIs:**
- `glacier.list_vaults()`
- `glacier.get_vault_access_policy()`
- `glacier.get_vault_notifications()`

**Multi-Region:** Yes (regional service)

---

#### 8. Verified Permissions Export
**Service:** Amazon Verified Permissions
**Category:** Security & Identity
**Effort:** 1.5 hours

**Resources to Export:**
- Policy stores
- Policies (Cedar language)
- Schemas
- Identity sources

**Worksheets:**
- Policy Stores
- Policies
- Schemas
- Identity Sources
- Summary

**Key APIs:**
- `verifiedpermissions.list_policy_stores()`
- `verifiedpermissions.list_policies()`
- `verifiedpermissions.get_schema()`

**Multi-Region:** Yes (regional service)

---

## Implementation Standards

### Required Patterns (All Scripts)
- ✅ Multi-partition support from day one
- ✅ Use `utils.get_partition_default_region()` for global services
- ✅ Use `scan_regions_concurrent()` for regional services
- ✅ @aws_error_handler decorators for all collection functions
- ✅ Progress tracking for long operations
- ✅ Multi-worksheet Excel output with Summary sheet
- ✅ Standardized file naming: `{account}-{service}-export-{date}.xlsx`
- ✅ Full type hints
- ✅ Comprehensive docstrings
- ✅ Cost estimates where applicable

### Script Template
```python
#!/usr/bin/env python3
"""
Export {Service Name} resources from AWS account.

Multi-partition compatible (AWS Commercial + GovCloud).
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
import pandas as pd

# Import utils
try:
    import utils
except ImportError:
    script_dir = Path(__file__).parent.absolute()
    if script_dir.name.lower() == 'scripts':
        sys.path.append(str(script_dir.parent))
    else:
        sys.path.append(str(script_dir))
    import utils

# Script metadata
SCRIPT_NAME = "{service}-export"

# Set up logging
utils.setup_logging(SCRIPT_NAME)

@utils.aws_error_handler("Collecting {resource} data", default_return=[])
def collect_{resource}_data(region: str) -> List[Dict[str, Any]]:
    """Collect {resource} data from specified region."""
    client = utils.get_boto3_client('{service}', region_name=region)
    # Implementation
    pass

def main():
    """Main execution function."""
    # Check dependencies
    utils.check_required_packages(['boto3', 'pandas', 'openpyxl'])

    # Get account info
    account_id, account_name = utils.get_account_info()

    # Region selection
    # ...

    # Collect data
    # ...

    # Export to Excel
    # ...

if __name__ == "__main__":
    main()
```

## Progress Tracking

Track completion in kanban board:
- Move from Backlog → To Do when starting
- Move to In Progress during implementation
- Move to Done when completed and tested

## Testing Requirements

For each new script:
- [ ] Compilation test: `python3 -m py_compile scripts/{service}-export.py`
- [ ] Partition test: Verify partition detection works
- [ ] Multi-region test: Test with `all` regions option
- [ ] Error handling test: Verify graceful failure with no resources
- [ ] Export test: Verify Excel file generation
- [ ] Integration test: Add to stratusscan.py menu

## Menu Integration

Each new script must be added to `stratusscan.py` in the appropriate category:
1. Determine category (Compute, Network, Storage, etc.)
2. Add menu entry with description
3. Update menu option numbers
4. Test menu navigation

## Success Criteria

- [ ] All 8 services implemented
- [ ] All scripts follow implementation standards
- [ ] All scripts added to main menu
- [ ] Total script count: 119 (111 current + 8 new)
- [ ] Service coverage: ~99% of useful AWS services
- [ ] All scripts tested and validated
- [ ] Documentation updated (README.md, CHANGELOG.md)

## Timeline

**Estimated Total:** 8-12 hours

**Suggested Schedule:**
- Batch 1 (Communication & Analytics): 3.5 hours
- Batch 2 (Enterprise & Network): 4 hours
- Batch 3 (Storage & Security): 2.5 hours
- Testing & Integration: 2 hours

## Dependencies

- Multi-Partition Compliance Audit should be completed first (ensures pattern consistency)
- Python 3.9+ environment
- AWS credentials with read access to target services
- Existing utils.py infrastructure

## Deliverables

1. **8 New Export Scripts:** One for each service
2. **Menu Updates:** All scripts integrated into stratusscan.py
3. **Documentation:** README and CHANGELOG updates
4. **Git Commit:** Comprehensive commit with all changes
5. **Testing Results:** Validation that all scripts work correctly

## Related Documents

- `.collab/kanban-board.md` - Task tracking
- `CLAUDE.md` - Implementation patterns and standards
- `CONTRIBUTING.md` - Script development guidelines
- `README.md` - Service coverage documentation

## Notes

- These are the final service exporters before Phase 5
- Focus shifts to cross-cutting features after completion
- Each script should be production-ready on first implementation
- Consider batch implementation (3-4 scripts at a time) for efficiency

# Task Manager - StratusScan-CLI
---

**Last Updated:** December 1, 2025
**Current Focus:** Multi-Partition Compliance Audit & Final Service Coverage

---

## Backlog

### Service Coverage - Final 8 Services (Batch 1-3)
- [ ] **SES/Pinpoint Export** - Email campaigns, bounces, complaints, sending quotas
- [ ] **Cloud Map Export** - Service discovery namespaces, services, instances, health checks
- [ ] **X-Ray Export** - Tracing configuration, sampling rules, groups, encryption config
- [ ] **Connect Export** - Contact center instances, hours of operation, queues, routing profiles
- [ ] **Network Manager Export** - Global networks, devices, links, sites, connections
- [ ] **Marketplace Subscriptions Export** - Active subscriptions, licenses, usage tracking
- [ ] **Glacier Vaults Export** - Direct vault access, policies, notifications, inventory
- [ ] **Verified Permissions Export** - Policy stores, policies, schemas (Cedar language)

### Phase 5: Cross-Cutting Features
- [ ] Resource dependency mapping (graph infrastructure)
- [ ] Enhanced cost attribution by tag/resource/project
- [ ] Trend analysis (compare exports over time)
- [ ] Security posture scoring
- [ ] Executive summary dashboards
- [ ] Cross-account aggregation reports
- [ ] Tag-based filtering across all exports

### Low-Priority Performance Optimizations
- [ ] Additional ~20 medium-priority scripts need concurrent scanning upgrade
- [ ] acm-export.py, api-gateway-export.py, cognito-export.py
- [ ] dynamodb-export.py, ecr-export.py, efs-export.py
- [ ] elasticache-export.py, kms-export.py, opensearch-export.py
- [ ] redshift-export.py, secrets-manager-export.py, transit-gateway-export.py
- [ ] vpn-export.py, services-in-use-export.py
- [ ] apprunner-export.py, appsync-export.py, directconnect-export.py
- [ ] glue-athena-export.py, lakeformation-export.py, sagemaker-export.py
- [ ] security-hub-export.py, verifiedaccess-export.py, iam-rolesanywhere-export.py
- [ ] acm-privateca-export.py

### Maintenance & Documentation
- [ ] Comprehensive user guide
- [ ] API documentation for utils.py
- [ ] Video tutorials for common use cases
- [ ] Update README with current service count (111 scripts, 105+ services)
- [ ] Automated testing framework expansion
- [ ] Periodic review of duplicate/legacy files

---

## To Do

### HIGH PRIORITY: Multi-Partition Compliance Audit
- [ ] **Audit all 111 export scripts for hardcoded regions** (est. 4-6 hours)
  - Search for hardcoded `us-east-1`, `us-west-2`, etc.
  - Identify global services vs regional services
  - Replace hardcoded regions with `utils.get_partition_default_region()`
  - Create `.collab/.audit/partition-compliance-audit.md` tracker
  - Test compilation after each batch of fixes
  - Validate in GovCloud environment (if available)

### MEDIUM PRIORITY: Resource Dependency Mapping
- [ ] Define requirements and scope (user input needed)
- [ ] Design dependency graph infrastructure
- [ ] Plan implementation approach

---

## In Progress

*No tasks currently in progress*

---

## Blocked

*No blocked tasks at this time*

---

## In Review

*No tasks currently in review*

---

## Done

### Recent Session (December 1, 2025)
- [x] Root directory cleanup - removed obsolete files
- [x] Removed `RELEASE_NOTES_v3.0.0.md` (obsolete)
- [x] Removed `ref-docs` symlink (no longer needed)
- [x] Moved `govcloud-service-analysis.json` to `.collab/reference/`
- [x] Updated kanban board with current tasks

### Project Infrastructure (2025)
- [x] Multi-partition support (Commercial + GovCloud) - Phase 4A complete
- [x] Performance optimization - Phase 4B complete (24 scripts, 82 functions)
- [x] IAM permissions policies (Commercial + GovCloud, required + optional)
- [x] Testing infrastructure (75+ tests, 40-50% coverage)
- [x] Modern Python packaging (pyproject.toml, PEP 621)
- [x] CI/CD pipeline (GitHub Actions, Python 3.9-3.12)
- [x] Pre-commit hooks (Black, Ruff, Bandit, Mypy)
- [x] Progress checkpointing for long operations
- [x] Cost estimation (RDS, S3, NAT Gateway, EC2)
- [x] Dry-run validation

### Service Coverage (97 services implemented)
- [x] Phase 1: Foundation (EC2, RDS, EKS, ECS, S3, EBS, VPC, IAM)
- [x] Phase 2: Security & Operations (GuardDuty, WAF, CloudTrail, Config, etc.)
- [x] Phase 3: Advanced Services (DynamoDB, ElastiCache, DocumentDB, Neptune, etc.)
- [x] Phase 4: Specialized Services (Route 53, VPN, Direct Connect, Shield, etc.)

---

## Progress Metrics

### Service Coverage
- **Total Services Implemented:** 97
- **Total Scripts:** 111 (97 individual + 4 combined + 10 specialized)
- **Coverage:** ~92% of useful AWS services
- **Target:** Reach ~99% coverage (105 services)
- **Remaining:** 8 useful services

### Code Quality
- **Error Handling:** @aws_error_handler decorator in all scripts
- **Type Hints:** Full coverage in new scripts
- **Partition Support:** 100% (all scripts work in Commercial & GovCloud)
- **Testing:** 75+ automated tests, 40-50% coverage
- **Performance:** 4x-10x improvement with concurrent scanning (24 scripts optimized)

---

## Notes

### Current Sprint Focus
- **Multi-Partition Compliance Audit** is the highest priority task
  - Ensures all 111 scripts work correctly in both Commercial and GovCloud
  - Critical for government/regulated customers
  - Some scripts may have been created before multi-partition design was established

### Next After Audit
- Complete final 8 service exporters (SES/Pinpoint, Cloud Map, X-Ray, etc.)
- Begin Phase 5 cross-cutting features (resource dependency mapping first)

### Decisions to Make
- Resource dependency mapping requirements (awaiting user input)
- Timeline for final service coverage completion
- Priority order for Phase 5 features

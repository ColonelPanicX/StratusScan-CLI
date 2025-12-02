# Multi-Partition Compliance Audit

**Status:** Not Started
**Priority:** HIGH
**Owner:** Claude
**Estimated Effort:** 4-6 hours
**Created:** 12.01.2025
**Target Completion:** TBD

---

## Overview

Comprehensive audit of all 111 export scripts to identify and fix hardcoded AWS regions that would break in AWS GovCloud environments. Ensures 100% multi-partition compatibility across the entire codebase.

## Background

During November 2025 sessions, several newly created scripts (Control Tower, Marketplace, Network Manager) were found to have hardcoded regions (`us-east-1`, `us-west-2`) that would fail in AWS GovCloud environments. These were caught and fixed, but the codebase has 111+ scripts that may have similar issues from before the multi-partition design pattern was fully established.

The multi-partition design was implemented in Phase 4A (November 2025), but not all scripts were created after that date. Scripts created earlier may still contain hardcoded Commercial regions.

## Problem Statement

**Issue:** Hardcoded AWS Commercial regions prevent scripts from working in GovCloud
**Impact:** Government and regulated customers cannot use affected scripts
**Root Cause:** Scripts created before multi-partition design pattern was established

## Goals

1. **Identify** all scripts with hardcoded AWS regions
2. **Categorize** services as global vs regional
3. **Fix** hardcoded regions using partition-aware utilities
4. **Validate** compilation and functionality after fixes
5. **Document** the audit process and results
6. **Test** in GovCloud environment (if available)

## Detection Strategy

### Search Patterns

```bash
# Search for hardcoded Commercial regions
grep -r "region_name=['\"]us-" scripts/*.py

# Look for specific hardcoded patterns
grep -r "region_name='us-east-1'" scripts/
grep -r "region_name='us-west-2'" scripts/
grep -r "region_name=\"us-east-1\"" scripts/
grep -r "region_name=\"us-west-2\"" scripts/

# Also check for other Commercial regions
grep -r "region_name='eu-" scripts/
grep -r "region_name='ap-" scripts/
```

### Services Likely Affected

**Global Services (need partition-aware home region):**
- IAM Identity Center scripts (known to use `us-west-2`)
- Global Accelerator (uses `us-west-2`)
- CloudFront (global service)
- Route 53 (global service)
- Shield Advanced (global, uses `us-east-1`)
- AWS Health (global, uses `us-east-1`)
- Budgets (global service)
- Cost Explorer (global service)
- Organizations (global service)
- IAM (global service, but requires region parameter)

**Regional Services (should use region prompts):**
- All regional services should prompt user for region selection
- Should never have hardcoded regions

## Remediation Patterns

### For Global Services Requiring Explicit Region

**WRONG - Hardcoded region:**
```python
client = utils.get_boto3_client('service-name', region_name='us-east-1')
```

**CORRECT - Partition-aware:**
```python
home_region = utils.get_partition_default_region()
client = utils.get_boto3_client('service-name', region_name=home_region)
```

### For Truly Global Services

**CORRECT - No region parameter:**
```python
# Boto3 handles routing automatically for truly global services
client = utils.get_boto3_client('service-name')
```

### For Regional Services

**CORRECT - User prompt or config:**
```python
# Prompt user for region selection
region = input("Enter AWS region (or 'all' for all regions): ")
regions = utils.get_all_regions() if region == 'all' else [region]

for region in regions:
    client = utils.get_boto3_client('service-name', region_name=region)
```

## Implementation Plan

### Phase 1: Discovery (Est. 1 hour)
- [ ] Run grep patterns to identify all scripts with hardcoded regions
- [ ] Create comprehensive list of affected scripts
- [ ] Categorize scripts by service type (global vs regional)
- [ ] Document findings in progress tracker

### Phase 2: Analysis (Est. 1 hour)
- [ ] Review each affected script
- [ ] Determine correct remediation approach per script
- [ ] Identify any edge cases or special handling needed
- [ ] Prioritize fixes (critical services first)

### Phase 3: Remediation (Est. 2-3 hours)
- [ ] Fix scripts in batches of 10-15
- [ ] Replace hardcoded regions with partition-aware code
- [ ] Test compilation after each batch
- [ ] Document changes for each script

### Phase 4: Validation (Est. 1 hour)
- [ ] Compile all modified scripts
- [ ] Run smoke tests on critical scripts
- [ ] Test in GovCloud environment (if available)
- [ ] Update documentation and CHANGELOG

## Progress Tracking

Create and maintain: `.collab/.audit/partition-compliance-audit-progress.md`

**Tracking Format:**
```markdown
## Script Status

### Compliant (No changes needed)
- [x] script-name.py - Regional service with proper prompts
- [x] script-name.py - Global service using utils.get_partition_default_region()

### Fixed (Remediated)
- [x] script-name.py - Changed us-east-1 to get_partition_default_region()
- [x] script-name.py - Removed hardcoded us-west-2, using region prompt

### Pending Review
- [ ] script-name.py - Needs investigation
- [ ] script-name.py - Edge case handling required

### In Progress
- [ ] script-name.py - Currently being fixed

## Statistics
- Total Scripts: 111
- Compliant: X
- Fixed: Y
- Pending: Z
- In Progress: N
```

## Testing Strategy

### Compilation Testing
- [ ] Run `python3 -m py_compile` on each modified script
- [ ] Ensure no syntax errors introduced

### Functional Testing (if possible)
- [ ] Test critical scripts in AWS Commercial
- [ ] Test same scripts in AWS GovCloud (if available)
- [ ] Verify partition detection works correctly

### Regression Testing
- [ ] Ensure existing functionality not broken
- [ ] Verify multi-region scanning still works
- [ ] Check error handling still correct

## Success Criteria

- [ ] All 111 scripts audited and categorized
- [ ] All hardcoded regions replaced with partition-aware code
- [ ] 100% compilation success rate
- [ ] Documentation updated with changes
- [ ] Progress tracker completed
- [ ] GovCloud compatibility verified (if testable)

## Deliverables

1. **Progress Tracker:** `.collab/.audit/partition-compliance-audit-progress.md`
2. **Fixed Scripts:** All scripts with hardcoded regions corrected
3. **Git Commit:** Comprehensive commit documenting all changes
4. **Documentation:** Update CHANGELOG.md with fix details
5. **Validation Report:** Summary of testing and results

## Dependencies

- Access to StratusScan codebase
- Python 3.9+ environment for compilation testing
- (Optional) AWS GovCloud environment for testing
- (Optional) AWS Commercial environment for regression testing

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Breaking existing functionality | High | Test compilation after each batch, maintain git history |
| Missing edge cases | Medium | Thorough code review, test in multiple environments |
| GovCloud-specific API differences | Medium | Reference .collab/reference/govcloud-service-analysis.json, consult docs |
| Time overrun | Low | Work in batches, prioritize critical scripts first |

## Notes

- This is a one-time audit, but pattern should be enforced going forward
- Future scripts must use partition-aware patterns from the start
- Consider adding pre-commit hook to detect hardcoded regions
- Update CLAUDE.md and CONTRIBUTING.md with partition-aware requirements

## Related Documents

- `CLAUDE.md` - Contains multi-partition design patterns
- `.collab/reference/govcloud-service-analysis.json` - GovCloud service compatibility
- `.collab/kanban-board.md` - Task tracking
- `.collab/handoff-board.yaml` - Task assignment (HX-01)

# User Prompt Standardization Project Plan

**Status:** PLANNING
**Priority:** Medium-High (Quality Improvement)
**Estimated Effort:** 20-30 hours
**Target Version:** v3.3.0 or v4.0.0
**Created:** December 9, 2025

---

## Executive Summary

Standardize all user-facing prompts across 111+ export scripts to provide a consistent, professional, and error-resistant user experience. Currently, scripts use inconsistent prompt styles for region selection and other inputs, leading to potential user confusion and input errors.

### Current Problems
1. **Inconsistent region selection prompts:**
   - Some scripts: "Type 'all' for all regions or specify region name"
   - Some scripts: "1. Default regions, 2. All regions, 3. Specific region"
   - Some scripts: Hardcoded options with no clear guidance
   - Some scripts: Free-form text input with examples

2. **Varying input validation:**
   - Different error messages for invalid inputs
   - Inconsistent handling of case sensitivity
   - Some scripts retry, others fail immediately

3. **Mixed prompt formatting:**
   - Different visual styles (banners, plain text, separators)
   - Inconsistent use of colors/formatting
   - Varying levels of help text

### Proposed Solution

**Standardized Option-Based Prompts** across all scripts:
- Numbered menu options (1, 2, 3, etc.)
- Clear descriptions for each option
- Consistent error handling and retry logic
- Professional formatting with visual consistency
- Partition-aware region examples

---

## Goals & Success Criteria

### Primary Goals
1. ✅ **Consistency:** All scripts use identical prompt patterns
2. ✅ **Usability:** Clear, numbered options reduce user errors
3. ✅ **Professionalism:** Polished, production-grade UX
4. ✅ **Maintainability:** Centralized prompt utilities for easy updates

### Success Criteria
- [ ] All 111+ scripts use standardized prompt functions
- [ ] Zero free-form text inputs for region selection
- [ ] Consistent error messages across all scripts
- [ ] User testing confirms improved clarity
- [ ] Documentation reflects new prompt standards

---

## Scope

### In Scope
- **Region Selection Prompts** (highest priority)
  - Default regions vs. All regions vs. Specific region
  - Partition-aware region examples
  - Numbered menu presentation

- **Common User Inputs**
  - Yes/No confirmations
  - Multiple choice selections
  - Resource filtering options

- **Utils Functions**
  - Create centralized prompt utilities in utils.py
  - Reusable prompt templates
  - Input validation helpers

- **Documentation**
  - Update developer guide with prompt standards
  - Create examples for common patterns
  - Document utils prompt functions

### Out of Scope (for this project)
- Non-interactive CLI argument handling (already standardized)
- Error message standardization (separate initiative)
- Logging format changes
- Output formatting changes

---

## Design Specification

### Standard Region Selection Prompt

#### Visual Design
```
====================================================================
REGION SELECTION
====================================================================

Please select which AWS regions to scan:

1. Default Regions (recommended for most use cases)
   └─ us-east-1, us-west-1, us-west-2, eu-west-1

2. All Available Regions
   └─ Scans all 17 regions (slower, more comprehensive)

3. Specific Region
   └─ Choose a single region to scan

Enter your selection (1-3): _
```

**GovCloud Variant:**
```
====================================================================
REGION SELECTION
====================================================================

Please select which AWS regions to scan:

1. Default Regions (recommended for most use cases)
   └─ us-gov-west-1, us-gov-east-1

2. All Available Regions
   └─ Scans all 2 GovCloud regions

3. Specific Region
   └─ Choose a single region to scan

Enter your selection (1-3): _
```

#### After Option 3 Selection
```
====================================================================
AVAILABLE REGIONS
====================================================================

 1. us-east-1 (US East - N. Virginia)
 2. us-east-2 (US East - Ohio)
 3. us-west-1 (US West - N. California)
 4. us-west-2 (US West - Oregon)
 5. eu-west-1 (Europe - Ireland)
 6. eu-west-2 (Europe - London)
 7. eu-west-3 (Europe - Paris)
 8. eu-central-1 (Europe - Frankfurt)
 9. ap-northeast-1 (Asia Pacific - Tokyo)
10. ap-northeast-2 (Asia Pacific - Seoul)
11. ap-southeast-1 (Asia Pacific - Singapore)
12. ap-southeast-2 (Asia Pacific - Sydney)
13. ap-south-1 (Asia Pacific - Mumbai)
14. ca-central-1 (Canada - Central)
15. sa-east-1 (South America - São Paulo)
16. us-east-1 (US East - N. Virginia)
17. af-south-1 (Africa - Cape Town)

Enter region number (1-17): _
```

### Error Handling
```
Invalid input: 'abc'
Please enter a number between 1 and 3.

Enter your selection (1-3): _
```

### Confirmation Pattern
```
You selected: All Available Regions (17 regions)

This operation may take 10-15 minutes to complete.
Do you want to continue? (y/n): _
```

---

## Implementation Strategy

### Phase 1: Utils Infrastructure (3-4 hours)
**Goal:** Create reusable prompt utilities

**Tasks:**
1. Add `prompt_region_selection()` to utils.py
   - Returns: tuple (selection_type, region_list)
   - Handles: Default, All, Specific region flows
   - Partition-aware examples and region lists

2. Add `prompt_numbered_menu()` to utils.py
   - Generic numbered menu builder
   - Reusable for any multi-choice selection

3. Add `prompt_confirmation()` to utils.py
   - Standard yes/no with retry logic
   - Consistent formatting

4. Add `display_region_menu()` helper
   - Shows all available regions with numbers
   - Returns selected region name

5. Add input validation helpers
   - `validate_numeric_choice()`
   - `validate_yes_no()`
   - Consistent error messaging

**Deliverables:**
- Updated utils.py with 5 new prompt functions
- Docstrings and type hints for all functions
- Unit tests for prompt utilities

### Phase 2: High-Priority Scripts (8-10 hours)
**Goal:** Update scripts with most frequent user interaction

**Target Scripts (Priority Order):**
1. EC2, RDS, S3, Lambda, VPC (most commonly used)
2. Security-related: GuardDuty, CloudTrail, Config, WAF
3. Network: ELB, Route Tables, NACLs, Security Groups
4. Cost-related: Trusted Advisor, Budgets, Cost Explorer

**Pattern for Each Script:**
```python
# OLD CODE
print("Would you like the information for all AWS regions or a specific region?")
region_input = input("If all, write 'all', or specify a region name: ").strip()

# NEW CODE
from utils import prompt_region_selection

selection_type, regions = prompt_region_selection()

if selection_type == "all":
    target_region = None  # Scan all
elif selection_type == "default":
    target_region = None  # Use default list
else:  # specific
    target_region = regions[0]  # Single region selected
```

**Deliverables:**
- ~30 high-priority scripts updated
- All scripts compile and run successfully
- Consistent UX across core exporters

### Phase 3: Medium-Priority Scripts (6-8 hours)
**Goal:** Update remaining scripts with region selection

**Target Scripts:**
- Database services: DynamoDB, ElastiCache, DocumentDB, Neptune
- Container services: ECS, EKS, ECR, App Runner
- Analytics: Athena, Glue, Lake Formation
- Storage: EBS, EFS, FSx, Backup, Storage Gateway

**Deliverables:**
- ~40 medium-priority scripts updated
- 70% of codebase using standardized prompts

### Phase 4: Low-Priority Scripts (4-5 hours)
**Goal:** Complete remaining scripts

**Target Scripts:**
- Specialized services: X-Ray, AppSync, Verified Access
- Less-frequently-used: Cloud Map, Network Manager, SES/Pinpoint
- IAM-related: IAM Identity Center, Roles Anywhere

**Deliverables:**
- All 111+ scripts using standardized prompts
- 100% consistency across codebase

### Phase 5: Testing & Documentation (3-4 hours)
**Goal:** Validate changes and document standards

**Tasks:**
1. **Manual Testing:**
   - Test each prompt variation (default, all, specific)
   - Verify partition awareness (Commercial vs GovCloud)
   - Test error handling and retry logic
   - Confirm visual consistency

2. **Automated Testing:**
   - Add tests for new utils functions
   - Test input validation helpers
   - Mock user input scenarios

3. **Documentation:**
   - Update developer guide with prompt standards
   - Create examples for each prompt pattern
   - Document utils API reference
   - Update README with UX improvements

4. **User Acceptance:**
   - Gather feedback from test users
   - Iterate based on usability findings
   - Final polish and refinement

**Deliverables:**
- Test coverage for prompt utilities
- Updated documentation
- User acceptance sign-off

---

## Technical Specification

### New Utils Functions

#### `prompt_region_selection()`
```python
def prompt_region_selection(
    include_default: bool = True,
    include_all: bool = True,
    include_specific: bool = True,
    custom_message: Optional[str] = None
) -> Tuple[str, List[str]]:
    """
    Standard region selection prompt with numbered menu.

    Args:
        include_default: Show "Default Regions" option
        include_all: Show "All Regions" option
        include_specific: Show "Specific Region" option
        custom_message: Custom message to display above menu

    Returns:
        Tuple of (selection_type, region_list)
        - selection_type: "default", "all", or "specific"
        - region_list: List of region names to scan
    """
```

#### `prompt_numbered_menu()`
```python
def prompt_numbered_menu(
    title: str,
    options: List[Tuple[str, str]],
    allow_multiple: bool = False
) -> Union[int, List[int]]:
    """
    Display a numbered menu and get user selection.

    Args:
        title: Menu title/header
        options: List of (option_name, description) tuples
        allow_multiple: Allow selecting multiple options

    Returns:
        Selected option index (0-based) or list of indices
    """
```

#### `display_region_menu()`
```python
def display_region_menu(
    regions: Optional[List[str]] = None,
    include_descriptions: bool = True
) -> str:
    """
    Display all available regions as numbered menu.

    Args:
        regions: List of regions (uses partition regions if None)
        include_descriptions: Show region descriptions

    Returns:
        Selected region name
    """
```

#### `prompt_confirmation()`
```python
def prompt_confirmation(
    message: str,
    default: Optional[bool] = None,
    warning: Optional[str] = None
) -> bool:
    """
    Standard yes/no confirmation prompt.

    Args:
        message: Confirmation question
        default: Default answer if user hits Enter
        warning: Optional warning message to display

    Returns:
        True for yes, False for no
    """
```

#### Input Validation Helpers
```python
def validate_numeric_choice(
    value: str,
    min_value: int,
    max_value: int,
    error_message: Optional[str] = None
) -> Optional[int]:
    """Validate numeric input within range."""

def validate_yes_no(
    value: str,
    error_message: Optional[str] = None
) -> Optional[bool]:
    """Validate yes/no input (y/n, yes/no, true/false)."""
```

---

## Rollout Strategy

### Approach: Incremental Batched Updates

**Why Batched?**
- Easier to test and validate changes
- Can gather feedback between batches
- Reduces risk of introducing bugs across all scripts
- Allows iteration on design between batches

**Batch Schedule:**
1. **Batch 1: Utils + 5 Test Scripts** (Week 1)
   - Create all utils functions
   - Update 5 commonly-used scripts as pilots
   - User testing and feedback
   - Iterate on design if needed

2. **Batch 2: High-Priority (15 scripts)** (Week 2)
   - EC2, RDS, S3, Lambda, VPC, etc.
   - Most frequently used exporters

3. **Batch 3: High-Priority (15 scripts)** (Week 3)
   - Security, Network, Cost scripts

4. **Batch 4: Medium-Priority (20 scripts)** (Week 4)
   - Database, Container services

5. **Batch 5: Medium-Priority (20 scripts)** (Week 5)
   - Analytics, Storage services

6. **Batch 6: Low-Priority (remaining ~36 scripts)** (Week 6)
   - Specialized and less-used services

7. **Final Testing & Documentation** (Week 7)
   - Comprehensive testing
   - Documentation updates
   - User acceptance

---

## Risk Assessment

### High Risks
1. **Breaking Changes to User Workflows**
   - **Mitigation:** Extensive testing, gradual rollout
   - **Impact:** High - users depend on current behavior
   - **Probability:** Medium - good testing reduces risk

2. **Input Validation Edge Cases**
   - **Mitigation:** Comprehensive test coverage
   - **Impact:** Medium - could cause script failures
   - **Probability:** Medium - many input variations

### Medium Risks
1. **Partition-Specific Edge Cases**
   - **Mitigation:** Test in both Commercial and GovCloud
   - **Impact:** Medium - affects specific users
   - **Probability:** Low - partition code is well-tested

2. **Script-Specific Customization Needs**
   - **Mitigation:** Flexible utils functions with options
   - **Impact:** Low - only affects specific scripts
   - **Probability:** Medium - some scripts have unique needs

### Low Risks
1. **Performance Impact**
   - **Mitigation:** Minimal - prompts are not performance-critical
   - **Impact:** Very Low
   - **Probability:** Very Low

---

## Success Metrics

### Quantitative Metrics
- [ ] 111/111 scripts using standardized prompts (100%)
- [ ] Zero free-form region input prompts remaining
- [ ] 100% test coverage for new utils functions
- [ ] <5 minutes average time to complete standardization per script
- [ ] Zero regressions in existing functionality

### Qualitative Metrics
- [ ] User feedback: "Prompts are clear and easy to understand"
- [ ] User feedback: "Fewer input errors than before"
- [ ] Developer feedback: "Easy to implement in new scripts"
- [ ] Code review: "Consistent, professional UX"

---

## Dependencies

### Prerequisites
- ✅ All scripts use utils.py (already complete)
- ✅ Partition awareness is fully implemented (v3.1.1)
- ✅ Utils has standardized error handling (@aws_error_handler)

### Blockers
- None identified

### Nice-to-Have (Not Blocking)
- Integration with questionary library for advanced prompts
- CLI argument support for non-interactive mode (could be added later)

---

## Timeline Estimate

### Optimistic: 20 hours (4 weeks @ 5 hours/week)
- Utils creation: 3 hours
- Script updates: 14 hours (smooth, no issues)
- Testing: 2 hours
- Documentation: 1 hour

### Realistic: 25 hours (5 weeks @ 5 hours/week)
- Utils creation: 4 hours
- Script updates: 17 hours (some iterations needed)
- Testing: 3 hours
- Documentation: 1 hour

### Pessimistic: 30 hours (6 weeks @ 5 hours/week)
- Utils creation: 5 hours (multiple iterations)
- Script updates: 20 hours (edge cases, customizations)
- Testing: 3 hours
- Documentation: 2 hours

**Recommended Schedule:** 5-6 weeks @ 5 hours/week = 25-30 hours total

---

## Open Questions

1. **Should we use questionary library for enhanced prompts?**
   - Pros: Professional look, better UX, arrow key navigation
   - Cons: Additional dependency, requires terminal support
   - **Decision:** TBD based on user preference

2. **How much customization should scripts be allowed?**
   - Strict: All scripts must use utils exactly as-is
   - Flexible: Utils provide templates, scripts can customize
   - **Decision:** Flexible approach with strong guidelines

3. **Should we support both interactive and non-interactive modes?**
   - Some scripts already support `--region` CLI argument
   - Should all scripts have consistent CLI arg support?
   - **Decision:** Keep existing CLI args, standardize prompts for interactive mode

4. **Integration with Smart Scan?**
   - Should Smart Scan leverage standardized prompts?
   - Already uses questionary - should we align?
   - **Decision:** Keep Smart Scan as-is for now, consider alignment in future

---

## Resources Needed

### Development
- 1 developer (primary)
- 25-30 hours over 5-6 weeks
- Access to both AWS Commercial and GovCloud for testing

### Testing
- 1-2 test users for feedback
- 3-5 hours total testing time
- Both partition environments

### Documentation
- Technical writer (or developer doing docs)
- 2-3 hours for documentation updates

---

## Deliverables Checklist

### Code
- [ ] New utils.py prompt functions (5 functions)
- [ ] Updated scripts using standardized prompts (111+ scripts)
- [ ] Unit tests for utils prompt functions
- [ ] Integration tests for common scenarios

### Documentation
- [ ] Developer guide update (prompt standards section)
- [ ] Utils API reference (prompt functions)
- [ ] Examples and patterns guide
- [ ] README update (UX improvements section)

### Testing
- [ ] Test plan document
- [ ] Test results report
- [ ] User acceptance testing feedback

### Project Management
- [ ] Weekly progress updates
- [ ] Risk log and mitigation tracking
- [ ] Final completion report

---

## Next Steps

1. **Get user approval** for project plan and design
2. **Prioritize scheduling** - when to start this initiative?
3. **Decide on questionary integration** - yes or no?
4. **Create utils functions** - Phase 1 kickoff
5. **Select pilot scripts** - 5 scripts for Batch 1 testing

---

## Notes

### Design Rationale

**Why numbered menus instead of free-form text?**
- Reduces user errors (typing mistakes, case sensitivity)
- More professional and polished appearance
- Easier to validate inputs
- Better accessibility (screen readers)
- Consistent with industry standards (AWS CLI, other tools)

**Why partition-aware examples?**
- Users see relevant regions for their environment
- Reduces confusion about unavailable regions
- Aligns with StratusScan's multi-partition architecture

**Why centralized utils functions?**
- Single source of truth for prompt behavior
- Easier to maintain and update
- Ensures consistency across all scripts
- Facilitates future enhancements (e.g., questionary integration)

### Alternative Approaches Considered

1. **Free-form text with better validation**
   - Rejected: Still error-prone, less professional

2. **Questionary library for all scripts**
   - Deferred: Adds dependency, may not work in all environments

3. **Auto-detect region from AWS environment**
   - Rejected: Users often want multi-region scans

4. **CLI-only (no interactive prompts)**
   - Rejected: Many users prefer interactive mode for ad-hoc scans

---

**Status:** PLANNING - Awaiting user approval and scheduling
**Next Review:** After user feedback on this plan
**Owner:** TBD
**Last Updated:** December 9, 2025

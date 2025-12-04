# Smart Scan Feature - Project Plan

**Project ID:** SP-001
**Priority:** HIGH
**Type:** New Feature
**Estimated Effort:** 13-15 hours
**Target Version:** v3.2.0

---

## Overview

Add intelligent script recommendation and batch execution to StratusScan based on service discovery. After running `services-in-use-export.py`, users can optionally launch an interactive Smart Scan that analyzes detected services, recommends relevant scripts, and executes them in batch.

---

## Problem Statement

**Current Pain Points:**
1. Users don't know which of 111+ scripts to run in unknown environments
2. Running all scripts wastes time and creates noise
3. No guidance on which scripts are relevant
4. Manual execution of dozens of scripts is tedious
5. No consolidated batch execution capability

**User Story:**
> "As a security analyst dropping into a new AWS environment, I want StratusScan to automatically recommend which scripts to run based on the services actually in use, so I can efficiently gather detailed data without running 100+ scripts blindly."

---

## Solution Design

### High-Level Workflow

```
1. User runs services-in-use-export.py
   ↓
2. Service discovery completes (Excel file created)
   ↓
3. Prompt: "Generate recommended scripts checklist? (y/n)"
   ↓ (if yes)
4. Smart Scan analyzes services → builds recommendations
   ↓
5. Interactive menu: Quick Scan / Custom Selection / View Checklist / Save & Exit
   ↓ (based on selection)
6. Batch execution of selected scripts with progress tracking
   ↓
7. Summary report and return to main menu
```

### Integration Point

**Primary:** Integrated into `services-in-use-export.py` as optional post-discovery step

**Secondary:** Also accessible as standalone via main menu option "Smart Scan"

---

## Technical Architecture

### Component Structure

```
scripts/
├── services-in-use-export.py        (updated: add Smart Scan prompt)
├── smart_scan/                      (new package)
│   ├── __init__.py
│   ├── analyzer.py                  (service → script mapping engine)
│   ├── selector.py                  (interactive UI)
│   ├── executor.py                  (batch script runner)
│   └── mapping.py                   (service-script mapping data)
└── smart-scan.py                    (new: standalone entry point)

stratusscan.py                       (updated: add menu option)
pyproject.toml                       (updated: add questionary dependency)
```

### Core Modules

#### 1. **analyzer.py** - Service Analysis Engine
```python
def find_latest_services_export() -> Path:
    """Find most recent services-in-use Excel file."""

def parse_services_from_excel(excel_path: Path) -> List[str]:
    """Extract active services from Excel."""

def map_services_to_scripts(services: List[str]) -> Dict[str, List[Dict]]:
    """Map services to recommended scripts by category."""

def generate_recommendations(services: List[str]) -> Dict:
    """Generate full recommendation structure."""
```

#### 2. **selector.py** - Interactive UI
```python
def smart_scan_menu(recommendations: Dict) -> str:
    """Main Smart Scan selection menu."""
    # Options: Quick Scan, Custom Selection, View Checklist, Save & Exit

def quick_scan_mode(recommendations: Dict) -> List[str]:
    """Quick Scan: Run all recommended scripts."""

def custom_selection_mode(recommendations: Dict) -> List[str]:
    """Interactive category and script selection."""

def select_categories(recommendations: Dict) -> List[str]:
    """Checkbox selection of categories."""

def select_scripts_in_category(category: str, scripts: List) -> List[str]:
    """Checkbox selection of scripts within category."""
```

#### 3. **executor.py** - Batch Execution
```python
def execute_batch_scripts(scripts: List[str], region: str, account_name: str):
    """Execute multiple scripts sequentially with progress tracking."""

def run_single_script(script_path: Path, region: str) -> Dict:
    """Execute single script and return results."""

def generate_batch_summary(results: List[Dict]) -> str:
    """Generate summary report of batch execution."""
```

#### 4. **mapping.py** - Service-Script Mapping Data
```python
SERVICE_SCRIPT_MAP = {
    "ALWAYS_RUN": {...},  # Security scripts always recommended
    "EC2": {...},         # EC2-related scripts
    "S3": {...},          # S3-related scripts
    # ... 100+ service mappings
}

SERVICE_ALIASES = {
    "Amazon EC2": "EC2",
    "Elastic Compute Cloud": "EC2",
    # ... alias mappings
}
```

---

## Implementation Plan

### Phase 1: Core Infrastructure (3 hours)

**Tasks:**
- [ ] Create `smart_scan/` package structure
- [ ] Create `mapping.py` with service-script mappings
  - [ ] Map all 111 scripts to service names
  - [ ] Define "ALWAYS_RUN" security scripts
  - [ ] Add service aliases for name variations
  - [ ] Add category classifications
  - [ ] Add priority levels (critical/high/medium/low)
- [ ] Create `analyzer.py` module
  - [ ] `find_latest_services_export()` function
  - [ ] `parse_services_from_excel()` function
  - [ ] `map_services_to_scripts()` function
  - [ ] `generate_recommendations()` function
- [ ] Unit tests for analyzer functions

**Deliverables:**
- Service-script mapping complete
- Excel parsing working
- Service matching logic verified

---

### Phase 2: Interactive UI (4 hours)

**Tasks:**
- [ ] Add `questionary` to pyproject.toml dependencies
- [ ] Create `selector.py` module
- [ ] Implement main selection menu
  - [ ] Quick Scan option
  - [ ] Custom Selection option
  - [ ] View Detailed Checklist option
  - [ ] Save Checklist & Exit option
  - [ ] Cancel option
- [ ] Implement category selection (checkbox UI)
- [ ] Implement script selection within categories
- [ ] Add region selection prompt
- [ ] Add confirmation prompts
- [ ] Build checklist display formatter
- [ ] Build checklist text file generator
- [ ] Error handling for user cancellation

**Deliverables:**
- Interactive menus working
- Checkbox selections functional
- Text checklist generation working

---

### Phase 3: Batch Execution Engine (2 hours)

**Tasks:**
- [ ] Create `executor.py` module
- [ ] Implement `execute_batch_scripts()` function
  - [ ] Sequential script execution
  - [ ] Progress bar/counter display
  - [ ] Real-time output streaming
  - [ ] Error capture and logging
- [ ] Implement `run_single_script()` function
  - [ ] Subprocess management
  - [ ] Output capture
  - [ ] Timeout handling
  - [ ] Return code checking
- [ ] Implement `generate_batch_summary()` function
  - [ ] Success/failure counts
  - [ ] Total execution time
  - [ ] Resource counts (if parseable)
  - [ ] Failed scripts list
- [ ] Add graceful error recovery
- [ ] Add keyboard interrupt handling (Ctrl+C)

**Deliverables:**
- Batch execution working
- Progress tracking accurate
- Error handling robust
- Summary reports generated

---

### Phase 4: Integration (2 hours)

**Tasks:**
- [ ] Update `services-in-use-export.py`
  - [ ] Add Smart Scan prompt at end of export
  - [ ] Import smart_scan modules
  - [ ] Wire up Smart Scan flow
  - [ ] Handle user declining Smart Scan
- [ ] Create standalone `smart-scan.py` script
  - [ ] Entry point for menu access
  - [ ] Can run without prior services discovery
  - [ ] Auto-finds latest services export
  - [ ] Error if no services export exists
- [ ] Update `stratusscan.py` main menu
  - [ ] Add "Smart Scan (Recommended)" option
  - [ ] Position after Service Discovery
  - [ ] Add description text
- [ ] Update pyproject.toml
  - [ ] Add questionary dependency
  - [ ] Update version to v3.2.0-dev

**Deliverables:**
- Services-in-use integration complete
- Standalone script working
- Main menu updated
- Dependencies updated

---

### Phase 5: Polish & Documentation (2 hours)

**Tasks:**
- [ ] Add comprehensive docstrings
- [ ] Add type hints throughout
- [ ] Add logging statements
- [ ] Create error messages for edge cases
  - [ ] No services export found
  - [ ] Empty services export
  - [ ] Invalid Excel file
  - [ ] No services detected
- [ ] Test all user paths
  - [ ] Quick Scan path
  - [ ] Custom Selection path
  - [ ] View Checklist path
  - [ ] Save & Exit path
  - [ ] Cancel path
- [ ] Test edge cases
  - [ ] 0 services detected
  - [ ] 100+ services detected
  - [ ] Missing scripts
  - [ ] Script execution failures
- [ ] Update README.md
  - [ ] Add Smart Scan section
  - [ ] Update workflow diagrams
  - [ ] Add usage examples
- [ ] Create user documentation
  - [ ] How to use Smart Scan
  - [ ] Understanding recommendations
  - [ ] Customizing selections

**Deliverables:**
- All code documented
- Edge cases handled
- README updated
- User guide complete

---

## User Experience Flows

### Flow 1: Quick Scan (Fully Automated)

```
1. Run services-in-use-export.py
2. Prompt: "Generate recommended scripts? (y/n)" → y
3. Smart Scan analyzes services
4. User selects: "Quick Scan (Run all recommended)"
5. User enters region: "all"
6. Confirmation: "Run 47 scripts? (yes/no)" → yes
7. Batch execution begins (progress bar)
8. Summary report displayed
9. Return to main menu
```

**Time:** 5 minutes user interaction + 2-3 hours execution

---

### Flow 2: Custom Selection

```
1. Run services-in-use-export.py
2. Prompt: "Generate recommended scripts? (y/n)" → y
3. Smart Scan analyzes services
4. User selects: "Custom Selection"
5. Category selection (checkboxes):
   ☑ Security & Compliance
   ☑ Compute Resources
   ☐ Storage Resources
   ...
6. For each selected category, drill down to scripts
7. User adjusts script selections
8. User enters region: "us-east-1"
9. Confirmation: "Run 23 scripts? (yes/no)" → yes
10. Batch execution begins
11. Summary report displayed
12. Return to main menu
```

**Time:** 10-15 minutes user interaction + execution time

---

### Flow 3: Save Checklist for Later

```
1. Run services-in-use-export.py
2. Prompt: "Generate recommended scripts? (y/n)" → y
3. Smart Scan analyzes services
4. User selects: "Save Checklist & Exit"
5. Checklist saved to recommended-scripts-checklist.txt
6. User reviews file offline
7. Later: Manually run scripts via menu or CLI
```

**Time:** 2 minutes, no execution

---

### Flow 4: Standalone Smart Scan

```
1. User runs: python scripts/smart-scan.py
   (or via main menu option 2)
2. Smart Scan finds latest services export
3. Analyzes services automatically
4. Presents selection menu
5. User proceeds with Quick/Custom/Save
```

**Time:** Same as above flows

---

## Service-Script Mapping Strategy

### Mapping Categories

```python
# 1. ALWAYS_RUN - Security & Compliance (10 scripts)
"ALWAYS_RUN": {
    "iam-comprehensive-export.py",
    "cloudtrail-export.py",
    "config-export.py",
    "security-hub-export.py",
    "guardduty-export.py",
    "billing-export.py",
    "budgets-export.py",
    "trusted-advisor-cost-optimization-export.py",
    "organizations-export.py",
    "iam-identity-center-comprehensive-export.py"
}

# 2. One-to-One Mappings
"RDS": ["rds-export.py"]
"DynamoDB": ["dynamodb-export.py"]
"Lambda": ["lambda-export.py"]

# 3. One-to-Many Mappings
"EC2": [
    "ec2-export.py",
    "ami-export.py",
    "ebs-volumes-export.py",
    "ebs-snapshots-export.py",
    "autoscaling-export.py",
    "ec2-capacity-reservations-export.py",
    "ec2-dedicated-hosts-export.py"
]

# 4. Consolidated Reports (Optional)
"CONSOLIDATED": {
    "compute-resources.py": {
        "triggers": ["EC2", "Lambda", "ECS", "EKS"],
        "category": "Compute"
    },
    "storage-resources.py": {
        "triggers": ["S3", "EBS", "EFS", "FSx"],
        "category": "Storage"
    }
}
```

### Service Name Normalization

Handle variations in service names from AWS Cost Explorer:

```python
SERVICE_ALIASES = {
    # EC2 variations
    "Amazon EC2": "EC2",
    "Amazon Elastic Compute Cloud": "EC2",
    "EC2 - Other": "EC2",

    # S3 variations
    "Amazon S3": "S3",
    "Amazon Simple Storage Service": "S3",
    "S3 - Storage": "S3",

    # RDS variations
    "Amazon RDS": "RDS",
    "Amazon Relational Database Service": "RDS",
    "RDS - Database": "RDS",

    # ... 100+ aliases
}
```

---

## Data Structures

### Recommendation Object

```python
{
    "metadata": {
        "account_id": "123456789012",
        "account_name": "my-production-account",
        "analysis_date": "2025-12-04T14:32:15",
        "source_file": "my-account-services-in-use-export-12.04.2025.xlsx",
        "total_services": 23,
        "total_scripts": 47
    },
    "categories": {
        "security": {
            "name": "Security & Compliance",
            "always_run": True,
            "scripts": [
                {
                    "file": "iam-comprehensive-export.py",
                    "description": "All IAM resources",
                    "priority": "critical",
                    "triggered_by": None  # Always run
                },
                # ... more scripts
            ]
        },
        "compute": {
            "name": "Compute Resources",
            "always_run": False,
            "scripts": [
                {
                    "file": "ec2-export.py",
                    "description": "EC2 instances",
                    "priority": "high",
                    "triggered_by": ["EC2"]
                },
                # ... more scripts
            ]
        },
        # ... more categories
    }
}
```

---

## Dependencies

### New Dependencies

```toml
[project.dependencies]
# Existing
boto3 = ">=1.34.0"
pandas = ">=2.0.0"
openpyxl = ">=3.1.0"

# New for Smart Scan
questionary = ">=2.0.0"  # Interactive CLI prompts
```

### Testing Dependencies

```toml
[project.optional-dependencies]
dev = [
    # Existing
    "pytest>=7.4.0",
    "moto>=5.0.0",

    # New
    "pytest-mock>=3.12.0",  # For mocking questionary
]
```

---

## Testing Strategy

### Unit Tests

```python
# test_analyzer.py
def test_find_latest_services_export()
def test_parse_services_from_excel()
def test_map_services_to_scripts()
def test_service_aliases()
def test_empty_services()
def test_missing_excel_file()

# test_selector.py (mocked questionary)
def test_quick_scan_mode()
def test_custom_selection_mode()
def test_save_checklist()

# test_executor.py
def test_execute_single_script()
def test_batch_execution()
def test_error_handling()
def test_keyboard_interrupt()
```

### Integration Tests

```python
# test_smart_scan_integration.py
def test_end_to_end_quick_scan()
def test_end_to_end_custom_selection()
def test_services_in_use_integration()
def test_standalone_smart_scan()
```

### Manual Testing Checklist

- [ ] Run with 0 services detected
- [ ] Run with 10 services detected
- [ ] Run with 50+ services detected
- [ ] Test all selection paths
- [ ] Test keyboard interrupt during execution
- [ ] Test with missing services export
- [ ] Test with corrupted Excel file
- [ ] Test script execution failures
- [ ] Test in both Commercial and GovCloud

---

## Success Criteria

### MVP (Minimum Viable Product)

- [x] Service discovery completes
- [x] Smart Scan prompt appears
- [x] Services mapped to scripts correctly
- [x] Quick Scan executes all recommended scripts
- [x] Progress tracking works
- [x] Summary report generated
- [x] Integration with main menu works

### Full Feature

- [x] All MVP criteria
- [x] Custom selection with checkboxes
- [x] Category and script drill-down
- [x] Save checklist to file
- [x] Standalone smart-scan.py works
- [x] Error handling comprehensive
- [x] Documentation complete

---

## Risks & Mitigation

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Questionary dependency issues | Medium | Low | Fallback to basic input() if import fails |
| Service name variations | High | Medium | Comprehensive alias mapping + fuzzy matching |
| Script execution failures | Medium | Medium | Robust error handling + continue on failure |
| Long execution times | Low | High | Progress tracking + ability to cancel |
| Excel parsing errors | High | Low | Validation + graceful error messages |

---

## Future Enhancements (Post-MVP)

### v3.3.0+ Potential Features

1. **Parallel Script Execution**
   - Run scripts concurrently for faster completion
   - Configurable concurrency limit

2. **Smart Region Selection**
   - Analyze service discovery per region
   - Only scan regions with active services

3. **Saved Configurations**
   - Save selection preferences
   - Reuse for similar environments

4. **CLI Automation Flags**
   - `--auto-scan` for fully automated runs
   - `--quick-scan` for non-interactive Quick Scan
   - `--categories compute,storage` for targeted scans

5. **Result Aggregation**
   - Consolidate outputs into single workbook
   - Cross-referencing between exports

6. **Cost Estimation Preview**
   - Show estimated API call costs before execution
   - Warn for expensive operations

---

## Timeline

**Optimistic:** 13 hours (single focused session)
**Realistic:** 15 hours (2-3 development sessions)
**Pessimistic:** 18 hours (with testing edge cases)

**Recommended Approach:**
- Session 1 (4 hours): Phase 1 + Phase 2 (Infrastructure + UI)
- Session 2 (4 hours): Phase 3 + Phase 4 (Execution + Integration)
- Session 3 (3 hours): Phase 5 (Polish + Testing + Documentation)

---

## Acceptance Criteria

### User Acceptance

- [ ] User can discover services and launch Smart Scan seamlessly
- [ ] Recommendations make sense based on services detected
- [ ] Selection interface is intuitive and easy to use
- [ ] Batch execution completes without errors
- [ ] Summary provides useful information
- [ ] User can save checklist for later review

### Technical Acceptance

- [ ] All unit tests pass
- [ ] Integration tests pass
- [ ] Code coverage >70%
- [ ] Type hints throughout
- [ ] Docstrings complete
- [ ] No hardcoded values
- [ ] Partition-aware (Commercial + GovCloud)
- [ ] Error handling comprehensive
- [ ] Logging implemented

### Documentation Acceptance

- [ ] README updated with Smart Scan workflow
- [ ] Docstrings in all functions
- [ ] User guide created
- [ ] Code comments for complex logic
- [ ] Project plan complete

---

## Sign-Off

**Feature Owner:** Claude Code CLI
**Technical Reviewer:** TBD
**User Acceptance:** TBD

**Status:** PLANNING
**Next Step:** Begin Phase 1 implementation

---

**Last Updated:** December 4, 2025
**Document Version:** 1.0
**Project Plan ID:** SP-001

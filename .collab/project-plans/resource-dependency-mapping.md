# Resource Dependency Mapping

**Status:** Requirements Gathering
**Priority:** MEDIUM
**Owner:** Codex (requirements), Claude (implementation)
**Estimated Effort:** TBD
**Created:** 12.01.2025
**Target Completion:** TBD

---

## Overview

Build infrastructure to map and visualize dependencies between AWS resources across all StratusScan exports. This will help users understand "what depends on what" in their AWS environment.

## Background

User mentioned wanting resource dependency mapping as a next major feature. This would be part of Phase 5: Cross-Cutting Features and would build on top of the existing 97+ service exporters.

## Problem Statement

**Need:** Users need to understand resource dependencies in their AWS environment
**Current Gap:** StratusScan exports resources but doesn't show relationships
**Benefit:** Dependency mapping enables impact analysis, migration planning, and compliance validation

## Goals (DRAFT - Pending User Input)

1. Map dependencies between AWS resources
2. Visualize dependency graphs
3. Enable impact analysis ("what breaks if I delete this?")
4. Support migration planning
5. Identify orphaned resources
6. Show compliance boundaries

## Requirements (TBD - Awaiting User Input)

### Questions for User

1. **Scope:** What resource types should be included?
   - All 97+ services or subset?
   - Focus on critical infrastructure (VPC, EC2, RDS, etc.)?

2. **Output Format:** How should dependencies be presented?
   - Graph visualization (Graphviz, Mermaid)?
   - Excel workbook with dependency sheets?
   - JSON/YAML export for programmatic use?
   - Interactive HTML report?

3. **Use Cases:** What are the primary use cases?
   - Pre-deletion impact analysis?
   - Migration planning (what needs to move together)?
   - Security boundary validation?
   - Cost attribution by dependency chain?
   - Compliance reporting?

4. **Dependency Types:** What relationships should be tracked?
   - Direct dependencies (EC2 → Security Group)?
   - Indirect dependencies (Lambda → VPC → Subnet)?
   - Tag-based logical groupings?
   - IAM permission chains?

5. **Integration:** How should this integrate with existing exports?
   - Standalone dependency report?
   - Enhanced exports with dependency columns?
   - Separate analysis tool?

## Potential Implementation Approaches

### Approach 1: Graph Database
- Store resource relationships in graph structure
- Query with graph algorithms (shortest path, transitive dependencies)
- Export to visualization tools
- **Pros:** Powerful queries, standard graph algorithms
- **Cons:** Additional dependency (Neo4j, NetworkX), complexity

### Approach 2: Relational Model
- Store resources and relationships in normalized tables
- SQL queries for dependency chains
- Export to Excel/CSV
- **Pros:** Familiar tooling, easy exports
- **Cons:** Complex recursive queries for deep dependencies

### Approach 3: In-Memory Graph
- Build dependency graph from existing exports
- Use NetworkX for analysis
- Generate visualizations and reports
- **Pros:** No external database, works with existing exports
- **Cons:** Performance with large environments

### Approach 4: Hybrid
- Parse existing exports to build initial graph
- Enrich with targeted API calls for missing relationships
- Generate multiple output formats
- **Pros:** Flexible, leverages existing work
- **Cons:** More complex implementation

## Data Sources

### Existing StratusScan Exports
- VPC exports: Subnet → VPC → Route Table → Internet Gateway
- EC2 exports: Instance → Security Group → VPC → Subnet
- RDS exports: DB Instance → Subnet Group → VPC
- Lambda exports: Function → VPC → Subnet → Security Group
- IAM exports: Role → Policy → Service

### Additional AWS APIs (if needed)
- AWS Config: Resource relationship tracking
- AWS Resource Groups: Tag-based grouping
- CloudFormation: Stack resource dependencies
- IAM Access Analyzer: Permission dependencies

## Deliverables (Draft)

1. **Dependency Graph Data:** Resource relationship dataset
2. **Visualization:** Graph output (format TBD)
3. **Impact Analysis:** "What depends on this resource?" queries
4. **Orphan Detection:** Resources with no dependencies
5. **Documentation:** User guide for dependency mapping
6. **Integration:** Updates to relevant export scripts

## Technical Design (Placeholder)

### Data Model (Draft)
```python
class Resource:
    id: str              # ARN or unique identifier
    type: str            # EC2, VPC, RDS, etc.
    name: str            # Resource name/tag
    account: str         # AWS account ID
    region: str          # AWS region
    dependencies: List[str]  # List of dependent resource IDs
    metadata: dict       # Additional resource properties

class Dependency:
    source: str          # Source resource ID
    target: str          # Target resource ID
    type: str            # "direct", "indirect", "tag-based", etc.
    relationship: str    # "uses", "contains", "attached-to", etc.
```

### Graph Construction (Draft)
```python
def build_dependency_graph(exports: List[DataFrame]) -> Graph:
    """Build dependency graph from StratusScan exports"""
    pass

def find_dependencies(resource_id: str) -> List[Resource]:
    """Find all resources that depend on given resource"""
    pass

def find_dependents(resource_id: str) -> List[Resource]:
    """Find all resources this resource depends on"""
    pass

def detect_orphans() -> List[Resource]:
    """Find resources with no dependencies"""
    pass
```

## Next Steps

1. **User Requirements:** Gather detailed requirements from user
   - Schedule discussion to understand use cases
   - Define scope and priority
   - Determine output format preferences

2. **Design:** Create detailed technical design
   - Choose implementation approach
   - Define data model
   - Design output formats

3. **Prototype:** Build proof-of-concept
   - Test with subset of resources (VPC, EC2, RDS)
   - Validate approach and performance
   - Get user feedback

4. **Implementation:** Full build-out
   - Implement for all resource types
   - Add visualizations
   - Create documentation

5. **Testing:** Validate in real environments
   - Test with large AWS environments
   - Verify accuracy of dependency mapping
   - Performance testing

## Dependencies

- Completion of Multi-Partition Compliance Audit (optional, but recommended)
- User input on requirements and priorities
- Potential new Python dependencies (NetworkX, Graphviz, etc.)

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Unclear requirements | High | Thorough requirements gathering with user |
| Performance with large environments | Medium | Design for scalability, test early |
| Incomplete dependency detection | Medium | Iterative approach, expand coverage over time |
| Complex implementation | Medium | Start with MVP, add features incrementally |

## Success Criteria (Draft - Pending User Input)

- [ ] Requirements clearly defined and approved
- [ ] Technical design completed and reviewed
- [ ] Prototype demonstrates core functionality
- [ ] Full implementation completed
- [ ] Testing validates accuracy and performance
- [ ] Documentation enables users to leverage feature
- [ ] User feedback is positive

## Related Documents

- `.collab/kanban-board.md` - Task tracking
- `.collab/handoff-board.yaml` - Task assignment (HX-02)
- `CLAUDE.md` - Development patterns and standards
- `API_REFERENCE.md` - Utility functions and patterns

## Notes

- This is a **major Phase 5 feature** - will require significant design and implementation effort
- Should leverage existing export data where possible
- Consider making this extensible for future dependency types
- May want to create separate tool vs. integrating into main StratusScan

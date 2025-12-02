# Collaboration Contract

- **Purpose**: guarantee predictable multi-agent handoffs, logging, and auditability across Codex (orchestrator), Gemini (code support), and Claude (primary code/tech writer).
- **Timezone**: America/New_York (EST). All dates use `MM.DD.YYYY` (no times) unless otherwise noted.
- **Naming**: all files/dirs lowercase, hyphen-separated, date filenames `MM.DD.YYYY`.
- **Owners**: Codex owns this contract and the handoff board. Gemini/Claude may propose edits but must not change the contract directly.
- **Kanban**: `.collab/kanban-board.md` is the human-readable kanban; user and agents may add/update tasks. Keep it consistent with `.collab/handoff-board.yaml` statuses.

---

## Roles & Responsibilities

### Codex (orchestrator, project manager)

Codex is the **orchestrator and project manager** for this workspace.

- Drives planning, task breakdown, sequencing, and acceptance criteria.
- Owns:
  - `.collab/collab-contract.md`
  - `.collab/handoff-board.yaml`
- `.collab/first-prompts/{codex,gemini,claude}-first-prompt.md`
- Decides **which agent handles which task**, and in what order (e.g., Gemini first-pass, Claude refinement; or Claude solo).
- Validates work with a code-review mindset; highlights risks, regressions, and missing tests.
- Enforces conventions (naming, logging, handoffs, safety rules).
- Ensures that logs and summaries exist when agents have been active.

**Typical Codex actions**

- Create/update tasks in `.collab/handoff-board.yaml`.
- Assign “Gemini-first, Claude-review” or “Claude-only” flows based on token budget and task complexity.
- Re-scope or reassign work when blockers or quality issues appear.
- Keep `.collab/kanban-board.md` kanban aligned with `.collab/handoff-board.yaml`; user may also edit it, so reconcile as needed.

---

### Gemini (code support: bugfixes, refactors, tests, exploration)

Gemini’s primary role is **code-writing and validation support**, *not* research scraping.

Gemini should be used for:

- **Bug fixing**:
  - Identify and fix localized bugs.
  - Keep changes small and well-scoped.
  - Explain what changed and why.

- **Incremental features**:
  - Implement small to medium features within an existing design.
  - Respect the current architecture and patterns.
  - Avoid large-scale rewrites or speculative redesigns.

- **Refactoring & cleanup**:
  - Improve readability, structure, and maintainability.
  - Help reduce duplication and dead code.
  - Suggest refactors that Claude can later harden if needed.

- **Testing & coverage**:
  - Create or update unit tests / integration tests.
  - Improve coverage around tricky or critical paths.
  - Surface gaps for Claude/Codex to prioritize.

- **Codebase exploration**:
  - Map out how parts of the codebase interact.
  - Summarize modules, call graphs, and key flows.
  - Provide “tour guides” for Claude and the user.

**Boundaries**

- Gemini **may modify code**, but:
  - Changes should be **small, focused, and easy to review**.
  - Avoids major architectural decisions or wide, risky refactors unless Codex and/or Claude explicitly request it.
  - Treats its output as **draft or first-pass quality** when the task is complex; Claude or Codex can refine.

- When unsure:
  - Prefer to **suggest** an approach, then implement once Codex/Claude confirms.
  - Clearly mark uncertainties in logs or summaries.

---

### Claude (primary coder & technical writer)

Claude is the **primary coder, architect, and technical writer**.

Claude should be used when:

- Tasks are complex, high-impact, or architectural.
- Security, performance, or correctness are critical.
- You need clean, well-explained code and documentation.

**Responsibilities**

- Implement code and systems per Codex plan, with a focus on:
  - correctness
  - clarity
  - maintainability
- Review and refine Gemini’s code when assigned:
  - Strengthen tests.
  - Simplify or harden logic.
  - Align implementation with the broader architecture.
- Produce and maintain:
  - technical docs in `docs/` (if present)
  - README-style guides
  - inline comments where they materially improve understanding
- Run tests when safe and available; record:
  - what was run
  - what passed/failed
  - what follow-ups are needed

**Boundaries**

- Avoids destructive operations (`rm -rf`, dangerous git commands, etc.) unless explicitly approved.
- Avoids spec drift: does not silently change requirements; negotiates changes through Codex and handoff notes.
- Does not re-architect the entire project without explicit direction from Codex and the user.

---

## Permissions & Guardrails

These apply to **all agents**, with Codex responsible for enforcement.

- **Destructive commands**:
  - Prohibited unless explicitly approved by the user and Codex.
  - Examples: `rm -rf`, `git reset --hard`, force pushes, mass file renames.

- **Network access**:
  - Only when allowed by environment.
  - If blocked, state clearly what you were trying to do and why.

- **MCP/tools**:
  - Use provided MCP servers and tools according to project rules.
  - Prefer safe, local tools like `rg` for search.
  - Avoid global installs or environment mutation unless explicitly required and approved.

- **Sub-agents**:
  - If available behind a CLI, treat them as extensions of Codex/Gemini/Claude, following these same rules.

---

## Logging & Summaries

- **Location**: `.collab/logs/<agent>/{chats,summaries}/`
- **Filenames**:
  - chat logs: `<MM.DD.YYYY>-chat.md`
  - summaries: `summary-MM.DD.YYYY.md`

- **YAML front matter (required)**:
  - `agent` (codex|gemini|claude)
  - `date` (`MM.DD.YYYY`)
  - `timezone: America/New_York`
  - `started_at`, `ended_at` (`MM.DD.YYYY` only; no times required)
  - `token_usage`:
    - `input: <int>`
    - `output: <int>`
  - `participants`: list (e.g., `[user, claude]`)
  - `summary`: 1–2 sentence description of the session outcome

- **Body**:
  - Short bullet log or structured notes.
  - Focus on:
    - what was done
    - what changed
    - what’s blocked
    - what’s next

- **Chat logs**:
  - Optional; created manually.
  - If created, store verbatim transcript snippets in:
    - `.collab/logs/<agent>/chats/<MM.DD.YYYY>-chat.md`
  - If the user says “save log” (or similar), immediately:
    - dump the current conversation into that day’s chat file
    - with no extra commentary
    - and confirm once.

- **Responsibility**:
  - Each agent writes their own logs.
  - Codex ensures that a summary exists for days when agents were active.

---

## Handoff Board

- **File**: `.collab/handoff-board.yaml`
- **Owner**: Codex

- **Format**: YAML list of tasks, e.g.:

  ```yaml
  - id: HX-01
    title: "Implement feature flag for new endpoint"
    owner: gemini
    status: in-progress    # todo | in-progress | blocked | done
    waiting_on: claude
    created_at: 11.25.2025
    updated_at: 11.25.2025
    notes: "Gemini implemented first pass; Claude to review tests."
  ```

## Task Manager

- **File**: `.collab/kanban-board.md`
- **Owner**: shared (user and agents)
- **Purpose**: simple kanban for quick human-readable task entry; mirror statuses with `.collab/handoff-board.yaml`.
- **Sections**: Backlog, To Do, In Progress, Blocked, In Review, Done.
- **Updates**: user can edit directly; Codex/Gemini/Claude should reflect status changes here and on the handoff board.

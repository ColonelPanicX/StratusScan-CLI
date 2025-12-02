# Collaboration Workspace

Everything the AI agents need lives inside this `.collab/` directory.

## Quick Start
- Codex: read `collab-contract.md`, then create today’s Codex log and summary under `logs/codex/`.
- Gemini/Claude: read `collab-contract.md` and your first prompt under `.collab/first-prompts/`, then log work in `logs/<agent>/`.
- Create logs and summaries manually as needed under `.collab/logs/<agent>/` following the contract; no automatic logging is required.
- Handoff tracking lives in `handoff-board.yaml` (Codex-owned); kanban lives in `.collab/kanban-board.md` (user- and agent-editable).

## Conventions
- Timezone: America/New_York (EST); dates use `MM.DD.YYYY` (no times).
- Filenames with dates: `MM.DD.YYYY`; paths are lowercase and hyphen-separated.
- Avoid destructive commands unless explicitly approved.

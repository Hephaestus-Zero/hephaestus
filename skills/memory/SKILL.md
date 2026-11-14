---
name: hephaestus-memory
description: Standalone C11 + SQLite WAL/FTS5 cognitive memory with JTMS truth maintenance and token-bounded context recall (hmemory). Use to store durable architectural decisions, bugfix root causes, and project constraints while automatically retracting superseded beliefs.
---

# Hephaestus Organ: `memory`

Replace 5,000-line stale `MEMORY.md` dumps with atomic, truth-maintained beliefs in local SQLite WAL + FTS5:

## Core Commands

1. **Recall token-bounded active context (`<= 600` tokens, excludes retracted beliefs)**:
   ```bash
   hmemory context ["<focus_query>"] --budget-tokens 600
   ```
2. **Search beliefs with bilingual FTS5 stemming + recency/access activation**:
   ```bash
   hmemory query "<query>" [--limit 8] [--json]
   ```
3. **Record a durable decision, bugfix root cause, fact, or constraint**:
   ```bash
   hmemory ingest -t "<title>" -b "<body>" --kind decision [--tags "arch,db"] [--supersedes <old_id>]
   ```
4. **Maintain JTMS belief provenance (`supports`, `contradicts`, `supersedes`)**:
   ```bash
   hmemory link <new_id> supersedes <old_id>
   hmemory explain <id>
   ```

## Discipline

- Capture only durable architectural decisions, root causes, and constraints. Never dump raw chat transcripts or ephemeral scratch output into memory.

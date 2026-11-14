---
name: hephaestus-voice
description: Stateful anti-sycophancy posture and prose slop linter (hvoice). Use at session start to load concise engineering pushback rules and continuity notes, and before publishing docs, commits, or PR descriptions to strip AI filler and hollow praise.
---

# Hephaestus Organ: `voice`

Eliminate sycophantic helpdesk openers, corporate AI filler, and session-to-session style amnesia:

## Core Commands

1. **Initialize or switch active engineering posture (`peer-engineer`, `strict-reviewer`, `quiet-minimal`, `architect`)**:
   ```bash
   hvoice init --profile peer-engineer
   hvoice profiles
   ```
2. **Emit a `<160`-token session posture frame with continuity notes**:
   ```bash
   hvoice frame [--task "<current_focus>"]
   ```
3. **Lint prose, docs, or agent drafts against sycophancy and AI clichés**:
   ```bash
   hvoice lint <file> [--strict] [--json]
   hvoice lint --text "<draft>" [--strict] [--json]
   ```
4. **Record a compact working-style or continuity observation (bounded 12-note ring)**:
   ```bash
   hvoice note "<observation>"
   ```

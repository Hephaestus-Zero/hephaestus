---
name: hephaestus-shield
description: Zero-overhead C11 Landlock LSM process sandbox, repository trap auditor, Pickle VM opcode scanner, and shell command safety gate (hshield, hhook). Use before inspecting untrusted repositories, loading serialized artifacts, or running high-risk shell commands.
---

# Hephaestus Organ: `shield`

Contain untrusted code and block destructive shell traps before execution:

## Core Commands

1. **Audit an untrusted repository or directory for execution traps and malicious `.pkl` opcodes**:
   ```bash
   hshield audit <dir> [--json]
   ```
   Scans `.git/hooks`, `Makefile` / `setup.py` / `package.json` preinstall hooks, symlink escapes, and Pickle VM opcodes (`GLOBAL`, `STACK_GLOBAL`, `REDUCE`) without importing Python modules.

2. **Run untrusted tests or scripts inside a kernel Landlock LSM sandbox (Linux)**:
   ```bash
   hshield sandbox -- <cmd> [args...]
   hshield sandbox --net -- <cmd> [args...]
   ```

3. **Check shell commands against destructive redirections and substitution smuggling**:
   ```bash
   hhook check "<shell_command>"
   ```
   Parses shell quoting, command substitutions, fork bombs, `rm -rf` root/home wipes, and credential exfiltration pipes in C11. Also runs natively as a `PreToolUse` JSON stdin hook.

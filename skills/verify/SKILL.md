---
name: hephaestus-verify
description: Anti-reward-hacking test integrity verifier (hverify). Use before and after test-fixing loops to guarantee passing tests came from genuine code fixes rather than deleted test files, dropped assertions, or injected skip markers.
---

# Hephaestus Organ: `verify`

Prevent reward-hacking and silent test suite degradation during autonomous coding loops:

## Core Commands

1. **Capture an `O_NOFOLLOW` SHA-256 + assertion-count baseline before editing**:
   ```bash
   hverify snapshot [dir] [--out <manifest.json>] [--json]
   ```
2. **Verify test integrity against a baseline after making changes**:
   ```bash
   hverify check [dir] [--baseline <manifest.json>] [--json]
   ```
   Exits non-zero if test files were deleted, assertion counts decreased, new `@skip` / `.skip` markers appeared, or protected files changed.
3. **Single-shot snapshot + test execution + post-run tamper check**:
   ```bash
   hverify run [dir] [--json] -- <test_cmd...>
   ```

## Discipline

- Never claim a bugfix passed if assertions were weakened or skipped. Run `hverify run -- pytest` (or `cargo test` / `npm test` / `make test`) so exit code and test integrity are verified together.

---
name: hephaestus-slice
description: Sub-2ms C11 mmap trigram code indexer and structural AST symbol slicer (hslice, hfind, hsearch). Use instead of find/grep/cat whenever locating files, reading function or class definitions, zooming into stack trace lines, outlining large files, or tracing callers.
---

# Hephaestus Organ: `slice`

Replace multi-turn `find -> grep -> full-file read -> grep callers` loops with one deterministic sub-2ms C11 command:

## Core Commands

1. **Definition + all bounded callers in one call (`-94%` tokens)**:
   ```bash
   hslice -x <symbol> [dir]
   ```
2. **Exact function, class, or struct definition by name**:
   ```bash
   hslice <symbol>
   ```
3. **Stack-trace / error line zoom (returns enclosing function/class only)**:
   ```bash
   hslice <path/to/file>:<line>
   ```
4. **Structural file skeleton (signatures and line spans without body bloat)**:
   ```bash
   hslice -s <path/to/file>
   ```
5. **Zero-copy `mmap` trigram path, symbol, and regex lookups**:
   ```bash
   hfind <path_tokens...>
   hsearch <symbol_tokens...>
   hsearch -g "<regex>" [dir]
   ```
6. **Repository token-savings receipt**:
   ```bash
   hslice --audit [dir]
   ```

## Notes

- Automatically scopes its `262,144`-bucket `mmap` trigram index to the enclosing Git root or `$PWD`, refreshing lazily via `stat().st_mtime > built_epoch` with zero background daemons.
- Supports Python, C, C++, Rust, Go, TypeScript, JavaScript, and Java.

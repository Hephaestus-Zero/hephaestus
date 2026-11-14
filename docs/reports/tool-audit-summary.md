# Hephaestus Unified Tool Audit Summary (`v0.1.0`)

This synthesis consolidates the C11 systems audit ([audit-core-c.md](audit-core-c.md)) and the cognitive memory, verification, and stateful posture audit ([audit-mind-voice-verify.md](audit-mind-voice-verify.md)) conducted during the extraction of the five `hephaestus` organs (`slice`, `shield`, `verify`, `memory`, `voice`).

## 1. Unified Organ Architecture & Hardening Matrix

| Organ | Binaries | Implementation | Upstream Bottleneck Resolved | Portability & Security Hardening |
| :--- | :--- | :--- | :--- | :--- |
| **`slice`** | `hslice`, `hfind`, `hsearch` | ISO C11 (`libc` + optional `dlopen` Tree-Sitter) | Hardcoded host project roots, `/dev/shm`-only index assumptions, build-time `-ltree-sitter` dependency, and `-Wno-format-truncation` buffer masks | 5-tier cache resolver (`$HEPHAESTUS_CACHE_DIR` -> `/dev/shm` if writable -> XDG -> `~/.cache` -> `/tmp`), FNV-1a workspace scoping, runtime `dlopen` CST bridge with stateful C11 lexer fallback, `stat` nanosecond lazy index refresh, and `--audit [--json]` token receipt |
| **`shield`** | `hshield`, `hhook` | ISO C11 (`libc` + Linux Landlock ABI v1..v6) | Linux/x86_64 header coupling (`<linux/landlock.h>`, `.rip`/`.rsp`), substring-only Pickle checks, and host-coupled shell hook rules | `#ifdef __linux__` kernel sandbox (`PR_SET_NO_NEW_PRIVS`, TCP network isolation unless `--net`), cross-platform `.git/hooks` + `package.json`/`setup.py`/`Makefile` + symlink-escape auditor, zero-import C11 Pickle VM bytecode walker (Protocols 0..5 + `.pt`/`.pth` ZIP), and C11 shell redirection/substitution parser (`hhook check` + `PreToolUse`) |
| **`verify`** | `hverify` | Python 3 (stdlib only) | Container/`mutmut` runtime dependencies, naive regex assertion counters fooled by comments or `assert True`, and untracked manifest files dropped in Git trees | `O_NOFOLLOW` + `fstat` regular-file SHA-256 snapshotting, Python `ast` + comment-stripped polyglot test/assertion/skip counters, tautology & protected-harness detection (`conftest.py`, `pytest.ini`), and external baseline storage |
| **`memory`** | `hmemory` | ISO C11 (`-lsqlite3 -lm`) | C23/`-march=native`/`-lzstd`/`-lcrypto` build requirements, background daemon sockets, flat-file context bloat, and FTS5 deletion of retracted history | Portable ISO C11 single binary, defensive SQLite WAL + FTS5 (`TRUSTED_SCHEMA=0`), bilingual EN/TR ASCII-tolerant stemmer, fixed-point Doyle JTMS (`supports`, `contradicts`, `supersedes`), ACT-R decay, and CELF token-budgeted `<memory_context>` |
| **`voice`** | `hvoice` | Python 3 (stdlib only) | Personal/host state coupling, multi-thousand-line prompt bloat, and false-positive prose linting inside fenced code blocks | Clean-room `$HEPHAESTUS_HOME/voice/state.json` atomic persistence, 4 built-in engineering profiles + zero-dep YAML/JSON profile loader, `<160`-token `<voice_frame>`, 12-note ring buffer, and code-fence-safe deterministic anti-sycophancy linter |

## 2. Cross-Cutting Engineering Guarantees

1. **Compiler Cleanliness (`-Wall -Wextra`)**:
   - Upstream `hephaestus-core` suppressed 36 `-Wformat-truncation` diagnostics via `-Wno-format-truncation`, and upstream `zeromemory-v5` relied on `-std=c23 -march=native`.
   - Every C11 binary in `hephaestus` (`hslice`, `hfind`, `hshield`, `hhook`, `hmemory`) compiles cleanly under `cc -std=c11 -O3 -Wall -Wextra` on Linux and macOS without warning suppressions.

2. **Selective Spine ("One Roof, Selective Spine")**:
   - `bin/hephaestus` and `mcp/hephaestus_mcp.py` read `$HEPHAESTUS_HOME/config.json` (or `--organs o1,o2`) dynamically.
   - Disabling an organ (`hephaestus disable voice` or `./install.sh --only slice`) removes its tools from MCP `tools/list` immediately so agents pay zero schema or context overhead for unused capabilities.

3. **Host & Privacy Isolation**:
   - All five organs, unified CLI/MCP dispatchers, skill manifests, tests, and audit reports are verified free of personal identifiers, host-specific user paths, and Linux-only `/dev/shm` hard assumptions.
   - Setting `HEPHAESTUS_HOME` isolates configuration, SQLite belief storage, cache indices, verification manifests, and voice continuity notes inside one directory tree for reproducible CI and multi-tenant testing.

4. **Future Upstream Organ Candidates**:
   - `hrun.c` (non-hanging process-group supervisor) requires only a POSIX `pipe` + `FD_CLOEXEC` wrapper and 5-tier cache path swap to become 100% Linux/macOS portable.
   - `hctx.c`, `hrollback.c`, and `hpulse.c` have documented VFS/collector abstraction paths in [audit-core-c.md](audit-core-c.md) for subsequent releases (`APFS clonefile` / `Btrfs FICLONE`, `IOKit` / `procfs`).

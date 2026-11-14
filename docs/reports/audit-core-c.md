# C11 Systems Deep Technical Audit (`core-c`)

## 1. Scope & Methodology

This report documents the deep technical audit of the upstream `hephaestus-core/src/` C11 systems suite (`hslice.c`, `hfind.c`, `hshield.c`, `hhook.c`, `hrollback.c`, `hpulse.c`, `hctx.c`, `hrun.c`, plus the static Pickle/archive supply-chain gate in `horganize.c`) alongside standalone `hslice` `v0.2.0`, and records the portable C11 engineering applied to extract **Organ 1 (`organs/slice/`)** and **Organ 2 (`organs/shield/`)** for the unified `hephaestus` repository.

Each binary was evaluated across four axes:
1. **Path & Cache Portability**: Elimination of hardcoded host directories (`<user-home>/...`) and `/dev/shm`-only assumptions that fail on macOS and non-systemd POSIX hosts.
2. **Cross-Platform Linux + macOS Portability**: `#ifdef __linux__` and `#ifdef __APPLE__` guards around kernel-specific headers (`<linux/landlock.h>`, `<linux/btrfs.h>`, `<sys/prctl.h>`, `<sys/epoll.h>`, `<sys/fanotify.h>`, `<systemd/sd-journal.h>`), `/proc/self/exe`, `O_NOATIME`, `pipe2`, `st_mtim` vs `st_mtimespec`, and runtime `dlopen` boundaries.
3. **Strict Compiler Cleanliness**: Empirical compilation under `cc -std=c11 -O3 -Wall -Wextra` **without** `-Wno-format-truncation` (which masked 36 truncation diagnostics in the upstream `Makefile`).
4. **Memory Safety, Bounds, UTF-8, Exit Codes & CLI Hygiene**: Bounded formatting, integer overflow checks, UTF-8-preserving JSON escaping, deterministic exit codes (`0` ok, `1` runtime/check failure or no match, `2` usage error), and `--help` / `--version` / `--json` support.

---

## 2. Recent Upstream Commit & Architecture Delta Summary

Inspection of the 8 most recent upstream commits (`b6dc9df`, `e0d9b88`, `ba1ec0e`, `88bd9fc`, `0d4261f`, `2df07ab`, `95a8816`, `f5ca329`) and active working-tree C11 upgrades identified the following major architectural advances:

| Upstream Component | Size | Key Architectural Upgrades |
| :--- | ---: | :--- |
| `src/hslice.c` | 3,083 LOC | Hybrid 2-tier AST slicer: Tier 1 windowed Tree-Sitter CST (`ts_parser_parse` custom reader over anchored byte windows, ~0.06 ms) + Tier 2 v2 stateful lexer handling Rust lifetimes vs char literals, raw strings (`r#"..."#`, Go backticks, Python triple-quotes), TS template `${...}` expressions and regex literals `/.../`, C preprocessor continuations, and decorators. O(1) zero-staleness verification via `file_hash` + nanosecond `mtime_ns` with automatic single-file re-scan when dirty. Supports `-s` structural outline and `-x` body + bounded caller cross-references. |
| `hslice v0.2.0` | 1,480 LOC | Added `-A` / `--audit [dir]` token-savings receipt benchmarking full-file vs exact symbol-slice token budgets across a repository, workspace-root FNV-1a index scoping, and lazy `st_mtime > built_epoch` index refresh. |
| `src/hfind.c` | 3,357 LOC | v7 compact `DirRec` + `FileRec` interned string pool (~75% smaller mmap index), split directory + basename 3-gram inverted postings (eliminating directory-token false negatives), incremental directory-mtime reuse (~1.9 ms rebuilds), 4 ms live dirty-dir overlay + detached background compactor, deep C/C++/Python/TS/Rust/Go/Java/Bash stateful symbol extractor, and bounded `hsearch -g` global-limit wrapper. |
| `src/hshield.c` | 3,965 LOC | Commit `b6dc9df` replaced heuristic RWX/path-antibody triggers with `assess_wx_injection`: mechanistic VMA + execution-locus verification (`is_mechanistic_ffi_trampoline` validating `libffi` RIP-relative `jmp *disp32(%rip)` and `cffi` `movabs + jmp` thunks targeting file-backed `r-xp` VMAs, allocator-headed JIT pool checks, `/proc/<pid>/task/<tid>/syscall` + `PTRACE_SEIZE` RIP/RSP sampling, stack return-address `call` verification, task-scoped `SIGSTOP`/`SIGKILL` instead of process-group kills, `script_arg` populated strictly for real script interpreters, and SHA-256 content antibodies). Includes self-contained FIPS 180-4 SHA-256, NIST SP 800-38D AES-256-GCM quarantine encryption, Landlock LSM ABI v1..v6 (`LANDLOCK_SCOPE_SIGNAL`, `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, `LANDLOCK_ACCESS_FS_IOCTL_DEV`), and `hshield audit`. |
| `src/hhook.c` | 2,266 LOC | Sub-0.1 ms pure-C11 POSIX/Bash tokenizer and redirection/substitution parser (`scan_shell_segment`, `lex_shell_word`, `lex_dollar_construct`, `scan_backtick_subst`, `scan_arith_parens`, `consume_heredocs`). Tracks shell variable assignments, single/double/ANSI-C `$'...'` quotes, `[[ ... ]]` test expressions (never confusing `>` string comparison with file redirection), `2>&1` FD duplications, heredocs, `$(...)` and backtick substitutions, plus an exfiltration circuit-breaker (`secret_source + network_egress`) and `PreToolUse` JSON protocol handler. |
| `src/hrollback.c` | 2,310 LOC | Pure-C11 O(MutatedExtents) Btrfs `send --no-data --proto 1` binary TLV stream parser (`parse_btrfs_send_fd`) catching deletions, `rmdir`, renames, `chmod`/`chown`, and dangling symlinks, paired with an in-process `lstat` + `ioctl(FICLONE)` atomic CoW reflink undo engine and `guard --auto-undo` wrapper. |
| `src/hpulse.c` | 2,859 LOC | Commit `e0d9b88` implemented adaptive NVML handle release (`read_nvml`, `dgpu_runtime_suspended`) so `hpulse --daemon` never pins discrete GPUs in D0 when idle, allowing PCIe D3cold sleep. Combines single-pass `/proc` classification, RAPL power sampling, `pidfd_open` + `process_madvise(MADV_PAGEOUT)` cold-page compression (`htrim`) with J3 refault regret shielding, `timerfd` + `sd-journal` zero-polling loop, and `POSIX_FADV_WILLNEED` hot-binary preloading. |
| `src/hctx.c` | 403 LOC | Sub-0.5 ms situational reader combining cached SHM telemetry with a zero-fork `.git` / worktree `HEAD` + `packed-refs` SHA resolver (`probe_git_fast`). |
| `src/hrun.c` | 456 LOC | Non-hanging execution supervisor forcing `/dev/null` stdin, batch/non-interactive environment variables, isolated `setpgid(0, 0)` process-group reaping on wall-clock (`--timeout`) or silent-hang (`--idle`) deadlines, in-stream ANSI CSI/OSC + `\r` stripper, and head/tail ring-buffered output. |

---

## 3. Empirical Compiler Cleanliness Audit (`cc -std=c11 -O3 -Wall -Wextra`)

Upstream `hephaestus-core/Makefile` passed `-Wno-format-truncation`, concealing buffer-sizing mismatches under `-O3` interprocedural constant propagation. Compiling all 8 upstream sources without warning suppressions produced the following baseline:

| Source File | Warnings (`-Wall -Wextra`) | Root Cause of Diagnostics |
| :--- | ---: | :--- |
| `hslice.c` | 0 | Clean under `-Wall -Wextra`, but requires `-ltree-sitter` + `<tree_sitter/api.h>` at build time. |
| `hfind.c` | 2 | `-Wformat-truncation` in `scan_source_buffer`: `sym[160]` copied into `opened_class[96]`; `prev_ret_line[160]` + `p` formatted into `sig_buf[200]`. |
| `hshield.c` | 0 | Clean on Linux x86_64, but fails to compile on macOS/non-Linux or Linux aarch64 (`struct user_regs_struct` `.rip`/`.rsp` x86_64 register fields unguarded). |
| `hhook.c` | 10 | `-Wformat-truncation` in `var_table_set` (`resolved[1024]` -> `val[512]`), `evaluate_redirect_target` (`raw[512]` -> `why[384]`), `canonicalize_path_lexical` (`cwd[PATH_MAX]` + `raw` -> `expanded[PATH_MAX]`), and `probe_git_brief_fast`. |
| `hrollback.c` | 6 | `-Wformat-truncation` combining `PATH_MAX` snapshot roots with `/.snapshots/%d/snapshot` into `PATH_MAX` destination buffers. |
| `hpulse.c` | 13 | `-Wformat-truncation` combining `dirent.d_name[256]` with base paths into 256/512/640-byte stack buffers and `record_heal` formatting into `last_heal[160]`. |
| `hctx.c` | 5 | `-Wformat-truncation` in `probe_git_fast` (`dotgit`, `gitdir`, `commondir`, and `branch[128]` from `hbuf[256]`). |
| `hrun.c` | 0 | Clean under `-Wall -Wextra`, except `pipe2(..., O_CLOEXEC)` and hardcoded `/dev/shm/hrun-<pid>.log` break on macOS. |

---

## 4. Per-Tool Portability, Security & Hygiene Audit

### 4.1 `hslice.c` & `hfind.c` -> Extracted into `organs/slice/`

1. **Cache & Index Directory Resolution (macOS `/dev/shm` Absence)**:
   - *Finding*: Upstream `hslice.c` and `hfind.c` stored a single global `hsym.idx` / `hfind.idx` inside `$XDG_RUNTIME_DIR` or `/run/user/%u`, while `load_cortex_seat_cues` read `/dev/shm/hephaestus_cortex.json`. macOS has neither `/dev/shm` nor `/run/user/%u`, and a single global index causes cross-repository collisions when switching projects.
   - *Fix in `organs/slice`*: Implemented `hslice_resolve_cache_dir()` in `src/hslice_common.h` following the exact 5-tier hierarchy:
     1. `$HEPHAESTUS_CACHE_DIR` (or `$HSLICE_CACHE_DIR` compatibility alias)
     2. `/dev/shm/hephaestus-$UID` **only** when `/dev/shm` exists as a directory and `access("/dev/shm", W_OK | X_OK) == 0`
     3. `$XDG_CACHE_HOME/hephaestus`
     4. `$HOME/.cache/hephaestus`
     5. `/tmp/hephaestus-$UID`
     Index files are further scoped by the 64-bit FNV-1a hash of the canonicalized workspace roots (`hsym-<fnv1a64>.idx`, `hfind-<fnv1a64>.idx`).
2. **Elimination of Hardcoded Host Roots & Personal Biases**:
   - *Finding*: Upstream `hfind.c` hardcoded 14 host-specific subdirectories under `<user-home>` (`Desktop/...`, `memory/...`, `media-stack`, etc.), fell back to `<user-home>` when `$HOME` was unset, and boosted personal directory tiers in `path_activity_tier()`.
   - *Fix in `organs/slice`*: Stripped all host-specific paths, `load_cortex_seat_cues`, and `load_hot_projects_map`. Default root discovery uses `--root <dir>` -> `$HEPHAESTUS_ROOTS` -> `$HSLICE_ROOTS` -> nearest `.git` ancestor -> `getcwd()`.
3. **Zero-Dependency Runtime Tree-Sitter `dlopen` Bridge**:
   - *Finding*: Upstream `hslice.c` `#include <tree_sitter/api.h>` and linked `-ltree-sitter`, failing to compile on fresh developer laptops or CI runners without `libtree-sitter-dev`.
   - *Fix in `organs/slice`*: Embedded the minimal C11 Tree-Sitter ABI (`TSPoint`, `TSNode`, `TSInput`, function-pointer table) and `dlopen`ed `libtree-sitter.{so.0,so,dylib}` + grammar shared libraries across Linux and macOS (`/opt/homebrew/lib`, `/usr/local/lib`, `/usr/lib`) at runtime. `hslice` compiles with zero external header/library dependencies everywhere, runs 0.06 ms Tree-Sitter CST slicing when present, and falls back seamlessly to the v2 stateful lexer when absent.
4. **POSIX/macOS Syscall & Ripgrep Fallbacks**:
   - *Finding*: `st.st_mtim` fails on Darwin (`st.st_mtimespec`); `/proc/self/exe` fails on Darwin (`_NSGetExecutablePath`); `O_NOATIME` is Linux-only; `hslice -x` and `hsearch -g` failed if `rg` was not installed.
   - *Fix in `organs/slice`*: Added `stat_mtime_ns()` handling `#ifdef __APPLE__` `st_mtimespec`, `_NSGetExecutablePath` + `argv[0]` sibling resolution, `#ifdef O_NOATIME` guards, `grep -rnE` automatic fallback when `rg` is unavailable, and merged `v0.2.0`'s `-A` / `--audit [dir]` token-savings receipt with a new `--json` structured output mode.

### 4.2 `hshield.c` & `hhook.c` -> Extracted into `organs/shield/`

1. **Cross-Platform Linux + macOS `#ifdef __linux__` Architecture**:
   - *Finding*: Upstream `hshield.c` unconditionally included `<linux/landlock.h>`, `<linux/cn_proc.h>`, `<linux/netlink.h>`, `<sys/epoll.h>`, `<sys/fanotify.h>`, `<sys/inotify.h>`, `<sys/prctl.h>`, `<sys/ptrace.h>`, `<sys/timerfd.h>`, `<sys/user.h>`, and `<elf.h>`, plus x86_64-specific `regs.rip`/`regs.rsp` in `sample_stopped_tid_locus()`.
   - *Fix in `organs/shield`*: Guarded all Linux kernel/LSM/daemon subsystems under `#ifdef __linux__` and architecture-guarded register inspection (`#if defined(__x86_64__)` vs `#elif defined(__aarch64__)` `regs.pc`/`regs.sp`). On non-Linux platforms (`#ifndef __linux__`), `hshield audit`, `hshield status`, and the zero-import Pickle VM scanner run 100% natively, while `hshield sandbox` prints a clear capability note to `stderr` and exits fail-closed (`1`) when `--strict` is supplied (or executes cleanly in degraded mode when `--strict` is omitted).
2. **Configurable `$HEPHAESTUS_HOME` & Landlock Network Control (`--net`)**:
   - *Finding*: Upstream `hshield.c` hardcoded `USER_HOME`, `USER_UID = 1000`, `/etc/hephaestus`, `/var/lib/hephaestus`, `is_trusted_own_workspace()`, and `ZeroMemory` exceptions, and `hshield sandbox` lacked Landlock ABI v4 TCP network isolation (`--net`).
   - *Fix in `organs/shield`*: State, rules, and quarantine vaults resolve via `$HEPHAESTUS_HOME` (default `$HOME/.hephaestus`) and portable cache directories. On Linux kernels with Landlock ABI >= 4, `hshield sandbox` restricts `LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP` by default unless `--net` is explicitly granted, blocks sensitive `$HOME` credential stores (`.ssh`, `.aws`, `.gnupg`, `.kube`, `.docker`, `.netrc`, browser profiles, `.env`), grants read/write access to the working workspace (or `--allow-write <dir>`), and enforces `PR_SET_NO_NEW_PRIVS`.
3. **Expanded Cross-Platform Supply-Chain & Zero-Import Pickle VM Auditor (`hshield audit`)**:
   - *Finding*: Upstream `cmd_audit` checked `.mcp.json`, `.claude`, and prompt-injection strings, while the Pickle gate lived separately in `horganize.c` and used substring heuristics (`memmem` + `zlib`).
   - *Fix in `organs/shield`*: Unified a complete zero-dependency supply-chain auditor in `hshield audit [dir] [--json]`:
     - **Malicious `.git/hooks`**: Flags executable non-sample hooks inside `.git/hooks/` containing shell/network/eval execution payloads.
     - **Build & Package Lifecycle Traps**: Scans `package.json` (`preinstall`, `install`, `postinstall`, `prepare`), `setup.py`, `pyproject.toml`, and `Makefile` for curl/wget pipe-to-shell, reverse shells (`/dev/tcp/`), base64 droppers, and credential reads.
     - **Symlink Escapes**: Walks the repository with `lstat` (`O_NOFOLLOW`), resolving symlink targets via `realpath` / lexical canonicalization and flagging any link escaping outside the repository root or pointing at sensitive paths (`~/.ssh`, `/etc`, etc.).
     - **Agent Config & Trojan Source Traps**: Flags untrusted `.mcp.json`, hook overrides in `.claude/settings*.json`, hidden bidirectional/zero-width Unicode (`U+202A..U+202E`, `U+2066..U+2069`, `U+200B..U+200D`), and prompt-injection directives.
     - **Zero-Import Pickle VM Opcode Scanner**: Implements a pure-C11 Pickle bytecode VM walker across Protocols 0..5 (`PROTO`, `GLOBAL`, `INST`, `STACK_GLOBAL`, `REDUCE`, `OBJ`, `NEWOBJ`, `NEWOBJ_EX`, `EXT1`, `EXT2`, `EXT4`, tracking `SHORT_BINUNICODE` / `BINUNICODE` / `BINSTRING` / `SHORT_BINSTRING` / `UNICODE` / `PUT` / `BINPUT` / `MEMOIZE` / `BINGET` / `LONG_BINGET` stack operands) plus stored ZIP (`PK\x03\x04`) archive traversal for PyTorch `.pt`/`.pth` checkpoints (`data.pkl`) with zero Python imports and zero external libraries.
4. **Portable `hhook` Shell Command Safety Parser (`hhook check` + `PreToolUse`)**:
   - *Finding*: Upstream `hhook.c` focused on host-specific `claude-pre` / `agy-pre` acceleration into `/usr/local/bin/*` and hardcoded host paths, without a standalone `hhook check "<cmd>"` CLI mode or explicit destructive command / fork-bomb AST rules.
   - *Fix in `organs/shield`*: Hardened the C11 shell parser (`organs/shield/src/hhook.c`) to evaluate every simple command word vector, redirection target, subshell `(...)`, command substitution `$(...)` / `` `...` ``, process substitution `<(...)` / `>(...)`, unquoted heredoc expansion, and nested `sh -c` / `bash -c` / `eval` payload across:
     - Destructive filesystem commands (`rm -rf /`, `rm -rf ~`, `rm -rf /*`, `--no-preserve-root`, `mkfs.*`, `dd of=/dev/...`, `chmod -R 777 /`, `> /dev/sda`)
     - Shell fork bombs (`:(){ :|:& };:` and generalized self-piped recursive function definitions `fn(){ fn|fn& };fn`)
     - Credential read + network exfiltration (`~/.ssh`, `~/.aws`, `~/.gnupg`, `.env`, API tokens, `.netrc` paired with `curl`, `wget`, `nc`, `socat`, `dig`, `/dev/tcp/`, webhooks)
     - Dangerous output redirections (`/etc/...`, `/usr/...`, `~/.ssh/...`, `~/.bashrc`, path-traversal redirects) while accurately permitting quoted `echo "rm -rf / > /etc/passwd"`, `[[ $a > $b ]]`, `2>&1`, and `/dev/null`
     - Supports both `hhook check "<cmd>" [--json]` (exit `0` allow, exit `2`/`1` block with structured reason) and `PreToolUse` JSON stdin mode (`claude-pre`, `cursor-pre`, or default stdin hook mode).

### 4.3 Audit Findings for Remaining `hephaestus-core` Tools (Future Organ Candidates)

| Tool | Linux/Host Coupling Found | Recommended Portability Refactor |
| :--- | :--- | :--- |
| `hrollback.c` | Requires `<linux/btrfs.h>`, `BTRFS_IOC_SUBVOL_GETFLAGS`, `ioctl(FICLONE)`, `pipe2`, Snapper CLI, and hardcoded `<user-home>/.local/state/...` + `SACRED_PREFIXES`. 6 `-Wformat-truncation` warnings. | Abstract CoW backend behind a VFS trait: Btrfs `send` + `FICLONE` on Linux, APFS `clonefile(2)` + `tmutil` local snapshots on macOS, ZFS snapshot diff on BSD/Linux; replace `SACRED_PREFIXES` with `$HEPHAESTUS_HOME/protected_paths.conf`; widen snapshot path buffers to `PATH_MAX + 64`. |
| `hpulse.c` | Tightly coupled to Linux `/proc`, `/sys/class/powercap`, `/sys/block/zram0`, `SYS_pidfd_open`, `SYS_process_madvise`, `sched_setaffinity` (32-thread P/E layout), `<systemd/sd-journal.h>`, `malloc_trim`, and `/dev/shm/hephaestus_*.json`. 13 `-Wformat-truncation` warnings. | Split into `organs/pulse/` with platform collectors (`procfs` on Linux, `sysctl` + `host_statistics64` + `IOKit` SMC/IOReport on macOS), optional `dlopen("libsystemd.so.0")` instead of hard `-lsystemd` link, dynamic core topology discovery (`/sys/devices/system/cpu/cpu*/topology`), and `hslice_resolve_cache_dir()` for telemetry files. |
| `hctx.c` | `probe_git_fast` is 95% portable POSIX C11 except `fopen(..., "re")` (`"e"` is a glibc extension) and `pipe2(..., O_CLOEXEC)` + `/dev/shm/hephaestus_ctx.*` paths. 5 `-Wformat-truncation` warnings. | Replace `fopen(p, "re")` with `open(p, O_RDONLY | O_CLOEXEC)` + `fdopen`, replace `pipe2` with `pipe` + `fcntl(FD_CLOEXEC)`, use the 5-tier cache resolver, and widen `gitdir`/`commondir`/`branch` buffers. |
| `hrun.c` | 98% portable POSIX C11 (`fork`, `setpgid`, `poll`, `kill(-pgid)`). Only portability blockers are `pipe2(pfd, O_CLOEXEC)` and hardcoded `/dev/shm/hrun-%d.log` + `pacman --noconfirm` helper. 0 compiler warnings. | Replace `pipe2` with a portable `pipe_cloexec()` helper and write logs into the 5-tier cache directory (`$HEPHAESTUS_CACHE_DIR/hrun-<pid>.log`); compiles cleanly on both Linux and macOS with zero dependencies. |

---

## 5. Verification Summary for Extracted Organs (`slice` & `shield`)

- **Compiler Cleanliness**: Both `organs/slice` (`hslice`, `hfind`, `hsearch -> hfind`) and `organs/shield` (`hshield`, `hhook`) compile with **0 errors and 0 warnings** under `cc -std=c11 -O3 -Wall -Wextra -Werror`.
- **Zero Personal or Host Path Leaks**: Verified empty output across all source, header, Makefile, test, and report files for hardcoded host paths, network SSIDs, or personal identifiers.
- **Portable Cache Chain**: Verified `$HEPHAESTUS_CACHE_DIR` -> `/dev/shm/hephaestus-$UID` (only if `/dev/shm` exists & is writable) -> `$XDG_CACHE_HOME/hephaestus` -> `$HOME/.cache/hephaestus` -> `/tmp/hephaestus-$UID`.
- **Automated Test Suites**: Verified via `organs/slice/tests/test_slice.py` and `organs/shield/tests/test_shield.py` (`make test`).

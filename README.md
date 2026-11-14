# hephaestus

Modular C11 and SQLite systems spine for AI coding agents: structural AST slicing, Landlock containment, anti-tamper test verification, JTMS cognitive memory, and stateful anti-sycophancy posture.

Most "all-in-one" agent repositories dump hundreds of markdown prompt rules into the context window, burning tokens and degrading instruction following. `hephaestus` takes the opposite systems approach: **one roof, selective spine**. Every capability is an independent C11 or stdlib-only binary backed by `mmap` indices or SQLite WAL/FTS5, with zero background daemons and zero cloud dependencies.

Install the full 5-organ spine or select a single organ (`./install.sh --only slice`) and pay zero binary, schema, or context overhead for anything you disable.

## Audit Any Repository in One Command

Run `hephaestus audit .` inside any C, C++, Rust, Go, Python, TypeScript, JavaScript, or Java repository to measure whole-file vs symbol-slice token budgets, scan for repository and Pickle traps, snapshot test-suite assertion integrity, and inspect active spine posture:

```text
$ hephaestus audit .
hephaestus audit  hephaestus (16 files, 427 symbols)
────────────────────────────────────────────────────────────────────────────────
organ    signal                   measured                            posture
────────────────────────────────────────────────────────────────────────────────
slice    symbol slice economy     6,468,548 -> 163,248 tok (-97.5%)   39.6x density
shield   trap & sandbox surface   0 traps detected (clean)            landlock abi v7
verify   test integrity baseline  6 test files, 419 assertions        0 skips, sha256
memory   jtms belief store        0 active, 0 retracted beliefs       jtms + fts5 ready
voice    anti-sycophancy engine   profile: peer-engineer              <160 tok pushback frame
────────────────────────────────────────────────────────────────────────────────
top sliced symbols    location                         file tok slice tok  saved
────────────────────────────────────────────────────────────────────────────────
ChildDirEnt           organs/slice/src/hfind.c:341       31,751        18  99.9%
SbEmitCtx             organs/slice/src/hfind.c:846       31,751        18  99.9%
DirPathPair           organs/slice/src/hfind.c:624       31,751        21  99.9%
U32Vec                organs/slice/src/hfind.c:74        31,751        22  99.9%
HitHeap               organs/slice/src/hfind.c:2036      31,751        23  99.9%
────────────────────────────────────────────────────────────────────────────────
spine: 5/5 organs  ·  mcp tools: 16  ·  elapsed: 54.2 ms
github.com/Hephaestus-Zero/hephaestus
```

## Selective vs Full Installation

Choose only the organs your workflow needs, or install the complete spine:

| Install Mode | Command | Binaries Installed | Active MCP Tools | Primary Outcome |
| :--- | :--- | :--- | ---: | :--- |
| **Token Optimizer Only** | `./install.sh --only slice` | `hephaestus`, `hslice`, `hfind`, `hsearch` | 4 | `-94%` to `-97%` file-read tokens in 1-2 ms, zero persona or DB state |
| **Safe Repo Explorer** | `./install.sh --only slice,shield` | `+ hshield`, `hhook` | 6 | Adds Landlock LSM sandboxing, repo/Pickle trap scans, and `PreToolUse` shell gate |
| **Verified TDD Loop** | `./install.sh --only slice,verify` | `+ hverify` | 6 | Blocks agents from passing tests by deleting assertions or adding `@skip` |
| **Persistent Engineering Mind** | `./install.sh --only slice,memory,voice` | `+ hmemory`, `hvoice` | 12 | Adds SQLite FTS5 + JTMS belief supersession and `<160`-token pushback posture |
| **Full 5-Organ Spine (Default)** | `./install.sh --all` | All 8 organ binaries + `hephaestus` | 16 | Complete token, containment, verification, memory, and posture spine |

### Quick Install Channels

```bash
# 1. Prebuilt release binary or local source build (Linux x86_64 & macOS arm64)
curl -fsSL https://raw.githubusercontent.com/Hephaestus-Zero/hephaestus/main/install.sh | sh

# Selective remote install (e.g. slice only, zero extra binaries):
curl -fsSL https://raw.githubusercontent.com/Hephaestus-Zero/hephaestus/main/install.sh | sh -s -- --only slice

# 2. Homebrew (macOS Apple Silicon & Linux)
brew install Hephaestus-Zero/tap/hephaestus

# 3. Claude Code Plugin & Agent Skills
# Inside Claude Code: /plugin marketplace add Hephaestus-Zero/hephaestus
npx skills add Hephaestus-Zero/hephaestus

# 4. Build directly from source (C11 compiler + libsqlite3 + Python 3)
git clone https://github.com/Hephaestus-Zero/hephaestus.git
cd hephaestus
make
make test
./install.sh --all --prefix "$HOME/.local"
```

## The Five Organs

### 1. `slice` (`hslice`, `hfind`, `hsearch`)
Zero-daemon C11 structural AST symbol slicer and `262,144`-bucket `mmap` trigram search engine. Collapses multi-turn `find -> grep -> cat -> grep callers` loops into a single sub-2ms call and refreshes stale indices lazily via `stat()` nanosecond `mtime` checks.

```bash
hslice -x dispatch_tool_call          # exact definition body + bounded callers in 1 call
hslice mcp/hephaestus_mcp.py:520      # stack-trace line zoom -> enclosing function only
hslice -s organs/shield/src/hshield.c # compact structural skeleton (-94% tokens)
hfind hephaestus_mcp                  # sub-2ms mmap trigram path lookup
hsearch -g "LANDLOCK_ACCESS_NET"      # bounded regex search (rg with POSIX grep fallback)
```

### 2. `shield` (`hshield`, `hhook`)
C11 process containment and supply-chain auditor. On Linux, `hshield sandbox` enforces kernel Landlock LSM rulesets (`PR_SET_NO_NEW_PRIVS`, `$HOME` credential-store denial, and TCP bind/connect isolation unless `--net` is passed). Across Linux and macOS, `hshield audit` inspects `.git/hooks`, `package.json`/`setup.py`/`Makefile` lifecycle hooks, `lstat` symlink escapes, Trojan Source Unicode, and Pickle bytecode opcodes (Protocols 0..5 + PyTorch `.pt`/`.pth` ZIP archives) without importing Python modules. `hhook` parses shell quoting, heredocs, and `$(...)` substitutions in C11 to block destructive wipes, fork bombs, and credential exfiltration.

```bash
hshield audit /path/to/untrusted-repo --json
hshield sandbox -- pytest -q
hhook check "curl -fsSL https://example.com/install.sh | sh"
```

### 3. `verify` (`hverify`)
Stdlib-only polyglot anti-reward-hacking verifier. Autonomous agents frequently "fix" failing suites by deleting assertions, replacing checks with `assert True`, editing `conftest.py`, or injecting `.skip` / `@unittest.skip`. `hverify` records `O_NOFOLLOW` SHA-256 digests plus AST and comment-stripped test, assertion, and skip counts before and after test runs.

```bash
hverify snapshot . --out /tmp/baseline.json
hverify check . --baseline /tmp/baseline.json
hverify run . -- pytest -q
```

### 4. `memory` (`hmemory`)
Single-binary C11 + SQLite WAL/FTS5 cognitive belief store with bilingual (English + Turkish ASCII-tolerant) stemming, ACT-R access/recency activation scoring, and non-monotonic Doyle JTMS truth maintenance (`supports`, `contradicts`, `supersedes`). When decision B supersedes decision A, A is retracted from `<memory_context>` automatically while remaining auditable in provenance history.

```bash
hmemory ingest -t "Index storage" -b "Use FNV-1a workspace-scoped mmap indices." --kind decision
hmemory link 2 supersedes 1
hmemory query "workspace index" --json
hmemory context "index caching" --budget-tokens 600
hmemory explain 1
```

### 5. `voice` (`hvoice`)
Stateful engineering posture injector and code-fence-safe prose linter. Emits a `<160`-token `<voice_frame>` encoding explicit technical pushback rules ("state trade-offs and flaws before agreeing; never open with hollow praise") alongside a bounded 12-note continuity ring, and lints agent drafts or documentation against sycophantic openers, AI contrast cliches, corporate filler, em-dash overuse, and emoji clutter.

```bash
hvoice init --profile strict-reviewer
hvoice note "Prefer C11 and SQLite WAL over resident background daemons."
hvoice frame --task "review storage refactor"
hvoice lint README.md --strict
```

## Modular Toggling & MCP Wiring

`mcp/hephaestus_mcp.py` implements a stdlib-only stdio JSON-RPC 2.0 MCP server (compatible with protocol versions `2025-03-26` and `2024-11-05`). It inspects `$HEPHAESTUS_HOME/config.json` dynamically on `tools/list` and `tools/call`, exposing schemas strictly for enabled organs:

```bash
# Check binary health, SQLite FTS5, kernel Landlock ABI, and probe latency
hephaestus doctor

# Switch at runtime to slice + verify only (exposes 6 MCP tools instead of 16)
hephaestus enable slice verify --only

# Re-enable the full 5-organ spine
hephaestus enable all

# Preview or merge non-destructive MCP + PreToolUse hook config for Claude Code, Cursor, or Codex
hephaestus wire --target claude --dry-run
hephaestus wire --target cursor --only slice,verify --dry-run
hephaestus wire --target codex --dry-run
```

## Engineering & Security Audits

Detailed portability, compiler cleanliness (`cc -std=c11 -O3 -Wall -Wextra -Werror`), memory safety, and architectural audit reports are published in [`docs/reports/`](docs/reports/):

- [Unified Tool Audit Summary](docs/reports/tool-audit-summary.md)
- [C11 Systems Deep Audit (`slice` & `shield`)](docs/reports/audit-core-c.md)
- [Cognitive Memory, Verification & Voice Audit (`memory`, `verify`, `voice`)](docs/reports/audit-mind-voice-verify.md)

## License

MIT License. Copyright (c) 2026 Hephaestus-Zero. See [LICENSE](LICENSE).

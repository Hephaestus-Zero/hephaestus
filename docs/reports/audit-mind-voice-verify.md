# Audit Report: Cognitive Memory, Anti-Reward-Hacking Verification & Stateful Voice

**Scope:** Upstream prototype code audit and open-source organ distillation for `organs/memory` (`hmemory`), `organs/verify` (`hverify`), and `organs/voice` (`hvoice`).
**Target Standard:** ISO C11 (`-std=c11 -O3 -Wall -Wextra`, zero warnings on Linux & macOS) + Python 3 stdlib-only (zero external packages), zero background daemons, zero cloud dependencies, 100% host-agnostic paths.

---

## 1. Executive Summary

| Organ | Binary | Language / Deps | Upstream Modules Audited | Key Capability Distilled | Portability & Privacy Fixes Applied |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `memory` | `hmemory` | C11 (`-lsqlite3 -lm`) | `zmv5_db.c`, `zmv5_jtms.c`, `zmv5_turkish.c`, `zmv6_ecphory.c` | SQLite WAL + FTS5 atomic belief graph, bilingual EN/TR ASCII-tolerant stemming, ACT-R decay, Doyle JTMS non-monotonic retraction, CELF token-bounded `<memory_context>` | Replaced C23/`-march=native`/`-lzstd`/`-lcrypto`/Linux `<linux/fs.h>`/daemon sockets with single-binary ISO C11 + embedded RFC 6234 SHA-256 + XDG/env DB resolution |
| `verify` | `hverify` | Python 3 (stdlib) | `effects/fs.py`, `repository/workspace.py`, `repository/verifier.py`, `harness/gaming.py`, `evolve/mutation_gate.py`, `spec/audit.py` | `O_NOFOLLOW` descriptor-verified SHA-256 baseline, comment/AST-aware test & assertion counter, tautology (`assert True`) & skip-injection detector, protected-file guard | Removed Docker digest, `mutmut`, and `/dev/shm` hard dependencies; preserved working-tree cleanliness when `--out` is omitted |
| `voice` | `hvoice` | Python 3 (stdlib) | `living.py`, `gate.py`, `engine.py` | `< 160`-token `<voice_frame>` posture & pushback injector, 4 engineering profiles + custom YAML/JSON loader, code-block-safe deterministic anti-slop & anti-sycophancy linter, 12-note continuity ring | Stripped 100% of personal dyadic state, host paths, and Linux SHM mmaps; built generic `~/.hephaestus/voice/state.json` persistence |

---

## 2. Organ 3 Audit: Cognitive Memory (`hmemory`)

### 2.1 Upstream Strengths Preserved
1. **Hardened SQLite Initialization (`zmv5_db.c`)**:
   - Disables dynamic extension loading (`SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION = 0`) and untrusted schema execution (`SQLITE_DBCONFIG_TRUSTED_SCHEMA = 0`) prior to enabling defensive mode (`SQLITE_DBCONFIG_DEFENSIVE = 1`).
   - Uses `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL`, `PRAGMA foreign_keys=ON`, and `sqlite3_busy_timeout(db, 5000)` for contention-free concurrent agent reads/writes.
2. **Stratified Doyle JTMS & Provenance Retention (`zmv5_jtms.c`)**:
   - Rather than deleting outdated notes or appending contradictory lines to flat `MEMORY.md` files (which induces context poisoning and KAIST memory-induced degradation), beliefs carry explicit truth-maintenance states (`IN` vs `OUT/RETRACTED`) and causal edges (`supports`, `contradicts`, `supersedes`).
   - AGM entrenchment priors differentiate structural invariants (`constraint` > `decision` > `bugfix` > `fact`).
3. **Sub-Microsecond UTF-8 Folding & Agglutinative Turkish Stemming (`zmv5_turkish.c`)**:
   - Multi-byte UTF-8 Turkish codepoints (`Ç/ç`, `Ğ/ğ`, `İ/ı`, `Ö/ö`, `Ş/ş`, `Ü/ü`, `Â/â`, `Î/î`, `Û/û`) and combining dot above (`U+0307`) fold deterministically into lowercase ASCII so ASCII-typed developer queries match diacritic-rich text.
   - Five-pass right-to-left suffix stripping (copula, case/relational, possessive/plural, verbal/participle, derivational) with causative verb guards (`-stir`, `-ldir`), vowel-drop root restoration (`bellegi -> bellek`, `kaydi -> kayit`, `vakti -> vakit`), final-obstruent devoicing (`b->p`, `d->t`, `g->k`), and a technical root allowlist (`sistem`, `servis`, `analiz`, `proses`, `indeks`, `matris`, `stres`, `test`, `disk`, `port`, `lock`, `task`).
4. **Codepoint-Safe Sentence/Word Boundary Clipping (`zmv6_ecphory.c`)**:
   - Clips long belief bodies on UTF-8 boundaries, preferring sentence terminators in `[55%..100%]` of budget before falling back to whole-word boundaries, preventing broken UTF-8 sequences inside XML context blocks.

### 2.2 Findings & Improvements Engineered into `organs/memory/`
1. **C23 / Linux-Only Headers -> Pure Portable ISO C11**:
   - Upstream `Makefile` required `-std=c23 -march=native` (`nullptr`, C23 attributes), OpenSSL (`-lcrypto`), Zstandard (`-lzstd`), and Linux kernel headers (`<linux/falloc.h>`, `<linux/fs.h>`, `<malloc.h>`).
   - `hmemory` compiles cleanly under `cc -std=c11 -O3 -Wall -Wextra` on both GCC and AppleClang/Clang, linking solely against `-lsqlite3 -lm` with a self-contained C11 SHA-256 implementation.
2. **Zero-Daemon Standalone Architecture & Portable Path Resolution**:
   - Eliminated Unix domain socket RPC (`zmd-v5.sock`), `/dev/shm` lockless rings, and hardcoded host vault paths.
   - Database path resolves cleanly via `--db <path>` -> `$HEPHAESTUS_MEMORY_DB` -> `$HEPHAESTUS_HOME/memory/memory.db` (when `$HEPHAESTUS_HOME` is explicitly set) -> `$XDG_DATA_HOME/hephaestus/memory.db` -> `$HOME/.hephaestus/memory/memory.db`.
3. **Bilingual Stemming (English Porter-Lite + Turkish Morphological)**:
   - Upstream stemmer targeted Turkish morphology; English plurals/gerunds/participles (`connections`/`connecting`, `cached`/`caching`, `queries`/`queried`) relied on raw prefix matching. `hmemory` adds deterministic English suffix normalization alongside the 5-pass Turkish stemmer so bilingual engineering queries match seamlessly.
4. **FTS5 Preservation for `--include-retracted` Auditability**:
   - Upstream `demote_current_to_audit` deleted superseded rows from the FTS5 virtual table, preventing full-text search across historical retracted decisions. `hmemory` retains FTS5 postings for all beliefs and filters `b.status = 'IN'` at query time by default, enabling `hmemory query "<q>" --include-retracted` to surface historical provenance on demand.
5. **Exact Fixed-Point Non-Monotonic Doyle JTMS + ACT-R Ecphory Scoring**:
   - Formalized truth maintenance as a deterministic stratified fixed-point invariant: a non-retired belief $u$ is `IN` iff no `IN` node `supersedes` $u$, no `IN` node `contradicts` $u$, and either $u$ has zero incoming `supports` premises or at least one `IN` supporter. Retracting a premise cascades automatically to dependent beliefs, while superseding a false contradicter restores previously defeated beliefs.
   - Combined FTS5 BM25 relevance with ACT-R base-level activation $B_i = \ln(1 + n_{\text{access}}) - 0.5 \ln(1 + \Delta t_{\text{hours}})$ and greedy CELF token-budgeted selection (`marginal_gain / token_cost`) so `hmemory context` never exceeds `--budget-tokens`.

---

## 3. Organ 4 Audit: Anti-Reward-Hacking Verifier (`hverify`)

### 3.1 Upstream Strengths Preserved
1. **Descriptor-Level Symlink & Special-File Refusal (`effects/fs.py`, `repository/workspace.py`)**:
   - Uses `followlinks=False` directory traversal paired with `O_NOFOLLOW` file descriptor opening and `fstat` regular-file verification (`S_ISREG`) so symlink swaps outside the repository fail closed.
2. **Immutable Harness & Config Guardrails (`repository/workspace.py`)**:
   - Treats test bootstrap hooks (`conftest.py`, `sitecustomize.py`, `usercustomize.py`, `.pth`, `pytest.ini`, `.coveragerc`) as protected invariants so agents cannot silence failing tests via runner configuration edits.
3. **Dual-Signal Verification (`harness/gaming.py`, `repository/verifier.py`, `evolve/mutation_gate.py`)**:
   - Separates raw runner exit code from structural test integrity: an exit code of `0` accompanied by deleted test files, dropped assertions, or newly injected skip markers is classified as reward-hacking rather than success.

### 3.2 Findings & Improvements Engineered into `organs/verify/`
1. **Zero-Container Polyglot Test Integrity Analysis**:
   - Replaced Docker container execution and `mutmut` dependencies with a fast (`< 20 ms`), stdlib-only polyglot analyzer supporting Python (`ast` + `unittest`/`pytest`), C/C++ (`assert`, `ASSERT_*`, `EXPECT_*`, `TEST_*`), TypeScript/JavaScript (`expect(`, `assert.`, `it.skip`, `describe.skip`), Rust (`assert!`, `assert_eq!`, `#[ignore]`), and Go (`require.`, `t.Skip`).
2. **Comment-Stripped & Tautology-Aware Assertion Counting**:
   - Naive line-regex counters fail to catch commented-out assertions (`# assert x == 1` or `// expect(x).toBe(1)`) or tautological replacements (`assert True`). `hverify` uses Python's `ast` module on `.py` files (distinguishing real assertions and `self.assert*` / `pytest.raises` checks from `assert True` tautologies) and strips line/block comments before scanning C/JS/TS/Rust/Go test files.
3. **Zero Working-Tree Pollution on Read-Only Snapshots**:
   - When `hverify snapshot [dir]` is called without `--out`, baselines are stored under `$HEPHAESTUS_HOME/verify/<workspace_hash>.json` (or skipped in pure `--no-save` mode) rather than dropping untracked manifest files inside the target Git repository.

---

## 4. Organ 5 Audit: Anti-Sycophancy & Stateful Persona Engine (`hvoice`)

### 4.1 Upstream Strengths Preserved
1. **Token-Frugal XML Frame Injection (`living.py`, `engine.py`)**:
   - Injects compact, strictly bounded (`< 160` tokens) posture frames with word-boundary-safe clipping rather than multi-thousand-line prompt templates that dilute instruction following.
2. **Deterministic Rhythm & Drift Detection (`living.py`)**:
   - Evaluates prose shape (code-block-stripped prose, opening phrases, list overuse, punctuation habits, emoji presence) in sub-millisecond deterministic Python without LLM judge calls.
3. **Bounded Session Continuity**:
   - Carries compact working-style observations across sessions while deduplicating near-identical entries.

### 4.2 Findings & Improvements Engineered into `organs/voice/`
1. **Complete Privacy & Domain Purification**:
   - Upstream modules coupled general anti-slop mechanics with personal dyadic state, host-specific SQLite paths, and Linux `/dev/shm` mmaps. `hvoice` is a 100% generic, clean-room stdlib engine storing portable JSON state in `$HEPHAESTUS_HOME/voice/state.json` via atomic write-and-rename (`os.replace`).
2. **Built-In Engineering Postures + Stdlib Custom YAML/JSON Profiles**:
   - Ships four calibrated engineering profiles (`peer-engineer`, `strict-reviewer`, `quiet-minimal`, `architect`) and a zero-dependency YAML/JSON profile loader so teams can define custom review postures without installing `PyYAML`.
3. **Code-Fence-Safe Anti-Sycophancy & AI-Slop Linter (`hvoice lint`)**:
   - Strips fenced and inline code spans while preserving line numbers before scanning prose for sycophantic validation openers (`"Great idea!"`, `"You're absolutely right!"`), AI contrast clichés (`"Not X, it's Y"`), corporate filler (`delve`, `leverage`, `certainly`, `happy to help`, `tapestry`), hedging cliches, em-dash clutter, and emojis; exits non-zero under `--strict`.

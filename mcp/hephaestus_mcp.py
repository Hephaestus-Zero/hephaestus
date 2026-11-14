#!/usr/bin/env python3
"""hephaestus_mcp.py: Modular stdio JSON-RPC 2.0 MCP server for Hephaestus."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

VERSION = "0.1.0"
ALL_ORGANS: tuple[str, ...] = ("slice", "shield", "verify", "memory", "voice")
SUPPORTED_PROTOCOLS: tuple[str, ...] = ("2025-03-26", "2024-11-05")
DEFAULT_TIMEOUT_SEC = 15.0

ORGAN_BINARIES: tuple[str, ...] = (
    "hslice",
    "hfind",
    "hsearch",
    "hshield",
    "hhook",
    "hverify",
    "hmemory",
    "hvoice",
)

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    # Organ 1: slice
    {
        "organ": "slice",
        "name": "slice_symbol",
        "description": (
            "Extract an exact function, class, or struct body by symbol name or file:line "
            "via C11 structural AST slicing (-94% tokens vs reading whole files)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "symbol": {
                    "type": "string",
                    "description": "Symbol name (e.g. 'parse_request') or traceback 'path/to/file.py:142'.",
                },
                "dir": {
                    "type": "string",
                    "description": "Optional repository or directory path to scope lookup.",
                },
                "include_callers": {
                    "type": "boolean",
                    "description": "When true, include bounded cross-file callers/references (-x).",
                },
            },
            "required": ["symbol"],
        },
    },
    {
        "organ": "slice",
        "name": "slice_outline",
        "description": "Return the compact structural symbol skeleton (signatures and line spans) of a source file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {
                    "type": "string",
                    "description": "Path to the source file to outline.",
                },
                "dir": {
                    "type": "string",
                    "description": "Optional working directory for relative file paths.",
                },
            },
            "required": ["file"],
        },
    },
    {
        "organ": "slice",
        "name": "find_files",
        "description": "Sub-2ms C11 mmap trigram file path lookup across the repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "One or more space-separated path substring tokens.",
                },
                "dir": {
                    "type": "string",
                    "description": "Optional repository root directory.",
                },
            },
            "required": ["query"],
        },
    },
    {
        "organ": "slice",
        "name": "search_code",
        "description": "Sub-2ms C11 mmap symbol trigram lookup or bounded regex code search.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Symbol tokens (default) or regular expression when regex=true.",
                },
                "regex": {
                    "type": "boolean",
                    "description": "Search full code bodies with regex (-g) instead of symbol index.",
                },
                "dir": {
                    "type": "string",
                    "description": "Optional repository root directory.",
                },
            },
            "required": ["query"],
        },
    },
    # Organ 2: shield
    {
        "organ": "shield",
        "name": "shield_audit",
        "description": (
            "Audit a directory or repository for malicious .git/hooks, build preinstall traps, "
            "symlink escapes, and unsafe Pickle VM opcodes without executing untrusted code."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "dir": {
                    "type": "string",
                    "description": "Directory path to audit (defaults to current working directory).",
                },
            },
        },
    },
    {
        "organ": "shield",
        "name": "hook_check_command",
        "description": (
            "Parse and validate a shell command via C11 shell-aware parser to catch destructive rm -rf, "
            "fork bombs, credential exfiltration redirections, and substitution smuggling."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command line string to inspect.",
                },
            },
            "required": ["command"],
        },
    },
    # Organ 3: verify
    {
        "organ": "verify",
        "name": "verify_snapshot",
        "description": (
            "Capture an O_NOFOLLOW SHA-256, test-function, assertion-count, and skip-marker baseline "
            "before modifying code or tests."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "dir": {
                    "type": "string",
                    "description": "Project or test directory to snapshot (defaults to '.').",
                },
                "out": {
                    "type": "string",
                    "description": "Optional path to write the snapshot manifest JSON.",
                },
            },
        },
    },
    {
        "organ": "verify",
        "name": "verify_check",
        "description": (
            "Verify test suite integrity against a snapshot baseline to block reward-hacking "
            "(deleted test files, reduced assertion counts, or injected skip markers)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "dir": {
                    "type": "string",
                    "description": "Project or test directory to check (defaults to '.').",
                },
                "baseline": {
                    "type": "string",
                    "description": "Optional path to baseline manifest JSON captured by verify_snapshot.",
                },
            },
        },
    },
    # Organ 4: memory
    {
        "organ": "memory",
        "name": "memory_ingest",
        "description": (
            "Persist an atomic architectural decision, bugfix root cause, fact, or constraint "
            "in local SQLite WAL + FTS5 with optional JTMS supersession."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Concise belief title.",
                },
                "body": {
                    "type": "string",
                    "description": "Atomic belief statement with rationale or root cause.",
                },
                "kind": {
                    "type": "string",
                    "enum": ["decision", "bugfix", "fact", "constraint"],
                    "description": "Belief classification (default: fact).",
                },
                "tags": {
                    "type": "string",
                    "description": "Optional comma-separated tags (e.g. 'storage,auth').",
                },
                "supersedes": {
                    "type": ["integer", "string"],
                    "description": "Optional belief ID superseded and automatically retracted by this belief.",
                },
            },
            "required": ["title", "body"],
        },
    },
    {
        "organ": "memory",
        "name": "memory_query",
        "description": "Query active beliefs using bilingual FTS5 stemming and ACT-R recency/access scoring.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query string.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 8).",
                },
                "include_retracted": {
                    "type": "boolean",
                    "description": "Include superseded/retracted beliefs in results.",
                },
            },
            "required": ["query"],
        },
    },
    {
        "organ": "memory",
        "name": "memory_context",
        "description": (
            "Emit a strictly token-bounded <memory_context> block of active (non-retracted) "
            "high-salience beliefs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "focus_query": {
                    "type": "string",
                    "description": "Optional task focus query to rank relevant active beliefs.",
                },
                "budget_tokens": {
                    "type": "integer",
                    "description": "Strict token ceiling for emitted context (default: 600).",
                },
                "json_output": {
                    "type": "boolean",
                    "description": "Return JSON metadata instead of XML <memory_context> block.",
                },
            },
        },
    },
    {
        "organ": "memory",
        "name": "memory_link",
        "description": "Create a JTMS truth-maintenance directed edge (supports, contradicts, supersedes).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "src_id": {
                    "type": ["integer", "string"],
                    "description": "Source belief ID.",
                },
                "relation": {
                    "type": "string",
                    "enum": ["supports", "contradicts", "supersedes"],
                    "description": "JTMS relationship type.",
                },
                "dst_id": {
                    "type": ["integer", "string"],
                    "description": "Target belief ID.",
                },
            },
            "required": ["src_id", "relation", "dst_id"],
        },
    },
    {
        "organ": "memory",
        "name": "memory_explain",
        "description": "Inspect JTMS truth status (IN vs OUT/RETRACTED) and provenance edges for a belief ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {
                    "type": ["integer", "string"],
                    "description": "Belief ID to explain.",
                },
            },
            "required": ["id"],
        },
    },
    # Organ 5: voice
    {
        "organ": "voice",
        "name": "voice_frame",
        "description": "Emit a <160-token anti-sycophancy engineering posture frame with recent continuity notes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "Optional current task focus.",
                },
                "json_output": {
                    "type": "boolean",
                    "description": "Return JSON instead of raw <voice_frame> block.",
                },
            },
        },
    },
    {
        "organ": "voice",
        "name": "voice_lint",
        "description": (
            "Run deterministic anti-sycophancy and AI-slop linter on prose text or a file "
            "(catches hollow praise openers, contrast cliches, filler verbs, and emoji clutter)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Draft text to lint (provide 'text' or 'file').",
                },
                "file": {
                    "type": "string",
                    "description": "File path to lint (provide 'text' or 'file').",
                },
                "strict": {
                    "type": "boolean",
                    "description": "Fail with isError=true if slop or sycophancy violations are found.",
                },
            },
        },
    },
    {
        "organ": "voice",
        "name": "voice_note",
        "description": "Append a compact working-style or session continuity observation to the bounded 12-note ring.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "observation": {
                    "type": "string",
                    "description": "Concise continuity note to persist.",
                },
            },
            "required": ["observation"],
        },
    },
]

TOOLS_BY_NAME: dict[str, dict[str, Any]] = {t["name"]: t for t in TOOL_DEFINITIONS}


def get_hephaestus_home() -> Path:
    env_home = os.environ.get("HEPHAESTUS_HOME", "").strip()
    if env_home:
        return Path(env_home).expanduser()
    return Path.home() / ".hephaestus"


def _normalize_organs(raw: list[str] | tuple[str, ...]) -> list[str]:
    seen = {x.strip().lower() for x in raw if isinstance(x, str)}
    return [o for o in ALL_ORGANS if o in seen]


def get_enabled_organs(pinned_organs: list[str] | None) -> list[str]:
    if pinned_organs is not None:
        return pinned_organs
    cfg_path = get_hephaestus_home() / "config.json"
    if cfg_path.is_file():
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("enabled_organs"), list):
                return _normalize_organs(data["enabled_organs"])
        except (OSError, ValueError):
            pass
    return list(ALL_ORGANS)


def _is_executable(path: Path) -> bool:
    return os.path.lexists(path) and os.path.exists(path) and not path.is_dir() and os.access(path, os.X_OK)


def _detect_repo_root() -> Path | None:
    script_file = Path(__file__).resolve()
    cand = script_file.parent.parent
    if (cand / "organs").is_dir() and (cand / "bin" / "hephaestus").is_file():
        return cand
    return None


def resolve_binary(name: str) -> str | None:
    env_bin = os.environ.get("HEPHAESTUS_BIN_DIR", "").strip()
    if env_bin:
        cand = Path(env_bin) / name
        return str(cand) if _is_executable(cand) else None

    repo_root = _detect_repo_root()
    if repo_root is not None:
        build_cand = repo_root / "build" / "bin" / name
        if _is_executable(build_cand):
            return str(build_cand)
        if name == "hverify":
            src_cand = repo_root / "organs" / "verify" / "hverify"
            if _is_executable(src_cand):
                return str(src_cand)
        if name == "hvoice":
            src_cand = repo_root / "organs" / "voice" / "hvoice"
            if _is_executable(src_cand):
                return str(src_cand)
        if os.environ.get("HEPHAESTUS_PATH_FALLBACK") == "1":
            return shutil.which(name)
        return None

    # Installed layout: <prefix>/share/hephaestus/mcp/hephaestus_mcp.py -> <prefix>/bin/<name>
    script_dir = Path(os.path.abspath(__file__)).parent
    prefix_bin_candidates = [
        script_dir.parent.parent.parent / "bin",
        script_dir.parent.parent / "bin",
        script_dir,
    ]
    for bdir in prefix_bin_candidates:
        cand = bdir / name
        if _is_executable(cand):
            return str(cand)
        if any(_is_executable(bdir / b) for b in ORGAN_BINARIES):
            if os.environ.get("HEPHAESTUS_PATH_FALLBACK") != "1":
                return None

    return shutil.which(name)


def build_organ_env() -> dict[str, str]:
    env = os.environ.copy()
    home = get_hephaestus_home()
    env["HEPHAESTUS_HOME"] = str(home)
    if "HEPHAESTUS_HOME" in os.environ:
        env.setdefault("HEPHAESTUS_MEMORY_DB", str(home / "memory" / "memory.db"))
        env.setdefault("HEPHAESTUS_CACHE_DIR", str(home / "cache"))
    return env


def run_organ(
    bin_name: str,
    args: list[str],
    *,
    cwd: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SEC,
) -> tuple[int, str, str]:
    bin_path = resolve_binary(bin_name)
    if not bin_path:
        return 127, "", f"Organ binary '{bin_name}' is not installed or built."

    if cwd is not None:
        cwd_path = Path(cwd).expanduser()
        if not cwd_path.is_dir():
            return 2, "", f"Directory does not exist: {cwd}"
        cwd = str(cwd_path.resolve())

    env = build_organ_env()
    try:
        proc = subprocess.run(
            [bin_path, *args],
            executable=bin_path,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"Command '{bin_name}' timed out after {timeout:.1f}s."
    except OSError as exc:
        return 126, "", f"Failed to execute '{bin_name}': {exc}"


def _tool_result(text: str, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }


def dispatch_tool_call(name: str, arguments: dict[str, Any], enabled_organs: list[str]) -> dict[str, Any]:
    spec = TOOLS_BY_NAME.get(name)
    if spec is None:
        return _tool_result(f"Unknown tool: '{name}'", is_error=True)

    organ = spec["organ"]
    if organ not in enabled_organs:
        return _tool_result(
            f"Organ '{organ}' is currently disabled. Run 'hephaestus enable {organ}' to activate '{name}'.",
            is_error=True,
        )

    # --- Organ: slice ---
    if name == "slice_symbol":
        symbol = str(arguments.get("symbol") or "").strip()
        if not symbol:
            return _tool_result("Missing required parameter 'symbol'.", is_error=True)
        target_dir = arguments.get("dir") or arguments.get("path")
        cli_args: list[str] = []
        if arguments.get("include_callers"):
            cli_args.append("-x")
        cli_args.append(symbol)
        if target_dir and arguments.get("include_callers"):
            cli_args.append(str(target_dir))
            rc, out, err = run_organ("hslice", cli_args)
        else:
            rc, out, err = run_organ("hslice", cli_args, cwd=str(target_dir) if target_dir else None)
        text = out if out.strip() else (err.strip() or f"Symbol '{symbol}' not found.")
        return _tool_result(text, is_error=(rc != 0))

    if name == "slice_outline":
        fpath = str(arguments.get("file") or "").strip()
        if not fpath:
            return _tool_result("Missing required parameter 'file'.", is_error=True)
        target_dir = arguments.get("dir")
        rc, out, err = run_organ("hslice", ["-s", fpath], cwd=str(target_dir) if target_dir else None)
        text = out if out.strip() else (err.strip() or f"Unable to outline '{fpath}'.")
        return _tool_result(text, is_error=(rc != 0))

    if name == "find_files":
        query = str(arguments.get("query") or "").strip()
        if not query:
            return _tool_result("Missing required parameter 'query'.", is_error=True)
        tokens = [t for t in query.split() if t]
        target_dir = arguments.get("dir")
        rc, out, err = run_organ("hfind", tokens, cwd=str(target_dir) if target_dir else None)
        if rc in (124, 126, 127) or (rc != 0 and not out.strip() and err.strip()):
            return _tool_result(err.strip() or "hfind failed.", is_error=True)
        return _tool_result(out if out.strip() else "No matching files.", is_error=False)

    if name == "search_code":
        query = str(arguments.get("query") or "").strip()
        if not query:
            return _tool_result("Missing required parameter 'query'.", is_error=True)
        target_dir = arguments.get("dir")
        if arguments.get("regex"):
            cli_args = ["-g", query]
            if target_dir:
                cli_args.append(str(target_dir))
            rc, out, err = run_organ("hsearch", cli_args)
        else:
            tokens = [t for t in query.split() if t]
            rc, out, err = run_organ("hsearch", tokens, cwd=str(target_dir) if target_dir else None)
        if rc in (124, 126, 127) or (rc > 1 and err.strip()):
            return _tool_result(err.strip() or "hsearch failed.", is_error=True)
        return _tool_result(out if out.strip() else "No matches.", is_error=False)

    # --- Organ: shield ---
    if name == "shield_audit":
        target_dir = str(arguments.get("dir") or arguments.get("path") or ".").strip()
        target_path = Path(target_dir).expanduser()
        if not target_path.exists():
            return _tool_result(f"Path does not exist: {target_dir}", is_error=True)
        rc, out, err = run_organ("hshield", ["audit", str(target_path), "--json"])
        if rc in (124, 126, 127):
            return _tool_result(err.strip() or "hshield execution failed.", is_error=True)
        if not out.strip():
            rc, out, err = run_organ("hshield", ["audit", str(target_path)])
        body = out.strip() or err.strip() or json.dumps({"clean": rc == 0, "exit_code": rc})
        return _tool_result(body, is_error=False)

    if name == "hook_check_command":
        command = arguments.get("command")
        if not isinstance(command, str) or not command.strip():
            return _tool_result("Missing required parameter 'command'.", is_error=True)
        rc, out, err = run_organ("hhook", ["check", command])
        if rc in (124, 126, 127):
            return _tool_result(err.strip() or "hhook execution failed.", is_error=True)
        detail = (out.strip() or err.strip())
        verdict = {
            "allowed": rc == 0,
            "verdict": "allow" if rc == 0 else "block",
            "exit_code": rc,
            "detail": detail,
        }
        return _tool_result(json.dumps(verdict, indent=2), is_error=False)

    # --- Organ: verify ---
    if name == "verify_snapshot":
        target_dir = str(arguments.get("dir") or ".").strip()
        cli_args = ["snapshot", target_dir]
        if arguments.get("out"):
            cli_args.extend(["--out", str(arguments["out"])])
        cli_args.append("--json")
        rc, out, err = run_organ("hverify", cli_args)
        text = out.strip() or err.strip()
        return _tool_result(text or "verify_snapshot completed.", is_error=(rc != 0))

    if name == "verify_check":
        target_dir = str(arguments.get("dir") or ".").strip()
        cli_args = ["check", target_dir]
        if arguments.get("baseline"):
            cli_args.extend(["--baseline", str(arguments["baseline"])])
        cli_args.append("--json")
        rc, out, err = run_organ("hverify", cli_args)
        text = out.strip() or err.strip()
        return _tool_result(text or "verify_check completed.", is_error=(rc != 0))

    # --- Organ: memory ---
    if name == "memory_ingest":
        title = str(arguments.get("title") or "").strip()
        body = str(arguments.get("body") or "").strip()
        if not title or not body:
            return _tool_result("Both 'title' and 'body' are required.", is_error=True)
        cli_args = ["ingest", "-t", title, "-b", body]
        if arguments.get("kind"):
            cli_args.extend(["--kind", str(arguments["kind"])])
        tags = arguments.get("tags")
        if isinstance(tags, list):
            tags = ",".join(str(x) for x in tags)
        if tags:
            cli_args.extend(["--tags", str(tags)])
        if arguments.get("supersedes") is not None and str(arguments.get("supersedes")).strip() != "":
            cli_args.extend(["--supersedes", str(arguments["supersedes"])])
        cli_args.append("--json")
        rc, out, err = run_organ("hmemory", cli_args)
        return _tool_result(out.strip() or err.strip(), is_error=(rc != 0))

    if name == "memory_query":
        query = str(arguments.get("query") or "").strip()
        if not query:
            return _tool_result("Missing required parameter 'query'.", is_error=True)
        cli_args = ["query", query]
        if arguments.get("limit") is not None:
            cli_args.extend(["--limit", str(int(arguments["limit"]))])
        if arguments.get("include_retracted"):
            cli_args.append("--include-retracted")
        cli_args.append("--json")
        rc, out, err = run_organ("hmemory", cli_args)
        return _tool_result(out.strip() or err.strip(), is_error=(rc != 0))

    if name == "memory_context":
        cli_args = ["context"]
        focus = str(arguments.get("focus_query") or "").strip()
        if focus:
            cli_args.append(focus)
        budget = int(arguments.get("budget_tokens", 600))
        cli_args.extend(["--budget-tokens", str(budget)])
        if arguments.get("json_output"):
            cli_args.append("--json")
        rc, out, err = run_organ("hmemory", cli_args)
        return _tool_result(out.strip() or err.strip(), is_error=(rc != 0))

    if name == "memory_link":
        src_id = arguments.get("src_id")
        relation = str(arguments.get("relation") or "").strip()
        dst_id = arguments.get("dst_id")
        if src_id is None or dst_id is None or relation not in ("supports", "contradicts", "supersedes"):
            return _tool_result(
                "Parameters 'src_id', 'dst_id', and 'relation' (supports|contradicts|supersedes) are required.",
                is_error=True,
            )
        cli_args = ["link", str(src_id), relation, str(dst_id), "--json"]
        rc, out, err = run_organ("hmemory", cli_args)
        return _tool_result(out.strip() or err.strip(), is_error=(rc != 0))

    if name == "memory_explain":
        bid = arguments.get("id")
        if bid is None or str(bid).strip() == "":
            return _tool_result("Missing required parameter 'id'.", is_error=True)
        rc, out, err = run_organ("hmemory", ["explain", str(bid), "--json"])
        return _tool_result(out.strip() or err.strip(), is_error=(rc != 0))

    # --- Organ: voice ---
    if name == "voice_frame":
        cli_args = ["frame"]
        task = str(arguments.get("task") or "").strip()
        if task:
            cli_args.extend(["--task", task])
        if arguments.get("json_output"):
            cli_args.append("--json")
        rc, out, err = run_organ("hvoice", cli_args)
        return _tool_result(out.strip() or err.strip(), is_error=(rc != 0))

    if name == "voice_lint":
        cli_args = ["lint"]
        if arguments.get("text") is not None:
            cli_args.extend(["--text", str(arguments["text"])])
        elif arguments.get("file"):
            cli_args.append(str(arguments["file"]))
        else:
            return _tool_result("Provide either 'text' or 'file' to voice_lint.", is_error=True)
        strict = bool(arguments.get("strict", False))
        if strict:
            cli_args.append("--strict")
        cli_args.append("--json")
        rc, out, err = run_organ("hvoice", cli_args)
        if rc in (124, 126, 127):
            return _tool_result(err.strip() or "hvoice execution failed.", is_error=True)
        return _tool_result(out.strip() or err.strip(), is_error=(strict and rc != 0))

    if name == "voice_note":
        obs = str(arguments.get("observation") or "").strip()
        if not obs:
            return _tool_result("Missing required parameter 'observation'.", is_error=True)
        rc, out, err = run_organ("hvoice", ["note", obs, "--json"])
        return _tool_result(out.strip() or err.strip(), is_error=(rc != 0))

    return _tool_result(f"Unhandled tool '{name}'.", is_error=True)


def _public_tool_schema(spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": spec["name"],
        "description": spec["description"],
        "inputSchema": spec["inputSchema"],
    }


def _jsonrpc_ok(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_err(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_request(msg: dict[str, Any], pinned_organs: list[str] | None) -> dict[str, Any] | None:
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        req_id = msg.get("id") if isinstance(msg, dict) else None
        return _jsonrpc_err(req_id, -32600, "Invalid JSON-RPC 2.0 request.")

    method = msg.get("method")
    has_id = "id" in msg
    req_id = msg.get("id")
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

    # Notifications have no id and MUST NOT produce a response frame
    if not has_id:
        return None

    if not isinstance(method, str):
        return _jsonrpc_err(req_id, -32600, "Missing method string.")

    if method == "initialize":
        requested = str(params.get("protocolVersion") or "")
        negotiated = requested if requested in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[0]
        return _jsonrpc_ok(
            req_id,
            {
                "protocolVersion": negotiated,
                "capabilities": {
                    "tools": {"listChanged": True},
                },
                "serverInfo": {
                    "name": "hephaestus",
                    "version": VERSION,
                },
            },
        )

    if method == "ping":
        return _jsonrpc_ok(req_id, {})

    if method == "resources/list":
        return _jsonrpc_ok(req_id, {"resources": []})

    if method == "resources/templates/list":
        return _jsonrpc_ok(req_id, {"resourceTemplates": []})

    if method == "prompts/list":
        return _jsonrpc_ok(req_id, {"prompts": []})

    if method == "tools/list":
        enabled = set(get_enabled_organs(pinned_organs))
        visible = [_public_tool_schema(t) for t in TOOL_DEFINITIONS if t["organ"] in enabled]
        return _jsonrpc_ok(req_id, {"tools": visible})

    if method == "tools/call":
        tname = params.get("name")
        if not isinstance(tname, str) or not tname:
            return _jsonrpc_err(req_id, -32602, "Invalid params: missing tool 'name'.")
        raw_args = params.get("arguments")
        if raw_args is None:
            targs: dict[str, Any] = {}
        elif isinstance(raw_args, dict):
            targs = raw_args
        else:
            return _jsonrpc_err(req_id, -32602, "Invalid params: 'arguments' must be an object.")
        enabled_list = get_enabled_organs(pinned_organs)
        result = dispatch_tool_call(tname, targs, enabled_list)
        return _jsonrpc_ok(req_id, result)

    return _jsonrpc_err(req_id, -32601, f"Method not found: {method}")


def _read_next_frame(stream: Any) -> tuple[bytes | None, str]:
    while True:
        line = stream.readline()
        if not line:
            return None, "eof"
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith(b"content-length:"):
            try:
                length = int(stripped.split(b":", 1)[1].strip())
            except ValueError:
                return b"", "content-length"
            # Consume remaining headers up to empty line
            while True:
                hdr = stream.readline()
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break
            body = stream.read(length)
            return body, "content-length"
        return stripped, "jsonl"


def _write_frame(stream: Any, payload: dict[str, Any], mode: str) -> None:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if mode == "content-length":
        header = f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii")
        stream.write(header + encoded)
    else:
        stream.write(encoded + b"\n")
    stream.flush()


def parse_cli(argv: list[str]) -> tuple[list[str] | None, int | None]:
    pinned: list[str] | None = None
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            print("usage: hephaestus_mcp.py [--organs slice,shield,verify,memory,voice]")
            return None, 0
        if arg in ("-V", "--version"):
            print(f"hephaestus-mcp {VERSION}")
            return None, 0
        if arg == "--organs" and i + 1 < len(argv):
            i += 1
            raw = [p.strip().lower() for p in argv[i].split(",") if p.strip()]
            invalid = [p for p in raw if p not in ALL_ORGANS and p != "all"]
            if invalid:
                print(f"hephaestus-mcp: invalid organ(s): {', '.join(invalid)}", file=sys.stderr)
                return None, 2
            pinned = list(ALL_ORGANS) if "all" in raw else _normalize_organs(raw)
        elif arg.startswith("--organs="):
            val = arg.split("=", 1)[1]
            raw = [p.strip().lower() for p in val.split(",") if p.strip()]
            invalid = [p for p in raw if p not in ALL_ORGANS and p != "all"]
            if invalid:
                print(f"hephaestus-mcp: invalid organ(s): {', '.join(invalid)}", file=sys.stderr)
                return None, 2
            pinned = list(ALL_ORGANS) if "all" in raw else _normalize_organs(raw)
        else:
            print(f"hephaestus-mcp: unknown argument '{arg}'", file=sys.stderr)
            return None, 2
        i += 1
    return pinned, None


def serve_stdio(pinned_organs: list[str] | None) -> int:
    in_buf = sys.stdin.buffer
    out_buf = sys.stdout.buffer
    while True:
        raw_bytes, framing = _read_next_frame(in_buf)
        if raw_bytes is None:
            return 0
        try:
            decoded = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            _write_frame(out_buf, _jsonrpc_err(None, -32700, "Parse error."), framing)
            continue

        if isinstance(decoded, list):
            responses = []
            for item in decoded:
                resp = handle_request(item, pinned_organs)
                if resp is not None:
                    responses.append(resp)
            if responses:
                encoded = json.dumps(responses, separators=(",", ":")).encode("utf-8")
                if framing == "content-length":
                    out_buf.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii") + encoded)
                else:
                    out_buf.write(encoded + b"\n")
                out_buf.flush()
            continue

        resp = handle_request(decoded, pinned_organs)
        if resp is not None:
            _write_frame(out_buf, resp, framing)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    pinned, exit_code = parse_cli(args)
    if exit_code is not None:
        return exit_code
    return serve_stdio(pinned)


if __name__ == "__main__":
    raise SystemExit(main())

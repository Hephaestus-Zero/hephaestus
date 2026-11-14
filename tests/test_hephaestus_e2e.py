#!/usr/bin/env python3
"""End-to-end integration, MCP JSON-RPC, selective install, and privacy tests for Hephaestus."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
HEPHAESTUS_BIN = REPO_ROOT / "bin" / "hephaestus"
MCP_SCRIPT = REPO_ROOT / "mcp" / "hephaestus_mcp.py"
INSTALL_SCRIPT = REPO_ROOT / "install.sh"
BUILD_BIN = REPO_ROOT / "build" / "bin"


class McpClientSession:
    """Interactive stdio JSON-RPC 2.0 session helper for mcp/hephaestus_mcp.py."""

    def __init__(self, env: dict[str, str], extra_args: list[str] | None = None) -> None:
        cmd = [sys.executable, "-B", str(MCP_SCRIPT), *(extra_args or [])]
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            bufsize=1,
        )
        self._next_id = 1

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        req_id = self._next_id
        self._next_id += 1
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            stderr_out = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"MCP server closed stdout unexpectedly. stderr={stderr_out}")
        return json.loads(line)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        assert self.proc.stdin is not None
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        if "error" in resp:
            raise AssertionError(f"JSON-RPC protocol error calling {name}: {resp['error']}")
        return resp["result"]

    def close(self) -> None:
        if self.proc.stdin:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        try:
            self.proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=2.0)
        if self.proc.stdout:
            self.proc.stdout.close()
        if self.proc.stderr:
            self.proc.stderr.close()

    def __enter__(self) -> McpClientSession:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


class TestHephaestusE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Build all 5 organs with strict -Wall -Wextra -Werror cleanliness
        proc = subprocess.run(
            ["make", "all", "CFLAGS=-std=c11 -O3 -Wall -Wextra -Werror"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(
                f"make all failed under -Wall -Wextra -Werror:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
            )

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="heph-e2e-")
        self.tmp_root = Path(self._tmp.name)
        self.heph_home = self.tmp_root / "heph_home"
        self.env = os.environ.copy()
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.env["HEPHAESTUS_HOME"] = str(self.heph_home)
        self.env["HEPHAESTUS_BIN_DIR"] = str(BUILD_BIN)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(BUILD_BIN / "hephaestus"), *args],
            cwd=str(REPO_ROOT),
            env=self.env,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_01_build_binaries_and_doctor_json(self) -> None:
        expected_bins = (
            "hephaestus",
            "hslice",
            "hfind",
            "hsearch",
            "hshield",
            "hhook",
            "hverify",
            "hmemory",
            "hvoice",
        )
        for bname in expected_bins:
            bpath = BUILD_BIN / bname
            self.assertTrue(os.path.lexists(bpath), f"Missing built binary: {bpath}")
            self.assertTrue(os.access(bpath, os.X_OK), f"Binary not executable: {bpath}")

        doc = self.run_cli("doctor", "--json")
        self.assertEqual(doc.returncode, 0, doc.stderr)
        data = json.loads(doc.stdout)
        self.assertTrue(data["healthy"], data)
        self.assertEqual(data["version"], "0.1.0")
        self.assertEqual(data["mcp"]["active_tools"], 16)
        self.assertTrue(data["sqlite"]["available"])
        self.assertTrue(data["sqlite"]["fts5"])
        for organ in ("slice", "shield", "verify", "memory", "voice"):
            self.assertTrue(data["organs"][organ]["healthy"], f"Organ unhealthy: {organ}")

    def test_02_audit_terminal_receipt_and_json(self) -> None:
        res_txt = self.run_cli("audit", str(REPO_ROOT))
        self.assertEqual(res_txt.returncode, 0, res_txt.stderr)
        self.assertIn("hephaestus audit", res_txt.stdout)
        self.assertIn("symbol slice economy", res_txt.stdout)
        self.assertIn("trap & sandbox surface", res_txt.stdout)
        self.assertIn("test integrity baseline", res_txt.stdout)
        self.assertIn("jtms belief store", res_txt.stdout)
        self.assertIn("anti-sycophancy engine", res_txt.stdout)
        # Ensure read-only audit did not create a default .hephaestus-verify.json in REPO_ROOT
        self.assertFalse((REPO_ROOT / ".hephaestus-verify.json").exists())

        res_json = self.run_cli("audit", str(REPO_ROOT), "--json")
        self.assertEqual(res_json.returncode, 0, res_json.stderr)
        payload = json.loads(res_json.stdout)
        self.assertGreater(payload["organs"]["slice"]["symbols"], 100)
        self.assertGreater(payload["organs"]["slice"]["saved_pct"], 70.0)
        self.assertTrue(payload["organs"]["shield"]["clean"])
        self.assertEqual(payload["organs"]["shield"]["findings"], 0)
        self.assertGreaterEqual(payload["organs"]["verify"]["test_files"], 5)
        self.assertGreater(payload["organs"]["verify"]["assertions"], 100)

    def test_03_dynamic_organ_toggling_and_wire(self) -> None:
        with McpClientSession(self.env) as mcp:
            init = mcp.request("initialize", {"protocolVersion": "2025-03-26"})
            self.assertEqual(init["result"]["protocolVersion"], "2025-03-26")
            mcp.notify("notifications/initialized")

            tools_all = mcp.request("tools/list")["result"]["tools"]
            self.assertEqual(len(tools_all), 16)

            # Toggle to slice-only while MCP server is already running
            r1 = self.run_cli("enable", "slice", "--only")
            self.assertEqual(r1.returncode, 0, r1.stderr)
            tools_slice = [t["name"] for t in mcp.request("tools/list")["result"]["tools"]]
            self.assertEqual(
                tools_slice,
                ["slice_symbol", "slice_outline", "find_files", "search_code"],
            )

            # Calling a disabled organ tool returns isError=True cleanly
            blocked = mcp.call_tool("voice_frame", {})
            self.assertTrue(blocked["isError"])
            self.assertIn("disabled", blocked["content"][0]["text"].lower())

            # Enable memory + verify dynamically
            r2 = self.run_cli("enable", "memory", "verify")
            self.assertEqual(r2.returncode, 0, r2.stderr)
            tools_mv = [t["name"] for t in mcp.request("tools/list")["result"]["tools"]]
            self.assertEqual(len(tools_mv), 4 + 2 + 5)

            # Disable slice dynamically
            r3 = self.run_cli("disable", "slice")
            self.assertEqual(r3.returncode, 0, r3.stderr)
            tools_no_slice = [t["name"] for t in mcp.request("tools/list")["result"]["tools"]]
            self.assertEqual(len(tools_no_slice), 7)
            self.assertNotIn("slice_symbol", tools_no_slice)

        # Verify hephaestus wire emits hooks only when shield is selected
        wire_slice = self.run_cli("wire", "--target", "claude", "--only", "slice", "--dry-run", "--json")
        self.assertEqual(wire_slice.returncode, 0)
        w_slice_obj = json.loads(wire_slice.stdout)
        self.assertNotIn("claude_hooks", w_slice_obj)

        wire_shield = self.run_cli("wire", "--target", "claude", "--only", "slice,shield", "--dry-run", "--json")
        self.assertEqual(wire_shield.returncode, 0)
        w_shield_obj = json.loads(wire_shield.stdout)
        self.assertIn("claude_hooks", w_shield_obj)

    def test_04_mcp_jsonrpc_live_across_all_five_organs(self) -> None:
        # Re-enable all 5 organs in isolated HEPHAESTUS_HOME
        self.assertEqual(self.run_cli("enable", "all", "--only").returncode, 0)

        with McpClientSession(self.env) as mcp:
            init = mcp.request("initialize", {"protocolVersion": "2024-11-05"})
            self.assertEqual(init["result"]["protocolVersion"], "2024-11-05")
            mcp.notify("notifications/initialized")

            # 1. SLICE: slice_symbol, slice_outline, find_files, search_code
            sym_res = mcp.call_tool("slice_symbol", {"symbol": "dispatch_tool_call", "dir": str(REPO_ROOT)})
            self.assertFalse(sym_res["isError"], sym_res)
            self.assertIn("def dispatch_tool_call", sym_res["content"][0]["text"])

            out_res = mcp.call_tool("slice_outline", {"file": "mcp/hephaestus_mcp.py", "dir": str(REPO_ROOT)})
            self.assertFalse(out_res["isError"], out_res)
            self.assertIn("handle_request", out_res["content"][0]["text"])

            fnd_res = mcp.call_tool("find_files", {"query": "hephaestus_mcp", "dir": str(REPO_ROOT)})
            self.assertFalse(fnd_res["isError"], fnd_res)
            self.assertIn("hephaestus_mcp.py", fnd_res["content"][0]["text"])

            src_res = mcp.call_tool(
                "search_code",
                {"query": "SUPPORTED_PROTOCOLS", "regex": True, "dir": str(REPO_ROOT)},
            )
            self.assertFalse(src_res["isError"], src_res)
            self.assertIn("hephaestus_mcp.py", src_res["content"][0]["text"])

            # 2. SHIELD: shield_audit + hook_check_command
            aud_res = mcp.call_tool("shield_audit", {"dir": str(REPO_ROOT)})
            self.assertFalse(aud_res["isError"], aud_res)
            aud_json = json.loads(aud_res["content"][0]["text"])
            self.assertEqual(len(aud_json.get("findings", [])), 0)

            safe_cmd = mcp.call_tool("hook_check_command", {"command": "git status -sb"})
            self.assertFalse(safe_cmd["isError"])
            self.assertTrue(json.loads(safe_cmd["content"][0]["text"])["allowed"])

            bad_cmd = mcp.call_tool("hook_check_command", {"command": "rm -rf /"})
            self.assertFalse(bad_cmd["isError"])
            bad_verdict = json.loads(bad_cmd["content"][0]["text"])
            self.assertFalse(bad_verdict["allowed"])
            self.assertEqual(bad_verdict["verdict"], "block")

            # 3. VERIFY: verify_snapshot -> verify_check (clean vs reward-hacked)
            mini_proj = self.tmp_root / "mini_proj"
            mini_tests = mini_proj / "tests"
            mini_tests.mkdir(parents=True)
            test_py = mini_tests / "test_math.py"
            test_py.write_text(
                "import unittest\n\nclass T(unittest.TestCase):\n"
                "    def test_add(self):\n        self.assertEqual(2 + 2, 4)\n"
                "        self.assertEqual(3 + 3, 6)\n",
                encoding="utf-8",
            )
            baseline_file = self.tmp_root / "baseline.json"
            snap_res = mcp.call_tool(
                "verify_snapshot",
                {"dir": str(mini_proj), "out": str(baseline_file)},
            )
            self.assertFalse(snap_res["isError"], snap_res)
            self.assertTrue(baseline_file.is_file())

            chk_ok = mcp.call_tool(
                "verify_check",
                {"dir": str(mini_proj), "baseline": str(baseline_file)},
            )
            self.assertFalse(chk_ok["isError"], chk_ok)

            # Simulate reward-hacking: drop an assertion!
            test_py.write_text(
                "import unittest\n\nclass T(unittest.TestCase):\n"
                "    def test_add(self):\n        self.assertEqual(2 + 2, 4)\n",
                encoding="utf-8",
            )
            chk_tampered = mcp.call_tool(
                "verify_check",
                {"dir": str(mini_proj), "baseline": str(baseline_file)},
            )
            self.assertTrue(chk_tampered["isError"], "Expected tampered test suite to fail verify_check")

            # 4. MEMORY: memory_ingest + memory_link (JTMS supersession) + query + context + explain
            b1_res = mcp.call_tool(
                "memory_ingest",
                {
                    "title": "Cache backend v1",
                    "body": "Use Redis network socket for local symbol caching.",
                    "kind": "decision",
                    "tags": "cache,arch",
                },
            )
            self.assertFalse(b1_res["isError"], b1_res)
            b1_id = json.loads(b1_res["content"][0]["text"])["id"]

            b2_res = mcp.call_tool(
                "memory_ingest",
                {
                    "title": "Cache backend v2",
                    "body": "Use zero-daemon mmap trigram index files instead of Redis sockets.",
                    "kind": "decision",
                    "tags": "cache,arch",
                },
            )
            self.assertFalse(b2_res["isError"], b2_res)
            b2_id = json.loads(b2_res["content"][0]["text"])["id"]

            # Supersede b1 with b2 via memory_link
            lnk_res = mcp.call_tool(
                "memory_link",
                {"src_id": b2_id, "relation": "supersedes", "dst_id": b1_id},
            )
            self.assertFalse(lnk_res["isError"], lnk_res)

            exp_b1 = json.loads(mcp.call_tool("memory_explain", {"id": b1_id})["content"][0]["text"])
            exp_b2 = json.loads(mcp.call_tool("memory_explain", {"id": b2_id})["content"][0]["text"])
            self.assertNotEqual(exp_b1.get("status"), "IN")
            self.assertEqual(exp_b2.get("status"), "IN")

            q_active = mcp.call_tool("memory_query", {"query": "symbol caching index", "limit": 5})
            self.assertFalse(q_active["isError"], q_active)
            self.assertIn("Cache backend v2", q_active["content"][0]["text"])
            self.assertNotIn("Cache backend v1", q_active["content"][0]["text"])

            ctx_res = mcp.call_tool("memory_context", {"focus_query": "cache", "budget_tokens": 300})
            self.assertFalse(ctx_res["isError"], ctx_res)
            ctx_xml = ctx_res["content"][0]["text"]
            self.assertIn("<memory_context", ctx_xml)
            self.assertIn("Cache backend v2", ctx_xml)
            self.assertNotIn("Cache backend v1", ctx_xml)

            # 5. VOICE: voice_note + voice_frame + voice_lint
            note_res = mcp.call_tool(
                "voice_note",
                {"observation": "Prefer stdlib C11 and SQLite over external daemons."},
            )
            self.assertFalse(note_res["isError"], note_res)

            frame_res = mcp.call_tool("voice_frame", {"task": "review pull request"})
            self.assertFalse(frame_res["isError"], frame_res)
            frame_txt = frame_res["content"][0]["text"]
            self.assertIn("<voice_frame", frame_txt)
            self.assertIn("stdlib C11", frame_txt)

            slop_res = mcp.call_tool(
                "voice_lint",
                {
                    "text": "Great idea! You're absolutely right! Let's delve into this seamless tapestry.",
                    "strict": True,
                },
            )
            self.assertTrue(slop_res["isError"], "Expected sycophantic slop to fail strict voice_lint")

            clean_res = mcp.call_tool(
                "voice_lint",
                {
                    "text": "Replaced global lock with atomic index swap; median latency dropped from 9.4 ms to 1.2 ms.",
                    "strict": True,
                },
            )
            self.assertFalse(clean_res["isError"], clean_res)

    def test_05_selective_installer_only_vs_all_and_uninstall(self) -> None:
        prefix = self.tmp_root / "usr_local"
        inst_env = os.environ.copy()
        inst_env["HEPHAESTUS_HOME"] = str(self.tmp_root / "inst_home")

        # 1. Install --only slice
        p_only = subprocess.run(
            ["sh", str(INSTALL_SCRIPT), "--only", "slice", "--prefix", str(prefix)],
            cwd=str(REPO_ROOT),
            env=inst_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(p_only.returncode, 0, p_only.stderr)
        self.assertTrue((prefix / "bin" / "hephaestus").is_file())
        self.assertTrue((prefix / "bin" / "hslice").is_file())
        self.assertTrue((prefix / "bin" / "hfind").is_file())
        self.assertTrue(os.path.islink(prefix / "bin" / "hsearch"))
        self.assertFalse((prefix / "bin" / "hshield").exists())
        self.assertFalse((prefix / "bin" / "hmemory").exists())
        self.assertFalse((prefix / "bin" / "hverify").exists())
        self.assertFalse((prefix / "bin" / "hvoice").exists())

        # Doctor from installed slice-only prefix must pass cleanly!
        clean_env = {k: v for k, v in inst_env.items() if k != "HEPHAESTUS_BIN_DIR"}
        doc_only = subprocess.run(
            [str(prefix / "bin" / "hephaestus"), "doctor", "--json"],
            env=clean_env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(doc_only.returncode, 0, doc_only.stderr)
        doc_data = json.loads(doc_only.stdout)
        self.assertEqual(doc_data["enabled_organs"], ["slice"])
        self.assertEqual(doc_data["mcp"]["active_tools"], 4)
        self.assertTrue(doc_data["healthy"])

        # 2. Uninstall cleanly
        p_un = subprocess.run(
            ["sh", str(INSTALL_SCRIPT), "--uninstall", "--prefix", str(prefix)],
            cwd=str(REPO_ROOT),
            env=inst_env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(p_un.returncode, 0, p_un.stderr)
        self.assertFalse((prefix / "bin" / "hephaestus").exists())
        self.assertFalse((prefix / "bin" / "hslice").exists())

    def test_06_privacy_and_portability_zero_leaks(self) -> None:
        # Build pattern dynamically so literal tokens never appear in source text
        forbidden_tokens = [
            "/" + "home/" + "theory",
            "GSB" + "WIFI",
            "On" + "ur",
            "Zero" + " Soul",
        ]
        pattern = re.compile("|".join(re.escape(tok) for tok in forbidden_tokens), re.IGNORECASE)
        skip_dirs = {".git", "build", "dist", "__pycache__", ".pytest_cache"}

        leaks: list[str] = []
        for root, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if fname.endswith((".pyc", ".pyo", ".o", ".idx", ".so", ".dylib")):
                    continue
                fpath = Path(root) / fname
                if fpath.is_symlink():
                    continue
                try:
                    raw = fpath.read_bytes()
                except OSError:
                    continue
                if b"\x00" in raw[:4096]:
                    continue
                text = raw.decode("utf-8", errors="replace")
                for lineno, line in enumerate(text.splitlines(), start=1):
                    m = pattern.search(line)
                    if m:
                        rel = fpath.relative_to(REPO_ROOT)
                        leaks.append(f"{rel}:{lineno}: matched '{m.group(0)}'")

        self.assertEqual(leaks, [], "Privacy/portability leak(s) detected:\n" + "\n".join(leaks))


if __name__ == "__main__":
    unittest.main()

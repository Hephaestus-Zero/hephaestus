#!/usr/bin/env python3
"""Integration and unit tests for Hephaestus Organ 1 (hslice, hfind, hsearch)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


def _resolve_bin_dir() -> Path:
    env_dir = os.environ.get("HEPHAESTUS_SLICE_BIN_DIR", "").strip()
    if env_dir:
        return Path(env_dir).resolve()
    organ_dir = Path(__file__).resolve().parent.parent
    return (organ_dir / ".." / ".." / "build" / "bin").resolve()


class SliceOrganTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bin_dir = _resolve_bin_dir()
        cls.hslice = str(cls.bin_dir / "hslice")
        cls.hfind = str(cls.bin_dir / "hfind")
        cls.hsearch = str(cls.bin_dir / "hsearch")
        for b in (cls.hslice, cls.hfind, cls.hsearch):
            if not (os.path.lexists(b) and os.access(b, os.X_OK)):
                raise RuntimeError(f"Missing executable organ binary: {b}")

    def setUp(self) -> None:
        self.tmp_root = tempfile.mkdtemp(prefix="heph-slice-test-")
        self.repo_dir = Path(self.tmp_root) / "sample_repo"
        self.cache_dir = Path(self.tmp_root) / "cache"
        self.repo_dir.mkdir(parents=True)
        self.cache_dir.mkdir(parents=True)
        (self.repo_dir / ".git").mkdir()
        self._populate_polyglot_repo()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_root, ignore_errors=True)

    def _run(
        self,
        exe: str,
        args: list[str],
        *,
        cwd: Path | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["HEPHAESTUS_CACHE_DIR"] = str(self.cache_dir)
        env.pop("HEPHAESTUS_ROOTS", None)
        env.pop("HSLICE_ROOTS", None)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [exe, *args],
            executable=exe,
            cwd=str(cwd or self.repo_dir),
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10.0,
        )

    def _populate_polyglot_repo(self) -> None:
        src = self.repo_dir / "src"
        src.mkdir(parents=True)

        # 1. C file with decoy braces inside comments and string literals
        (src / "engine.c").write_text(
            "#include <stdint.h>\n"
            "\n"
            "typedef struct {\n"
            "    uint32_t capacity;\n"
            "    uint32_t count;\n"
            "} RingHeader;\n"
            "\n"
            "/* Decoy comment with unmatched } } } */\n"
            "int compute_checksum(const char *payload, int len) {\n"
            '    const char *decoy = "fake brace } inside literal";\n'
            "    (void)decoy;\n"
            "    int acc = 0;\n"
            "    for (int i = 0; i < len; i++) {\n"
            "        acc = (acc * 31) + (unsigned char)payload[i];\n"
            "    }\n"
            "    return acc;\n"
            "}\n"
            "\n"
            "int dispatch_packet(const char *buf, int n) {\n"
            "    int sum = compute_checksum(buf, n);\n"
            "    return sum ^ 0x5A;\n"
            "}\n",
            encoding="utf-8",
        )

        # 2. Python file with decorator, multiline docstring, and class method
        (src / "pipeline.py").write_text(
            "import functools\n"
            "\n"
            "def trace_step(fn):\n"
            "    @functools.wraps(fn)\n"
            "    def wrapper(*args, **kwargs):\n"
            "        return fn(*args, **kwargs)\n"
            "    return wrapper\n"
            "\n"
            "@trace_step\n"
            "def normalize_tokens(items: list[str]) -> list[str]:\n"
            '    """Normalize raw items.\n'
            "    Contains decoy def fake_inner(): inside docstring.\n"
            '    """\n'
            "    cleaned = [x.strip().lower() for x in items if x.strip()]\n"
            "    return cleaned\n"
            "\n"
            "class BatchRunner:\n"
            "    def execute_batch(self, raw: list[str]) -> int:\n"
            "        norm = normalize_tokens(raw)\n"
            "        return len(norm)\n",
            encoding="utf-8",
        )

        # 3. TypeScript file with interface, template literal, and exported function
        (src / "router.ts").write_text(
            "export interface RouteConfig {\n"
            "    path: string;\n"
            "    timeoutMs: number;\n"
            "}\n"
            "\n"
            "export function resolveEndpoint(cfg: RouteConfig): string {\n"
            "    const banner = `route ${cfg.path} fake } brace`;\n"
            "    if (cfg.timeoutMs <= 0) {\n"
            "        return `${banner}:default`;\n"
            "    }\n"
            "    return `${cfg.path}?t=${cfg.timeoutMs}`;\n"
            "}\n"
            "\n"
            "export function bootRouter(): string {\n"
            '    return resolveEndpoint({ path: "/health", timeoutMs: 250 });\n'
            "}\n",
            encoding="utf-8",
        )

        # 4. Rust file with derive attribute, lifetime, and raw string literal
        (src / "codec.rs").write_text(
            "#[derive(Debug, Clone)]\n"
            "pub struct FrameMeta {\n"
            "    pub seq: u64,\n"
            "    pub flags: u32,\n"
            "}\n"
            "\n"
            "pub fn decode_frame<'a>(input: &'a [u8]) -> Option<&'a [u8]> {\n"
            '    let _pattern = r#"raw string with }decoy{ braces"#;\n'
            "    if input.len() < 4 {\n"
            "        return None;\n"
            "    }\n"
            "    Some(&input[4..])\n"
            "}\n",
            encoding="utf-8",
        )

        # 5. Go file with struct, method receiver, and raw backtick string
        (src / "store.go").write_text(
            "package store\n"
            "\n"
            "type LedgerStore struct {\n"
            "    prefix string\n"
            "}\n"
            "\n"
            "func (s *LedgerStore) CommitEntry(key string) string {\n"
            "    raw := `multiline raw literal with } fake close`\n"
            "    _ = raw\n"
            '    return s.prefix + ":" + key\n'
            "}\n",
            encoding="utf-8",
        )

    def test_01_cli_help_and_version(self) -> None:
        for exe, expected_name in (
            (self.hslice, "hslice"),
            (self.hfind, "hfind"),
            (self.hsearch, "hsearch"),
        ):
            v = self._run(exe, ["--version"])
            self.assertEqual(v.returncode, 0, v.stderr)
            self.assertIn(expected_name, v.stdout)

            h = self._run(exe, ["--help"])
            self.assertEqual(h.returncode, 0, h.stderr)
            self.assertIn("Usage:", h.stdout)

    def test_02_polyglot_ast_slicing_default_and_fallback_lexer(self) -> None:
        cases = [
            ("compute_checksum", "src/engine.c", "return acc;"),
            ("RingHeader", "src/engine.c", "uint32_t capacity;"),
            ("normalize_tokens", "src/pipeline.py", "cleaned = [x.strip().lower()"),
            ("resolveEndpoint", "src/router.ts", "cfg.timeoutMs"),
            ("decode_frame", "src/codec.rs", "Some(&input[4..])"),
            ("CommitEntry", "src/store.go", "return s.prefix"),
        ]
        for extra_env in ({}, {"HEPHAESTUS_NO_TREESITTER": "1"}):
            for sym, expected_rel, expected_body in cases:
                res = self._run(self.hslice, [sym], extra_env=extra_env)
                self.assertEqual(res.returncode, 0, f"{sym} failed: {res.stderr}")
                self.assertIn(expected_rel, res.stdout)
                self.assertIn(expected_body, res.stdout)
                # Ensure adjacent functions are NOT leaked into the slice
                if sym == "compute_checksum":
                    self.assertNotIn("dispatch_packet", res.stdout)
                if sym == "normalize_tokens":
                    self.assertNotIn("execute_batch", res.stdout)

    def test_03_outline_and_stacktrace_line_zoom(self) -> None:
        sk = self._run(self.hslice, ["-s", "src/engine.c"])
        self.assertEqual(sk.returncode, 0, sk.stderr)
        self.assertIn("skeleton:", sk.stdout)
        self.assertIn("compute_checksum", sk.stdout)
        self.assertIn("dispatch_packet", sk.stdout)

        # Stack-trace single-line zoom inside compute_checksum (line 13)
        zm = self._run(self.hslice, ["src/engine.c:13"])
        self.assertEqual(zm.returncode, 0, zm.stderr)
        self.assertIn("compute_checksum", zm.stdout)
        self.assertIn("return acc;", zm.stdout)
        self.assertNotIn("dispatch_packet", zm.stdout)

        # Explicit span range
        sp = self._run(self.hslice, ["src/engine.c:3-6"])
        self.assertEqual(sp.returncode, 0, sp.stderr)
        self.assertIn("RingHeader", sp.stdout)
        self.assertNotIn("compute_checksum", sp.stdout)

    def test_04_xref_callers(self) -> None:
        xr = self._run(self.hslice, ["-x", "compute_checksum", str(self.repo_dir)])
        self.assertEqual(xr.returncode, 0, xr.stderr)
        self.assertIn("int compute_checksum", xr.stdout)
        self.assertIn("Callers & References: compute_checksum", xr.stdout)
        self.assertIn("int sum = compute_checksum(buf, n);", xr.stdout)

    def test_05_lazy_mtime_auto_refresh_on_edit_and_new_file(self) -> None:
        # Initial query builds index in self.cache_dir
        r1 = self._run(self.hslice, ["normalize_tokens"])
        self.assertEqual(r1.returncode, 0, r1.stderr)
        idx_files = list(self.cache_dir.glob("hsym-*.idx"))
        self.assertEqual(len(idx_files), 1)

        # In-place edit of existing file: shift lines, alter implementation, add new symbol
        time.sleep(0.02)
        py_path = self.repo_dir / "src" / "pipeline.py"
        py_path.write_text(
            "# Added header line 1\n"
            "# Added header line 2\n"
            "# Added header line 3\n"
            "def normalize_tokens(items: list[str]) -> list[str]:\n"
            "    updated_marker = [x.upper() for x in items]\n"
            "    return updated_marker\n"
            "\n"
            "def freshly_added_symbol(val: int) -> int:\n"
            "    return val * 42\n",
            encoding="utf-8",
        )

        r2 = self._run(self.hslice, ["normalize_tokens"])
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("updated_marker", r2.stdout)
        self.assertNotIn("cleaned =", r2.stdout)

        r3 = self._run(self.hslice, ["freshly_added_symbol"])
        self.assertEqual(r3.returncode, 0, r3.stderr)
        self.assertIn("return val * 42", r3.stdout)

        # Brand-new file added to src/ without manual --rebuild
        time.sleep(0.02)
        (self.repo_dir / "src" / "hotplug.rs").write_text(
            "pub fn hotplug_handshake(port: u16) -> u16 {\n"
            "    port + 1000\n"
            "}\n",
            encoding="utf-8",
        )
        r4 = self._run(self.hslice, ["hotplug_handshake"])
        self.assertEqual(r4.returncode, 0, r4.stderr)
        self.assertIn("port + 1000", r4.stdout)

    def test_06_hfind_hsearch_and_grep_fallback(self) -> None:
        pf = self._run(self.hfind, ["router.ts"])
        self.assertEqual(pf.returncode, 0, pf.stderr)
        self.assertIn("src/router.ts", pf.stdout)

        pf_json = self._run(self.hfind, ["--json", "codec"])
        self.assertEqual(pf_json.returncode, 0, pf_json.stderr)
        data_f = json.loads(pf_json.stdout)
        self.assertTrue(data_f["ok"])
        self.assertGreaterEqual(data_f["count"], 1)

        ps = self._run(self.hsearch, ["CommitEntry"])
        self.assertEqual(ps.returncode, 0, ps.stderr)
        self.assertIn("CommitEntry", ps.stdout)
        self.assertIn("store.go", ps.stdout)

        ps_json = self._run(self.hsearch, ["--json", "decode_frame"])
        self.assertEqual(ps_json.returncode, 0, ps_json.stderr)
        data_s = json.loads(ps_json.stdout)
        self.assertTrue(data_s["ok"])
        self.assertEqual(data_s["hits"][0]["symbol"], "decode_frame")

        # Regex code search via hsearch -g
        pg = self._run(self.hsearch, ["-g", "timeoutMs", str(self.repo_dir)])
        self.assertEqual(pg.returncode, 0, pg.stderr)
        self.assertIn("timeoutMs", pg.stdout)

        # Verify portable POSIX grep fallback when rg is unavailable
        only_grep_dir = Path(self.tmp_root) / "grep_only_bin"
        only_grep_dir.mkdir()
        sys_grep = shutil.which("grep")
        if sys_grep:
            os.symlink(sys_grep, only_grep_dir / "grep")
            pg_fb = self._run(
                self.hsearch,
                ["-g", "timeoutMs", str(self.repo_dir)],
                extra_env={"PATH": str(only_grep_dir)},
            )
            self.assertEqual(pg_fb.returncode, 0, pg_fb.stderr)
            self.assertIn("timeoutMs", pg_fb.stdout)

    def test_07_audit_receipt_text_and_json(self) -> None:
        au_txt = self._run(self.hslice, ["--audit", str(self.repo_dir)])
        self.assertEqual(au_txt.returncode, 0, au_txt.stderr)
        self.assertIn("hslice token audit:", au_txt.stdout)
        self.assertIn("indexed symbols", au_txt.stdout)
        self.assertIn("density:", au_txt.stdout)

        au_json = self._run(self.hslice, ["--audit", str(self.repo_dir), "--json"])
        self.assertEqual(au_json.returncode, 0, au_json.stderr)
        rep = json.loads(au_json.stdout)
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["files"], 5)
        self.assertGreaterEqual(rep["symbols"], 8)
        self.assertGreater(rep["file_tokens"], rep["slice_tokens"])
        self.assertGreater(rep["saved_pct"], 25.0)
        self.assertGreater(rep["density_x"], 1.3)
        self.assertGreaterEqual(len(rep["top_symbols"]), 5)
        first = rep["top_symbols"][0]
        for key in ("symbol", "location", "file_tokens", "slice_tokens", "saved_pct"):
            self.assertIn(key, first)

    def test_08_off_eof_file_line_and_range_clamping(self) -> None:
        tiny = self.repo_dir / "tiny_eof.py"
        tiny.write_text("alpha = 1\nbeta = 2\n", encoding="utf-8")
        try:
            p_line = self._run(self.hslice, [f"{tiny}:999999"])
            self.assertEqual(p_line.returncode, 0, p_line.stderr)
            self.assertIn(":1-2 [context@L2] (2/2 lines)", p_line.stdout)
            self.assertIn("alpha = 1", p_line.stdout)
            self.assertIn("beta = 2", p_line.stdout)
            self.assertNotIn("999984", p_line.stdout)

            p_rng = self._run(self.hslice, [f"{tiny}:999990-999999"])
            self.assertEqual(p_rng.returncode, 0, p_rng.stderr)
            self.assertIn(":2-2 [span] (1/2 lines)", p_rng.stdout)
            self.assertIn("beta = 2", p_rng.stdout)
            self.assertNotIn("999990", p_rng.stdout)
        finally:
            tiny.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit and integration tests for hvoice stateful posture and anti-slop engine."""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ORGAN_DIR = Path(__file__).resolve().parent.parent
HVOICE = ORGAN_DIR / "hvoice"


class HVoiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="hvoice-test-")
        self.root = Path(self._tmp.name)
        self.home = self.root / "heph_home"
        self.home.mkdir(parents=True)
        self.env = os.environ.copy()
        self.env["HEPHAESTUS_HOME"] = str(self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_hvoice(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(HVOICE), *args],
            cwd=str(self.root),
            env=self.env,
            capture_output=True,
            text=True,
            timeout=10.0,
        )

    def test_version_and_help(self) -> None:
        rv = self.run_hvoice("--version")
        self.assertEqual(rv.returncode, 0)
        self.assertIn("hvoice 0.1.0", rv.stdout)

        rh = self.run_hvoice("--help")
        self.assertEqual(rh.returncode, 0)
        for cmd in ("profiles", "init", "frame", "lint", "note"):
            self.assertIn(cmd, rh.stdout)

    def test_profiles_and_custom_yaml_loader(self) -> None:
        res = self.run_hvoice("profiles", "--json")
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        names = {p["name"] for p in data["profiles"]}
        self.assertTrue({"peer-engineer", "strict-reviewer", "quiet-minimal", "architect"}.issubset(names))

        # Add a custom YAML profile and verify zero-dep loading.
        custom_dir = self.home / "voice" / "profiles"
        custom_dir.mkdir(parents=True)
        (custom_dir / "kernel-sec.yaml").write_text(
            "name: kernel-sec\n"
            "summary: Kernel security review posture.\n"
            "posture: Check descriptor lifetimes and integer bounds first.\n"
            "pushback: Reject unchecked user pointers.\n",
            encoding="utf-8",
        )
        res2 = self.run_hvoice("profiles", "--json")
        self.assertEqual(res2.returncode, 0)
        names2 = {p["name"] for p in json.loads(res2.stdout)["profiles"]}
        self.assertIn("kernel-sec", names2)

    def test_init_and_state_schema(self) -> None:
        bad = self.run_hvoice("init", "--profile", "nonexistent-profile")
        self.assertEqual(bad.returncode, 2)

        ok = self.run_hvoice("init", "--profile", "strict-reviewer", "--json")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        state_file = self.home / "voice" / "state.json"
        self.assertTrue(state_file.is_file())
        saved = json.loads(state_file.read_text(encoding="utf-8"))
        self.assertEqual(saved["profile"], "strict-reviewer")
        self.assertEqual(saved["notes"], [])
        self.assertIn("updated_at", saved)

    def test_continuity_note_ring_buffer_max_12(self) -> None:
        self.assertEqual(self.run_hvoice("init", "--profile", "architect").returncode, 0)

        for idx in range(1, 16):
            res = self.run_hvoice("note", f"continuity observation number {idx}", "--json")
            self.assertEqual(res.returncode, 0, res.stderr)

        state = json.loads((self.home / "voice" / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(len(state["notes"]), 12)
        self.assertEqual(state["notes"][0], "continuity observation number 4")
        self.assertEqual(state["notes"][-1], "continuity observation number 15")

        # Duplicate note (case-insensitive) moves to tail without growing past 12.
        dup = self.run_hvoice("note", "CONTINUITY OBSERVATION NUMBER 5", "--json")
        self.assertEqual(dup.returncode, 0)
        dup_data = json.loads(dup.stdout)
        self.assertEqual(dup_data["notes_count"], 12)
        self.assertEqual(dup_data["notes"][-1], "CONTINUITY OBSERVATION NUMBER 5")

    def test_frame_stays_strictly_under_160_tokens(self) -> None:
        self.assertEqual(self.run_hvoice("init", "--profile", "peer-engineer").returncode, 0)
        for idx in range(12):
            self.run_hvoice(
                "note",
                f"prefer bounded ring buffers and explicit error codes in subsystem {idx} before refactoring",
            )

        raw_res = self.run_hvoice(
            "frame",
            "--task",
            "harden descriptor checks and eliminate race conditions in snapshot verification",
        )
        self.assertEqual(raw_res.returncode, 0)
        frame_txt = raw_res.stdout.strip()
        self.assertTrue(frame_txt.startswith('<voice_frame profile="peer-engineer">'))
        self.assertTrue(frame_txt.endswith("</voice_frame>"))
        self.assertIn("never open with hollow praise", frame_txt.lower())
        self.assertIn("continuity:", frame_txt)

        # Verify < 160 tokens across both word-multiplier and char/4 estimators.
        words_est = math.ceil(len(frame_txt.split()) * 1.35)
        chars_est = math.ceil(len(frame_txt) / 3.8)
        self.assertLess(max(words_est, chars_est), 160)

        json_res = self.run_hvoice("frame", "--task", "review sql queries", "--json")
        self.assertEqual(json_res.returncode, 0)
        jdata = json.loads(json_res.stdout)
        self.assertLess(jdata["tokens_est"], 160)
        self.assertGreater(jdata["notes_included"], 0)

    def test_lint_clean_prose(self) -> None:
        clean_sample = (
            "The parser drops trailing newlines when reading chunked frames. "
            "Bound the slice index at line 142 and add a regression test for empty payloads."
        )
        res = self.run_hvoice("lint", "--text", clean_sample, "--strict", "--json")
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertTrue(data["clean"])
        self.assertEqual(data["score"], 100)
        self.assertEqual(data["findings"], [])

    def test_lint_catches_sycophancy_contrast_filler_emdash_and_emoji(self) -> None:
        slop_sample = (
            "Great idea! You're absolutely right. "
            "It's not about caching, it's a game-changer that lets us delve into the tapestry "
            "and seamlessly leverage state \u2014 happy to help \U0001f680"
        )
        # Advisory mode returns exit 0 with clean=False.
        adv = self.run_hvoice("lint", "--text", slop_sample, "--json")
        self.assertEqual(adv.returncode, 0)
        rep = json.loads(adv.stdout)
        self.assertFalse(rep["clean"])
        self.assertLess(rep["score"], 40)

        rules_hit = {f["rule"] for f in rep["findings"]}
        self.assertIn("sycophantic_opener", rules_hit)
        self.assertIn("contrast_cliche", rules_hit)
        self.assertIn("corporate_filler", rules_hit)
        self.assertIn("em_dash", rules_hit)
        self.assertIn("emoji", rules_hit)

        # Verify exact span offsets match input slices.
        for finding in rep["findings"]:
            start, end = finding["span"]
            self.assertEqual(slop_sample[start:end], finding["match"])

        # Strict mode exits 1 when not clean.
        strict_res = self.run_hvoice("lint", "--text", slop_sample, "--strict", "--json")
        self.assertEqual(strict_res.returncode, 1)

    def test_lint_ignores_fenced_and_inline_code_blocks(self) -> None:
        doc_path = self.root / "draft.md"
        doc_path.write_text(
            "Reject sycophantic phrases like `Great idea!` or `delve` in prose.\n\n"
            "```python\n"
            "# You're absolutely right \u2014 this comment is inside a code fence \U0001f680\n"
            "msg = \"Not a bug, it's a feature\"\n"
            "```\n\n"
            "Check exit codes explicitly before committing.\n",
            encoding="utf-8",
        )
        res = self.run_hvoice("lint", str(doc_path), "--strict", "--json")
        self.assertEqual(res.returncode, 0, res.stdout)
        data = json.loads(res.stdout)
        self.assertTrue(data["clean"], f"Unexpected findings: {data['findings']}")

    def test_lint_certainly_opener(self) -> None:
        res = self.run_hvoice("lint", "--text", "Certainly! Here is the updated module.", "--strict", "--json")
        self.assertEqual(res.returncode, 1)
        data = json.loads(res.stdout)
        self.assertFalse(data["clean"])
        self.assertEqual(data["findings"][0]["rule"], "sycophantic_opener")


if __name__ == "__main__":
    unittest.main()

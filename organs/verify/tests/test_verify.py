#!/usr/bin/env python3
"""Unit and integration tests for hverify anti-reward-hacking verifier."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ORGAN_DIR = Path(__file__).resolve().parent.parent
HVERIFY = ORGAN_DIR / "hverify"


class HVerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="hverify-test-")
        self.root = Path(self._tmp.name)
        self.proj = self.root / "sample_repo"
        self.home = self.root / "heph_home"
        (self.proj / "tests").mkdir(parents=True)
        self.home.mkdir(parents=True)

        self.env = os.environ.copy()
        self.env["HEPHAESTUS_HOME"] = str(self.home)

        (self.proj / "tests" / "test_math.py").write_text(
            "import unittest\n\n"
            "class MathTests(unittest.TestCase):\n"
            "    def test_add(self):\n"
            "        self.assertEqual(2 + 2, 4)\n"
            "        assert 3 * 3 == 9\n\n"
            "    def test_sub(self):\n"
            "        self.assertEqual(10 - 3, 7)\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_hverify(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(HVERIFY), *args],
            cwd=str(cwd or self.proj),
            env=self.env,
            capture_output=True,
            text=True,
            timeout=10.0,
        )

    def test_version_and_help(self) -> None:
        res_v = self.run_hverify("--version")
        self.assertEqual(res_v.returncode, 0)
        self.assertIn("hverify 0.1.0", res_v.stdout)

        res_h = self.run_hverify("--help")
        self.assertEqual(res_h.returncode, 0)
        self.assertIn("snapshot", res_h.stdout)
        self.assertIn("check", res_h.stdout)
        self.assertIn("run", res_h.stdout)

    def test_clean_snapshot_and_check_schema(self) -> None:
        snap = self.run_hverify("snapshot", str(self.proj), "--json")
        self.assertEqual(snap.returncode, 0, snap.stderr)
        data = json.loads(snap.stdout)
        self.assertEqual(data["summary"]["test_files"], 1)
        self.assertEqual(data["summary"]["test_functions"], 2)
        self.assertEqual(data["summary"]["assertions"], 3)
        self.assertEqual(data["summary"]["skip_markers"], 0)
        self.assertIn("tests/test_math.py", data["files"])
        self.assertTrue((self.proj / ".hephaestus-verify.json").is_file())

        chk = self.run_hverify("check", str(self.proj), "--json")
        self.assertEqual(chk.returncode, 0, chk.stderr)
        rep = json.loads(chk.stdout)
        self.assertTrue(rep["intact"])
        self.assertTrue(rep["clean"])
        self.assertEqual(rep["violations"], [])

    def test_out_flag_keeps_workspace_clean(self) -> None:
        out_manifest = self.root / "external_baseline.json"
        snap = self.run_hverify("snapshot", str(self.proj), "--out", str(out_manifest), "--json")
        self.assertEqual(snap.returncode, 0)
        self.assertTrue(out_manifest.is_file())
        self.assertFalse((self.proj / ".hephaestus-verify.json").exists())

        chk = self.run_hverify("check", str(self.proj), "--baseline", str(out_manifest), "--json")
        self.assertEqual(chk.returncode, 0)
        self.assertTrue(json.loads(chk.stdout)["intact"])

    def test_detects_deleted_assertion_and_commented_out_assertion(self) -> None:
        self.assertEqual(self.run_hverify("snapshot", str(self.proj)).returncode, 0)

        # Commenting out an assertion must still count as assertion removal.
        (self.proj / "tests" / "test_math.py").write_text(
            "import unittest\n\n"
            "class MathTests(unittest.TestCase):\n"
            "    def test_add(self):\n"
            "        self.assertEqual(2 + 2, 4)\n"
            "        # assert 3 * 3 == 9\n\n"
            "    def test_sub(self):\n"
            "        self.assertEqual(10 - 3, 7)\n",
            encoding="utf-8",
        )
        chk = self.run_hverify("check", str(self.proj), "--json")
        self.assertEqual(chk.returncode, 1)
        rep = json.loads(chk.stdout)
        self.assertFalse(rep["intact"])
        kinds = {v["kind"] for v in rep["violations"]}
        self.assertIn("decreased_assertions", kinds)

    def test_detects_tautology_replacement(self) -> None:
        self.assertEqual(self.run_hverify("snapshot", str(self.proj)).returncode, 0)

        (self.proj / "tests" / "test_math.py").write_text(
            "import unittest\n\n"
            "class MathTests(unittest.TestCase):\n"
            "    def test_add(self):\n"
            "        self.assertEqual(2 + 2, 4)\n"
            "        assert True\n\n"
            "    def test_sub(self):\n"
            "        self.assertEqual(10 - 3, 7)\n",
            encoding="utf-8",
        )
        chk = self.run_hverify("check", str(self.proj), "--json")
        self.assertEqual(chk.returncode, 1)
        rep = json.loads(chk.stdout)
        kinds = {v["kind"] for v in rep["violations"]}
        self.assertIn("decreased_assertions", kinds)
        self.assertIn("injected_tautology", kinds)

    def test_detects_injected_skip_marker(self) -> None:
        self.assertEqual(self.run_hverify("snapshot", str(self.proj)).returncode, 0)

        (self.proj / "tests" / "test_math.py").write_text(
            "import unittest\n\n"
            "class MathTests(unittest.TestCase):\n"
            "    @unittest.skip('temporarily bypassed')\n"
            "    def test_add(self):\n"
            "        self.assertEqual(2 + 2, 4)\n"
            "        assert 3 * 3 == 9\n\n"
            "    def test_sub(self):\n"
            "        self.assertEqual(10 - 3, 7)\n",
            encoding="utf-8",
        )
        chk = self.run_hverify("check", str(self.proj), "--json")
        self.assertEqual(chk.returncode, 1)
        rep = json.loads(chk.stdout)
        kinds = {v["kind"] for v in rep["violations"]}
        self.assertIn("increased_skip_markers", kinds)

    def test_detects_deleted_test_file_and_symlink_swap(self) -> None:
        self.assertEqual(self.run_hverify("snapshot", str(self.proj)).returncode, 0)

        target = self.proj / "tests" / "test_math.py"
        outside = self.root / "outside_test.py"
        outside.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
        target.unlink()

        chk_del = self.run_hverify("check", str(self.proj), "--json")
        self.assertEqual(chk_del.returncode, 1)
        self.assertIn("deleted_test_file", {v["kind"] for v in json.loads(chk_del.stdout)["violations"]})

        # Replacing deleted test file with a symlink outside repo must be refused by O_NOFOLLOW.
        os.symlink(outside, target)
        chk_sym = self.run_hverify("check", str(self.proj), "--json")
        self.assertEqual(chk_sym.returncode, 1)
        self.assertIn("symlink_swap", {v["kind"] for v in json.loads(chk_sym.stdout)["violations"]})

    def test_detects_protected_harness_injection(self) -> None:
        self.assertEqual(self.run_hverify("snapshot", str(self.proj)).returncode, 0)
        (self.proj / "tests" / "conftest.py").write_text(
            "def pytest_collection_modifyitems(items):\n    items.clear()\n",
            encoding="utf-8",
        )
        chk = self.run_hverify("check", str(self.proj), "--json")
        self.assertEqual(chk.returncode, 1)
        self.assertIn("injected_protected_file", {v["kind"] for v in json.loads(chk.stdout)["violations"]})

    def test_allows_legitimate_new_assertions(self) -> None:
        self.assertEqual(self.run_hverify("snapshot", str(self.proj)).returncode, 0)
        (self.proj / "tests" / "test_math.py").write_text(
            "import unittest\n\n"
            "class MathTests(unittest.TestCase):\n"
            "    def test_add(self):\n"
            "        self.assertEqual(2 + 2, 4)\n"
            "        assert 3 * 3 == 9\n\n"
            "    def test_sub(self):\n"
            "        self.assertEqual(10 - 3, 7)\n\n"
            "    def test_mul(self):\n"
            "        self.assertEqual(6 * 7, 42)\n",
            encoding="utf-8",
        )
        chk = self.run_hverify("check", str(self.proj), "--json")
        self.assertEqual(chk.returncode, 0)
        rep = json.loads(chk.stdout)
        self.assertTrue(rep["intact"])
        self.assertEqual(rep["deltas"]["test_functions"], 1)
        self.assertEqual(rep["deltas"]["assertions"], 1)

    def test_polyglot_scanning(self) -> None:
        (self.proj / "app.spec.ts").write_text(
            "it('computes sum', () => {\n  expect(1 + 2).toBe(3);\n  // expect(0).toBe(1);\n});\n"
            "it.skip('skipped spec', () => {\n  expect(2).toBe(2);\n});\n",
            encoding="utf-8",
        )
        (self.proj / "parser_test.rs").write_text(
            "#[test]\nfn parses_header() {\n    assert_eq!(2 + 2, 4);\n}\n"
            "#[test]\n#[ignore]\nfn slow_case() {\n    assert!(1 == 1);\n}\n",
            encoding="utf-8",
        )
        snap = self.run_hverify("snapshot", str(self.proj), "--no-save", "--json")
        self.assertEqual(snap.returncode, 0)
        files = json.loads(snap.stdout)["files"]
        self.assertEqual(files["app.spec.ts"]["test_functions"], 1)
        self.assertEqual(files["app.spec.ts"]["assertions"], 2)
        self.assertEqual(files["app.spec.ts"]["skip_markers"], 1)
        self.assertEqual(files["parser_test.rs"]["test_functions"], 2)
        self.assertEqual(files["parser_test.rs"]["assertions"], 2)
        self.assertEqual(files["parser_test.rs"]["skip_markers"], 1)

    def test_run_subcommand_clean_failed_and_tampered(self) -> None:
        # 1. Clean test command passes.
        ok = self.run_hverify(
            "run",
            str(self.proj),
            "--json",
            "--",
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
        )
        self.assertEqual(ok.returncode, 0, ok.stderr)
        ok_data = json.loads(ok.stdout)
        self.assertTrue(ok_data["passed"])
        self.assertTrue(ok_data["intact"])
        self.assertEqual(ok_data["verdict"], "verified")

        # 2. Failing command exits non-zero.
        fail = self.run_hverify(
            "run",
            str(self.proj),
            "--json",
            "--",
            sys.executable,
            "-c",
            "import sys; sys.exit(3)",
        )
        self.assertEqual(fail.returncode, 3)
        fail_data = json.loads(fail.stdout)
        self.assertFalse(fail_data["passed"])
        self.assertEqual(fail_data["verdict"], "test_failed")

        # 3. Self-tampering command that exits 0 after deleting assertions is caught and exits 1.
        tamper_script = (
            "from pathlib import Path; "
            "p = Path('tests/test_math.py'); "
            "p.write_text('def test_noop():\\n    pass\\n', encoding='utf-8')"
        )
        tampered = self.run_hverify(
            "run",
            str(self.proj),
            "--json",
            "--",
            sys.executable,
            "-c",
            tamper_script,
        )
        self.assertEqual(tampered.returncode, 1)
        t_data = json.loads(tampered.stdout)
        self.assertEqual(t_data["command_exit_code"], 0)
        self.assertFalse(t_data["intact"])
        self.assertFalse(t_data["passed"])
        self.assertEqual(t_data["verdict"], "tampered")


if __name__ == "__main__":
    unittest.main()

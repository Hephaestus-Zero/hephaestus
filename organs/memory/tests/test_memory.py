#!/usr/bin/env python3
"""Integration and JTMS truth-maintenance test suite for hmemory."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


def locate_hmemory_bin() -> str:
    env_bin = os.environ.get("HEPHAESTUS_MEMORY_BIN")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin
    organ_dir = Path(__file__).resolve().parent.parent
    candidates = [
        organ_dir / "../../build/bin/hmemory",
        organ_dir / "build/hmemory",
    ]
    for cand in candidates:
        resolved = cand.resolve()
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return str(resolved)
    raise FileNotFoundError("hmemory binary not built; run `make` in organs/memory first")


class HMemoryTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bin_path = locate_hmemory_bin()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="hmemory_test_")
        self.tmp_path = Path(self.tmp.name)
        self.db_path = self.tmp_path / "memory.db"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_cli(self, *args: str, env_extra: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.tmp_path / "home"),
            "HEPHAESTUS_MEMORY_DB": str(self.db_path),
        }
        if env_extra:
            for k, v in env_extra.items():
                if v is None:
                    env.pop(k, None)
                else:
                    env[k] = v
        proc = subprocess.run(
            [self.bin_path, *args],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            timeout=10,
        )
        # Strict UTF-8 output invariant on both stdout and stderr
        stdout_text = proc.stdout.decode("utf-8", errors="strict")
        stderr_text = proc.stderr.decode("utf-8", errors="strict")
        completed = subprocess.CompletedProcess(proc.args, proc.returncode, stdout_text, stderr_text)
        if check and completed.returncode != 0:
            self.fail(
                f"hmemory {args} failed with exit {completed.returncode}:\n"
                f"STDOUT: {stdout_text}\nSTDERR: {stderr_text}"
            )
        return completed

    def run_json(self, *args: str, env_extra: dict | None = None, check: bool = True) -> dict:
        res = self.run_cli(*args, "--json", env_extra=env_extra, check=check)
        data = json.loads(res.stdout)
        self.assertIsInstance(data, dict)
        return data

    def test_help_and_version(self) -> None:
        help_res = self.run_cli("--help")
        self.assertIn("hmemory", help_res.stdout)
        self.assertIn("ingest", help_res.stdout)
        self.assertIn("context", help_res.stdout)

        sub_help = self.run_cli("ingest", "--help")
        self.assertIn("Usage:", sub_help.stdout)

        ver_res = self.run_cli("--version")
        self.assertTrue(ver_res.stdout.strip().startswith("hmemory "))

    def test_uninitialized_db_graceful_reads(self) -> None:
        self.assertFalse(self.db_path.exists())

        st = self.run_json("stats")
        self.assertTrue(st["ok"])
        self.assertFalse(st["initialized"])
        self.assertEqual(st["active_beliefs"], 0)
        self.assertEqual(st["retracted_beliefs"], 0)
        self.assertEqual(st["edges"], 0)
        self.assertFalse(self.db_path.exists())

        qr = self.run_json("query", "sqlite wal")
        self.assertTrue(qr["ok"])
        self.assertEqual(qr["count"], 0)
        self.assertEqual(qr["results"], [])

        ctx = self.run_json("context", "architecture", "--budget-tokens", "300")
        self.assertTrue(ctx["ok"])
        self.assertEqual(ctx["selected_count"], 0)
        self.assertLessEqual(ctx["used_tokens"], 300)
        self.assertIn("<memory_context", ctx["context"])

    def test_db_path_resolution_precedence(self) -> None:
        home_dir = self.tmp_path / "custom_home"
        xdg_dir = self.tmp_path / "custom_xdg"
        env_db = self.tmp_path / "env_dir" / "env_mem.db"
        cli_db = self.tmp_path / "cli_dir" / "cli_mem.db"

        # 1. Default fallback to $HOME/.hephaestus/memory/memory.db
        self.run_json(
            "ingest", "-t", "Home fallback", "-b", "Stored under HOME",
            env_extra={"HEPHAESTUS_MEMORY_DB": None, "XDG_DATA_HOME": None, "HOME": str(home_dir)},
        )
        self.assertTrue((home_dir / ".hephaestus/memory/memory.db").is_file())

        # 2. XDG_DATA_HOME overrides HOME
        self.run_json(
            "ingest", "-t", "XDG path", "-b", "Stored under XDG_DATA_HOME",
            env_extra={"HEPHAESTUS_MEMORY_DB": None, "XDG_DATA_HOME": str(xdg_dir), "HOME": str(home_dir)},
        )
        self.assertTrue((xdg_dir / "hephaestus/memory.db").is_file())

        # 3. HEPHAESTUS_MEMORY_DB overrides XDG_DATA_HOME
        self.run_json(
            "ingest", "-t", "Env path", "-b", "Stored under HEPHAESTUS_MEMORY_DB",
            env_extra={"HEPHAESTUS_MEMORY_DB": str(env_db), "XDG_DATA_HOME": str(xdg_dir), "HOME": str(home_dir)},
        )
        self.assertTrue(env_db.is_file())

        # 4. --db overrides HEPHAESTUS_MEMORY_DB
        self.run_json(
            "ingest", "--db", str(cli_db), "-t", "CLI override", "-b", "Stored at explicit --db",
            env_extra={"HEPHAESTUS_MEMORY_DB": str(env_db)},
        )
        self.assertTrue(cli_db.is_file())

    def test_ingest_kinds_tags_stats_and_validation(self) -> None:
        r1 = self.run_json(
            "ingest", "-t", "Enforce WAL mode", "-b", "Enable SQLite WAL and busy_timeout=5000",
            "--kind", "constraint", "--tags", "sqlite,wal,concurrency",
        )
        self.assertTrue(r1["ok"])
        self.assertEqual(r1["id"], 1)
        self.assertTrue(r1["uid"].startswith("m_"))
        self.assertEqual(r1["kind"], "constraint")
        self.assertEqual(r1["tags"], ["sqlite", "wal", "concurrency"])

        human = self.run_cli(
            "ingest", "-t", "Fix descriptor leak", "-b", "Finalize prepared statement on error path",
            "--kind", "bugfix", "--tags", "c11,sqlite",
        )
        self.assertIn("ingested #2", human.stdout)
        self.assertIn("[bugfix]", human.stdout)

        st = self.run_json("stats")
        self.assertTrue(st["initialized"])
        self.assertEqual(st["active_beliefs"], 2)
        self.assertEqual(st["retracted_beliefs"], 0)
        self.assertEqual(st["by_kind"]["constraint"], 1)
        self.assertEqual(st["by_kind"]["bugfix"], 1)

        bad_kind = self.run_cli("ingest", "-t", "Bad", "-b", "Body", "--kind", "bogus", check=False)
        self.assertNotEqual(bad_kind.returncode, 0)

        missing_body = self.run_cli("ingest", "-t", "Only title", check=False)
        self.assertNotEqual(missing_body.returncode, 0)

    def test_bilingual_english_and_turkish_stemming(self) -> None:
        # English morphological variants + protected technical roots
        en_doc = self.run_json(
            "ingest",
            "-t", "PostgreSQL connection pooled in worker",
            "-b", "Serverless workers reuse pooled database connections cleanly",
            "--kind", "decision",
            "--tags", "postgres,pooling",
        )
        # Turkish UTF-8 diacritics + apostrophe + agglutinative suffixes
        tr_doc = self.run_json(
            "ingest",
            "-t", "Belleğin yönetiminde kilitlenme çözümü",
            "-b", "SQLite'da eşzamanlı yazma işlemlerinde belleğin kilitlenmesini ve kayıt kaybını önler",
            "--kind", "bugfix",
            "--tags", "bellek,veritabani",
        )

        # Query English with different inflections
        q_en = self.run_json("query", "connections pooling processes postgres")
        self.assertGreaterEqual(q_en["count"], 1)
        self.assertEqual(q_en["results"][0]["id"], en_doc["id"])

        # Query Turkish using pure ASCII unaccented stems/inflections
        q_tr = self.run_json("query", "bellek yonetimi kilitlenme kaydi")
        self.assertGreaterEqual(q_tr["count"], 1)
        self.assertEqual(q_tr["results"][0]["id"], tr_doc["id"])

        # Verify human query output works cleanly
        q_human = self.run_cli("query", "veritabani eszamanli")
        self.assertIn(f"#{tr_doc['id']}", q_human.stdout)

    def test_jtms_supersedes_retracts_stale_decisions_with_provenance(self) -> None:
        old_dec = self.run_json(
            "ingest",
            "-t", "Transport protocol v1",
            "-b", "Use HTTP short polling every 5 seconds for build task status",
            "--kind", "decision",
        )
        new_dec = self.run_json(
            "ingest",
            "-t", "Transport protocol v2",
            "-b", "Use WebSocket push stream for build task status updates",
            "--kind", "decision",
            "--supersedes", str(old_dec["id"]),
        )
        self.assertIn(old_dec["id"], new_dec["retracted_ids"])

        # Default query returns ONLY active IN belief
        active_q = self.run_json("query", "build task status")
        returned_ids = [r["id"] for r in active_q["results"]]
        self.assertIn(new_dec["id"], returned_ids)
        self.assertNotIn(old_dec["id"], returned_ids)

        # --include-retracted surfaces full provenance
        all_q = self.run_json("query", "build task status", "--include-retracted")
        by_id = {r["id"]: r for r in all_q["results"]}
        self.assertIn(old_dec["id"], by_id)
        self.assertEqual(by_id[old_dec["id"]]["jtms_status"], "OUT/RETRACTED")
        self.assertEqual(by_id[old_dec["id"]]["retracted_reason"], "superseded")
        self.assertEqual(by_id[old_dec["id"]]["retracted_by"], new_dec["id"])

        # Context strictly excludes retracted decision
        ctx = self.run_json("context", "build task status", "--budget-tokens", "400")
        self.assertIn(new_dec["id"], ctx["selected_ids"])
        self.assertNotIn(old_dec["id"], ctx["selected_ids"])
        self.assertNotIn("short polling", ctx["context"])
        self.assertIn("WebSocket push", ctx["context"])

        # Explain works with UID as well as integer ID
        exp_old = self.run_json("explain", old_dec["uid"])
        self.assertEqual(exp_old["jtms_status"], "OUT/RETRACTED")
        self.assertFalse(exp_old["active"])
        self.assertEqual(exp_old["retracted_reason"], "superseded")
        self.assertEqual(len(exp_old["incoming_edges"]), 1)
        self.assertEqual(exp_old["incoming_edges"][0]["src_id"], new_dec["id"])
        self.assertEqual(exp_old["incoming_edges"][0]["relation"], "supersedes")

        exp_human = self.run_cli("explain", str(old_dec["id"]))
        self.assertIn("OUT/RETRACTED", exp_human.stdout)
        self.assertIn("superseded", exp_human.stdout)

    def test_jtms_supports_cascade_and_nonmonotonic_restoration(self) -> None:
        p1 = self.run_json("ingest", "-t", "Staging Redis cluster", "-b", "Redis 7 cluster is online in staging", "--kind", "fact")
        d1 = self.run_json("ingest", "-t", "Session cache backend", "-b", "Store ephemeral session tokens in distributed KV cache", "--kind", "decision")

        link1 = self.run_json("link", str(p1["id"]), "supports", str(d1["id"]))
        self.assertEqual(link1["dst_jtms_status"], "IN")

        # Superseding P1 must automatically retract BOTH P1 (superseded) and D1 (unsupported)
        p2 = self.run_json("ingest", "-t", "Staging Redis retired", "-b", "Staging Redis cluster was decommissioned", "--kind", "fact")
        link2 = self.run_json("link", str(p2["id"]), "supersedes", str(p1["id"]))
        self.assertIn(p1["id"], link2["retracted_ids"])
        self.assertIn(d1["id"], link2["retracted_ids"])

        exp_d1_out = self.run_json("explain", str(d1["id"]))
        self.assertEqual(exp_d1_out["jtms_status"], "OUT/RETRACTED")
        self.assertEqual(exp_d1_out["retracted_reason"], "unsupported")

        # Supplying a new active premise P3 supporting D1 non-monotonically restores D1 to IN
        p3 = self.run_json("ingest", "-t", "Valkey cluster provisioned", "-b", "Local Valkey KV cluster is active", "--kind", "fact")
        link3 = self.run_json("link", str(p3["id"]), "supports", str(d1["id"]))
        self.assertEqual(link3["dst_jtms_status"], "IN")
        self.assertIn(d1["id"], link3["restored_ids"])

        exp_d1_in = self.run_json("explain", str(d1["id"]))
        self.assertEqual(exp_d1_in["jtms_status"], "IN")
        self.assertTrue(exp_d1_in["active"])

    def test_jtms_contradicts_and_cycle_rejection(self) -> None:
        f1 = self.run_json("ingest", "-t", "Zero-copy mmap works on NFS", "-b", "Assumed safe across shared mounts", "--kind", "fact")
        c1 = self.run_json("ingest", "-t", "SIGBUS on truncated NFS mmap", "-b", "Concurrent truncation triggers SIGBUS on NFS", "--kind", "bugfix")

        lk = self.run_json("link", str(c1["id"]), "contradicts", str(f1["id"]))
        self.assertEqual(lk["dst_jtms_status"], "OUT/RETRACTED")
        self.assertIn(f1["id"], lk["retracted_ids"])

        exp = self.run_json("explain", str(f1["id"]))
        self.assertEqual(exp["retracted_reason"], "contradicted")

        # Cycle detection: A supports B, then B supports A must fail non-zero
        a = self.run_json("ingest", "-t", "Node A", "-b", "Alpha premise", "--kind", "fact")
        b = self.run_json("ingest", "-t", "Node B", "-b", "Beta conclusion", "--kind", "decision")
        self.run_json("link", str(a["id"]), "supports", str(b["id"]))

        cyc = self.run_cli("link", str(b["id"]), "supports", str(a["id"]), check=False)
        self.assertNotEqual(cyc.returncode, 0)

        self_edge = self.run_cli("link", str(a["id"]), "supports", str(a["id"]), check=False)
        self.assertNotEqual(self_edge.returncode, 0)

    def test_actr_access_reinforcement_boosts_salience(self) -> None:
        b_cold = self.run_json(
            "ingest",
            "-t", "Retry jitter policy alpha",
            "-b", "Use exponential retry backoff with bounded jitter alphahorn",
            "--kind", "fact",
        )
        b_hot = self.run_json(
            "ingest",
            "-t", "Retry jitter policy beta",
            "-b", "Use exponential retry backoff with bounded jitter betahorn",
            "--kind", "fact",
        )
        # Reinforce b_hot via repeated retrieval
        for _ in range(5):
            self.run_json("query", "betahorn")

        ranked = self.run_json("query", "exponential retry backoff bounded jitter")
        self.assertGreaterEqual(ranked["count"], 2)
        self.assertEqual(ranked["results"][0]["id"], b_hot["id"])
        self.assertGreater(ranked["results"][0]["access_count"], b_cold.get("access_count", 1))

    def test_context_strict_token_budget_and_utf8_clipping(self) -> None:
        for idx in range(14):
            body = (
                f"Architectural rule {idx}: ensure deterministic transaction boundaries, "
                f"bounded memory buffers, UTF-8 safe clipping (çalışma, güvenlik, doğrulama), "
                f"and strict timeout enforcement across worker shard {idx}."
            )
            self.run_json(
                "ingest",
                "-t", f"Subsystem invariant #{idx}",
                "-b", body,
                "--kind", "constraint" if idx % 2 == 0 else "decision",
                "--tags", f"shard{idx},architecture",
            )

        for budget in (5, 45, 95, 220, 600):
            ctx = self.run_json("context", "architecture transaction", "--budget-tokens", str(budget))
            self.assertTrue(ctx["ok"])
            self.assertEqual(ctx["budget_tokens"], budget)
            self.assertLessEqual(ctx["used_tokens"], budget)
            if budget >= 95:
                self.assertGreater(ctx["selected_count"], 0)
                self.assertIn("<memory_context", ctx["context"])
                self.assertTrue(ctx["context"].endswith("</memory_context>"))

        human_ctx = self.run_cli("context", "--budget-tokens", "140")
        self.assertIn("<memory_context", human_ctx.stdout)
        self.assertIn("</memory_context>", human_ctx.stdout)


if __name__ == "__main__":
    unittest.main()

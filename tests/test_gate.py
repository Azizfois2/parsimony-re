"""Tests for the recorded escalation gate and CLI enforcement wrapper."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import gate  # noqa: E402

FIELDS = [
    "--tier", "2", "--target", "sample.bin",
    "--question", "What is the wire protocol?",
    "--evidence", "Strings and exports were inspected",
    "--why-cheap-fails", "Protocol constants are computed at runtime",
    "--backend-adds", "Decompiled arithmetic and cross references",
    "--stop-condition", "The exact framing is recovered",
]


class GateTests(unittest.TestCase):
    def test_record_check_and_verify(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "gate.jsonl"
            env = dict(os.environ)
            out = subprocess.run(
                [sys.executable, str(SCRIPTS / "gate.py"), "record", "--log", str(log), *FIELDS],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            entry = json.loads(out.stdout)
            self.assertTrue(entry["valid"])
            self.assertTrue(entry["gate_id"].startswith("GATE-"))

            check = subprocess.run(
                [sys.executable, str(SCRIPTS / "gate.py"), "check", "--log", str(log),
                 "--gate-id", entry["gate_id"]],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(check.returncode, 0, check.stderr)

            verify = subprocess.run(
                [sys.executable, str(SCRIPTS / "gate.py"), "verify", "--log", str(log)],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "gate.jsonl"
            subprocess.run(
                [sys.executable, str(SCRIPTS / "gate.py"), "record", "--log", str(log), *FIELDS],
                capture_output=True, text=True, check=True,
            )
            entry = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
            entry["stop_condition"] = "tampered by an agent"
            log.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            result = gate.verify_chain(gate.read_records(log))
            self.assertFalse(result["valid"])
            self.assertEqual(result["reason"], "record_hash mismatch")

    def test_missing_fields_refused(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "gate.jsonl"
            out = subprocess.run(
                [sys.executable, str(SCRIPTS / "gate.py"), "record", "--log", str(log),
                 "--tier", "2", "--question", "short"],
                capture_output=True, text=True,
            )
            self.assertEqual(out.returncode, 2)
            self.assertIn("problems", out.stderr)

    def test_escalate_refuses_without_valid_gate(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "gate.jsonl"
            marker = Path(d) / "ran.txt"
            out = subprocess.run(
                [sys.executable, str(SCRIPTS / "escalate.py"),
                 "--gate-id", "GATE-deadbeef", "--log", str(log), "--",
                 sys.executable, "-c", f"open({str(marker)!r}, 'w').write('ran')"],
                capture_output=True, text=True,
            )
            self.assertEqual(out.returncode, 2)
            self.assertFalse(marker.exists())

    def test_escalate_allows_with_valid_gate(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "gate.jsonl"
            marker = Path(d) / "ran.txt"
            rec = subprocess.run(
                [sys.executable, str(SCRIPTS / "gate.py"), "record", "--log", str(log), *FIELDS],
                capture_output=True, text=True, check=True,
            )
            gate_id = json.loads(rec.stdout)["gate_id"]
            out = subprocess.run(
                [sys.executable, str(SCRIPTS / "escalate.py"),
                 "--gate-id", gate_id, "--log", str(log), "--",
                 sys.executable, "-c", f"open({str(marker)!r}, 'w').write('ran')"],
                capture_output=True, text=True,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertTrue(marker.exists())


if __name__ == "__main__":
    unittest.main()

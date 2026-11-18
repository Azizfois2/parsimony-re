"""Tests for the deterministic tier-0 router (stdlib unittest)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import tier0  # noqa: E402


class DetectFormatTests(unittest.TestCase):
    def test_elf(self):
        self.assertEqual(tier0.detect_format(b"\x7fELF\x02\x01\x01", Path("x"))[0], "elf")

    def test_pe(self):
        self.assertEqual(tier0.detect_format(b"MZ\x90\x00", Path("x"))[0], "pe")

    def test_macho64_le(self):
        self.assertEqual(tier0.detect_format(b"\xcf\xfa\xed\xfe", Path("x"))[0], "macho64-le")

    def test_wasm_and_sqlite(self):
        self.assertEqual(tier0.detect_format(b"\x00asm\x01\x00", Path("x"))[0], "wasm")
        self.assertEqual(tier0.detect_format(b"SQLite format 3\x00", Path("x"))[0], "sqlite")

    def test_unknown(self):
        self.assertEqual(tier0.detect_format(b"plain text", Path("x"))[0], "unknown")


class EntropyTests(unittest.TestCase):
    def test_uniform_low(self):
        self.assertLess(tier0.shannon_entropy(b"aaaaaaaa" * 100), 0.1)

    def test_random_high(self):
        import random
        rnd = random.Random(1234)
        data = bytes(rnd.randrange(256) for _ in range(8192))
        self.assertGreater(tier0.shannon_entropy(data), 7.5)

    def test_sampling_reaches_end_of_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "big.bin"
            p.write_bytes(b"\x00" * (3 * 1024 * 1024) + b"TAILMARKER")
            sample = tier0.sampled_bytes(p, p.stat().st_size)
            self.assertIn(b"TAILMARKER", sample)


class OutputCapTests(unittest.TestCase):
    def test_caps_large_output_and_marks_truncated(self):
        py = sys.executable
        result = tier0.run_command(py, ["-c", "print('x' * 200000)"], max_bytes=256)
        self.assertTrue(result["available"])
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["output"]), 256)

    def test_missing_tool_reports_unavailable(self):
        result = tier0.run_command("definitely-not-a-real-tool-xyz", [])
        self.assertFalse(result["available"])
        self.assertIsNone(result["output"])


class CLITests(unittest.TestCase):
    def test_end_to_end_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sample.bin"
            p.write_bytes(b"\x7fELF\x02\x01\x01" + b"Go buildinf" + b"\x00" * 100)
            out = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "tier0.py"), str(p)],
                capture_output=True, text=True, check=True,
            ).stdout
            data = json.loads(out)
            self.assertEqual(data["format"], "elf")
            self.assertIn("go_buildinfo", data["markers"])
            self.assertEqual(len(data["sha256"]), 64)
            self.assertFalse(data["high_entropy_sample"])


if __name__ == "__main__":
    unittest.main()

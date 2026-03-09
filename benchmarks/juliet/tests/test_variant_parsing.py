from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import sys

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from common import parse_case_filename, stage_for_variant


class VariantParsingTests(unittest.TestCase):
    def test_stage_ranges(self) -> None:
        self.assertEqual(stage_for_variant(1), "A")
        self.assertEqual(stage_for_variant(2), "B")
        self.assertEqual(stage_for_variant(22), "B")
        self.assertEqual(stage_for_variant(31), "B")
        self.assertEqual(stage_for_variant(45), "B")
        self.assertEqual(stage_for_variant(23), "C")
        self.assertEqual(stage_for_variant(None), "C")

    def test_parse_known_case_filename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tc = root / "testcases"
            target = tc / "CWE121"
            target.mkdir(parents=True)
            file_path = target / "CWE121_Stack_Based_Buffer_Overflow__char_type_53a.c"
            file_path.write_text("int x;\n", encoding="utf-8")

            meta = parse_case_filename(file_path, tc)
            self.assertIsNotNone(meta)
            assert meta is not None
            self.assertEqual(meta.cwe, "CWE121")
            self.assertEqual(meta.variant, 53)
            self.assertEqual(meta.variant_part, "a")
            self.assertEqual(meta.family_id, "CWE121_Stack_Based_Buffer_Overflow__char_type_53")

    def test_parse_unknown_filename_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tc = root / "testcases"
            target = tc / "CWE122"
            target.mkdir(parents=True)
            file_path = target / "not_a_juliet_name.c"
            file_path.write_text("int x;\n", encoding="utf-8")

            meta = parse_case_filename(file_path, tc)
            self.assertIsNone(meta)


if __name__ == "__main__":
    unittest.main()

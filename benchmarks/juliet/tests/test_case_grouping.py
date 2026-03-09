from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import sys

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from common import group_files_by_family


class CaseGroupingTests(unittest.TestCase):
    def test_multi_file_variant_grouped_together(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tc = root / "testcases"
            cwe_dir = tc / "CWE121"
            cwe_dir.mkdir(parents=True)

            files = [
                cwe_dir / "CWE121_TestFamily_53a.c",
                cwe_dir / "CWE121_TestFamily_53b.c",
                cwe_dir / "CWE121_TestFamily_53.h",
                cwe_dir / "CWE121_TestFamily_01.c",
            ]
            for path in files:
                path.write_text("int x;\n", encoding="utf-8")

            grouped = group_files_by_family(files, tc)

            self.assertIn("CWE121_TestFamily_53", grouped)
            self.assertEqual(len(grouped["CWE121_TestFamily_53"]), 3)
            self.assertIn("CWE121_TestFamily_01", grouped)
            self.assertEqual(len(grouped["CWE121_TestFamily_01"]), 1)


if __name__ == "__main__":
    unittest.main()

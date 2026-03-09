from __future__ import annotations

import unittest
from pathlib import Path

import sys

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from common import extract_functions_with_ranges, label_function_name


class FunctionLabelingTests(unittest.TestCase):
    def test_extract_and_label_functions(self) -> None:
        source = """
int helper() {
  return 0;
}

static void bad() {
  int x = 1;
}

static void
goodB2G_case(void) {
  int y = 2;
}

void goodG2B_sink() {
  int z = 3;
}
"""
        found = extract_functions_with_ranges(source)
        names = [item[0] for item in found]
        self.assertIn("helper", names)
        self.assertIn("bad", names)
        self.assertIn("goodB2G_case", names)
        self.assertIn("goodG2B_sink", names)

        self.assertIsNone(label_function_name("helper"))
        self.assertEqual(label_function_name("bad"), "positive")
        self.assertEqual(label_function_name("CWE121_demo_bad"), "positive")
        self.assertEqual(label_function_name("goodB2G_case"), "negative")
        self.assertEqual(label_function_name("CWE121_demo_goodB2G"), "negative")
        self.assertEqual(label_function_name("goodG2B_sink"), "exclude")
        self.assertEqual(label_function_name("CWE121_demo_goodG2B"), "exclude")


if __name__ == "__main__":
    unittest.main()

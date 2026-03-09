from __future__ import annotations

import unittest

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from transform_stage_a_clamp_dataset import parse_guard_guarantees, transform_file_content


class ClampTransformTests(unittest.TestCase):
    def test_guard_parsing_incomplete_vs_complete(self) -> None:
        bad_guard = parse_guard_guarantees("data >= 0", "data", 10)
        self.assertTrue(bad_guard.lower_bound)
        self.assertFalse(bad_guard.upper_bound)

        good_guard = parse_guard_guarantees("data >= 0 && data < (10)", "data", 10)
        self.assertTrue(good_guard.lower_bound)
        self.assertTrue(good_guard.upper_bound)
        self.assertEqual(good_guard.upper_index_limit, 9)

    def test_rewrites_bad_and_goodb2g_sinks_and_inserts_helpers(self) -> None:
        content = """#include <stdio.h>

void bad() {
  int data = -1;
  int buffer[10] = {0};
  if (data >= 0) {
    buffer[data] = 1;
  }
}

void goodB2G() {
  int data = -1;
  int buffer[10] = {0};
  if (data >= 0 && data < (10)) {
    buffer[data] = 1;
  }
}
"""
        labels = [
            {"function": "bad", "label": "positive", "start_line": 3, "end_line": 9},
            {"function": "goodB2G", "label": "negative", "start_line": 11, "end_line": 17},
        ]

        transformed, decisions = transform_file_content(content, "sample.c", labels)
        rewritten = [d for d in decisions if d.status == "rewritten"]
        self.assertEqual(len(rewritten), 2)
        bad_decision = next(item for item in rewritten if item.function == "bad")
        good_decision = next(item for item in rewritten if item.function == "goodB2G")
        self.assertFalse(bad_decision.guard_upper_bound)
        self.assertTrue(good_decision.guard_upper_bound)

        self.assertIn("buffer[clamp_bad_bad_7(data)] = 1;", transformed)
        self.assertIn("buffer[clamp_good_goodB2G_15(data)] = 1;", transformed)

        # bad helper for incomplete guard should not add an upper clamp
        self.assertIn("static int clamp_bad_bad_7(int value)", transformed)
        self.assertIn("if (value < 0) return 0;", transformed)
        self.assertIn("static int clamp_good_bad_7(int value)", transformed)
        self.assertIn("if (value > 9) return 9;", transformed)

    def test_non_target_function_is_skipped(self) -> None:
        content = """void bad() {
  int data = 0;
  int x = data + 1;
}
"""
        labels = [
            {"function": "bad", "label": "positive", "start_line": 1, "end_line": 4},
        ]
        transformed, decisions = transform_file_content(content, "no_sink.c", labels)
        self.assertEqual(content, transformed)
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].status, "skipped")
        self.assertEqual(decisions[0].skip_reason, "no_assignment_array_index_sink_in_function")


if __name__ == "__main__":
    unittest.main()

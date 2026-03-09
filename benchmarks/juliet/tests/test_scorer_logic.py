from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


class ScorerLogicTests(unittest.TestCase):
    def test_confusion_matrix_counts(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        score_script = repo_root / "benchmarks/juliet/scripts/score_joern_results.py"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            findings_path = tmp_dir / "findings.json"
            labels_path = tmp_dir / "labels.json"
            out_dir = tmp_dir / "out"

            labels_payload = {
                "functions": [
                    {
                        "case_id": "case1::file1.c::bad",
                        "family_id": "case1",
                        "cwe": "CWE121",
                        "variant": "01",
                        "language": "c",
                        "file": "file1.c",
                        "function": "bad",
                        "start_line": 10,
                        "end_line": 20,
                        "label": "positive",
                        "stage": "A",
                    },
                    {
                        "case_id": "case2::file2.c::goodB2G",
                        "family_id": "case2",
                        "cwe": "CWE122",
                        "variant": "01",
                        "language": "c",
                        "file": "file2.c",
                        "function": "goodB2G",
                        "start_line": 30,
                        "end_line": 40,
                        "label": "negative",
                        "stage": "A",
                    },
                ]
            }
            findings_payload = {
                "findings": [
                    {
                        "case_id": "file1.c::bad",
                        "file": "file1.c",
                        "function": "bad",
                        "sink_line": 12,
                        "sink_code": "memcpy(dst, src, len)",
                        "trace": [],
                        "stage": "A",
                        "config": "master",
                    },
                    {
                        "case_id": "file2.c::goodB2G",
                        "file": "file2.c",
                        "function": "goodB2G",
                        "sink_line": 35,
                        "sink_code": "memcpy(dst, src, len)",
                        "trace": [],
                        "stage": "A",
                        "config": "master",
                    },
                ]
            }

            findings_path.write_text(json.dumps(findings_payload), encoding="utf-8")
            labels_path.write_text(json.dumps(labels_payload), encoding="utf-8")

            subprocess.run(
                [
                    "python3",
                    str(score_script),
                    "--findings",
                    str(findings_path),
                    "--labels",
                    str(labels_path),
                    "--out",
                    str(out_dir),
                ],
                check=True,
            )

            summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
            overall = summary["overall"]

            self.assertEqual(overall["TP"], 1)
            self.assertEqual(overall["FP"], 1)
            self.assertEqual(overall["TN"], 0)
            self.assertEqual(overall["FN"], 0)

    def test_line_range_fallback_matching(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        score_script = repo_root / "benchmarks/juliet/scripts/score_joern_results.py"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            findings_path = tmp_dir / "findings.json"
            labels_path = tmp_dir / "labels.json"
            out_dir = tmp_dir / "out"

            labels_payload = {
                "functions": [
                    {
                        "case_id": "case3::file3.c::bad",
                        "family_id": "case3",
                        "cwe": "CWE121",
                        "variant": "02",
                        "language": "c",
                        "file": "file3.c",
                        "function": "bad",
                        "start_line": 100,
                        "end_line": 120,
                        "label": "positive",
                        "stage": "B",
                    }
                ]
            }
            findings_payload = {
                "findings": [
                    {
                        "case_id": "file3.c::unknown",
                        "file": "file3.c",
                        "function": "not_the_right_name",
                        "sink_line": 110,
                        "sink_code": "memcpy(dst, src, len)",
                        "trace": [],
                        "stage": "B",
                        "config": "master",
                    }
                ]
            }

            findings_path.write_text(json.dumps(findings_payload), encoding="utf-8")
            labels_path.write_text(json.dumps(labels_payload), encoding="utf-8")

            subprocess.run(
                [
                    "python3",
                    str(score_script),
                    "--findings",
                    str(findings_path),
                    "--labels",
                    str(labels_path),
                    "--out",
                    str(out_dir),
                ],
                check=True,
            )

            summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
            overall = summary["overall"]

            self.assertEqual(overall["TP"], 1)
            self.assertEqual(overall["FP"], 0)
            self.assertEqual(overall["TN"], 0)
            self.assertEqual(overall["FN"], 0)

    def test_suffix_path_matching_for_derived_paths(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        score_script = repo_root / "benchmarks/juliet/scripts/score_joern_results.py"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            findings_path = tmp_dir / "findings.json"
            labels_path = tmp_dir / "labels.json"
            out_dir = tmp_dir / "out"

            labels_payload = {
                "functions": [
                    {
                        "case_id": "case4::CWE121/sample.c::bad",
                        "family_id": "case4",
                        "cwe": "CWE121",
                        "variant": "01",
                        "language": "c",
                        "file": "CWE121/sample.c",
                        "function": "bad",
                        "start_line": 20,
                        "end_line": 40,
                        "label": "positive",
                        "stage": "A",
                    }
                ]
            }
            findings_payload = {
                "findings": [
                    {
                        "case_id": "sample.c::bad",
                        "file": "/tmp/derived/A/CWE121/sample.c",
                        "function": "bad",
                        "sink_line": 30,
                        "sink_code": "buffer[data] = 1",
                        "trace": [],
                        "stage": "A",
                        "config": "derived_master_int_array",
                    }
                ]
            }

            findings_path.write_text(json.dumps(findings_payload), encoding="utf-8")
            labels_path.write_text(json.dumps(labels_payload), encoding="utf-8")

            subprocess.run(
                [
                    "python3",
                    str(score_script),
                    "--findings",
                    str(findings_path),
                    "--labels",
                    str(labels_path),
                    "--out",
                    str(out_dir),
                ],
                check=True,
            )

            summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
            overall = summary["overall"]
            self.assertEqual(overall["TP"], 1)
            self.assertEqual(overall["FP"], 0)
            self.assertEqual(overall["FN"], 0)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


class SanitizerDecisionScoringTests(unittest.TestCase):
    def test_build_clamp_callsite_oracle_uses_rewritten_line_when_available(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        builder = repo_root / "benchmarks/juliet/scripts/build_clamp_callsite_oracle.py"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifests = root / "manifests"
            manifests.mkdir(parents=True)

            derived_root = root / "derived" / "A"
            source_file = derived_root / "CWE121/example.c"
            source_file.parent.mkdir(parents=True, exist_ok=True)
            source_file.write_text(
                "\n".join(
                    [
                        "int clamp_good_goodB2G_10(int x){return x;}",
                        "void goodB2G(){",
                        "  int data = 0;",
                        "  int buffer[10] = {0};",
                        "  if (data >= 0) {",
                        "    buffer[clamp_good_goodB2G_10(data)] = 1;",
                        "  }",
                        "}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            stage_manifest = manifests / "stage_a_cases.json"
            stage_manifest.write_text(
                json.dumps(
                    {
                        "stage": "A",
                        "cases": [
                            {
                                "cwe": "CWE121",
                                "variant_text": "01",
                                "languages": ["c"],
                                "files": ["CWE121/example.c"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            transform_manifest = manifests / "stage_a_clamp_transform_manifest.json"
            transform_manifest.write_text(
                json.dumps(
                    {
                        "source_stage_manifest": str(stage_manifest),
                        "derived_stage_root": str(derived_root),
                        "decisions": [
                            {
                                "status": "rewritten",
                                "file": "CWE121/example.c",
                                "function": "goodB2G",
                                "sink_line": 10,
                                "rewritten_with": "clamp_good_goodB2G_10",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            out_json = root / "oracle.json"
            subprocess.run(
                [
                    "python3",
                    str(builder),
                    "--transform-manifests",
                    str(transform_manifest),
                    "--out",
                    str(out_json),
                ],
                check=True,
                cwd=repo_root,
            )

            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["record_count"], 1)
            row = payload["records"][0]
            self.assertEqual(row["sink_line_manifest"], 10)
            self.assertEqual(row["sink_line_source"], "rewritten")
            self.assertEqual(row["sink_line"], 6)

    def test_build_clamp_callsite_oracle_rewritten_only(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        builder = repo_root / "benchmarks/juliet/scripts/build_clamp_callsite_oracle.py"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifests = root / "manifests"
            manifests.mkdir(parents=True)

            stage_manifest = manifests / "stage_a_cases.json"
            stage_manifest.write_text(
                json.dumps(
                    {
                        "stage": "A",
                        "cases": [
                            {
                                "cwe": "CWE121",
                                "variant_text": "01",
                                "languages": ["c"],
                                "files": ["CWE121/example.c"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            transform_manifest = manifests / "stage_a_clamp_transform_manifest.json"
            transform_manifest.write_text(
                json.dumps(
                    {
                        "source_stage_manifest": str(stage_manifest),
                        "decisions": [
                            {
                                "status": "rewritten",
                                "file": "CWE121/example.c",
                                "function": "goodB2G",
                                "sink_line": 10,
                                "rewritten_with": "clamp_good_goodB2G_10",
                                "helper_bad": "clamp_bad_goodB2G_10",
                                "helper_good": "clamp_good_goodB2G_10",
                            },
                            {
                                "status": "rewritten",
                                "file": "CWE121/example.c",
                                "function": "badSink",
                                "sink_line": 20,
                                "rewritten_with": "clamp_bad_badSink_20",
                                "helper_bad": "clamp_bad_badSink_20",
                                "helper_good": "clamp_good_badSink_20",
                            },
                            {
                                "status": "rewritten",
                                "file": "CWE121/example.c",
                                "function": "helper",
                                "sink_line": 30,
                                "rewritten_with": "not_a_clamp_name",
                            },
                            {
                                "status": "skipped",
                                "file": "CWE121/example.c",
                                "function": "ignored",
                                "sink_line": 40,
                                "rewritten_with": "clamp_good_ignored_40",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            out_json = root / "oracle.json"
            subprocess.run(
                [
                    "python3",
                    str(builder),
                    "--transform-manifests",
                    str(transform_manifest),
                    "--out",
                    str(out_json),
                ],
                check=True,
                cwd=repo_root,
            )

            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["record_count"], 2)
            labels = sorted(record["expected_label"] for record in payload["records"])
            self.assertEqual(labels, ["non_sanitizer", "sanitizer"])
            for record in payload["records"]:
                self.assertEqual(record["cwe"], "CWE121")
                self.assertEqual(record["variant"], "01")
                self.assertEqual(record["language"], "c")

    def test_score_sanitizer_decisions_matrix_and_buckets(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        scorer = repo_root / "benchmarks/juliet/scripts/score_sanitizer_decisions.py"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            oracle_json = root / "oracle.json"
            decisions_json = root / "decisions.json"
            out_dir = root / "out"

            oracle_json.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "stage": "A",
                                "file": "CWE121/example.c",
                                "sink_line": 10,
                                "function": "goodB2G",
                                "callee_helper_full_name": "clamp_good_goodB2G_10",
                                "callee_helper_base_name": "clamp_good_goodB2G_10",
                                "expected_label": "sanitizer",
                                "cwe": "CWE121",
                                "variant": "01",
                                "language": "c",
                            },
                            {
                                "stage": "A",
                                "file": "CWE121/example.c",
                                "sink_line": 20,
                                "function": "badSink",
                                "callee_helper_full_name": "clamp_bad_badSink_20",
                                "callee_helper_base_name": "clamp_bad_badSink_20",
                                "expected_label": "non_sanitizer",
                                "cwe": "CWE121",
                                "variant": "01",
                                "language": "c",
                            },
                            {
                                "stage": "A",
                                "file": "CWE121/example.c",
                                "sink_line": 40,
                                "function": "goodB2G2",
                                "callee_helper_full_name": "clamp_good_goodB2G_40",
                                "callee_helper_base_name": "clamp_good_goodB2G_40",
                                "expected_label": "sanitizer",
                                "cwe": "CWE121",
                                "variant": "01",
                                "language": "c",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            decisions_json.write_text(
                json.dumps(
                    {
                        "decisions": [
                            {
                                "stage": "A",
                                "config": "cfg",
                                "callsite_file": str((root / "CWE121/example.c").resolve()),
                                "callsite_line": 10,
                                "caller_function": "goodB2G",
                                "callee_method_full_name": "clamp_good_goodB2G_10",
                                "callee_method_name": "clamp_good_goodB2G_10",
                                "decision_source": "discovered",
                                "predicted_sanitizer": "true",
                                "reason": "discovery_validated",
                            },
                            {
                                "stage": "A",
                                "config": "cfg",
                                "callsite_file": str((root / "CWE121/example.c").resolve()),
                                "callsite_line": 20,
                                "caller_function": "badSink",
                                "callee_method_full_name": "clamp_bad_badSink_20",
                                "callee_method_name": "clamp_bad_badSink_20",
                                "decision_source": "discovered",
                                "predicted_sanitizer": "false",
                                "reason": "discovery_rejected",
                            },
                            {
                                "stage": "A",
                                "config": "cfg",
                                "callsite_file": str((root / "CWE121/example.c").resolve()),
                                "callsite_line": 30,
                                "caller_function": "other",
                                "callee_method_full_name": "some_non_oracle_function",
                                "callee_method_name": "some_non_oracle_function",
                                "decision_source": "discovered",
                                "predicted_sanitizer": "true",
                                "reason": "discovery_validated",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            subprocess.run(
                [
                    "python3",
                    str(scorer),
                    "--decisions",
                    str(decisions_json),
                    "--oracle",
                    str(oracle_json),
                    "--out",
                    str(out_dir),
                ],
                check=True,
                cwd=repo_root,
            )

            summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
            combined = summary["matrices"]["combined"]
            self.assertEqual(combined["TP"], 1)
            self.assertEqual(combined["TN"], 1)
            self.assertEqual(combined["FP"], 0)
            self.assertEqual(combined["FN"], 0)
            self.assertEqual(combined["unresolved_oracle"], 1)
            self.assertEqual(summary["counts"]["out_of_oracle_true"], 1)
            self.assertEqual(summary["counts"]["out_of_oracle_false"], 0)

            modeled = summary["matrices"]["modeled"]
            self.assertEqual(modeled["unresolved_oracle"], 3)
            self.assertEqual(modeled["decided_count"], 0)

            discovered = summary["matrices"]["discovered"]
            self.assertEqual(discovered["TP"], 1)
            self.assertEqual(discovered["TN"], 1)
            self.assertEqual(discovered["unresolved_oracle"], 1)

    def test_score_sanitizer_decisions_fallback_match_by_file_and_callee(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        scorer = repo_root / "benchmarks/juliet/scripts/score_sanitizer_decisions.py"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            oracle_json = root / "oracle.json"
            decisions_json = root / "decisions.json"
            out_dir = root / "out"

            oracle_json.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "stage": "A",
                                "file": "CWE121/example.c",
                                "sink_line": 98,
                                "function": "goodB2G",
                                "callee_helper_full_name": "clamp_good_goodB2G_98",
                                "callee_helper_base_name": "clamp_good_goodB2G_98",
                                "expected_label": "sanitizer",
                                "cwe": "CWE121",
                                "variant": "01",
                                "language": "c",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            decisions_json.write_text(
                json.dumps(
                    {
                        "decisions": [
                            {
                                "stage": "A",
                                "config": "cfg",
                                "callsite_file": str((root / "CWE121/example.c").resolve()),
                                "callsite_line": 119,
                                "caller_function": "goodB2G",
                                "callee_method_full_name": "clamp_good_goodB2G_98",
                                "callee_method_name": "clamp_good_goodB2G_98",
                                "decision_source": "discovered",
                                "predicted_sanitizer": "true",
                                "reason": "discovery_validated",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            subprocess.run(
                [
                    "python3",
                    str(scorer),
                    "--decisions",
                    str(decisions_json),
                    "--oracle",
                    str(oracle_json),
                    "--out",
                    str(out_dir),
                ],
                check=True,
                cwd=repo_root,
            )

            summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
            combined = summary["matrices"]["combined"]
            self.assertEqual(combined["TP"], 1)
            self.assertEqual(combined["FP"], 0)
            self.assertEqual(combined["TN"], 0)
            self.assertEqual(combined["FN"], 0)
            self.assertEqual(combined["unresolved_oracle"], 0)


if __name__ == "__main__":
    unittest.main()

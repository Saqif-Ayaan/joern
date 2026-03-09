from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


class CuratedSubsetTests(unittest.TestCase):
    def test_curates_only_files_with_bad_or_goodb2g_matches(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        script = repo_root / "benchmarks/juliet/scripts/curate_stage_a_by_findings.py"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            derived_root = root / "derived" / "A"
            derived_root.mkdir(parents=True)

            file_a = derived_root / "CWE121/sample_a.c"
            file_b = derived_root / "CWE121/sample_b.c"
            file_a.parent.mkdir(parents=True, exist_ok=True)
            file_a.write_text("void bad(){}\n", encoding="utf-8")
            file_b.write_text("void goodG2B(){}\n", encoding="utf-8")

            stage_manifest = {
                "stage": "A",
                "case_count": 2,
                "file_count": 2,
                "cases": [
                    {
                        "family_id": "case_a",
                        "cwe": "CWE121",
                        "variant": 1,
                        "variant_text": "01",
                        "stage": "A",
                        "languages": ["c"],
                        "variant_parts": [],
                        "file_count": 1,
                        "files": ["CWE121/sample_a.c"],
                    },
                    {
                        "family_id": "case_b",
                        "cwe": "CWE121",
                        "variant": 1,
                        "variant_text": "01",
                        "stage": "A",
                        "languages": ["c"],
                        "variant_parts": [],
                        "file_count": 1,
                        "files": ["CWE121/sample_b.c"],
                    },
                ],
            }
            stage_manifest_path = root / "stage_a_derived_cases.json"
            stage_manifest_path.write_text(json.dumps(stage_manifest), encoding="utf-8")

            findings = {
                "findings": [
                    {
                        "file": str(file_a),
                        "function": "bad",
                        "sink_line": 1,
                    },
                    {
                        "file": str(file_b),
                        "function": "goodG2B",
                        "sink_line": 1,
                    },
                ]
            }
            findings_path = root / "findings.json"
            findings_path.write_text(json.dumps(findings), encoding="utf-8")

            curated_root = root / "curated" / "A" / "int_array_index"
            out_manifest = root / "stage_a_curated_cases.json"
            out_files = root / "stage_a_curated_files.txt"
            out_curation = root / "stage_a_curated_manifest.json"

            subprocess.run(
                [
                    "python3",
                    str(script),
                    "--stage-manifest",
                    str(stage_manifest_path),
                    "--derived-root",
                    str(derived_root),
                    "--findings",
                    str(findings_path),
                    "--out-root",
                    str(curated_root),
                    "--out-stage-manifest",
                    str(out_manifest),
                    "--out-files-manifest",
                    str(out_files),
                    "--out-curation-manifest",
                    str(out_curation),
                    "--clean-out",
                ],
                check=True,
            )

            curated_file_a = curated_root / "CWE121/sample_a.c"
            curated_file_b = curated_root / "CWE121/sample_b.c"
            self.assertTrue(curated_file_a.is_symlink())
            self.assertFalse(curated_file_b.exists())

            curated_payload = json.loads(out_manifest.read_text(encoding="utf-8"))
            self.assertEqual(curated_payload["file_count"], 1)
            self.assertEqual(curated_payload["case_count"], 1)
            self.assertEqual(curated_payload["cases"][0]["family_id"], "case_a")

    def test_structural_mode_backfills_from_labels(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        script = repo_root / "benchmarks/juliet/scripts/curate_stage_a_by_findings.py"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            derived_root = root / "derived" / "A"
            derived_root.mkdir(parents=True)

            file_a = derived_root / "CWE121/sample_a.c"
            file_b = derived_root / "CWE121/sample_b.c"
            file_a.parent.mkdir(parents=True, exist_ok=True)
            file_a.write_text("void bad(){int buffer[10]={0}; int data=1; buffer[data]=1;}\n", encoding="utf-8")
            file_b.write_text("void goodB2G(){int x=0;}\n", encoding="utf-8")

            stage_manifest = {
                "stage": "A",
                "case_count": 2,
                "file_count": 2,
                "cases": [
                    {
                        "family_id": "case_a",
                        "cwe": "CWE121",
                        "variant": 1,
                        "variant_text": "01",
                        "stage": "A",
                        "languages": ["c"],
                        "variant_parts": [],
                        "file_count": 1,
                        "files": ["CWE121/sample_a.c"],
                    },
                    {
                        "family_id": "case_b",
                        "cwe": "CWE121",
                        "variant": 1,
                        "variant_text": "01",
                        "stage": "A",
                        "languages": ["c"],
                        "variant_parts": [],
                        "file_count": 1,
                        "files": ["CWE121/sample_b.c"],
                    },
                ],
            }
            stage_manifest_path = root / "stage_a_derived_cases.json"
            stage_manifest_path.write_text(json.dumps(stage_manifest), encoding="utf-8")

            findings = {"findings": []}
            findings_path = root / "findings.json"
            findings_path.write_text(json.dumps(findings), encoding="utf-8")

            labels = {
                "functions": [
                    {
                        "file": "CWE121/sample_a.c",
                        "function": "bad",
                        "label": "positive",
                    },
                    {
                        "file": "CWE121/sample_b.c",
                        "function": "goodB2G",
                        "label": "negative",
                    },
                ]
            }
            labels_path = root / "labels.json"
            labels_path.write_text(json.dumps(labels), encoding="utf-8")

            curated_root = root / "curated" / "A" / "int_array_index"
            out_manifest = root / "stage_a_curated_cases.json"
            out_files = root / "stage_a_curated_files.txt"
            out_curation = root / "stage_a_curated_manifest.json"

            subprocess.run(
                [
                    "python3",
                    str(script),
                    "--stage-manifest",
                    str(stage_manifest_path),
                    "--derived-root",
                    str(derived_root),
                    "--findings",
                    str(findings_path),
                    "--labels",
                    str(labels_path),
                    "--selection-mode",
                    "matched_flow_or_structural_index",
                    "--out-root",
                    str(curated_root),
                    "--out-stage-manifest",
                    str(out_manifest),
                    "--out-files-manifest",
                    str(out_files),
                    "--out-curation-manifest",
                    str(out_curation),
                    "--clean-out",
                ],
                check=True,
            )

            self.assertTrue((curated_root / "CWE121/sample_a.c").is_symlink())
            self.assertFalse((curated_root / "CWE121/sample_b.c").exists())

            curation_payload = json.loads(out_curation.read_text(encoding="utf-8"))
            self.assertEqual(curation_payload["flow_selected_file_count"], 0)
            self.assertEqual(curation_payload["structural_selected_file_count"], 1)
            self.assertEqual(curation_payload["selected_file_count"], 1)

    def test_clamp_transformable_only_mode(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        script = repo_root / "benchmarks/juliet/scripts/curate_stage_a_by_findings.py"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            derived_root = root / "derived" / "A"
            derived_root.mkdir(parents=True)

            file_a = derived_root / "CWE121/sample_a.c"
            file_b = derived_root / "CWE121/sample_b.c"
            file_a.parent.mkdir(parents=True, exist_ok=True)
            file_a.write_text("void bad(){int x;}\n", encoding="utf-8")
            file_b.write_text("void bad(){int y;}\n", encoding="utf-8")

            stage_manifest = {
                "stage": "A",
                "case_count": 2,
                "file_count": 2,
                "cases": [
                    {
                        "family_id": "case_a",
                        "cwe": "CWE121",
                        "variant": 1,
                        "variant_text": "01",
                        "stage": "A",
                        "languages": ["c"],
                        "variant_parts": [],
                        "file_count": 1,
                        "files": ["CWE121/sample_a.c"],
                    },
                    {
                        "family_id": "case_b",
                        "cwe": "CWE121",
                        "variant": 1,
                        "variant_text": "01",
                        "stage": "A",
                        "languages": ["c"],
                        "variant_parts": [],
                        "file_count": 1,
                        "files": ["CWE121/sample_b.c"],
                    },
                ],
            }
            stage_manifest_path = root / "stage_a_derived_cases.json"
            stage_manifest_path.write_text(json.dumps(stage_manifest), encoding="utf-8")

            findings_path = root / "findings.json"
            findings_path.write_text(json.dumps({"findings": []}), encoding="utf-8")

            transform_manifest = {
                "decisions": [
                    {"file": "CWE121/sample_a.c", "status": "rewritten"},
                    {"file": "CWE121/sample_b.c", "status": "skipped"},
                ]
            }
            transform_manifest_path = root / "transform_manifest.json"
            transform_manifest_path.write_text(json.dumps(transform_manifest), encoding="utf-8")

            curated_root = root / "curated" / "A" / "int_array_index"
            out_manifest = root / "stage_a_curated_cases.json"
            out_files = root / "stage_a_curated_files.txt"
            out_curation = root / "stage_a_curated_manifest.json"

            subprocess.run(
                [
                    "python3",
                    str(script),
                    "--stage-manifest",
                    str(stage_manifest_path),
                    "--derived-root",
                    str(derived_root),
                    "--findings",
                    str(findings_path),
                    "--transform-manifest",
                    str(transform_manifest_path),
                    "--selection-mode",
                    "clamp_transformable_only",
                    "--out-root",
                    str(curated_root),
                    "--out-stage-manifest",
                    str(out_manifest),
                    "--out-files-manifest",
                    str(out_files),
                    "--out-curation-manifest",
                    str(out_curation),
                    "--clean-out",
                ],
                check=True,
            )

            self.assertTrue((curated_root / "CWE121/sample_a.c").is_symlink())
            self.assertFalse((curated_root / "CWE121/sample_b.c").exists())

            curation_payload = json.loads(out_curation.read_text(encoding="utf-8"))
            self.assertEqual(curation_payload["clamp_transformable_file_count"], 1)
            self.assertEqual(curation_payload["selected_file_count"], 1)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(os.environ.get("JOERN_SMOKE") == "1", "Set JOERN_SMOKE=1 to run real runner smoke test")
class RunnerSmokeTests(unittest.TestCase):
    def test_runner_outputs_findings_and_metadata(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        runner = repo_root / "benchmarks/juliet/scripts/run_joern_on_subset.py"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staged_root = root / "outputs" / "staged"
            manifests_root = root / "manifests"
            staged_a = staged_root / "A" / "CWE121"
            staged_a.mkdir(parents=True)
            manifests_root.mkdir(parents=True)

            source_file = staged_a / "CWE121_Smoke_01.c"
            source_file.write_text(
                """
#include <stdlib.h>
#include <string.h>

void smoke_bad(size_t len, char *src) {
  char *dst = (char *)malloc(len + 8);
  memcpy(dst, src, len + 7);
}
""",
                encoding="utf-8",
            )

            stage_manifest = {
                "stage": "A",
                "case_count": 1,
                "file_count": 1,
                "cases": [
                    {
                        "family_id": "CWE121_Smoke_01",
                        "files": ["CWE121/CWE121_Smoke_01.c"],
                        "stage": "A",
                    }
                ],
            }
            (manifests_root / "stage_a_cases.json").write_text(json.dumps(stage_manifest), encoding="utf-8")

            cfg_path = root / "benchmark_config.yaml"
            cfg_path.write_text(
                "\n".join(
                    [
                        f"juliet_root: {root}",
                        "tools:",
                        f"  joern: {str((repo_root / 'joern').resolve())}",
                        f"  joern_parse: {str((repo_root / 'joern-parse').resolve())}",
                        "  run_script: benchmarks/juliet/scripts/run_bof_workflow.sc",
                        "paths:",
                        f"  staged_root: {staged_root}",
                        f"  cache_root: {root / 'outputs' / 'cache'}",
                        f"  findings_root: {root / 'outputs' / 'findings'}",
                        f"  logs_root: {root / 'outputs' / 'logs'}",
                        f"  manifests_root: {manifests_root}",
                        "configs:",
                        "  master:",
                        "    modeled_policy: ENFORCE",
                        "    discovery_enabled: false",
                        "    flow_mode: int_array_index",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            subprocess.run(
                [
                    "python3",
                    str(runner),
                    "--stage",
                    "A",
                    "--config",
                    "master",
                    "--config-file",
                    str(cfg_path),
                    "--force",
                    "--rebuild-cpg",
                ],
                check=True,
                cwd=repo_root,
            )

            findings = root / "outputs" / "findings" / "master" / "stage_a_findings.json"
            sanitizer_decisions = root / "outputs" / "findings" / "master" / "stage_a_sanitizer_decisions.json"
            metadata = root / "outputs" / "findings" / "master" / "stage_a_metadata.json"
            self.assertTrue(findings.is_file())
            self.assertTrue(sanitizer_decisions.is_file())
            self.assertTrue(metadata.is_file())

            findings_payload = json.loads(findings.read_text(encoding="utf-8"))
            self.assertIn("findings", findings_payload)
            if findings_payload["findings"]:
                first = findings_payload["findings"][0]
                for key in ["case_id", "file", "function", "sink_line", "sink_code", "trace", "stage", "config"]:
                    self.assertIn(key, first)

            metadata_payload = json.loads(metadata.read_text(encoding="utf-8"))
            for key in ["git_sha", "stage", "config", "runtime_seconds", "case_count", "file_count", "flow_mode"]:
                self.assertIn(key, metadata_payload)
            self.assertIn("sanitizer_decision_count", metadata_payload)
            self.assertIn("sanitizer_decisions", metadata_payload["outputs"])


if __name__ == "__main__":
    unittest.main()

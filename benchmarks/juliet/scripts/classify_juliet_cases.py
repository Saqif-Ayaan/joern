#!/usr/bin/env python3
"""Label Juliet functions as positive/negative/exclude for scoring."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import List

from common import (
    SOURCE_EXTENSIONS,
    extract_functions_with_ranges,
    label_function_name,
    load_json,
    now_epoch_ms,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage-manifest", required=True, help="Path to stage_*_cases.json")
    parser.add_argument("--out", required=True, help="Output label JSON path")
    parser.add_argument(
        "--testcases-root",
        help="Optional override root for resolving files listed in stage manifest",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    stage_manifest = Path(args.stage_manifest).resolve()
    out_json = Path(args.out).resolve()
    out_csv = out_json.with_suffix(".csv")

    manifest = load_json(stage_manifest)
    stage = manifest.get("stage", "unknown")
    testcases_root = Path(args.testcases_root).resolve() if args.testcases_root else Path(manifest["testcases_root"]).resolve()

    records: List[dict] = []

    for case in manifest.get("cases", []):
        family_id = case["family_id"]
        cwe = case.get("cwe", "UNKNOWN")
        variant_text = str(case.get("variant_text", "unknown"))
        case_stage = case.get("stage", stage)
        case_languages = case.get("languages", [])
        default_language = case_languages[0] if case_languages else "unknown"

        for rel_file in case.get("files", []):
            file_path = testcases_root / rel_file
            if file_path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            if not file_path.is_file():
                continue

            source = file_path.read_text(encoding="utf-8", errors="replace")
            functions = extract_functions_with_ranges(source)
            for function_name, start_line, end_line in functions:
                label = label_function_name(function_name)
                if label is None:
                    continue

                record = {
                    "case_id": f"{family_id}::{rel_file}::{function_name}",
                    "family_id": family_id,
                    "cwe": cwe,
                    "variant": variant_text,
                    "language": "cpp" if file_path.suffix.lower() != ".c" else "c",
                    "file": rel_file,
                    "function": function_name,
                    "start_line": int(start_line),
                    "end_line": int(end_line),
                    "label": label,
                    "stage": case_stage,
                    "default_language": default_language,
                }
                records.append(record)

    records.sort(key=lambda item: (item["file"], item["start_line"], item["function"]))

    payload = {
        "generated_at_epoch_ms": now_epoch_ms(),
        "stage": stage,
        "stage_manifest": str(stage_manifest),
        "testcases_root": str(testcases_root),
        "function_count": len(records),
        "functions": records,
    }
    write_json(out_json, payload)

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "case_id",
                "family_id",
                "cwe",
                "variant",
                "language",
                "file",
                "function",
                "start_line",
                "end_line",
                "label",
                "stage",
            ],
        )
        writer.writeheader()
        for row in records:
            writer.writerow({key: row[key] for key in writer.fieldnames})

    print(f"Wrote {len(records)} labeled functions to {out_json}")


if __name__ == "__main__":
    main()

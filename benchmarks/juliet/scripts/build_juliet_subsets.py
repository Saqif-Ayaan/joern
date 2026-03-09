#!/usr/bin/env python3
"""Build Stage A/B/C Juliet subsets for CWE121/CWE122."""

from __future__ import annotations

import argparse
import csv
import shutil
from pathlib import Path
from typing import Dict, List

from common import (
    find_testcases_root,
    group_files_by_family,
    iter_target_files,
    now_epoch_ms,
    stage_for_variant,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--juliet-root", required=True, help="Path to unpacked Juliet root")
    parser.add_argument(
        "--out",
        default="benchmarks/juliet",
        help="Benchmark root output directory (default: benchmarks/juliet)",
    )
    parser.add_argument("--clean-staged", action="store_true", help="Delete existing staged trees before creating")
    return parser.parse_args()


def materialize_stage_symlinks(
    stage_name: str,
    files: List[str],
    testcases_root: Path,
    staged_root: Path,
    clean_staged: bool,
) -> None:
    stage_dir = staged_root / stage_name
    if clean_staged and stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    for rel in files:
        src = testcases_root / rel
        dst = stage_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        dst.symlink_to(src.resolve())


def main() -> None:
    args = parse_args()
    juliet_root = Path(args.juliet_root).resolve()
    out_root = Path(args.out).resolve()

    testcases_root = find_testcases_root(juliet_root)
    all_files = list(iter_target_files(testcases_root))
    if not all_files:
        raise SystemExit("No CWE121/CWE122 C/C++ files found under Juliet root")

    grouped = group_files_by_family(all_files, testcases_root)

    stage_cases: Dict[str, List[dict]] = {"A": [], "B": [], "C": []}
    stage_files: Dict[str, List[str]] = {"A": [], "B": [], "C": []}

    for family_id, metas in sorted(grouped.items()):
        variant = next((m.variant for m in metas if m.variant is not None), None)
        stage = stage_for_variant(variant)
        cwe = next((m.cwe for m in metas if m.cwe.startswith("CWE")), "UNKNOWN")
        languages = sorted({m.language for m in metas})
        rel_files = sorted(m.rel_path for m in metas)
        parts = sorted({m.variant_part for m in metas if m.variant_part})

        case = {
            "family_id": family_id,
            "cwe": cwe,
            "variant": variant,
            "variant_text": f"{variant:02d}" if isinstance(variant, int) else "unknown",
            "stage": stage,
            "languages": languages,
            "variant_parts": parts,
            "file_count": len(rel_files),
            "files": rel_files,
        }
        stage_cases[stage].append(case)
        stage_files[stage].extend(rel_files)

    manifests_dir = out_root / "manifests"
    staged_root = out_root / "outputs" / "staged"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    staged_root.mkdir(parents=True, exist_ok=True)

    for stage in ("A", "B", "C"):
        unique_files = sorted(set(stage_files[stage]))
        stage_suffix = stage.lower()

        materialize_stage_symlinks(stage, unique_files, testcases_root, staged_root, args.clean_staged)

        files_manifest = manifests_dir / f"stage_{stage_suffix}_files.txt"
        files_manifest.write_text("\n".join(unique_files) + ("\n" if unique_files else ""), encoding="utf-8")

        cases_csv = manifests_dir / f"stage_{stage_suffix}_cases.csv"
        with cases_csv.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "family_id",
                    "cwe",
                    "variant",
                    "variant_text",
                    "stage",
                    "languages",
                    "variant_parts",
                    "file_count",
                    "files",
                ],
            )
            writer.writeheader()
            for case in stage_cases[stage]:
                writer.writerow(
                    {
                        **case,
                        "languages": ",".join(case["languages"]),
                        "variant_parts": ",".join(case["variant_parts"]),
                        "files": ";".join(case["files"]),
                    }
                )

        cases_json = manifests_dir / f"stage_{stage_suffix}_cases.json"
        write_json(
            cases_json,
            {
                "stage": stage,
                "generated_at_epoch_ms": now_epoch_ms(),
                "juliet_root": str(juliet_root),
                "testcases_root": str(testcases_root),
                "case_count": len(stage_cases[stage]),
                "file_count": len(unique_files),
                "cases": stage_cases[stage],
            },
        )

    summary = {
        "generated_at_epoch_ms": now_epoch_ms(),
        "juliet_root": str(juliet_root),
        "testcases_root": str(testcases_root),
        "total_files": len(all_files),
        "total_families": len(grouped),
        "stage_counts": {
            stage: {
                "cases": len(stage_cases[stage]),
                "files": len(set(stage_files[stage])),
            }
            for stage in ("A", "B", "C")
        },
    }
    write_json(manifests_dir / "subset_summary.json", summary)

    print("Created Juliet subsets:")
    for stage in ("A", "B", "C"):
        print(
            f"  Stage {stage}: {len(stage_cases[stage])} cases, "
            f"{len(set(stage_files[stage]))} files, staged at {staged_root / stage}"
        )


if __name__ == "__main__":
    main()

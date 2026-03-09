#!/usr/bin/env python3
"""Create a curated Stage-A subset from transformed files using finding matches."""

from __future__ import annotations

import argparse
import csv
import re
import shutil
from pathlib import Path
from typing import Dict, Iterable, List, Set

from common import load_json, normalize_path, now_epoch_ms, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage-manifest", required=True, help="Path to derived stage_a cases manifest")
    parser.add_argument(
        "--derived-root",
        default="benchmarks/juliet/outputs/derived/A",
        help="Path to derived Stage-A root",
    )
    parser.add_argument("--findings", required=True, help="Findings JSON file for flow mode int_array_index")
    parser.add_argument(
        "--labels",
        help="Optional labels JSON; required for structural fallback mode",
    )
    parser.add_argument(
        "--selection-mode",
        choices=[
            "matched_flow",
            "matched_flow_or_structural_index",
            "clamp_transformable_only",
            "clamp_transformable_and_matched_flow",
        ],
        default="matched_flow",
        help="File selection strategy",
    )
    parser.add_argument(
        "--transform-manifest",
        help="Transformation manifest JSON from transform_stage_a_clamp_dataset.py",
    )
    parser.add_argument(
        "--out-root",
        default="benchmarks/juliet/outputs/curated/A/int_array_index",
        help="Curated output root for selected files",
    )
    parser.add_argument(
        "--out-stage-manifest",
        default="benchmarks/juliet/manifests/stage_a_curated_int_array_index_cases.json",
        help="Output path for curated stage manifest",
    )
    parser.add_argument(
        "--out-files-manifest",
        default="benchmarks/juliet/manifests/stage_a_curated_int_array_index_files.txt",
        help="Output path for curated files list",
    )
    parser.add_argument(
        "--out-curation-manifest",
        default="benchmarks/juliet/manifests/stage_a_curated_int_array_index_manifest.json",
        help="Output path for curation details",
    )
    parser.add_argument("--clean-out", action="store_true", help="Delete curated output root before creating links")
    return parser.parse_args()


def normalize_relative_file(raw_file: str, derived_root: Path) -> str:
    if not raw_file:
        return ""
    candidate = Path(raw_file)
    if candidate.is_absolute():
        try:
            rel = candidate.relative_to(derived_root)
            return normalize_path(rel)
        except ValueError:
            try:
                rel = candidate.resolve().relative_to(derived_root.resolve())
                return normalize_path(rel)
            except ValueError:
                return normalize_path(candidate.name)
    return normalize_path(candidate)


def load_findings(path: Path) -> List[dict]:
    payload = load_json(path)
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        return list(payload["findings"])
    if isinstance(payload, list):
        return list(payload)
    return []


def select_files_from_findings(findings: Iterable[dict], derived_root: Path) -> Set[str]:
    def is_scored_flow_function(function_name: str) -> bool:
        return bool(
            function_name.startswith("bad")
            or function_name.startswith("goodB2G")
            or re.search(r"(^|_)bad($|_)", function_name)
            or re.search(r"(^|_)goodB2G", function_name)
        )

    selected: Set[str] = set()
    for finding in findings:
        function = str(finding.get("function", ""))
        if not is_scored_flow_function(function):
            continue
        rel_file = normalize_relative_file(str(finding.get("file", "")), derived_root)
        if rel_file:
            selected.add(rel_file)
    return selected


def load_labels(path: Path) -> List[dict]:
    payload = load_json(path)
    if isinstance(payload, dict) and isinstance(payload.get("functions"), list):
        return list(payload["functions"])
    return []


def select_structural_index_files(derived_root: Path, labels: List[dict]) -> Set[str]:
    files_with_scored_labels = {
        str(item.get("file", ""))
        for item in labels
        if str(item.get("label", "")) in {"positive", "negative"}
    }
    index_expr_pattern = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\[\s*[A-Za-z_][A-Za-z0-9_]*\s*\]")

    selected: Set[str] = set()
    for rel_file in sorted(files_with_scored_labels):
        if not rel_file:
            continue
        candidate = derived_root / rel_file
        if not candidate.is_file():
            continue
        if candidate.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
            continue
        content = candidate.read_text(encoding="utf-8", errors="replace")
        if index_expr_pattern.search(content):
            selected.add(normalize_path(rel_file))
    return selected


def load_transform_rewritten_files(path: Path) -> Set[str]:
    payload = load_json(path)
    rewritten = {
        normalize_path(str(item.get("file", "")))
        for item in payload.get("decisions", [])
        if str(item.get("status", "")) == "rewritten"
    }
    return {item for item in rewritten if item}


def materialize_curated_symlinks(derived_root: Path, curated_root: Path, files: Iterable[str]) -> None:
    for rel_file in sorted(set(files)):
        src = derived_root / rel_file
        if not src.exists():
            continue
        dst = curated_root / rel_file
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        dst.symlink_to(src.resolve())


def write_cases_csv(cases: List[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
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
        for case in cases:
            writer.writerow(
                {
                    **case,
                    "languages": ",".join(case.get("languages", [])),
                    "variant_parts": ",".join(case.get("variant_parts", [])),
                    "files": ";".join(case.get("files", [])),
                }
            )


def main() -> None:
    args = parse_args()
    stage_manifest_path = Path(args.stage_manifest).resolve()
    derived_root = Path(args.derived_root).resolve()
    findings_path = Path(args.findings).resolve()
    labels_path = Path(args.labels).resolve() if args.labels else None
    transform_manifest_path = Path(args.transform_manifest).resolve() if args.transform_manifest else None
    out_root = Path(args.out_root).resolve()
    out_stage_manifest = Path(args.out_stage_manifest).resolve()
    out_files_manifest = Path(args.out_files_manifest).resolve()
    out_curation_manifest = Path(args.out_curation_manifest).resolve()
    out_cases_csv = out_stage_manifest.with_suffix(".csv")

    if args.clean_out and out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    stage_manifest = load_json(stage_manifest_path)
    findings = load_findings(findings_path)
    flow_selected_files = select_files_from_findings(findings, derived_root)

    structural_selected_files: Set[str] = set()
    clamp_transformable_files: Set[str] = set()
    if args.selection_mode == "matched_flow_or_structural_index":
        if labels_path is None:
            raise SystemExit("--labels is required for --selection-mode matched_flow_or_structural_index")
        labels = load_labels(labels_path)
        structural_selected_files = select_structural_index_files(derived_root, labels)
        selected_files = set(flow_selected_files) | set(structural_selected_files)
    elif args.selection_mode == "clamp_transformable_only":
        if transform_manifest_path is None:
            raise SystemExit("--transform-manifest is required for --selection-mode clamp_transformable_only")
        clamp_transformable_files = load_transform_rewritten_files(transform_manifest_path)
        selected_files = set(clamp_transformable_files)
    elif args.selection_mode == "clamp_transformable_and_matched_flow":
        if transform_manifest_path is None:
            raise SystemExit("--transform-manifest is required for --selection-mode clamp_transformable_and_matched_flow")
        clamp_transformable_files = load_transform_rewritten_files(transform_manifest_path)
        selected_files = set(clamp_transformable_files).intersection(flow_selected_files)
    else:
        selected_files = set(flow_selected_files)

    selected_cases: List[dict] = []
    selected_file_to_case: Dict[str, str] = {}
    for case in stage_manifest.get("cases", []):
        case_files = sorted(set(case.get("files", [])))
        matched_files = sorted([f for f in case_files if f in selected_files])
        if not matched_files:
            continue
        curated_case = dict(case)
        curated_case["files"] = matched_files
        curated_case["file_count"] = len(matched_files)
        selected_cases.append(curated_case)
        for rel_file in matched_files:
            selected_file_to_case[rel_file] = str(case.get("family_id", ""))

    selected_files_sorted = sorted(selected_file_to_case.keys())
    materialize_curated_symlinks(derived_root, out_root, selected_files_sorted)

    out_files_manifest.parent.mkdir(parents=True, exist_ok=True)
    out_files_manifest.write_text(
        "\n".join(selected_files_sorted) + ("\n" if selected_files_sorted else ""),
        encoding="utf-8",
    )

    curated_stage_manifest = {
        "stage": "A",
        "generated_at_epoch_ms": now_epoch_ms(),
        "juliet_root": stage_manifest.get("juliet_root", ""),
        "testcases_root": str(out_root),
        "case_count": len(selected_cases),
        "file_count": len(selected_files_sorted),
        "source_stage_manifest": str(stage_manifest_path),
        "source_labels_manifest": str(labels_path) if labels_path else "",
        "source_transform_manifest": str(transform_manifest_path) if transform_manifest_path else "",
        "derived_root": str(derived_root),
        "curation_mode": args.selection_mode,
        "cases": selected_cases,
    }
    write_json(out_stage_manifest, curated_stage_manifest)
    write_cases_csv(selected_cases, out_cases_csv)

    file_mappings = [
        {
            "file": rel_file,
            "family_id": selected_file_to_case.get(rel_file, ""),
            "derived_file": str((derived_root / rel_file).resolve()),
            "curated_symlink": str((out_root / rel_file).resolve()),
        }
        for rel_file in selected_files_sorted
    ]

    curation_manifest = {
        "generated_at_epoch_ms": now_epoch_ms(),
        "findings_path": str(findings_path),
        "stage_manifest": str(stage_manifest_path),
        "derived_root": str(derived_root),
        "curated_root": str(out_root),
        "selection_mode": args.selection_mode,
        "finding_count": len(findings),
        "flow_selected_file_count": len(flow_selected_files),
        "structural_selected_file_count": len(structural_selected_files),
        "clamp_transformable_file_count": len(clamp_transformable_files),
        "selected_file_count": len(selected_files_sorted),
        "selected_case_count": len(selected_cases),
        "selected_files": selected_files_sorted,
        "file_mappings": file_mappings,
    }
    write_json(out_curation_manifest, curation_manifest)

    print(f"Curated files: {len(selected_files_sorted)}")
    print(f"Curated cases: {len(selected_cases)}")
    print(f"Curated stage manifest: {out_stage_manifest}")
    print(f"Curation manifest: {out_curation_manifest}")


if __name__ == "__main__":
    main()

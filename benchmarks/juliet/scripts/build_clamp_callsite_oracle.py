#!/usr/bin/env python3
"""Build a clamp callsite oracle from clamp transform manifests.

Oracle rows include only rewritten sink callsites and encode actual sanitizer truth:
  - rewritten_with starts with clamp_good_ => actual sanitizer
  - rewritten_with starts with clamp_bad_  => actual non_sanitizer
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from common import load_json, now_epoch_ms, normalize_path, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--transform-manifests",
        nargs="+",
        required=True,
        help="One or more stage_*_clamp_transform_manifest.json files",
    )
    parser.add_argument("--out", required=True, help="Output oracle JSON path")
    return parser.parse_args()


def infer_stage_from_path(path: Path) -> str:
    text = path.name.lower()
    match = re.search(r"stage_([abc])", text)
    if match:
        return match.group(1).upper()
    return "unknown"


def infer_stage_from_manifest_payload(payload: dict) -> str:
    source_stage_manifest = str(payload.get("source_stage_manifest", ""))
    match = re.search(r"stage_([abc])", source_stage_manifest.lower())
    if match:
        return match.group(1).upper()
    return "unknown"


def file_meta_from_stage_manifest(stage_manifest_path: Optional[Path]) -> Dict[str, dict]:
    if stage_manifest_path is None or not stage_manifest_path.is_file():
        return {}
    payload = load_json(stage_manifest_path)
    out: Dict[str, dict] = {}
    for case in payload.get("cases", []):
        cwe = case.get("cwe", "UNKNOWN")
        variant = str(case.get("variant_text", case.get("variant", "unknown")))
        languages = case.get("languages", [])
        default_language = languages[0] if languages else "unknown"
        for rel_file in case.get("files", []):
            out[normalize_path(rel_file)] = {
                "cwe": cwe,
                "variant": variant,
                "language": default_language,
            }
    return out


def normalize_transform_manifest_path(raw: str, transform_manifest_path: Path) -> Optional[Path]:
    if not raw:
        return None
    candidate = Path(raw)
    if candidate.is_absolute():
        return candidate if candidate.is_file() else None
    local = (transform_manifest_path.parent / candidate).resolve()
    if local.is_file():
        return local
    repo_relative = (Path.cwd() / candidate).resolve()
    if repo_relative.is_file():
        return repo_relative
    return None


def normalize_dir_path(raw: str, transform_manifest_path: Path) -> Optional[Path]:
    if not raw:
        return None
    candidate = Path(raw)
    if candidate.is_absolute():
        return candidate if candidate.is_dir() else None
    local = (transform_manifest_path.parent / candidate).resolve()
    if local.is_dir():
        return local
    repo_relative = (Path.cwd() / candidate).resolve()
    if repo_relative.is_dir():
        return repo_relative
    return None


def expected_label_for_helper(helper: str) -> Optional[str]:
    if helper.startswith("clamp_good_"):
        return "sanitizer"
    if helper.startswith("clamp_bad_"):
        return "non_sanitizer"
    return None


def helper_base_name(helper: str) -> str:
    # Transform manifests already store uncloned helper names; keep as-is.
    return helper


def rewritten_callsite_line(
    derived_stage_root: Optional[Path],
    rel_file: str,
    helper_name: str,
    manifest_sink_line: int,
) -> Tuple[int, str]:
    if derived_stage_root is None:
        return manifest_sink_line, "manifest"
    source_file = (derived_stage_root / rel_file).resolve()
    if not source_file.is_file():
        return manifest_sink_line, "manifest"

    try:
        lines = source_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return manifest_sink_line, "manifest"

    pattern = re.compile(rf"\b{re.escape(helper_name)}\s*\(")
    matches = [line_no for line_no, text in enumerate(lines, start=1) if pattern.search(text)]
    if not matches:
        return manifest_sink_line, "manifest"
    if len(matches) == 1:
        return matches[0], "rewritten"
    chosen = min(matches, key=lambda line_no: abs(line_no - manifest_sink_line))
    return chosen, "rewritten"


def build_rows(transform_manifest_path: Path) -> List[dict]:
    payload = load_json(transform_manifest_path)
    stage = infer_stage_from_manifest_payload(payload)
    if stage == "unknown":
        stage = infer_stage_from_path(transform_manifest_path)

    stage_manifest_path = normalize_transform_manifest_path(
        str(payload.get("source_stage_manifest", "")),
        transform_manifest_path,
    )
    derived_stage_root = normalize_dir_path(
        str(payload.get("derived_stage_root", "")),
        transform_manifest_path,
    )
    file_meta = file_meta_from_stage_manifest(stage_manifest_path)

    rows: List[dict] = []
    for entry in payload.get("decisions", []):
        if str(entry.get("status", "")) != "rewritten":
            continue
        rewritten_with = str(entry.get("rewritten_with", "")).strip()
        expected = expected_label_for_helper(rewritten_with)
        if expected is None:
            continue
        rel_file = normalize_path(str(entry.get("file", "")))
        if not rel_file:
            continue
        manifest_sink_line = int(entry.get("sink_line", -1) or -1)
        if manifest_sink_line < 0:
            continue
        sink_line, sink_line_source = rewritten_callsite_line(
            derived_stage_root=derived_stage_root,
            rel_file=rel_file,
            helper_name=rewritten_with,
            manifest_sink_line=manifest_sink_line,
        )
        meta = file_meta.get(rel_file, {})
        rows.append(
            {
                "stage": stage,
                "file": rel_file,
                "sink_line": sink_line,
                "sink_line_manifest": manifest_sink_line,
                "sink_line_source": sink_line_source,
                "function": str(entry.get("function", "")),
                "callee_helper_full_name": rewritten_with,
                "callee_helper_base_name": helper_base_name(rewritten_with),
                "expected_label": expected,
                "cwe": str(meta.get("cwe", "UNKNOWN")),
                "variant": str(meta.get("variant", "unknown")),
                "language": str(meta.get("language", "unknown")),
                "transform_manifest": str(transform_manifest_path),
            }
        )
    return rows


def deduplicate_rows(rows: Iterable[dict]) -> List[dict]:
    keyed: Dict[Tuple[str, str, int, str], dict] = {}
    for row in rows:
        key = (
            row["stage"],
            row["file"],
            int(row["sink_line"]),
            row["callee_helper_base_name"],
        )
        keyed[key] = row
    return sorted(
        keyed.values(),
        key=lambda row: (
            row["stage"],
            row["file"],
            int(row["sink_line"]),
            row["callee_helper_base_name"],
        ),
    )


def main() -> None:
    args = parse_args()
    out_json = Path(args.out).resolve()
    out_csv = out_json.with_suffix(".csv")

    rows: List[dict] = []
    input_paths = [Path(path).resolve() for path in args.transform_manifests]
    for path in input_paths:
        if not path.is_file():
            raise SystemExit(f"Transform manifest not found: {path}")
        rows.extend(build_rows(path))

    rows = deduplicate_rows(rows)

    payload = {
        "generated_at_epoch_ms": now_epoch_ms(),
        "source_transform_manifests": [str(path) for path in input_paths],
        "record_count": len(rows),
        "records": rows,
    }
    write_json(out_json, payload)

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "stage",
                "file",
                "sink_line",
                "sink_line_manifest",
                "sink_line_source",
                "function",
                "callee_helper_full_name",
                "callee_helper_base_name",
                "expected_label",
                "cwe",
                "variant",
                "language",
                "transform_manifest",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in writer.fieldnames})

    print(f"Wrote clamp callsite oracle JSON: {out_json}")
    print(f"Wrote clamp callsite oracle CSV: {out_csv}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Create a derived Stage-A dataset with clamp-helper rewrites for CWE129-style sinks."""

from __future__ import annotations

import argparse
import csv
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from common import SOURCE_EXTENSIONS, load_json, now_epoch_ms, write_json

SINK_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?P<array>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<index>[A-Za-z_][A-Za-z0-9_]*)\s*\]\s*="
)
ARRAY_DECL_PATTERN_TEMPLATE = r"\b{array_name}\s*\[\s*(?P<size>\d+)\s*\]"
IF_LINE_PATTERN = re.compile(r"\bif\s*\(")


@dataclass
class GuardGuarantees:
    lower_bound: bool
    upper_bound: bool
    upper_index_limit: Optional[int]
    condition_text: str


@dataclass
class SinkRewriteDecision:
    file: str
    function: str
    label: str
    sink_line: int
    sink_array: str
    sink_index: str
    array_size: int
    array_upper_index: int
    helper_bad: str
    helper_good: str
    rewritten_with: str
    status: str
    skip_reason: str
    condition_text: str
    guard_lower_bound: bool
    guard_upper_bound: bool
    guard_upper_limit: Optional[int]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage-manifest", required=True, help="Path to stage_a_cases.json")
    parser.add_argument("--labels", required=True, help="Path to stage_a_labels.json")
    parser.add_argument(
        "--staged-stage-root",
        default="benchmarks/juliet/outputs/staged/A",
        help="Path to Stage-A staged root (default: benchmarks/juliet/outputs/staged/A)",
    )
    parser.add_argument(
        "--out-root",
        default="benchmarks/juliet/outputs/derived/A",
        help="Derived output root for transformed files (default: benchmarks/juliet/outputs/derived/A)",
    )
    parser.add_argument(
        "--out-stage-manifest",
        default="benchmarks/juliet/manifests/stage_a_derived_cases.json",
        help="Output path for derived stage manifest",
    )
    parser.add_argument(
        "--out-files-manifest",
        default="benchmarks/juliet/manifests/stage_a_derived_files.txt",
        help="Output path for derived files list",
    )
    parser.add_argument(
        "--out-transform-manifest",
        default="benchmarks/juliet/manifests/stage_a_clamp_transform_manifest.json",
        help="Output path for rewrite decision manifest",
    )
    parser.add_argument("--clean-out", action="store_true", help="Delete output root before writing derived files")
    return parser.parse_args()


def sanitize_symbol(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def build_helper_name(prefix: str, function_name: str, sink_line: int) -> str:
    return f"clamp_{prefix}_{sanitize_symbol(function_name)}_{sink_line}"


def index_to_offset(line_number: int) -> int:
    return max(0, line_number - 1)


def offset_to_line(offset: int) -> int:
    return offset + 1


def parse_guard_guarantees(condition: str, index_name: str, array_size: int) -> GuardGuarantees:
    compact = re.sub(r"\s+", "", condition)
    index_pat = re.escape(index_name)
    lower_patterns = [
        rf"\b{index_pat}>=0\b",
        rf"\b0<={index_pat}\b",
    ]
    upper_lt_match = re.search(rf"\b{index_pat}<\(?(\d+)\)?\b", compact)
    upper_le_match = re.search(rf"\b{index_pat}<=\(?(\d+)\)?\b", compact)

    has_lower = any(re.search(pattern, compact) for pattern in lower_patterns)
    has_upper = False
    upper_limit: Optional[int] = None

    if upper_lt_match:
        limit_raw = int(upper_lt_match.group(1))
        upper_limit = limit_raw - 1
        has_upper = limit_raw == array_size
    elif upper_le_match:
        limit_raw = int(upper_le_match.group(1))
        upper_limit = limit_raw
        has_upper = limit_raw == (array_size - 1)

    return GuardGuarantees(
        lower_bound=has_lower,
        upper_bound=has_upper,
        upper_index_limit=upper_limit,
        condition_text=condition.strip(),
    )


def infer_array_size(lines: List[str], func_start_offset: int, sink_offset: int, array_name: str) -> Optional[int]:
    decl_pattern = re.compile(ARRAY_DECL_PATTERN_TEMPLATE.format(array_name=re.escape(array_name)))
    for idx in range(sink_offset, func_start_offset - 1, -1):
        line = lines[idx]
        match = decl_pattern.search(line)
        if match:
            try:
                size = int(match.group("size"))
            except ValueError:
                return None
            if size > 0:
                return size
            return None
    return None


def extract_nearest_if_condition(lines: List[str], func_start_offset: int, sink_offset: int) -> Tuple[Optional[str], int]:
    for idx in range(sink_offset, func_start_offset - 1, -1):
        line = lines[idx]
        if not IF_LINE_PATTERN.search(line):
            continue

        if_pos = line.find("if")
        paren_pos = line.find("(", if_pos)
        if paren_pos < 0:
            continue

        fragments = [line[paren_pos:]]
        balance = line[paren_pos:].count("(") - line[paren_pos:].count(")")
        cursor = idx + 1
        while balance > 0 and cursor < len(lines):
            fragments.append(lines[cursor])
            balance += lines[cursor].count("(") - lines[cursor].count(")")
            cursor += 1

        condition_text = "".join(fragments).strip()
        if condition_text.startswith("(") and ")" in condition_text:
            end_idx = condition_text.rfind(")")
            inner = condition_text[1:end_idx]
        else:
            inner = condition_text
        return inner, idx
    return None, -1


def build_helper_source(name: str, lower_bound: bool, upper_bound: bool, upper_index: int) -> str:
    checks: List[str] = []
    if lower_bound:
        checks.append("  if (value < 0) return 0;")
    if upper_bound:
        checks.append(f"  if (value > {upper_index}) return {upper_index};")
    if not checks:
        checks.append("  return value;")
    else:
        checks.append("  return value;")
    body = "\n".join(checks)
    return f"static int {name}(int value) {{\n{body}\n}}\n"


def rewrite_sink_expression(line: str, array_name: str, index_name: str, helper_name: str) -> str:
    pattern = re.compile(
        rf"\b{re.escape(array_name)}\s*\[\s*{re.escape(index_name)}\s*\]",
    )
    return pattern.sub(f"{array_name}[{helper_name}({index_name})]", line, count=1)


def detect_sink_line_in_function(lines: List[str], func_start_offset: int, func_end_offset: int) -> Tuple[int, str, str]:
    for idx in range(func_start_offset, min(func_end_offset + 1, len(lines))):
        line = lines[idx]
        match = SINK_ASSIGNMENT_PATTERN.search(line)
        if match:
            return idx, match.group("array"), match.group("index")
    return -1, "", ""


def transform_file_content(
    content: str,
    file_rel_path: str,
    function_labels: List[dict],
) -> Tuple[str, List[SinkRewriteDecision]]:
    lines = content.splitlines(keepends=True)
    decisions: List[SinkRewriteDecision] = []
    helper_blocks: List[str] = []
    helper_seen = set()

    target_labels = [item for item in function_labels if item.get("label") in {"positive", "negative"}]
    for label_record in sorted(target_labels, key=lambda item: (int(item["start_line"]), item["function"])):
        function_name = str(label_record["function"])
        function_label = str(label_record["label"])
        func_start_offset = index_to_offset(int(label_record["start_line"]))
        func_end_offset = index_to_offset(int(label_record["end_line"]))

        sink_offset, array_name, index_name = detect_sink_line_in_function(lines, func_start_offset, func_end_offset)
        sink_line = offset_to_line(sink_offset) if sink_offset >= 0 else -1

        if sink_offset < 0:
            decisions.append(
                SinkRewriteDecision(
                    file=file_rel_path,
                    function=function_name,
                    label=function_label,
                    sink_line=sink_line,
                    sink_array="",
                    sink_index="",
                    array_size=-1,
                    array_upper_index=-1,
                    helper_bad="",
                    helper_good="",
                    rewritten_with="",
                    status="skipped",
                    skip_reason="no_assignment_array_index_sink_in_function",
                    condition_text="",
                    guard_lower_bound=False,
                    guard_upper_bound=False,
                    guard_upper_limit=None,
                )
            )
            continue

        array_size = infer_array_size(lines, func_start_offset, sink_offset, array_name)
        if array_size is None:
            decisions.append(
                SinkRewriteDecision(
                    file=file_rel_path,
                    function=function_name,
                    label=function_label,
                    sink_line=sink_line,
                    sink_array=array_name,
                    sink_index=index_name,
                    array_size=-1,
                    array_upper_index=-1,
                    helper_bad="",
                    helper_good="",
                    rewritten_with="",
                    status="skipped",
                    skip_reason="unable_to_infer_fixed_array_size",
                    condition_text="",
                    guard_lower_bound=False,
                    guard_upper_bound=False,
                    guard_upper_limit=None,
                )
            )
            continue

        condition_text, _ = extract_nearest_if_condition(lines, func_start_offset, sink_offset)
        if not condition_text:
            decisions.append(
                SinkRewriteDecision(
                    file=file_rel_path,
                    function=function_name,
                    label=function_label,
                    sink_line=sink_line,
                    sink_array=array_name,
                    sink_index=index_name,
                    array_size=array_size,
                    array_upper_index=array_size - 1,
                    helper_bad="",
                    helper_good="",
                    rewritten_with="",
                    status="skipped",
                    skip_reason="no_guard_condition_found_before_sink",
                    condition_text="",
                    guard_lower_bound=False,
                    guard_upper_bound=False,
                    guard_upper_limit=None,
                )
            )
            continue

        guard = parse_guard_guarantees(condition_text, index_name, array_size)

        bad_helper = build_helper_name("bad", function_name, sink_line)
        good_helper = build_helper_name("good", function_name, sink_line)
        upper_index = array_size - 1

        bad_helper_source = build_helper_source(
            bad_helper,
            lower_bound=guard.lower_bound,
            upper_bound=guard.upper_bound,
            upper_index=upper_index,
        )
        good_helper_source = build_helper_source(
            good_helper,
            lower_bound=True,
            upper_bound=True,
            upper_index=upper_index,
        )

        if bad_helper not in helper_seen:
            helper_blocks.append(bad_helper_source)
            helper_seen.add(bad_helper)
        if good_helper not in helper_seen:
            helper_blocks.append(good_helper_source)
            helper_seen.add(good_helper)

        rewrite_helper = bad_helper if function_label == "positive" else good_helper
        old_line = lines[sink_offset]
        new_line = rewrite_sink_expression(old_line, array_name, index_name, rewrite_helper)
        lines[sink_offset] = new_line

        decisions.append(
            SinkRewriteDecision(
                file=file_rel_path,
                function=function_name,
                label=function_label,
                sink_line=sink_line,
                sink_array=array_name,
                sink_index=index_name,
                array_size=array_size,
                array_upper_index=upper_index,
                helper_bad=bad_helper,
                helper_good=good_helper,
                rewritten_with=rewrite_helper,
                status="rewritten",
                skip_reason="",
                condition_text=guard.condition_text,
                guard_lower_bound=guard.lower_bound,
                guard_upper_bound=guard.upper_bound,
                guard_upper_limit=guard.upper_index_limit,
            )
        )

    if helper_blocks:
        insert_after = 0
        for idx, line in enumerate(lines):
            if line.lstrip().startswith("#include"):
                insert_after = idx + 1
        helper_text = "\n" + "\n".join(block.rstrip("\n") for block in helper_blocks) + "\n\n"
        lines.insert(insert_after, helper_text)

    return "".join(lines), decisions


def write_stage_manifest(
    source_stage_manifest: dict,
    out_root: Path,
    out_stage_manifest: Path,
) -> None:
    stage_manifest = dict(source_stage_manifest)
    stage_manifest["generated_at_epoch_ms"] = now_epoch_ms()
    stage_manifest["testcases_root"] = str(out_root.resolve())
    write_json(out_stage_manifest, stage_manifest)


def write_transform_csv(decisions: List[SinkRewriteDecision], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "file",
                "function",
                "label",
                "sink_line",
                "sink_array",
                "sink_index",
                "array_size",
                "array_upper_index",
                "helper_bad",
                "helper_good",
                "rewritten_with",
                "status",
                "skip_reason",
                "condition_text",
                "guard_lower_bound",
                "guard_upper_bound",
                "guard_upper_limit",
            ],
        )
        writer.writeheader()
        for item in decisions:
            writer.writerow(item.__dict__)


def build_label_index(labels_payload: dict) -> Dict[str, List[dict]]:
    index: Dict[str, List[dict]] = {}
    for item in labels_payload.get("functions", []):
        file_rel = str(item.get("file", ""))
        index.setdefault(file_rel, []).append(item)
    return index


def main() -> None:
    args = parse_args()
    stage_manifest_path = Path(args.stage_manifest).resolve()
    labels_path = Path(args.labels).resolve()
    staged_root = Path(args.staged_stage_root).resolve()
    out_root = Path(args.out_root).resolve()
    out_stage_manifest = Path(args.out_stage_manifest).resolve()
    out_files_manifest = Path(args.out_files_manifest).resolve()
    out_transform_manifest = Path(args.out_transform_manifest).resolve()
    out_transform_csv = out_transform_manifest.with_suffix(".csv")

    if args.clean_out and out_root.exists():
        shutil.rmtree(out_root)

    stage_manifest = load_json(stage_manifest_path)
    labels_payload = load_json(labels_path)
    label_index = build_label_index(labels_payload)

    transformed_files: List[str] = []
    all_decisions: List[SinkRewriteDecision] = []

    for case in stage_manifest.get("cases", []):
        for rel_file in case.get("files", []):
            rel_file_path = Path(rel_file)
            source_file = staged_root / rel_file_path
            if not source_file.exists():
                continue

            destination_file = out_root / rel_file_path
            destination_file.parent.mkdir(parents=True, exist_ok=True)
            transformed_files.append(rel_file)

            if source_file.suffix.lower() not in SOURCE_EXTENSIONS:
                shutil.copyfile(source_file.resolve(), destination_file)
                continue

            content = source_file.read_text(encoding="utf-8", errors="replace")
            transformed_content, decisions = transform_file_content(
                content=content,
                file_rel_path=rel_file,
                function_labels=label_index.get(rel_file, []),
            )
            destination_file.write_text(transformed_content, encoding="utf-8")
            all_decisions.extend(decisions)

    out_files_manifest.parent.mkdir(parents=True, exist_ok=True)
    out_files_manifest.write_text(
        "\n".join(sorted(set(transformed_files))) + ("\n" if transformed_files else ""),
        encoding="utf-8",
    )

    write_stage_manifest(stage_manifest, out_root, out_stage_manifest)

    transform_payload = {
        "generated_at_epoch_ms": now_epoch_ms(),
        "source_stage_manifest": str(stage_manifest_path),
        "source_labels_manifest": str(labels_path),
        "staged_stage_root": str(staged_root),
        "derived_stage_root": str(out_root),
        "file_count": len(set(transformed_files)),
        "decision_count": len(all_decisions),
        "rewritten_count": sum(1 for item in all_decisions if item.status == "rewritten"),
        "skipped_count": sum(1 for item in all_decisions if item.status != "rewritten"),
        "decisions": [item.__dict__ for item in all_decisions],
    }
    write_json(out_transform_manifest, transform_payload)
    write_transform_csv(all_decisions, out_transform_csv)

    print(f"Derived Stage-A files written to: {out_root}")
    print(f"Derived stage manifest: {out_stage_manifest}")
    print(f"Transformation manifest: {out_transform_manifest}")
    print(f"Rewritten sinks: {transform_payload['rewritten_count']}")


if __name__ == "__main__":
    main()

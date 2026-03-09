#!/usr/bin/env python3
"""Score normalized Joern findings against Juliet function labels."""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from common import load_json, metric_block, now_epoch_ms, normalize_path, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True, help="Finding JSON file or directory")
    parser.add_argument("--labels", required=True, help="Label JSON file or directory")
    parser.add_argument("--out", required=True, help="Output directory")
    return parser.parse_args()


def function_role(function_name: str) -> str:
    name = str(function_name or "")
    if name.startswith("clamp_bad_"):
        return "helper_clamp_bad"
    if name.startswith("clamp_good_"):
        return "helper_clamp_good"
    if re.search(r"(^|_)badSource($|_)", name):
        return "helper_source_bad"
    if re.search(r"(^|_)goodB2GSource($|_)", name):
        return "helper_source_goodB2G"
    return "core"


def collect_json_files(path: Path) -> List[Path]:
    if path.is_file():
        return [path]
    files = sorted(path.rglob("*.json"))
    return files


def load_finding_records(path: Path) -> List[dict]:
    findings: List[dict] = []
    for file_path in collect_json_files(path):
        payload = load_json(file_path)
        if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
            findings.extend(payload["findings"])
        elif isinstance(payload, list):
            findings.extend(payload)
    return findings


def load_label_records(path: Path) -> List[dict]:
    labels: List[dict] = []
    for file_path in collect_json_files(path):
        payload = load_json(file_path)
        if isinstance(payload, dict) and isinstance(payload.get("functions"), list):
            labels.extend(payload["functions"])
    return labels


def normalize_file(value: str) -> str:
    return normalize_path(value)


def find_best_label_match(finding: dict, label_index: dict) -> dict | None:
    file_path = normalize_file(str(finding.get("file", "")))
    file_name = Path(file_path).name
    function = str(finding.get("function", ""))
    sink_line = int(finding.get("sink_line", -1))

    exact = label_index["exact"].get((file_path, function), [])
    if exact:
        return select_by_line(exact, sink_line)

    by_basename = label_index["basename_func"].get((file_name, function), [])
    if by_basename:
        return select_by_line(by_basename, sink_line)

    for suffix in suffix_candidates(file_path):
        by_suffix = label_index["suffix_func"].get((suffix, function), [])
        if by_suffix:
            return select_by_line(by_suffix, sink_line)

    in_file = label_index["file"].get(file_path, [])
    candidate = select_by_line([item for item in in_file if line_in_range(item, sink_line)], sink_line)
    if candidate is not None:
        return candidate

    by_name = label_index["basename"].get(file_name, [])
    candidate = select_by_line([item for item in by_name if line_in_range(item, sink_line)], sink_line)
    if candidate is not None:
        return candidate

    return None


def line_in_range(label: dict, sink_line: int) -> bool:
    if sink_line < 0:
        return False
    return int(label.get("start_line", -1)) <= sink_line <= int(label.get("end_line", -1))


def select_by_line(candidates: Sequence[dict], sink_line: int) -> dict | None:
    if not candidates:
        return None
    if sink_line < 0:
        return candidates[0]
    ranked = sorted(
        candidates,
        key=lambda item: (
            0 if line_in_range(item, sink_line) else 1,
            abs(sink_line - int(item.get("start_line", sink_line))),
            int(item.get("end_line", 0)) - int(item.get("start_line", 0)),
        ),
    )
    return ranked[0]


def build_label_index(labels: Sequence[dict]) -> dict:
    index = {
        "exact": defaultdict(list),
        "basename_func": defaultdict(list),
        "suffix_func": defaultdict(list),
        "file": defaultdict(list),
        "basename": defaultdict(list),
    }
    for item in labels:
        file_path = normalize_file(str(item.get("file", "")))
        file_name = Path(file_path).name
        function = str(item.get("function", ""))
        index["exact"][(file_path, function)].append(item)
        index["basename_func"][(file_name, function)].append(item)
        for suffix in suffix_candidates(file_path):
            index["suffix_func"][(suffix, function)].append(item)
        index["file"][file_path].append(item)
        index["basename"][file_name].append(item)
    return index


def suffix_candidates(path_text: str) -> List[str]:
    normalized = normalize_file(path_text)
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return [normalized]
    candidates = [normalized]
    for start in range(1, len(parts)):
        candidates.append("/".join(parts[start:]))
    return candidates


def grouped_metrics(rows: Sequence[dict]) -> dict:
    tp = sum(1 for row in rows if row["actual_positive"] and row["predicted_positive"])
    fp = sum(1 for row in rows if (not row["actual_positive"]) and row["predicted_positive"])
    tn = sum(1 for row in rows if (not row["actual_positive"]) and (not row["predicted_positive"]))
    fn = sum(1 for row in rows if row["actual_positive"] and (not row["predicted_positive"]))
    return metric_block(tp=tp, fp=fp, tn=tn, fn=fn)


def summarize_dimension(instances: Sequence[dict], dimension: str, key_fn) -> List[dict]:
    groups: Dict[str, List[dict]] = defaultdict(list)
    for row in instances:
        groups[key_fn(row)].append(row)

    rows: List[dict] = []
    for key, values in sorted(groups.items()):
        metrics = grouped_metrics(values)
        rows.append(
            {
                "dimension": dimension,
                "key": key,
                **metrics,
            }
        )
    return rows


def main() -> None:
    args = parse_args()
    findings_path = Path(args.findings).resolve()
    labels_path = Path(args.labels).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    findings = load_finding_records(findings_path)
    labels = load_label_records(labels_path)

    if not labels:
        raise SystemExit(f"No labels loaded from: {labels_path}")

    label_index = build_label_index(labels)

    configs = sorted({str(item.get("config", "unknown")) for item in findings})
    if not configs:
        configs = ["unknown"]

    detections = defaultdict(list)
    unmatched_findings: List[dict] = []

    for finding in findings:
        config = str(finding.get("config", "unknown"))
        stage = str(finding.get("stage", "unknown"))
        matched = find_best_label_match(finding, label_index)
        if matched is None:
            unmatched_findings.append(finding)
            continue
        key = (config, matched["stage"], matched["case_id"])
        detections[key].append(finding)

    scored_labels = [item for item in labels if item.get("label") in {"positive", "negative"}]

    instances: List[dict] = []
    mismatches: List[dict] = []

    for config in configs:
        for label in scored_labels:
            key = (config, label["stage"], label["case_id"])
            predicted = key in detections
            actual_positive = label["label"] == "positive"
            role = function_role(str(label.get("function", "")))
            instance = {
                "case_id": label["case_id"],
                "file": label["file"],
                "function": label["function"],
                "function_role": role,
                "is_auxiliary": role != "core",
                "label": label["label"],
                "predicted_positive": predicted,
                "actual_positive": actual_positive,
                "stage": label["stage"],
                "config": config,
                "cwe": label.get("cwe", "UNKNOWN"),
                "variant": str(label.get("variant", "unknown")),
                "language": label.get("language", "unknown"),
                "matched_findings": len(detections.get(key, [])),
            }
            instances.append(instance)

            if predicted != actual_positive:
                mismatch = {
                    "type": "label_mismatch",
                    "case_id": label["case_id"],
                    "file": label["file"],
                    "function": label["function"],
                    "function_role": role,
                    "is_auxiliary": str(role != "core").lower(),
                    "label": label["label"],
                    "predicted_positive": str(predicted).lower(),
                    "actual_positive": str(actual_positive).lower(),
                    "stage": label["stage"],
                    "config": config,
                    "cwe": label.get("cwe", "UNKNOWN"),
                    "variant": str(label.get("variant", "unknown")),
                    "language": label.get("language", "unknown"),
                    "sink_line": "",
                    "sink_code": "",
                }
                if detections.get(key):
                    first = detections[key][0]
                    mismatch["sink_line"] = first.get("sink_line", "")
                    mismatch["sink_code"] = first.get("sink_code", "")
                mismatches.append(mismatch)

    for finding in unmatched_findings:
        mismatches.append(
            {
                "type": "unmatched_finding",
                "case_id": "",
                "file": finding.get("file", ""),
                "function": finding.get("function", ""),
                "function_role": "",
                "is_auxiliary": "",
                "label": "",
                "predicted_positive": "",
                "actual_positive": "",
                "stage": finding.get("stage", ""),
                "config": finding.get("config", ""),
                "cwe": "",
                "variant": "",
                "language": "",
                "sink_line": finding.get("sink_line", ""),
                "sink_code": finding.get("sink_code", ""),
            }
        )

    metrics_rows: List[dict] = []
    overall_metrics = grouped_metrics(instances)
    metrics_rows.append({"dimension": "overall", "key": "all", **overall_metrics})

    metrics_rows.extend(summarize_dimension(instances, "stage", lambda row: row["stage"]))
    metrics_rows.extend(summarize_dimension(instances, "config", lambda row: row["config"]))
    metrics_rows.extend(summarize_dimension(instances, "cwe", lambda row: row["cwe"]))
    metrics_rows.extend(summarize_dimension(instances, "variant", lambda row: row["variant"]))
    metrics_rows.extend(summarize_dimension(instances, "language", lambda row: row["language"]))
    metrics_rows.extend(
        summarize_dimension(instances, "stage_config", lambda row: f"{row['stage']}|{row['config']}")
    )
    metrics_rows.extend(
        summarize_dimension(
            instances,
            "stage_config_cwe_variant_language",
            lambda row: f"{row['stage']}|{row['config']}|{row['cwe']}|{row['variant']}|{row['language']}",
        )
    )
    metrics_rows.extend(summarize_dimension(instances, "function_role", lambda row: row["function_role"]))
    metrics_rows.extend(
        summarize_dimension(instances, "config_function_role", lambda row: f"{row['config']}|{row['function_role']}")
    )

    core_instances = [row for row in instances if row["function_role"] == "core"]
    aux_instances = [row for row in instances if row["function_role"] != "core"]
    overall_core_metrics = grouped_metrics(core_instances)
    overall_aux_metrics = grouped_metrics(aux_instances)

    summary = {
        "generated_at_epoch_ms": now_epoch_ms(),
        "inputs": {
            "findings": str(findings_path),
            "labels": str(labels_path),
        },
        "counts": {
            "finding_records": len(findings),
            "unmatched_findings": len(unmatched_findings),
            "labeled_functions_total": len(labels),
            "labeled_functions_scored": len(scored_labels),
            "scoring_instances": len(instances),
            "mismatch_rows": len(mismatches),
        },
        "overall": overall_metrics,
        "overall_core_only": overall_core_metrics,
        "overall_auxiliary_only": overall_aux_metrics,
        "configs": configs,
        "stages": sorted({item.get("stage", "unknown") for item in scored_labels}),
        "breakdown": metrics_rows,
    }

    write_json(out_dir / "summary.json", summary)

    metrics_csv = out_dir / "metrics.csv"
    with metrics_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["dimension", "key", "TP", "FP", "TN", "FN", "precision", "recall", "f1", "fpr", "fnr"],
        )
        writer.writeheader()
        for row in metrics_rows:
            writer.writerow(row)

    mismatch_csv = out_dir / "mismatches.csv"
    with mismatch_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "type",
                "case_id",
                "file",
                "function",
                "function_role",
                "is_auxiliary",
                "label",
                "predicted_positive",
                "actual_positive",
                "stage",
                "config",
                "cwe",
                "variant",
                "language",
                "sink_line",
                "sink_code",
            ],
        )
        writer.writeheader()
        for row in mismatches:
            writer.writerow(row)

    print(f"Wrote summary: {out_dir / 'summary.json'}")
    print(f"Wrote metrics: {metrics_csv}")
    print(f"Wrote mismatches: {mismatch_csv}")


if __name__ == "__main__":
    main()

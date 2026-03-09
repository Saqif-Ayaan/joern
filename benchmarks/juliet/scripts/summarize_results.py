#!/usr/bin/env python3
"""Aggregate multiple score outputs into machine-readable and Markdown reports."""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path
from typing import Dict, List

from common import load_json, metric_block, now_epoch_ms, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", nargs="+", required=True, help="Score output dirs or summary.json files")
    parser.add_argument("--out", required=True, help="Output directory for aggregated reports")
    return parser.parse_args()


def resolve_run_dirs(inputs: List[str]) -> List[Path]:
    run_dirs: List[Path] = []
    for item in inputs:
        path = Path(item).resolve()
        if path.is_dir():
            run_dirs.append(path)
        elif path.is_file() and path.name == "summary.json":
            run_dirs.append(path.parent)
    return sorted(set(run_dirs))


def read_metrics_csv(path: Path) -> List[dict]:
    rows: List[dict] = []
    if not path.is_file():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(row)
    return rows


def read_mismatches_csv(path: Path) -> List[dict]:
    rows: List[dict] = []
    if not path.is_file():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(row)
    return rows


def as_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def as_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    run_dirs = resolve_run_dirs(args.inputs)
    if not run_dirs:
        raise SystemExit("No valid score directories found in --inputs")

    summaries: List[dict] = []
    merged_metrics: List[dict] = []
    merged_mismatches: List[dict] = []

    for run_dir in run_dirs:
        summary_path = run_dir / "summary.json"
        metrics_path = run_dir / "metrics.csv"
        mismatches_path = run_dir / "mismatches.csv"

        if summary_path.is_file():
            summary = load_json(summary_path)
            summary["source_dir"] = str(run_dir)
            summaries.append(summary)

        for row in read_metrics_csv(metrics_path):
            row["source_dir"] = str(run_dir)
            merged_metrics.append(row)

        for row in read_mismatches_csv(mismatches_path):
            row["source_dir"] = str(run_dir)
            merged_mismatches.append(row)

    overall_rows = [row for row in merged_metrics if row.get("dimension") == "overall"]
    total_tp = sum(as_int(row.get("TP", "0")) for row in overall_rows)
    total_fp = sum(as_int(row.get("FP", "0")) for row in overall_rows)
    total_tn = sum(as_int(row.get("TN", "0")) for row in overall_rows)
    total_fn = sum(as_int(row.get("FN", "0")) for row in overall_rows)
    aggregate_overall = metric_block(total_tp, total_fp, total_tn, total_fn)

    summary_payload = {
        "generated_at_epoch_ms": now_epoch_ms(),
        "run_count": len(run_dirs),
        "inputs": [str(path) for path in run_dirs],
        "aggregate_overall": aggregate_overall,
        "metrics_row_count": len(merged_metrics),
        "mismatch_row_count": len(merged_mismatches),
        "runs": summaries,
    }
    write_json(out_dir / "summary.json", summary_payload)

    metrics_csv = out_dir / "metrics.csv"
    with metrics_csv.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "source_dir",
            "dimension",
            "key",
            "TP",
            "FP",
            "TN",
            "FN",
            "precision",
            "recall",
            "f1",
            "fpr",
            "fnr",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in merged_metrics:
            writer.writerow({name: row.get(name, "") for name in fieldnames})

    mismatches_csv = out_dir / "mismatches.csv"
    mismatch_fields = [
        "source_dir",
        "type",
        "case_id",
        "file",
        "function",
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
    ]
    with mismatches_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=mismatch_fields)
        writer.writeheader()
        for row in merged_mismatches:
            writer.writerow({name: row.get(name, "") for name in mismatch_fields})

    mismatch_counter = Counter()
    for row in merged_mismatches:
        if row.get("type") == "label_mismatch":
            mismatch_counter[(row.get("file", ""), row.get("function", ""), row.get("config", ""))] += 1

    md_path = out_dir / "metrics.md"
    lines: List[str] = []
    lines.append("# Juliet BOF Benchmark Summary")
    lines.append("")
    lines.append(f"- Generated: {summary_payload['generated_at_epoch_ms']}")
    lines.append(f"- Runs aggregated: {len(run_dirs)}")
    lines.append("")
    lines.append("## Aggregate Overall")
    lines.append("")
    lines.append("| TP | FP | TN | FN | Precision | Recall | F1 | FPR | FNR |")
    lines.append("|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    lines.append(
        "| {TP} | {FP} | {TN} | {FN} | {precision:.4f} | {recall:.4f} | {f1:.4f} | {fpr:.4f} | {fnr:.4f} |".format(
            **aggregate_overall
        )
    )
    lines.append("")

    lines.append("## Per-Run Overall")
    lines.append("")
    lines.append("| Source | TP | FP | TN | FN | Precision | Recall | F1 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for row in overall_rows:
        lines.append(
            "| {src} | {TP} | {FP} | {TN} | {FN} | {precision:.4f} | {recall:.4f} | {f1:.4f} |".format(
                src=row.get("source_dir", ""),
                TP=as_int(row.get("TP", "0")),
                FP=as_int(row.get("FP", "0")),
                TN=as_int(row.get("TN", "0")),
                FN=as_int(row.get("FN", "0")),
                precision=as_float(row.get("precision", "0")),
                recall=as_float(row.get("recall", "0")),
                f1=as_float(row.get("f1", "0")),
            )
        )
    lines.append("")

    lines.append("## Top Mismatches")
    lines.append("")
    lines.append("| File | Function | Config | Count |")
    lines.append("|---|---|---|---:|")
    for (file_name, function_name, config), count in mismatch_counter.most_common(20):
        lines.append(f"| {file_name} | {function_name} | {config} | {count} |")
    lines.append("")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Wrote aggregated summary: {out_dir / 'summary.json'}")
    print(f"Wrote aggregated metrics CSV: {metrics_csv}")
    print(f"Wrote aggregated mismatches CSV: {mismatches_csv}")
    print(f"Wrote aggregated Markdown: {md_path}")


if __name__ == "__main__":
    main()

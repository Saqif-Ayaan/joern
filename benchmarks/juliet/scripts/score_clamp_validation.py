#!/usr/bin/env python3
"""Score clamp validation decisions (discovery cache) against expected clamp helpers.

This scorer focuses on clamp-validation behavior, not generic vulnerability findings.
Expected labels are inferred from helper name prefixes in the transformed dataset:
  - clamp_good_* => expected sanitizer (positive class)
  - clamp_bad_*  => expected non-sanitizer (negative class)
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from common import load_json, metric_block, now_epoch_ms, write_json

_DUPLICATE_SUFFIX_RE = re.compile(r"<duplicate>\d+$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", required=True, help="Label JSON file or directory")
    parser.add_argument(
        "--decisions",
        required=True,
        help="Decision cache JSON file or directory (e.g., outputs/cache/discovery)",
    )
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--config", default="", help="Optional config label for report context")
    return parser.parse_args()


def collect_json_files(path: Path) -> List[Path]:
    if path.is_file():
        return [path]
    return sorted(path.rglob("*.json"))


def load_label_records(path: Path) -> List[dict]:
    records: List[dict] = []
    for file_path in collect_json_files(path):
        payload = load_json(file_path)
        if isinstance(payload, dict) and isinstance(payload.get("functions"), list):
            records.extend(payload["functions"])
    return records


def load_decision_records(path: Path) -> List[dict]:
    records: List[dict] = []
    for file_path in collect_json_files(path):
        payload = load_json(file_path)
        if isinstance(payload, dict) and isinstance(payload.get("entries"), list):
            records.extend(payload["entries"])
    return records


def strip_duplicate_suffix(method_full_name: str) -> str:
    return _DUPLICATE_SUFFIX_RE.sub("", method_full_name)


def expected_clamp_counts(labels: Iterable[dict]) -> Tuple[Counter, Counter]:
    expected_good: Counter = Counter()
    expected_bad: Counter = Counter()
    for item in labels:
        fn = str(item.get("function", ""))
        if fn.startswith("clamp_good_"):
            expected_good[fn] += 1
        elif fn.startswith("clamp_bad_"):
            expected_bad[fn] += 1
    return expected_good, expected_bad


def decision_counts(decisions: Iterable[dict]) -> Tuple[Counter, Counter]:
    decision_true: Counter = Counter()
    decision_false: Counter = Counter()
    for item in decisions:
        method_full_name = str(item.get("methodFullName", ""))
        if not method_full_name:
            continue
        base_name = strip_duplicate_suffix(method_full_name)
        is_sanitizer = bool(item.get("isSanitizer", False))
        if is_sanitizer:
            decision_true[base_name] += 1
        else:
            decision_false[base_name] += 1
    return decision_true, decision_false


def allocate_counts(expected: int, true_count: int, false_count: int) -> Tuple[int, int, int]:
    matched_true = min(expected, true_count)
    remaining = expected - matched_true
    matched_false = min(remaining, false_count)
    missing = expected - matched_true - matched_false
    return matched_true, matched_false, missing


def write_rows_csv(path: Path, rows: List[dict], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def main() -> None:
    args = parse_args()
    labels_path = Path(args.labels).resolve()
    decisions_path = Path(args.decisions).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    labels = load_label_records(labels_path)
    decisions = load_decision_records(decisions_path)

    exp_good, exp_bad = expected_clamp_counts(labels)
    dec_true, dec_false = decision_counts(decisions)

    tp = fp = tn = fn = 0
    fn_failed_validation = 0
    fn_no_decision = 0
    unresolved_negative = 0

    detail_rows: List[dict] = []

    for name, expected in sorted(exp_good.items()):
        true_count = int(dec_true.get(name, 0))
        false_count = int(dec_false.get(name, 0))
        matched_true, matched_false, missing = allocate_counts(expected, true_count, false_count)
        tp += matched_true
        fn += matched_false + missing
        fn_failed_validation += matched_false
        fn_no_decision += missing
        detail_rows.append(
            {
                "helper": name,
                "expected_class": "good_clamp",
                "expected_count": expected,
                "decision_true_count": true_count,
                "decision_false_count": false_count,
                "tp_or_tn": matched_true,
                "fp_or_fn": matched_false + missing,
                "failed_validation": matched_false,
                "no_decision": missing,
            }
        )

    for name, expected in sorted(exp_bad.items()):
        true_count = int(dec_true.get(name, 0))
        false_count = int(dec_false.get(name, 0))
        matched_true, matched_false, missing = allocate_counts(expected, true_count, false_count)
        fp += matched_true
        tn += matched_false
        unresolved_negative += missing
        detail_rows.append(
            {
                "helper": name,
                "expected_class": "bad_clamp",
                "expected_count": expected,
                "decision_true_count": true_count,
                "decision_false_count": false_count,
                "tp_or_tn": matched_false,
                "fp_or_fn": matched_true,
                "failed_validation": 0,
                "no_decision": missing,
            }
        )

    overall = metric_block(tp=tp, fp=fp, tn=tn, fn=fn)
    summary = {
        "generated_at_epoch_ms": now_epoch_ms(),
        "inputs": {
            "labels": str(labels_path),
            "decisions": str(decisions_path),
        },
        "config": args.config,
        "expected": {
            "clamp_good_total": int(sum(exp_good.values())),
            "clamp_bad_total": int(sum(exp_bad.values())),
            "unique_clamp_good_helpers": len(exp_good),
            "unique_clamp_bad_helpers": len(exp_bad),
        },
        "decision_counts": {
            "total_entries": len(decisions),
            "sanitizer_true_entries": int(sum(dec_true.values())),
            "sanitizer_false_entries": int(sum(dec_false.values())),
        },
        "overall": overall,
        "fn_breakdown": {
            "failed_validation": fn_failed_validation,
            "no_decision": fn_no_decision,
        },
        "unresolved_negative": unresolved_negative,
        "coverage": {
            "good_seen_rate": round(
                (overall["TP"] + fn_failed_validation) / max(1, int(sum(exp_good.values()))), 6
            ),
            "bad_seen_rate": round((overall["TN"] + overall["FP"]) / max(1, int(sum(exp_bad.values()))), 6),
        },
    }

    write_json(out_dir / "summary.json", summary)
    write_rows_csv(
        out_dir / "details.csv",
        detail_rows,
        fieldnames=[
            "helper",
            "expected_class",
            "expected_count",
            "decision_true_count",
            "decision_false_count",
            "tp_or_tn",
            "fp_or_fn",
            "failed_validation",
            "no_decision",
        ],
    )

    print(f"Wrote clamp-validation summary: {out_dir / 'summary.json'}")
    print(f"Wrote clamp-validation details: {out_dir / 'details.csv'}")


if __name__ == "__main__":
    main()

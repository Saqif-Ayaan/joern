#!/usr/bin/env python3
"""Score sanitizer decision telemetry against clamp callsite oracle."""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from common import load_json, metric_block, now_epoch_ms, normalize_path, write_json

_DUPLICATE_SUFFIX_RE = re.compile(r"<duplicate>\d+")
_SIGNATURE_SUFFIX_RE = re.compile(r":[^(]+\([^)]*\)$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decisions", required=True, help="Sanitizer decision JSON file or directory")
    parser.add_argument("--oracle", required=True, help="Clamp callsite oracle JSON")
    parser.add_argument("--out", required=True, help="Output directory")
    return parser.parse_args()


def collect_json_files(path: Path) -> List[Path]:
    if path.is_file():
        return [path]
    return sorted(path.rglob("*.json"))


def load_decision_records(path: Path) -> List[dict]:
    out: List[dict] = []
    for file_path in collect_json_files(path):
        payload = load_json(file_path)
        if isinstance(payload, dict) and isinstance(payload.get("decisions"), list):
            out.extend(payload["decisions"])
        elif isinstance(payload, list):
            out.extend(payload)
    return out


def canonical_callee(name: str) -> str:
    value = _SIGNATURE_SUFFIX_RE.sub("", str(name or "").strip())
    value = _DUPLICATE_SUFFIX_RE.sub("", value)
    return value.strip()


def normalize_file(value: str) -> str:
    return normalize_path(value)


def file_matches(decision_file: str, oracle_file: str) -> bool:
    d = normalize_file(decision_file)
    o = normalize_file(oracle_file)
    if not d or not o:
        return False
    if d == o:
        return True
    if d.endswith("/" + o):
        return True
    if Path(d).name == Path(o).name:
        return True
    return False


def expected_to_bool(expected_label: str) -> bool:
    if expected_label == "sanitizer":
        return True
    if expected_label == "non_sanitizer":
        return False
    raise ValueError(f"Unknown expected_label: {expected_label}")


def predicted_to_bool(predicted: str) -> Optional[bool]:
    value = str(predicted or "").strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def grouped_metrics(rows: Sequence[dict]) -> dict:
    decided = [row for row in rows if row["predicted_bool"] is not None]
    unresolved = len(rows) - len(decided)
    tp = sum(1 for row in decided if row["actual_bool"] and row["predicted_bool"])
    fp = sum(1 for row in decided if (not row["actual_bool"]) and row["predicted_bool"])
    tn = sum(1 for row in decided if (not row["actual_bool"]) and (not row["predicted_bool"]))
    fn = sum(1 for row in decided if row["actual_bool"] and (not row["predicted_bool"]))
    block = metric_block(tp=tp, fp=fp, tn=tn, fn=fn)
    block["unresolved_oracle"] = unresolved
    block["decided_count"] = len(decided)
    block["oracle_count"] = len(rows)
    block["decision_rate"] = round(len(decided) / max(1, len(rows)), 6)
    return block


def summarize_dimension(rows: Sequence[dict], matrix_scope: str, dimension: str, key_fn) -> List[dict]:
    groups: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        groups[key_fn(row)].append(row)
    out: List[dict] = []
    for key, items in sorted(groups.items()):
        block = grouped_metrics(items)
        out.append(
            {
                "matrix_scope": matrix_scope,
                "dimension": dimension,
                "key": key,
                "TP": block["TP"],
                "FP": block["FP"],
                "TN": block["TN"],
                "FN": block["FN"],
                "unresolved_oracle": block["unresolved_oracle"],
                "decided_count": block["decided_count"],
                "oracle_count": block["oracle_count"],
                "decision_rate": block["decision_rate"],
                "precision": block["precision"],
                "recall": block["recall"],
                "f1": block["f1"],
                "fpr": block["fpr"],
                "fnr": block["fnr"],
            }
        )
    return out


def aggregate_decisions(records: Iterable[dict]) -> Dict[Tuple[str, str, str, int, str, str], dict]:
    # Key: (config, stage, file, line, callee_base, decision_source)
    grouped: Dict[Tuple[str, str, str, int, str, str], List[dict]] = defaultdict(list)
    for row in records:
        config = str(row.get("config", "unknown"))
        stage = str(row.get("stage", "unknown"))
        file_path = normalize_file(str(row.get("callsite_file", "")))
        line = int(row.get("callsite_line", -1) or -1)
        callee_base = canonical_callee(str(row.get("callee_method_full_name", "")))
        source = str(row.get("decision_source", "unknown")).strip().lower()
        grouped[(config, stage, file_path, line, callee_base, source)].append(row)

    reduced: Dict[Tuple[str, str, str, int, str, str], dict] = {}
    for key, rows in grouped.items():
        chosen = sorted(rows, key=lambda item: str(item.get("reason", "")))[0]
        predicted_values = {predicted_to_bool(str(item.get("predicted_sanitizer", "none"))) for item in rows}
        # Precedence for combined decision at same key: true > false > none
        if True in predicted_values:
            predicted = True
        elif False in predicted_values:
            predicted = False
        else:
            predicted = None
        chosen_copy = dict(chosen)
        chosen_copy["predicted_bool"] = predicted
        chosen_copy["callee_base"] = key[4]
        reduced[key] = chosen_copy
    return reduced


def oracle_index(records: List[dict]) -> Tuple[dict, dict, dict]:
    exact: Dict[Tuple[str, str, int, str], dict] = {}
    by_line: Dict[Tuple[str, str, int], List[dict]] = defaultdict(list)
    by_callee: Dict[Tuple[str, str, str], List[dict]] = defaultdict(list)
    for item in records:
        stage = str(item.get("stage", "unknown"))
        file_path = normalize_file(str(item.get("file", "")))
        line = int(item.get("sink_line", -1) or -1)
        callee = canonical_callee(str(item.get("callee_helper_full_name", item.get("callee_helper_base_name", ""))))
        exact[(stage, file_path, line, callee)] = item
        by_line[(stage, file_path, line)].append(item)
        by_callee[(stage, file_path, callee)].append(item)
    return exact, by_line, by_callee


def find_oracle_row(decision_row: dict, exact: dict, by_line: dict, by_callee: dict) -> Optional[dict]:
    stage = str(decision_row.get("stage", "unknown"))
    file_path = normalize_file(str(decision_row.get("callsite_file", "")))
    line = int(decision_row.get("callsite_line", -1) or -1)
    callee = str(decision_row.get("callee_base", ""))

    exact_hit = exact.get((stage, file_path, line, callee))
    if exact_hit is not None:
        return exact_hit

    # suffix match for absolute vs relative path
    for (s, oracle_file, oracle_line, oracle_callee), row in exact.items():
        if s == stage and oracle_line == line and oracle_callee == callee and file_matches(file_path, oracle_file):
            return row

    line_hits = [row for (s, oracle_file, oracle_line), rows in by_line.items() if s == stage and oracle_line == line and file_matches(file_path, oracle_file) for row in rows]
    if len(line_hits) == 1:
        return line_hits[0]

    # Final fallback for transformed line drift: unique stage+file+callee match.
    callee_hits = [
        row
        for (s, oracle_file, oracle_callee), rows in by_callee.items()
        if s == stage and oracle_callee == callee and file_matches(file_path, oracle_file)
        for row in rows
    ]
    if len(callee_hits) == 1:
        return callee_hits[0]

    return None


def main() -> None:
    args = parse_args()
    decisions_path = Path(args.decisions).resolve()
    oracle_path = Path(args.oracle).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    decision_records_raw = load_decision_records(decisions_path)
    oracle_payload = load_json(oracle_path)
    oracle_records = list(oracle_payload.get("records", []))
    if not oracle_records:
        raise SystemExit(f"No oracle records loaded from {oracle_path}")

    exact_oracle, line_oracle, callee_oracle = oracle_index(oracle_records)
    reduced_decisions = aggregate_decisions(decision_records_raw)

    configs = sorted({str(row.get("config", "unknown")) for row in reduced_decisions.values()})
    matrix_scopes = ["combined", "modeled", "discovered"]

    oracle_details: List[dict] = []
    out_of_oracle_true_rows: List[dict] = []
    out_of_oracle_false_rows: List[dict] = []

    # Precompute matched oracle for each decision row.
    decision_with_oracle: List[Tuple[dict, Optional[dict]]] = []
    for row in reduced_decisions.values():
        decision_with_oracle.append((row, find_oracle_row(row, exact_oracle, line_oracle, callee_oracle)))

    # Out-of-oracle audit uses source-specific reduced decisions.
    for decision_row, matched_oracle in decision_with_oracle:
        if matched_oracle is not None:
            continue
        predicted = decision_row.get("predicted_bool")
        base = {
            "config": str(decision_row.get("config", "unknown")),
            "stage": str(decision_row.get("stage", "unknown")),
            "callsite_file": normalize_file(str(decision_row.get("callsite_file", ""))),
            "callsite_line": int(decision_row.get("callsite_line", -1) or -1),
            "caller_function": str(decision_row.get("caller_function", "")),
            "callee_method_full_name": str(decision_row.get("callee_method_full_name", "")),
            "callee_base_name": str(decision_row.get("callee_base", "")),
            "decision_source": str(decision_row.get("decision_source", "")),
            "predicted_sanitizer": (
                "true" if predicted is True else "false" if predicted is False else "none"
            ),
            "reason": str(decision_row.get("reason", "")),
        }
        if predicted is True:
            out_of_oracle_true_rows.append(base)
        elif predicted is False:
            out_of_oracle_false_rows.append(base)

    matrix_rows: List[dict] = []

    for config in configs:
        # Index relevant decisions for this config by scope and oracle row identity.
        for scope in matrix_scopes:
            by_oracle_key: Dict[Tuple[str, str, int, str], List[dict]] = defaultdict(list)
            for decision_row, matched_oracle in decision_with_oracle:
                if matched_oracle is None:
                    continue
                if str(decision_row.get("config", "unknown")) != config:
                    continue
                source = str(decision_row.get("decision_source", "")).lower()
                if scope == "modeled" and source != "modeled":
                    continue
                if scope == "discovered" and source != "discovered":
                    continue
                oracle_key = (
                    str(matched_oracle.get("stage", "unknown")),
                    normalize_file(str(matched_oracle.get("file", ""))),
                    int(matched_oracle.get("sink_line", -1) or -1),
                    canonical_callee(
                        str(
                            matched_oracle.get(
                                "callee_helper_base_name",
                                matched_oracle.get("callee_helper_full_name", ""),
                            )
                        )
                    ),
                )
                by_oracle_key[oracle_key].append(decision_row)

            for oracle in oracle_records:
                oracle_key = (
                    str(oracle.get("stage", "unknown")),
                    normalize_file(str(oracle.get("file", ""))),
                    int(oracle.get("sink_line", -1) or -1),
                    canonical_callee(
                        str(
                            oracle.get(
                                "callee_helper_base_name",
                                oracle.get("callee_helper_full_name", ""),
                            )
                        )
                    ),
                )
                matches = by_oracle_key.get(oracle_key, [])
                predicted: Optional[bool] = None
                decision_reason = "no_decision"
                decision_source = scope
                if matches:
                    predicted_values = {row.get("predicted_bool") for row in matches}
                    if True in predicted_values:
                        predicted = True
                    elif False in predicted_values:
                        predicted = False
                    else:
                        predicted = None
                    chosen = sorted(matches, key=lambda row: str(row.get("reason", "")))[0]
                    decision_reason = str(chosen.get("reason", ""))
                    decision_source = str(chosen.get("decision_source", scope))

                expected_label = str(oracle.get("expected_label", "non_sanitizer"))
                actual_bool = expected_to_bool(expected_label)

                if predicted is None:
                    bucket = "unresolved_oracle"
                elif predicted and actual_bool:
                    bucket = "TP"
                elif predicted and not actual_bool:
                    bucket = "FP"
                elif (not predicted) and (not actual_bool):
                    bucket = "TN"
                else:
                    bucket = "FN"

                matrix_rows.append(
                    {
                        "matrix_scope": scope,
                        "config": config,
                        "stage": str(oracle.get("stage", "unknown")),
                        "file": normalize_file(str(oracle.get("file", ""))),
                        "sink_line": int(oracle.get("sink_line", -1) or -1),
                        "function": str(oracle.get("function", "")),
                        "callee_helper_base_name": canonical_callee(
                            str(
                                oracle.get(
                                    "callee_helper_base_name",
                                    oracle.get("callee_helper_full_name", ""),
                                )
                            )
                        ),
                        "expected_label": expected_label,
                        "actual_bool": actual_bool,
                        "predicted_bool": predicted,
                        "predicted_label": (
                            "true" if predicted is True else "false" if predicted is False else "none"
                        ),
                        "bucket": bucket,
                        "decision_source": decision_source,
                        "reason": decision_reason,
                        "cwe": str(oracle.get("cwe", "UNKNOWN")),
                        "variant": str(oracle.get("variant", "unknown")),
                        "language": str(oracle.get("language", "unknown")),
                    }
                )

    metrics_rows: List[dict] = []
    summary_matrices: Dict[str, dict] = {}
    for scope in matrix_scopes:
        scoped = [row for row in matrix_rows if row["matrix_scope"] == scope]
        overall = grouped_metrics(scoped)
        summary_matrices[scope] = {
            "TP": overall["TP"],
            "FP": overall["FP"],
            "TN": overall["TN"],
            "FN": overall["FN"],
            "unresolved_oracle": overall["unresolved_oracle"],
            "oracle_count": overall["oracle_count"],
            "decided_count": overall["decided_count"],
            "decision_rate": overall["decision_rate"],
            "precision": overall["precision"],
            "recall": overall["recall"],
            "f1": overall["f1"],
            "fpr": overall["fpr"],
            "fnr": overall["fnr"],
        }
        metrics_rows.extend(summarize_dimension(scoped, scope, "overall", lambda _: "all"))
        metrics_rows.extend(summarize_dimension(scoped, scope, "config", lambda row: row["config"]))
        metrics_rows.extend(summarize_dimension(scoped, scope, "stage", lambda row: row["stage"]))
        metrics_rows.extend(summarize_dimension(scoped, scope, "cwe", lambda row: row["cwe"]))
        metrics_rows.extend(summarize_dimension(scoped, scope, "variant", lambda row: row["variant"]))
        metrics_rows.extend(summarize_dimension(scoped, scope, "language", lambda row: row["language"]))

    summary_payload = {
        "generated_at_epoch_ms": now_epoch_ms(),
        "inputs": {
            "decisions": str(decisions_path),
            "oracle": str(oracle_path),
        },
        "counts": {
            "decision_records_raw": len(decision_records_raw),
            "decision_records_reduced": len(reduced_decisions),
            "oracle_records": len(oracle_records),
            "details_rows": len(matrix_rows),
            "out_of_oracle_true": len(out_of_oracle_true_rows),
            "out_of_oracle_false": len(out_of_oracle_false_rows),
        },
        "configs": configs,
        "matrices": summary_matrices,
    }
    write_json(out_dir / "summary.json", summary_payload)

    with (out_dir / "metrics.csv").open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "matrix_scope",
            "dimension",
            "key",
            "TP",
            "FP",
            "TN",
            "FN",
            "unresolved_oracle",
            "oracle_count",
            "decided_count",
            "decision_rate",
            "precision",
            "recall",
            "f1",
            "fpr",
            "fnr",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in metrics_rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})

    with (out_dir / "details.csv").open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "matrix_scope",
            "config",
            "stage",
            "file",
            "sink_line",
            "function",
            "callee_helper_base_name",
            "expected_label",
            "predicted_label",
            "bucket",
            "decision_source",
            "reason",
            "cwe",
            "variant",
            "language",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in matrix_rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})

    for name, rows in [
        ("out_of_oracle_true.csv", out_of_oracle_true_rows),
        ("out_of_oracle_false.csv", out_of_oracle_false_rows),
    ]:
        with (out_dir / name).open("w", newline="", encoding="utf-8") as handle:
            fieldnames = [
                "config",
                "stage",
                "callsite_file",
                "callsite_line",
                "caller_function",
                "callee_method_full_name",
                "callee_base_name",
                "decision_source",
                "predicted_sanitizer",
                "reason",
            ]
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({name_key: row.get(name_key, "") for name_key in fieldnames})

    print(f"Wrote summary: {out_dir / 'summary.json'}")
    print(f"Wrote metrics: {out_dir / 'metrics.csv'}")
    print(f"Wrote details: {out_dir / 'details.csv'}")
    print(f"Wrote out-of-oracle true audit: {out_dir / 'out_of_oracle_true.csv'}")
    print(f"Wrote out-of-oracle false audit: {out_dir / 'out_of_oracle_false.csv'}")


if __name__ == "__main__":
    main()

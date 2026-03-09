#!/usr/bin/env python3
"""Shared helpers for Juliet benchmarking scripts."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx"}
HEADER_EXTENSIONS = {".h", ".hpp"}
ALL_EXTENSIONS = SOURCE_EXTENSIONS | HEADER_EXTENSIONS

FUNCTION_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "sizeof",
    "return",
}


@dataclass(frozen=True)
class JulietFileMeta:
    rel_path: str
    abs_path: str
    cwe: str
    variant: Optional[int]
    variant_text: Optional[str]
    variant_part: str
    prefix: str
    family_id: str
    language: str


@dataclass(frozen=True)
class JulietFunctionRecord:
    case_id: str
    family_id: str
    cwe: str
    variant: str
    language: str
    file: str
    function: str
    start_line: int
    end_line: int
    label: str
    stage: str


def now_epoch_ms() -> int:
    return int(time.time() * 1000)


def normalize_path(path: str | Path) -> str:
    return Path(path).as_posix()


def load_yaml(path: Path) -> dict:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise RuntimeError("PyYAML is required. Install with `pip install pyyaml`.") from exc
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def find_testcases_root(juliet_root: Path) -> Path:
    candidates = [
        juliet_root,
        juliet_root / "testcases",
        juliet_root / "C" / "testcases",
    ]
    for candidate in candidates:
        if cwe_directories(candidate):
            return candidate
    raise ValueError(
        f"Unable to find Juliet testcases root under {juliet_root} containing both CWE121 and CWE122"
    )


def cwe_directories(testcases_root: Path) -> List[Path]:
    cwe121_dirs: List[Path] = []
    cwe122_dirs: List[Path] = []
    for child in sorted(testcases_root.iterdir()) if testcases_root.is_dir() else []:
        if not child.is_dir():
            continue
        name = child.name
        if name == "CWE121" or name.startswith("CWE121_"):
            cwe121_dirs.append(child)
        if name == "CWE122" or name.startswith("CWE122_"):
            cwe122_dirs.append(child)
    return cwe121_dirs + cwe122_dirs if cwe121_dirs and cwe122_dirs else []


def detect_language_from_extension(path: Path) -> str:
    ext = path.suffix.lower()
    if ext == ".c":
        return "c"
    if ext in {".cc", ".cpp", ".cxx"}:
        return "cpp"
    return "header"


def parse_case_filename(file_path: Path, testcases_root: Path) -> Optional[JulietFileMeta]:
    rel = file_path.relative_to(testcases_root)
    stem = file_path.stem
    match = re.match(r"^(?P<prefix>.+)_(?P<variant>\d{2})(?P<part>[a-z]?)$", stem)
    if not match:
        return None

    prefix = match.group("prefix")
    cwe_match = re.match(r"^CWE(?P<cwe>\d+)", prefix)
    if not cwe_match:
        return None

    cwe_num = cwe_match.group("cwe")
    if cwe_num not in {"121", "122"}:
        return None

    variant_text = match.group("variant")
    variant = int(variant_text)
    part = match.group("part") or ""
    family_id = f"{prefix}_{variant_text}"

    return JulietFileMeta(
        rel_path=normalize_path(rel),
        abs_path=normalize_path(file_path),
        cwe=f"CWE{cwe_num}",
        variant=variant,
        variant_text=variant_text,
        variant_part=part,
        prefix=prefix,
        family_id=family_id,
        language=detect_language_from_extension(file_path),
    )


def fallback_file_meta(file_path: Path, testcases_root: Path) -> JulietFileMeta:
    rel = file_path.relative_to(testcases_root)
    cwe = "UNKNOWN"
    for token in rel.parts:
        if token.startswith("CWE") and token[3:].isdigit():
            cwe = token
            break

    family_id = f"{file_path.stem}__unparsed"
    return JulietFileMeta(
        rel_path=normalize_path(rel),
        abs_path=normalize_path(file_path),
        cwe=cwe,
        variant=None,
        variant_text=None,
        variant_part="",
        prefix=file_path.stem,
        family_id=family_id,
        language=detect_language_from_extension(file_path),
    )


def stage_for_variant(variant: Optional[int]) -> str:
    if variant == 1:
        return "A"
    if variant is not None and ((2 <= variant <= 22) or (31 <= variant <= 45) or variant == 1):
        return "B"
    return "C"


def iter_target_files(testcases_root: Path) -> Iterator[Path]:
    for cwe_dir in cwe_directories(testcases_root):
        for path in cwe_dir.rglob("*"):
            if path.is_file() and path.suffix.lower() in ALL_EXTENSIONS:
                yield path


def group_files_by_family(file_paths: Iterable[Path], testcases_root: Path) -> Dict[str, List[JulietFileMeta]]:
    grouped: Dict[str, List[JulietFileMeta]] = {}
    for file_path in sorted(file_paths):
        meta = parse_case_filename(file_path, testcases_root)
        if meta is None:
            meta = fallback_file_meta(file_path, testcases_root)
        grouped.setdefault(meta.family_id, []).append(meta)
    return grouped


def label_function_name(function_name: str) -> Optional[str]:
    if re.search(r"(^|_)goodG2B", function_name):
        return "exclude"
    if re.search(r"(^|_)goodB2G", function_name):
        return "negative"
    if function_name.startswith("bad") or re.search(r"(^|_)bad($|_)", function_name):
        return "positive"
    return None


def strip_comments_and_strings(source: str) -> str:
    out: List[str] = []
    in_block_comment = False
    in_line_comment = False
    in_string = False
    in_char = False
    escape_next = False

    index = 0
    while index < len(source):
        ch = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append("\n")
            else:
                out.append(" ")
            index += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                out.append(" ")
                out.append(" ")
                in_block_comment = False
                index += 2
            else:
                out.append("\n" if ch == "\n" else " ")
                index += 1
            continue

        if in_string:
            if escape_next:
                escape_next = False
            elif ch == "\\":
                escape_next = True
            elif ch == '"':
                in_string = False
            out.append("\n" if ch == "\n" else " ")
            index += 1
            continue

        if in_char:
            if escape_next:
                escape_next = False
            elif ch == "\\":
                escape_next = True
            elif ch == "'":
                in_char = False
            out.append("\n" if ch == "\n" else " ")
            index += 1
            continue

        if ch == "/" and nxt == "/":
            out.append(" ")
            out.append(" ")
            in_line_comment = True
            index += 2
            continue

        if ch == "/" and nxt == "*":
            out.append(" ")
            out.append(" ")
            in_block_comment = True
            index += 2
            continue

        if ch == '"':
            in_string = True
            out.append(" ")
            index += 1
            continue

        if ch == "'":
            in_char = True
            out.append(" ")
            index += 1
            continue

        out.append(ch)
        index += 1

    return "".join(out)


def _extract_candidate_function_name(signature: str) -> Optional[str]:
    normalized = " ".join(signature.strip().split())
    if not normalized:
        return None
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}()]*\)\s*$", normalized)
    if not match:
        return None
    name = match.group(1)
    if name in FUNCTION_KEYWORDS:
        return None
    return name


def extract_functions_with_ranges(source: str) -> List[Tuple[str, int, int]]:
    cleaned = strip_comments_and_strings(source)
    lines = cleaned.splitlines()

    functions: List[Tuple[str, int, int]] = []
    pending: List[str] = []
    pending_start = 0
    in_function = False
    brace_depth = 0
    current_name = ""
    current_start = 0

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()

        if in_function:
            brace_depth += line.count("{")
            brace_depth -= line.count("}")
            if brace_depth <= 0:
                functions.append((current_name, current_start, idx))
                in_function = False
                brace_depth = 0
                current_name = ""
                current_start = 0
            continue

        if not stripped:
            continue

        if stripped.startswith("#"):
            pending = []
            pending_start = 0
            continue

        if not pending:
            pending_start = idx
        pending.append(stripped)

        if ";" in stripped and "{" not in stripped:
            pending = []
            pending_start = 0
            continue

        if "{" in stripped:
            signature = " ".join(pending).split("{", 1)[0]
            candidate = _extract_candidate_function_name(signature)
            pending = []
            pending_start = 0
            if candidate is None:
                continue

            current_name = candidate
            current_start = idx
            brace_depth = line.count("{") - line.count("}")
            if brace_depth <= 0:
                functions.append((current_name, current_start, idx))
                current_name = ""
                current_start = 0
                brace_depth = 0
            else:
                in_function = True

    return functions


def relative_or_self(path: Path, root: Path) -> str:
    try:
        return normalize_path(path.relative_to(root))
    except ValueError:
        return normalize_path(path)


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def metric_block(tp: int, fp: int, tn: int, fn: int) -> dict:
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1 = safe_divide(2 * precision * recall, precision + recall)
    fpr = safe_divide(fp, fp + tn)
    fnr = safe_divide(fn, fn + tp)
    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "fpr": round(fpr, 6),
        "fnr": round(fnr, 6),
    }

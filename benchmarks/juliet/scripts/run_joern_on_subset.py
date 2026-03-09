#!/usr/bin/env python3
"""Execute Joern BOF workflow for one (stage, config) benchmark cell."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

from common import load_json, load_yaml, now_epoch_ms, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, choices=["A", "B", "C"])
    parser.add_argument("--config", required=True, help="Config key from benchmark_config.yaml")
    parser.add_argument(
        "--config-file",
        default="benchmarks/juliet/configs/benchmark_config.yaml",
        help="Benchmark YAML config path",
    )
    parser.add_argument("--force", action="store_true", help="Re-run and overwrite findings even if cached")
    parser.add_argument("--rebuild-cpg", action="store_true", help="Force CPG rebuild")
    parser.add_argument(
        "--flow-mode",
        choices=["malloc_memcpy", "int_array_index", "int_array_index_clamp_io"],
        help="Override flow mode configured in benchmark_config.yaml",
    )
    return parser.parse_args()


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_path(base: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    return (base / candidate).resolve()


def cache_suffix_for_path(path: Path) -> str:
    digest = hashlib.sha1(str(path.resolve()).encode("utf-8")).hexdigest()
    return digest[:12]


def run_command(cmd: List[str], log_handle, cwd: Path) -> Tuple[int, float]:
    start = time.monotonic()
    log_handle.write(f"$ {' '.join(cmd)}\n")
    log_handle.flush()
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        log_handle.write(line)
        log_handle.flush()
    proc.wait()
    elapsed = time.monotonic() - start
    log_handle.write(f"[exit={proc.returncode}] [elapsed_s={elapsed:.3f}]\n\n")
    log_handle.flush()
    return proc.returncode, elapsed


def git_sha(repo_root: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    if proc.returncode == 0:
        return proc.stdout.strip()
    return "unknown"


def main() -> None:
    args = parse_args()
    repo_root = repo_root_from_script()
    config_file = resolve_path(repo_root, args.config_file)
    cfg = load_yaml(config_file)

    config_map: Dict[str, dict] = cfg.get("configs", {})
    if args.config not in config_map:
        raise SystemExit(f"Unknown config '{args.config}'. Available: {', '.join(sorted(config_map))}")

    paths_cfg = cfg.get("paths", {})
    tools_cfg = cfg.get("tools", {})

    staged_root = resolve_path(repo_root, paths_cfg.get("staged_root", "benchmarks/juliet/outputs/staged"))
    cache_root = resolve_path(repo_root, paths_cfg.get("cache_root", "benchmarks/juliet/outputs/cache"))
    findings_root = resolve_path(repo_root, paths_cfg.get("findings_root", "benchmarks/juliet/outputs/findings"))
    logs_root = resolve_path(repo_root, paths_cfg.get("logs_root", "benchmarks/juliet/outputs/logs"))
    manifests_root = resolve_path(repo_root, paths_cfg.get("manifests_root", "benchmarks/juliet/manifests"))

    stage_dir_override = config_map[args.config].get("stage_dir")
    input_root_override = config_map[args.config].get("input_root")
    if stage_dir_override:
        stage_dir = resolve_path(repo_root, str(stage_dir_override))
    elif input_root_override:
        stage_dir = resolve_path(repo_root, str(input_root_override)) / args.stage
    else:
        stage_dir = staged_root / args.stage
    if not stage_dir.is_dir():
        raise SystemExit(f"Missing staged subset directory: {stage_dir}")

    stage_suffix = args.stage.lower()
    stage_manifest_override = config_map[args.config].get("stage_manifest")
    stage_manifest = (
        resolve_path(repo_root, str(stage_manifest_override))
        if stage_manifest_override
        else manifests_root / f"stage_{stage_suffix}_cases.json"
    )
    if not stage_manifest.is_file():
        raise SystemExit(f"Missing stage manifest: {stage_manifest}")
    stage_manifest_data = load_json(stage_manifest)

    joern_bin = resolve_path(repo_root, tools_cfg.get("joern", "./joern"))
    joern_parse_bin = resolve_path(repo_root, tools_cfg.get("joern_parse", "./joern-parse"))
    run_script = resolve_path(repo_root, tools_cfg.get("run_script", "benchmarks/juliet/scripts/run_bof_workflow.sc"))

    config_item = config_map[args.config]
    modeled_policy = str(config_item.get("modeled_policy", "ENFORCE")).upper()
    discovery_enabled = bool(config_item.get("discovery_enabled", False))
    flow_mode = str(config_item.get("flow_mode", "malloc_memcpy"))
    if args.flow_mode:
        flow_mode = args.flow_mode

    cpg_dir = cache_root / "cpg"
    discovery_dir = cache_root / "discovery"
    findings_dir = findings_root / args.config
    logs_dir = logs_root / args.config

    for directory in (cpg_dir, discovery_dir, findings_dir, logs_dir):
        directory.mkdir(parents=True, exist_ok=True)

    cpg_suffix = cache_suffix_for_path(stage_dir)
    cpg_path = cpg_dir / f"stage_{args.stage}_{cpg_suffix}.bin"
    findings_path = findings_dir / f"stage_{stage_suffix}_findings.json"
    decisions_path = findings_dir / f"stage_{stage_suffix}_sanitizer_decisions.json"
    metadata_path = findings_dir / f"stage_{stage_suffix}_metadata.json"
    log_path = logs_dir / f"stage_{stage_suffix}_joern.log"

    if findings_path.exists() and not args.force:
        print(f"Using cached findings: {findings_path}")
        return

    discovery_cache_path = discovery_dir / f"{args.config}_stage_{args.stage}_{cpg_suffix}.json"
    discovery_cache_arg = str(discovery_cache_path) if discovery_enabled else ""

    parse_cmd = [str(joern_parse_bin), str(stage_dir), "--output", str(cpg_path)]
    run_cmd = [
        str(joern_bin),
        "--script",
        str(run_script),
        "--param",
        f"cpgPath={cpg_path}",
        "--param",
        f"outputPath={findings_path}",
        "--param",
        f"decisionOutputPath={decisions_path}",
        "--param",
        f"stage={args.stage}",
        "--param",
        f"configName={args.config}",
        "--param",
        f"flowMode={flow_mode}",
        "--param",
        f"modeledPolicy={modeled_policy}",
        "--param",
        f"discoveryEnabled={'true' if discovery_enabled else 'false'}",
        "--param",
        f"discoveryCachePath={discovery_cache_arg}",
    ]

    started_at = now_epoch_ms()
    parse_elapsed = 0.0
    run_elapsed = 0.0

    with log_path.open("w", encoding="utf-8") as log_handle:
        log_handle.write(f"stage={args.stage} config={args.config}\n")
        log_handle.write(f"config_file={config_file}\n\n")
        log_handle.flush()

        if args.rebuild_cpg or not cpg_path.exists():
            code, parse_elapsed = run_command(parse_cmd, log_handle, repo_root)
            if code != 0:
                raise SystemExit(f"joern-parse failed for stage {args.stage}. See log: {log_path}")
        else:
            log_handle.write(f"Skipping CPG build, cache hit: {cpg_path}\n\n")
            log_handle.flush()

        code, run_elapsed = run_command(run_cmd, log_handle, repo_root)
        if code != 0:
            raise SystemExit(f"Joern workflow failed for stage {args.stage}, config {args.config}. See log: {log_path}")

    if not findings_path.is_file():
        raise SystemExit(f"Expected findings output not found: {findings_path}")
    if not decisions_path.is_file():
        raise SystemExit(f"Expected sanitizer decisions output not found: {decisions_path}")

    findings_data = load_json(findings_path)
    findings_count = 0
    if isinstance(findings_data, dict):
        findings_count = len(findings_data.get("findings", []))
    elif isinstance(findings_data, list):
        findings_count = len(findings_data)

    decisions_data = load_json(decisions_path)
    sanitizer_decision_count = 0
    if isinstance(decisions_data, dict):
        sanitizer_decision_count = len(decisions_data.get("decisions", []))
    elif isinstance(decisions_data, list):
        sanitizer_decision_count = len(decisions_data)

    ended_at = now_epoch_ms()

    metadata = {
        "git_sha": git_sha(repo_root),
        "timestamp_epoch_ms": ended_at,
        "stage": args.stage,
        "config": args.config,
        "flow_mode": flow_mode,
        "config_alias": config_item.get("alias", ""),
        "juliet_root": cfg.get("juliet_root", ""),
        "stage_manifest": str(stage_manifest),
        "stage_input_dir": str(stage_dir),
        "case_count": int(stage_manifest_data.get("case_count", 0)),
        "file_count": int(stage_manifest_data.get("file_count", 0)),
        "finding_count": findings_count,
        "sanitizer_decision_count": sanitizer_decision_count,
        "counts": {
            "finding_count": findings_count,
            "sanitizer_decision_count": sanitizer_decision_count,
        },
        "runtime_seconds": round((ended_at - started_at) / 1000.0, 3),
        "parse_seconds": round(parse_elapsed, 3),
        "analysis_seconds": round(run_elapsed, 3),
        "started_at_epoch_ms": started_at,
        "ended_at_epoch_ms": ended_at,
        "commands": {
            "parse": parse_cmd,
            "analysis": run_cmd,
        },
        "outputs": {
            "findings": str(findings_path),
            "sanitizer_decisions": str(decisions_path),
            "metadata": str(metadata_path),
            "log": str(log_path),
            "cpg": str(cpg_path),
            "discovery_cache": str(discovery_cache_path) if discovery_enabled else "",
        },
    }

    write_json(metadata_path, metadata)
    print(f"Completed stage={args.stage} config={args.config}")
    print(f"Findings: {findings_path}")
    print(f"Metadata: {metadata_path}")


if __name__ == "__main__":
    main()

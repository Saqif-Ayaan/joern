# Juliet BOF Benchmark Pipeline

This directory contains a reproducible benchmark pipeline for Joern-based buffer-overflow analysis on Juliet C/C++ (`CWE121`, `CWE122`).

## What It Does

1. Builds Stage `A/B/C` subsets from a local unpacked Juliet tree.
2. Labels Juliet functions at function level:
   - `bad*` => positive
   - `goodB2G*` => negative
   - `goodG2B*` => excluded
3. Runs Joern BOF workflow for selected benchmark configs.
4. Optionally transforms Stage-A CWE129 sinks into clamp-helper variants for sanitizer-validation experiments.
5. Optionally curates a reduced Stage-A subset with files that match the selected flow family.
6. Scores findings at function level and reports metrics.
7. Aggregates score outputs into machine-readable and Markdown summaries.

## Requirements

- Python 3.9+
- `PyYAML` (`pip install pyyaml`)
- Built Joern binaries in repo root (`./joern`, `./joern-parse`)
- Local unpacked Juliet C/C++ 1.3 or 1.3.1 tree

## Directory Layout

- `scripts/build_juliet_subsets.py`
- `scripts/classify_juliet_cases.py`
- `scripts/run_joern_on_subset.sh`
- `scripts/run_joern_on_subset.py`
- `scripts/run_bof_workflow.sc`
- `scripts/score_joern_results.py`
- `scripts/build_clamp_callsite_oracle.py`
- `scripts/score_sanitizer_decisions.py`
- `scripts/summarize_results.py`
- `scripts/transform_stage_a_clamp_dataset.py`
- `scripts/curate_stage_a_by_findings.py`
- `configs/benchmark_config.yaml`
- `manifests/`
- `outputs/`
- `tests/`

## Stage Definitions

- Stage `A`: variant `01`
- Stage `B`: variants `01..22` and `31..45`
- Stage `C`: all remaining `CWE121/CWE122` cases

Multi-file variants are grouped by case family so files like `53a..53e` stay together.

## Quick Start

1. Set `juliet_root` in `configs/benchmark_config.yaml`.

2. Build staged subsets and manifests.

```bash
python3 benchmarks/juliet/scripts/build_juliet_subsets.py \
  --juliet-root /path/to/Juliet_Test_Suite_v1.3_for_C_Cpp \
  --out benchmarks/juliet \
  --clean-staged
```

3. Label functions for each stage.

```bash
python3 benchmarks/juliet/scripts/classify_juliet_cases.py \
  --stage-manifest benchmarks/juliet/manifests/stage_a_cases.json \
  --out benchmarks/juliet/manifests/stage_a_labels.json

python3 benchmarks/juliet/scripts/classify_juliet_cases.py \
  --stage-manifest benchmarks/juliet/manifests/stage_b_cases.json \
  --out benchmarks/juliet/manifests/stage_b_labels.json

python3 benchmarks/juliet/scripts/classify_juliet_cases.py \
  --stage-manifest benchmarks/juliet/manifests/stage_c_cases.json \
  --out benchmarks/juliet/manifests/stage_c_labels.json
```

4. Run one stage/config cell.

```bash
bash benchmarks/juliet/scripts/run_joern_on_subset.sh \
  --stage A \
  --config branch_enforce_discovery_on \
  --config-file benchmarks/juliet/configs/benchmark_config.yaml
```

You can switch the workflow family on demand:

```bash
bash benchmarks/juliet/scripts/run_joern_on_subset.sh \
  --stage A \
  --config branch_enforce_discovery_on \
  --config-file benchmarks/juliet/configs/benchmark_config.yaml \
  --flow-mode int_array_index
```

5. (Optional) Build derived Stage-A clamp dataset (`bad*` uses bad clamp, `goodB2G*` uses good clamp).

```bash
python3 benchmarks/juliet/scripts/transform_stage_a_clamp_dataset.py \
  --stage-manifest benchmarks/juliet/manifests/stage_a_cases.json \
  --labels benchmarks/juliet/manifests/stage_a_labels.json \
  --staged-stage-root benchmarks/juliet/outputs/staged/A \
  --out-root benchmarks/juliet/outputs/derived/A \
  --out-stage-manifest benchmarks/juliet/manifests/stage_a_derived_cases.json \
  --out-transform-manifest benchmarks/juliet/manifests/stage_a_clamp_transform_manifest.json \
  --clean-out
```

6. (Optional) Curate transformed Stage-A files by `int_array_index` findings.

```bash
python3 benchmarks/juliet/scripts/curate_stage_a_by_findings.py \
  --stage-manifest benchmarks/juliet/manifests/stage_a_derived_cases.json \
  --derived-root benchmarks/juliet/outputs/derived/A \
  --findings benchmarks/juliet/outputs/findings/branch_enforce_discovery_on/stage_a_findings.json \
  --out-root benchmarks/juliet/outputs/curated/A/int_array_index \
  --out-stage-manifest benchmarks/juliet/manifests/stage_a_curated_int_array_index_cases.json \
  --out-curation-manifest benchmarks/juliet/manifests/stage_a_curated_int_array_index_manifest.json \
  --clean-out
```

To build a larger relaxed set (strict flow matches + structural index candidates in `bad*`/`goodB2G*`):

```bash
python3 benchmarks/juliet/scripts/curate_stage_a_by_findings.py \
  --stage-manifest benchmarks/juliet/manifests/stage_a_derived_cases.json \
  --derived-root benchmarks/juliet/outputs/derived/A \
  --findings benchmarks/juliet/outputs/findings/derived_master_int_array/stage_a_findings.json \
  --labels benchmarks/juliet/manifests/stage_a_derived_labels.json \
  --selection-mode matched_flow_or_structural_index \
  --out-root benchmarks/juliet/outputs/curated/A/int_array_index_relaxed \
  --out-stage-manifest benchmarks/juliet/manifests/stage_a_curated_int_array_index_relaxed_cases.json \
  --out-curation-manifest benchmarks/juliet/manifests/stage_a_curated_int_array_index_relaxed_manifest.json \
  --clean-out
```

7. (Optional) Run transformed Stage-A with all 5 policies using the provided config.

```bash
for cfg in master branch_enforce_discovery_off branch_enforce_discovery_on branch_warn_discovery_off branch_trust_discovery_off; do
  bash benchmarks/juliet/scripts/run_joern_on_subset.sh \
    --stage A \
    --config "$cfg" \
    --config-file benchmarks/juliet/configs/benchmark_config_stage_a_derived_int_array.yaml \
    --force
done
```

8. Score one run (or a directory of runs).

```bash
python3 benchmarks/juliet/scripts/score_joern_results.py \
  --findings benchmarks/juliet/outputs/findings \
  --labels benchmarks/juliet/manifests \
  --out benchmarks/juliet/outputs/scored
```

9. (Optional) Build clamp callsite oracle and score sanitizer decisions.

```bash
python3 benchmarks/juliet/scripts/build_clamp_callsite_oracle.py \
  --transform-manifests \
    benchmarks/juliet/manifests/stage_a_clamp_transform_manifest.json \
    benchmarks/juliet/manifests/stage_b_clamp_transform_manifest.json \
    benchmarks/juliet/manifests/stage_c_clamp_transform_manifest.json \
  --out benchmarks/juliet/manifests/clamp_callsite_oracle_all_stages.json

python3 benchmarks/juliet/scripts/score_sanitizer_decisions.py \
  --decisions benchmarks/juliet/outputs/findings \
  --oracle benchmarks/juliet/manifests/clamp_callsite_oracle_all_stages.json \
  --out benchmarks/juliet/outputs/scored/sanitizer_decisions
```

10. Aggregate final summary.

```bash
python3 benchmarks/juliet/scripts/summarize_results.py \
  --inputs benchmarks/juliet/outputs/scored \
  --out benchmarks/juliet/outputs/summary
```

## Config Names

Runner supports these config keys:

- `master` (baseline alias: `ENFORCE` + discovery off)
- `branch_enforce_discovery_off`
- `branch_enforce_discovery_on`
- `branch_warn_discovery_off`
- `branch_trust_discovery_off`

Flow modes:
- `malloc_memcpy` (legacy baseline query)
- `int_array_index` (integer-source to array-index sink query for CWE129-like patterns)
- `int_array_index_clamp_io` (expanded clamp-compatible int-array flow with scanf/fscanf output-arg source tracking)

Optional per-config overrides:
- `flow_mode`: override query family for that config
- `stage_dir`: absolute/relative path to one specific stage directory (useful for derived Stage A)
- `input_root`: root containing `A|B|C` stage folders (fallback when `stage_dir` is not set)
- `stage_manifest`: manifest path to pair with custom `stage_dir`/`input_root`

Curation selection modes in `curate_stage_a_by_findings.py`:
- `matched_flow`
- `matched_flow_or_structural_index`
- `clamp_transformable_only` (requires `--transform-manifest`)
- `clamp_transformable_and_matched_flow` (requires `--transform-manifest`)

## Output Artifacts

- Findings: `outputs/findings/<config>/stage_<x>_findings.json`
- Sanitizer decisions: `outputs/findings/<config>/stage_<x>_sanitizer_decisions.json`
- Metadata: `outputs/findings/<config>/stage_<x>_metadata.json`
- Logs: `outputs/logs/<config>/stage_<x>_joern.log`
- Scores:
  - `summary.json`
  - `metrics.csv`
  - `mismatches.csv`
- Sanitizer decision scores:
  - `summary.json`
  - `metrics.csv`
  - `details.csv`
  - `out_of_oracle_true.csv`
  - `out_of_oracle_false.csv`
- Aggregated summary:
  - `summary.json`
  - `metrics.csv`
  - `metrics.md`
  - `mismatches.csv`

## Reproducibility Metadata

Each run metadata file records:

- git SHA
- timestamp
- stage
- config
- Juliet root
- case and file counts
- runtime
- command lines used

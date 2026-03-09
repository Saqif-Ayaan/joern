# Clamp Curation All-Stages Runbook

This runbook reproduces the current all-stage clamp workflow:

1. Build/label Juliet stages.
2. Transform to clamp-derived datasets.
3. Keep only clamp-transformable files.
4. Run clamp-compatible flow (`int_array_index_clamp_io`) on those files.
5. Curate final subset = `clamp-transformable AND matched-flow`.
6. Merge manifests and score.

All commands are run from repo root.

## 0) Prerequisites

```bash
python3 --version
./joern --help >/dev/null
./joern-parse --help >/dev/null
```

Set Juliet root in config files if needed:

- `benchmarks/juliet/configs/benchmark_config.yaml`
- `benchmarks/juliet/configs/benchmark_config_all_stages_clamp_transformable_only.yaml`

## 1) Build A/B/C staged subsets

```bash
python3 benchmarks/juliet/scripts/build_juliet_subsets.py \
  --juliet-root /Users/saqif/Downloads/C \
  --out benchmarks/juliet \
  --clean-staged
```

## 2) Label A/B/C staged subsets

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

## 3) Transform A/B/C into derived clamp datasets

Note: script name contains `stage_a` but works for any stage manifest/root.

```bash
python3 benchmarks/juliet/scripts/transform_stage_a_clamp_dataset.py \
  --stage-manifest benchmarks/juliet/manifests/stage_a_cases.json \
  --labels benchmarks/juliet/manifests/stage_a_labels.json \
  --staged-stage-root benchmarks/juliet/outputs/staged/A \
  --out-root benchmarks/juliet/outputs/derived/A \
  --out-stage-manifest benchmarks/juliet/manifests/stage_a_derived_cases.json \
  --out-files-manifest benchmarks/juliet/manifests/stage_a_derived_files.txt \
  --out-transform-manifest benchmarks/juliet/manifests/stage_a_clamp_transform_manifest.json \
  --clean-out

python3 benchmarks/juliet/scripts/transform_stage_a_clamp_dataset.py \
  --stage-manifest benchmarks/juliet/manifests/stage_b_cases.json \
  --labels benchmarks/juliet/manifests/stage_b_labels.json \
  --staged-stage-root benchmarks/juliet/outputs/staged/B \
  --out-root benchmarks/juliet/outputs/derived/B \
  --out-stage-manifest benchmarks/juliet/manifests/stage_b_derived_cases.json \
  --out-files-manifest benchmarks/juliet/manifests/stage_b_derived_files.txt \
  --out-transform-manifest benchmarks/juliet/manifests/stage_b_clamp_transform_manifest.json \
  --clean-out

python3 benchmarks/juliet/scripts/transform_stage_a_clamp_dataset.py \
  --stage-manifest benchmarks/juliet/manifests/stage_c_cases.json \
  --labels benchmarks/juliet/manifests/stage_c_labels.json \
  --staged-stage-root benchmarks/juliet/outputs/staged/C \
  --out-root benchmarks/juliet/outputs/derived/C \
  --out-stage-manifest benchmarks/juliet/manifests/stage_c_derived_cases.json \
  --out-files-manifest benchmarks/juliet/manifests/stage_c_derived_files.txt \
  --out-transform-manifest benchmarks/juliet/manifests/stage_c_clamp_transform_manifest.json \
  --clean-out
```

## 4) Curate clamp-transformable-only per stage

```bash
cat >/tmp/empty_findings.json <<'JSON'
{"findings":[]}
JSON

python3 benchmarks/juliet/scripts/curate_stage_a_by_findings.py \
  --stage-manifest benchmarks/juliet/manifests/stage_a_derived_cases.json \
  --derived-root benchmarks/juliet/outputs/derived/A \
  --findings /tmp/empty_findings.json \
  --transform-manifest benchmarks/juliet/manifests/stage_a_clamp_transform_manifest.json \
  --selection-mode clamp_transformable_only \
  --out-root benchmarks/juliet/outputs/curated/all_stages/clamp_transformable_only/A \
  --out-stage-manifest benchmarks/juliet/manifests/stage_a_curated_clamp_transformable_only_cases.json \
  --out-files-manifest benchmarks/juliet/manifests/stage_a_curated_clamp_transformable_only_files.txt \
  --out-curation-manifest benchmarks/juliet/manifests/stage_a_curated_clamp_transformable_only_manifest.json \
  --clean-out

python3 benchmarks/juliet/scripts/curate_stage_a_by_findings.py \
  --stage-manifest benchmarks/juliet/manifests/stage_b_derived_cases.json \
  --derived-root benchmarks/juliet/outputs/derived/B \
  --findings /tmp/empty_findings.json \
  --transform-manifest benchmarks/juliet/manifests/stage_b_clamp_transform_manifest.json \
  --selection-mode clamp_transformable_only \
  --out-root benchmarks/juliet/outputs/curated/all_stages/clamp_transformable_only/B \
  --out-stage-manifest benchmarks/juliet/manifests/stage_b_curated_clamp_transformable_only_cases.json \
  --out-files-manifest benchmarks/juliet/manifests/stage_b_curated_clamp_transformable_only_files.txt \
  --out-curation-manifest benchmarks/juliet/manifests/stage_b_curated_clamp_transformable_only_manifest.json \
  --clean-out

python3 benchmarks/juliet/scripts/curate_stage_a_by_findings.py \
  --stage-manifest benchmarks/juliet/manifests/stage_c_derived_cases.json \
  --derived-root benchmarks/juliet/outputs/derived/C \
  --findings /tmp/empty_findings.json \
  --transform-manifest benchmarks/juliet/manifests/stage_c_clamp_transform_manifest.json \
  --selection-mode clamp_transformable_only \
  --out-root benchmarks/juliet/outputs/curated/all_stages/clamp_transformable_only/C \
  --out-stage-manifest benchmarks/juliet/manifests/stage_c_curated_clamp_transformable_only_cases.json \
  --out-files-manifest benchmarks/juliet/manifests/stage_c_curated_clamp_transformable_only_files.txt \
  --out-curation-manifest benchmarks/juliet/manifests/stage_c_curated_clamp_transformable_only_manifest.json \
  --clean-out
```

## 5) Prepare per-stage manifests for clamp-transformable-only runs

```bash
mkdir -p benchmarks/juliet/manifests/curated_allstage_clamp_transformable_only
cp benchmarks/juliet/manifests/stage_a_curated_clamp_transformable_only_cases.json benchmarks/juliet/manifests/curated_allstage_clamp_transformable_only/stage_a_cases.json
cp benchmarks/juliet/manifests/stage_b_curated_clamp_transformable_only_cases.json benchmarks/juliet/manifests/curated_allstage_clamp_transformable_only/stage_b_cases.json
cp benchmarks/juliet/manifests/stage_c_curated_clamp_transformable_only_cases.json benchmarks/juliet/manifests/curated_allstage_clamp_transformable_only/stage_c_cases.json
```

## 6) Run flow on clamp-transformable-only A/B/C

Config: `benchmarks/juliet/configs/benchmark_config_all_stages_clamp_transformable_only.yaml`

```bash
python3 benchmarks/juliet/scripts/run_joern_on_subset.py \
  --stage A \
  --config clamp_subset_master \
  --config-file benchmarks/juliet/configs/benchmark_config_all_stages_clamp_transformable_only.yaml \
  --force --rebuild-cpg

python3 benchmarks/juliet/scripts/run_joern_on_subset.py \
  --stage B \
  --config clamp_subset_master \
  --config-file benchmarks/juliet/configs/benchmark_config_all_stages_clamp_transformable_only.yaml \
  --force --rebuild-cpg

python3 benchmarks/juliet/scripts/run_joern_on_subset.py \
  --stage C \
  --config clamp_subset_master \
  --config-file benchmarks/juliet/configs/benchmark_config_all_stages_clamp_transformable_only.yaml \
  --force --rebuild-cpg
```

## 7) Final curate: clamp-transformable AND matched-flow

```bash
python3 benchmarks/juliet/scripts/curate_stage_a_by_findings.py \
  --stage-manifest benchmarks/juliet/manifests/stage_a_curated_clamp_transformable_only_cases.json \
  --derived-root benchmarks/juliet/outputs/curated/all_stages/clamp_transformable_only/A \
  --findings benchmarks/juliet/outputs/findings/clamp_subset_master/stage_a_findings.json \
  --selection-mode matched_flow \
  --out-root benchmarks/juliet/outputs/curated/all_stages/clamp_transformable_and_matched_flow/A \
  --out-stage-manifest benchmarks/juliet/manifests/stage_a_curated_clamp_transformable_and_matched_flow_allstages_cases.json \
  --out-files-manifest benchmarks/juliet/manifests/stage_a_curated_clamp_transformable_and_matched_flow_allstages_files.txt \
  --out-curation-manifest benchmarks/juliet/manifests/stage_a_curated_clamp_transformable_and_matched_flow_allstages_manifest.json \
  --clean-out

python3 benchmarks/juliet/scripts/curate_stage_a_by_findings.py \
  --stage-manifest benchmarks/juliet/manifests/stage_b_curated_clamp_transformable_only_cases.json \
  --derived-root benchmarks/juliet/outputs/curated/all_stages/clamp_transformable_only/B \
  --findings benchmarks/juliet/outputs/findings/clamp_subset_master/stage_b_findings.json \
  --selection-mode matched_flow \
  --out-root benchmarks/juliet/outputs/curated/all_stages/clamp_transformable_and_matched_flow/B \
  --out-stage-manifest benchmarks/juliet/manifests/stage_b_curated_clamp_transformable_and_matched_flow_allstages_cases.json \
  --out-files-manifest benchmarks/juliet/manifests/stage_b_curated_clamp_transformable_and_matched_flow_allstages_files.txt \
  --out-curation-manifest benchmarks/juliet/manifests/stage_b_curated_clamp_transformable_and_matched_flow_allstages_manifest.json \
  --clean-out

python3 benchmarks/juliet/scripts/curate_stage_a_by_findings.py \
  --stage-manifest benchmarks/juliet/manifests/stage_c_curated_clamp_transformable_only_cases.json \
  --derived-root benchmarks/juliet/outputs/curated/all_stages/clamp_transformable_only/C \
  --findings benchmarks/juliet/outputs/findings/clamp_subset_master/stage_c_findings.json \
  --selection-mode matched_flow \
  --out-root benchmarks/juliet/outputs/curated/all_stages/clamp_transformable_and_matched_flow/C \
  --out-stage-manifest benchmarks/juliet/manifests/stage_c_curated_clamp_transformable_and_matched_flow_allstages_cases.json \
  --out-files-manifest benchmarks/juliet/manifests/stage_c_curated_clamp_transformable_and_matched_flow_allstages_files.txt \
  --out-curation-manifest benchmarks/juliet/manifests/stage_c_curated_clamp_transformable_and_matched_flow_allstages_manifest.json \
  --clean-out
```

## 8) Merge all-stage final manifests

```bash
python3 - <<'PY'
import json, csv, time
from pathlib import Path
base=Path('benchmarks/juliet/manifests')
inputs={
 'A': base/'stage_a_curated_clamp_transformable_and_matched_flow_allstages_cases.json',
 'B': base/'stage_b_curated_clamp_transformable_and_matched_flow_allstages_cases.json',
 'C': base/'stage_c_curated_clamp_transformable_and_matched_flow_allstages_cases.json',
}
all_cases=[]; all_files=[]; stage_counts={}
for stage,p in inputs.items():
  o=json.load(open(p))
  cases=o.get('cases',[])
  stage_counts[stage]={'cases':o.get('case_count',len(cases)),'files':o.get('file_count',sum(len(c.get('files',[])) for c in cases))}
  for c in cases:
    c2=dict(c); c2['stage']=stage; all_cases.append(c2)
    for f in c.get('files',[]): all_files.append(f'{stage}/{f}')
payload={
 'generated_at_epoch_ms': int(time.time()*1000),
 'stages':['A','B','C'],
 'case_count': len(all_cases),
 'file_count': len(set(all_files)),
 'stage_counts': stage_counts,
 'cases': all_cases,
}
(base/'all_stages_curated_clamp_transformable_and_matched_flow_cases.json').write_text(json.dumps(payload,indent=2,sort_keys=True),encoding='utf-8')
(base/'all_stages_curated_clamp_transformable_and_matched_flow_files.txt').write_text('\\n'.join(sorted(set(all_files)))+'\\n',encoding='utf-8')
with (base/'all_stages_curated_clamp_transformable_and_matched_flow_cases.csv').open('w',newline='',encoding='utf-8') as h:
  w=csv.DictWriter(h,fieldnames=['stage','family_id','cwe','variant','variant_text','file_count','files'])
  w.writeheader()
  for c in all_cases:
    w.writerow({
      'stage':c.get('stage',''),
      'family_id':c.get('family_id',''),
      'cwe':c.get('cwe',''),
      'variant':c.get('variant',''),
      'variant_text':c.get('variant_text',''),
      'file_count':c.get('file_count',''),
      'files':';'.join(c.get('files',[])),
    })
print('total_cases', payload['case_count'], 'total_files', payload['file_count'])
print('stage_counts', payload['stage_counts'])
PY
```

## 9) Label final all-stage curated subset

```bash
python3 benchmarks/juliet/scripts/classify_juliet_cases.py \
  --stage-manifest benchmarks/juliet/manifests/stage_a_curated_clamp_transformable_and_matched_flow_allstages_cases.json \
  --out benchmarks/juliet/manifests/stage_a_curated_clamp_transformable_and_matched_flow_allstages_labels.json

python3 benchmarks/juliet/scripts/classify_juliet_cases.py \
  --stage-manifest benchmarks/juliet/manifests/stage_b_curated_clamp_transformable_and_matched_flow_allstages_cases.json \
  --out benchmarks/juliet/manifests/stage_b_curated_clamp_transformable_and_matched_flow_allstages_labels.json

python3 benchmarks/juliet/scripts/classify_juliet_cases.py \
  --stage-manifest benchmarks/juliet/manifests/stage_c_curated_clamp_transformable_and_matched_flow_allstages_cases.json \
  --out benchmarks/juliet/manifests/stage_c_curated_clamp_transformable_and_matched_flow_allstages_labels.json

python3 - <<'PY'
import json, time
from pathlib import Path
base=Path('benchmarks/juliet/manifests')
inputs=[
  base/'stage_a_curated_clamp_transformable_and_matched_flow_allstages_labels.json',
  base/'stage_b_curated_clamp_transformable_and_matched_flow_allstages_labels.json',
  base/'stage_c_curated_clamp_transformable_and_matched_flow_allstages_labels.json',
]
functions=[]
for p in inputs:
  functions.extend(json.load(open(p)).get('functions',[]))
out=base/'all_stages_curated_clamp_transformable_and_matched_flow_labels.json'
out.write_text(json.dumps({'generated_at_epoch_ms':int(time.time()*1000),'function_count':len(functions),'functions':functions},indent=2,sort_keys=True),encoding='utf-8')
print('function_count',len(functions))
PY
```

## 10) Score final all-stage curated subset

```bash
python3 benchmarks/juliet/scripts/score_joern_results.py \
  --findings benchmarks/juliet/outputs/findings/clamp_subset_master \
  --labels benchmarks/juliet/manifests/all_stages_curated_clamp_transformable_and_matched_flow_labels.json \
  --out benchmarks/juliet/outputs/scored/all_stages_clamp_transformable_and_matched_flow
```

## 11) Build clamp callsite oracle and score sanitizer decisions

```bash
python3 benchmarks/juliet/scripts/build_clamp_callsite_oracle.py \
  --transform-manifests \
    benchmarks/juliet/manifests/stage_a_clamp_transform_manifest.json \
    benchmarks/juliet/manifests/stage_b_clamp_transform_manifest.json \
    benchmarks/juliet/manifests/stage_c_clamp_transform_manifest.json \
  --out benchmarks/juliet/manifests/clamp_callsite_oracle_all_stages.json

python3 benchmarks/juliet/scripts/score_sanitizer_decisions.py \
  --decisions benchmarks/juliet/outputs/findings/clamp_subset_73 \
  --oracle benchmarks/juliet/manifests/clamp_callsite_oracle_all_stages.json \
  --out benchmarks/juliet/outputs/scored/sanitizer_decisions_all_stages
```

## Sanity checks

```bash
python3 - <<'PY'
import json
m=json.load(open('benchmarks/juliet/manifests/all_stages_curated_clamp_transformable_and_matched_flow_cases.json'))
print('final_cases',m['case_count'],'final_files',m['file_count'],'stage_counts',m['stage_counts'])
s=json.load(open('benchmarks/juliet/outputs/scored/all_stages_clamp_transformable_and_matched_flow/summary.json'))
print('scoring_instances',s['counts']['scoring_instances'],'finding_records',s['counts']['finding_records'])
print('overall',s['overall'])
PY
```

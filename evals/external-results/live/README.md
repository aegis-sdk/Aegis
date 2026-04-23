# Live E2E Results

Per-run summary JSONs from `pnpm eval:live`. Each file is an `E2ESummary`
(see `evals/live-e2e/types.ts`) containing baseline and with-Aegis ASR
numbers for one corpus/sensitivity/model-triple combination.

JSONL per-payload streams are **not** committed (see `.gitignore`). They
contain full attacker payloads and live only on the machine that ran the
eval. Summary JSONs contain aggregated numbers only and are safe to
redistribute.

## Headline results

See [BASELINE_REPORT.md](./BASELINE_REPORT.md) for the full writeup
including methodology, caveats, and the data behind every number.

**Phase A measurement (2026-04-23):** Aegis reduces ASR by ~55% at
balanced and ~67% at paranoid across 200 TensorTrust attacks. Two
independent model triples agree to within 2 percentage points on
relative reduction — the defense is not a single-model artifact.

| Sensitivity | n | Baseline ASR | Aegis ASR | Reduction (rel) |
|---|---:|---:|---:|---:|
| permissive | 50 | 34.00% | 38.00% | **-11.76%** (noise) |
| balanced (triple 1) | 100 | 45.00% | 20.00% | **55.56%** |
| balanced (triple 2, cross-family) | 50 | 52.00% | 24.00% | **53.85%** |
| paranoid | 50 | 30.00% | 10.00% | **66.67%** |

## How to reproduce

```bash
AEGIS_LIVE_E2E=1 OPENROUTER_API_KEY=sk-or-... \
  pnpm eval:live --corpus tensortrust --limit 100 --sensitivity balanced
```

Full reproduction of the matrix is in the baseline report.

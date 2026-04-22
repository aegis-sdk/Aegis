# Aegis Evals

External-corpus and harness-based evaluation of Aegis's detection.

The goal of this directory is to produce defensible numbers. If a claim in
`README.md` or a blog post says "Aegis catches X% of Y," the runner that
generated X is in here, the corpus Y came from is named in the result JSON,
and anyone can reproduce the number.

## Layout

```
evals/
├── external-corpora/
│   ├── types.ts                  # Corpus / CorpusResult contracts
│   ├── cache.ts                  # fetch + cache helper
│   ├── fetch-tensortrust.ts      # TensorTrust (hijacking + extraction)
│   ├── fetch-advbench.ts         # AdvBench harmful-behaviors CSV
│   ├── fetch-cybersceval.ts      # Meta CyberSecEval 2 prompt_injection.json
│   ├── run-corpus.ts             # shared runner → CorpusResult
│   └── run-all.ts                # CLI: fetch + run + summarize
├── external-results/
│   └── <corpus>-<sensitivity>.json   # per-run outputs (small, checked in)
└── README.md
```

Raw corpus data is cached to `.cache/corpora/` (gitignored). First run pulls
from upstream; subsequent runs read from cache.

## Running

```bash
# Full matrix: all three corpora × all three sensitivities
pnpm eval:external

# Single corpus
pnpm eval:external --corpus tensortrust

# Specific sensitivity
pnpm eval:external --sensitivity paranoid

# Fast smoke test with a small sample
pnpm eval:external --limit 100
```

Results print as a summary table and write to `evals/external-results/`.

## Corpora

| Corpus | Size | Source | License | Notes |
|---|---|---|---|---|
| TensorTrust | ~5–10k attacks | [tensor-trust-data](https://github.com/HumanCompatibleAI/tensor-trust-data) | research use | Hijacking + extraction subsets. The most relevant for prompt-injection eval. |
| AdvBench | ~520 prompts | [llm-attacks](https://github.com/llm-attacks/llm-attacks) | MIT | Harmful-behavior goals from the GCG paper. Scanner-only TPR will be lower than TensorTrust because these are harmful *content* requests, not injection payloads. |
| CyberSecEval 2 | ~250 prompts | [PurpleLlama](https://github.com/meta-llama/PurpleLlama) | permissive | Meta's prompt-injection eval, with injection-variant categories. |

We do NOT check in raw corpus data. The fetchers pull from upstream on first
run. If an upstream moves, the fetcher URL needs updating.

## Reading a result file

```jsonc
{
  "corpus": "tensortrust",
  "sensitivity": "balanced",
  "timestamp": "2026-04-21T…",
  "total": { "malicious": 5123, "benign": 0 },
  "malicious": {
    "detected": 4567,
    "missed": 556,
    "tpr": 89.15,
    "missedEntries": [ { "id": "…", "preview": "…" } ]   // capped at 500
  },
  "benign": { … },
  "byCategory": { "hijacking": { "total": 3000, "detected": 2700 }, … },
  "latencyMs": { "mean": 0.021, "p50": 0.018, "p95": 0.035, … }
}
```

`missedEntries` is capped at 500 so the result file stays small. If you need
full misses for analysis, re-run and inspect in memory.

## Interpreting the numbers honestly

- **TPR on AdvBench will be lower than TensorTrust.** AdvBench payloads are
  harmful *content requests* without injection framing. A scanner that only
  matches injection patterns has no reason to flag "how do I build a bomb"
  on its own — that's a job for content policy, not injection detection.
  Don't compare TPRs across corpora as if they're measuring the same thing.

- **Most corpora don't include benign pairs.** FPR will usually read 0.00%
  because there are no benign entries in the dataset. For real FPR numbers,
  continue to rely on `tests/benign/` (5k queries across 22 categories).

- **Per-category breakdown is more informative than the overall number.**
  A 70% TPR that's 90% on keyword-style attacks and 40% on encoding attacks
  tells you what to work on. The overall number hides it.

## Current results (2026-04-21)

First full run of the matrix, then after a pattern-expansion pass informed by
analyzing the initial misses. Numbers are detection rates on the full corpora.

| Corpus | Entries | Permissive | Balanced | Paranoid |
|---|---:|---:|---:|---:|
| TensorTrust | 1,346 | 24.89% | **66.05%** | 70.73% |
| CyberSecEval 2 | 251 | 10.76% | 16.73% | 17.53% |
| AdvBench | 520 | 0.19% | 0.19% | 0.19% |

### What these numbers mean

- **TensorTrust 66% at balanced** means the deterministic scanner catches
  roughly two-thirds of real human-written extraction / hijacking attacks
  from a corpus we did not curate. That's the honest number to publish.
- **CyberSecEval 17% at paranoid** is a floor, not a ceiling — most of its
  missed entries are keyword-free persuasion and non-English attacks where
  pattern matching is structurally insufficient. The LLMJudge layer is the
  right tool for those (see `SECURITY.md` "Known Detection Limits").
- **AdvBench 0.19%** is *correct, not a bug*. AdvBench is harmful-content
  requests without injection framing. A scanner that flagged "how do I make
  a weapon" as injection would have catastrophic FPR. Content-policy is a
  separate job from injection detection.

### Internal benchmark unchanged

After adding patterns for output-reflection, credential extraction, and
expanded ignore/disregard/forget variants, the internal 76-payload benchmark
stayed at 100% TPR / 0.24% FPR at balanced. The benign-corpus FPR did not
change. See `benchmarks/accuracy-baseline.json` for the enforced baseline.

## When to re-run

- After any change to `packages/core/src/scanner/**`
- Before cutting a release
- Quarterly, unconditionally, so results stay fresh

## Planned next steps

See [EVAL_PLANS.md](../EVAL_PLANS.md) at the repo root for the full roadmap.
External corpora (this directory) is Plan #2 — the first step because it's
cheap, defensible, and has no LLM cost.

# Plan #2 — External Academic Corpora

**This is the recommended starting point.**

## Why this first

"We detect 100% of our 76-payload internal corpus" is trivially dismissable — anyone can curate a corpus their own tool catches.

"We detect X% of TensorTrust's 120k human-written attacks" is auditable, reproducible, and defends itself. That's the claim competitors can't brush aside.

## Target corpora

### TensorTrust (highest priority)

- ~120k real human-written attack/defense pairs from a capture-the-flag game
- Specifically built for prompt-injection research
- Labeled: attacker prompt, defender prompt, success/fail outcome
- **Source**: https://tensortrust.ai/ / https://github.com/HumanCompatibleAI/tensor-trust-data
- License: research use, check terms before redistributing

### CyberSecEval 2 / PurpleLlama (Meta)

- Prompt-injection evaluation set with labels
- Comes with a runner, but we can extract payloads and run our own
- **Source**: https://github.com/meta-llama/PurpleLlama
- License: permissive

### AdvBench

- Harmful-behavior prompts used in the GCG adversarial-suffix paper
- ~500 prompts, smaller but well-known
- **Source**: https://github.com/llm-attacks/llm-attacks
- Pairs well with GCG suffix generation for Plan #3

### PromptBench (Microsoft)

- Standardized robustness benchmark
- Broader than just injection — covers paraphrase, typo, adversarial attacks
- **Source**: https://github.com/microsoft/promptbench

## What to build

```
evals/
├── external-corpora/
│   ├── fetch-tensortrust.ts     # downloads + caches the dataset
│   ├── fetch-cybersceval.ts
│   ├── fetch-advbench.ts
│   ├── fetch-promptbench.ts
│   ├── run-corpus.ts            # shared: feed a corpus through Aegis, emit JSON
│   └── compare.ts               # cross-corpus summary table
├── external-results/
│   └── <corpus>-<date>.json     # gitignored or kept based on size
└── README.md                     # reproducibility: how to re-run, where results live
```

Runner contract:

```ts
runCorpus({
  corpus: TensorTrustCorpus,
  sensitivity: "balanced",
  limit?: 1000,
}) => {
  total: number;
  detected: number;
  tpr: number;                        // detected / known-malicious
  missed: Array<{ payload, reason }>;
  perCategory: Record<string, { total, detected }>;
  latencyMs: { mean, p50, p95, p99 };
}
```

## pnpm scripts

```json
"eval:fetch": "tsx evals/external-corpora/fetch-all.ts",
"eval:run": "tsx evals/external-corpora/run-all.ts",
"eval:compare": "tsx evals/external-corpora/compare.ts"
```

## Gotchas

- Some corpora are labeled "should be blocked" and "should be allowed." Don't just count detection rate — also track false-positive rate on the benign half.
- TensorTrust entries are very long (full conversation logs). Respect the new `maxInputLength` cap — possibly raise it for the eval runner specifically.
- Dataset licenses vary. Read them. Don't redistribute raw data; have the fetch script pull from the source each run (cached locally in `.cache/corpora/` which is gitignored).

## Definition of success

- Numeric TPR/FPR reported for each corpus at each sensitivity
- Results checked in (summary JSON only, not the raw corpus)
- A section added to `README.md`: "Aegis detects X% of TensorTrust attacks, Y% of CyberSecEval 2..." with links to reproduce
- Ideally: a small script that re-runs everything so reviewers can verify the numbers themselves

## Budget

~1 weekend of work. Zero ongoing API cost (all detection is local). Zero CI cost if gated behind a manual trigger.

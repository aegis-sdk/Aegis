# Live E2E Results

Per-run summary JSONs from `pnpm eval:live`. Each file is an `E2ESummary`
(see `evals/live-e2e/types.ts`) containing baseline and with-Aegis ASR
numbers for one corpus/sensitivity/model-triple combination.

JSONL per-payload streams are **not** committed (see `.gitignore`). They
contain full attacker payloads and live only on the machine that ran the
eval. Summary JSONs contain aggregated numbers only and are safe to
redistribute.

## First recorded run — 2026-04-23

`tensortrust-balanced-2026-04-23T17-20-17-961Z.summary.json`

| | Count | ASR |
|---|---|---|
| Baseline (no Aegis) | 8/10 complied | **80.00%** |
| With Aegis | 2/10 complied, 8 blocked at input | **20.00%** |
| **ASR reduction** | | **60pp absolute, 75% relative** |

- **Corpus**: TensorTrust (hijacking + extraction subsets), 10-payload smoke
- **Victim**: `openai/gpt-oss-20b:free` (OpenRouter free tier)
- **Aegis judge**: same
- **Compliance detector**: same
- **Sensitivity**: balanced

### Honest caveats on these numbers

1. **10 payloads is too small to generalize.** Treat this as a sanity check
   that the harness works, not a defensible claim about Aegis's real-world
   effectiveness. A 100-200 payload run is the next step.

2. **Victim + judge + compliance all on the same model.** When the three
   roles share a model the eval is biased — both directions. A stronger
   victim or a weaker judge would change the numbers. For serious
   comparisons, use different model families for each role.

3. **The two Aegis failures are a documented gap.** Both were "Access granted"
   outcome-coercion attacks (classic TensorTrust CTF pattern). The external-
   corpora evaluation already identified this category as the largest
   remaining scanner gap (128 entries). It's the category Plan #3 (red-team
   loop) is specifically designed to grow patterns against.

4. **Free-tier rate limits are real.** The harness hit upstream 429s on the
   first two attempted runs with other free models. The OpenRouter adapter
   now has retry-with-backoff, but large-corpus runs may still take hours
   on the free tier.

## How to reproduce

```bash
AEGIS_LIVE_E2E=1 \
OPENROUTER_API_KEY=sk-or-... \
pnpm eval:live --corpus tensortrust --limit 10
```

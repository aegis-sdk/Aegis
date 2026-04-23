# Live End-to-End Eval Harness (Plan #1)

Measures *attack success rate (ASR) reduction* by running adversarial payloads through a real victim model twice — once direct, once through Aegis — and letting a separate compliance-detector model label each response.

This is the claim that matters: "Aegis reduces attack success against real models by X%." Pattern TPR is a proxy; ASR reduction is the outcome.

## Three models per run

1. **Victim**: the target model receiving attacks. Represents a typical LLM app.
2. **Aegis judge**: the model Aegis uses for grey-band input/output second-pass.
3. **Compliance detector**: eval-only oracle that labels "did the model comply?"

They can be the same model or different models. Defaults use OpenRouter's free Llama-3.1-8b for all three to keep cost at zero at the expense of eval quality.

## Gating

This harness makes real API calls. It refuses to run unless `AEGIS_LIVE_E2E=1` is set explicitly. `OPENROUTER_API_KEY` is required.

## Usage

```bash
# Smallest smoke run — 10 tensortrust payloads, free Llama for all three
AEGIS_LIVE_E2E=1 \
OPENROUTER_API_KEY=sk-or-... \
pnpm eval:live --corpus tensortrust --limit 10

# Larger run with a stronger judge (paid)
AEGIS_LIVE_E2E=1 \
OPENROUTER_API_KEY=sk-or-... \
pnpm eval:live --corpus tensortrust --limit 100 \
  --judge anthropic/claude-haiku-4.5 \
  --compliance anthropic/claude-haiku-4.5

# Sensitivity sweep
for s in permissive balanced paranoid; do
  AEGIS_LIVE_E2E=1 OPENROUTER_API_KEY=... pnpm eval:live \
    --corpus tensortrust --limit 50 --sensitivity "$s"
done
```

## Output

Two files per run, written to `evals/external-results/live/`:

- **`<corpus>-<sensitivity>-<timestamp>.jsonl`** — one JSON per payload, streamed as the run progresses so partial results survive a crash. Contains the payload, baseline and Aegis responses, and compliance verdicts for both.
- **`<corpus>-<sensitivity>-<timestamp>.summary.json`** — aggregated summary with baseline ASR, Aegis ASR, reduction, and per-category breakdown.

## Cost expectations

Each payload costs 3 API calls (victim baseline + victim with Aegis + compliance × 2 of those). At OpenRouter's free tier this is ~$0 but rate-limited to ~20 req/min — a 100-payload run takes ~30 minutes. On paid Haiku it's ~$0.002/payload, so a 100-payload run is ~$0.20.

## Known sources of noise

1. **Free-model quality**: Small models give less reliable compliance judgments. Run with Haiku or GPT-4o-mini if the numbers need to be trustworthy.
2. **Victim model variance**: Even at `temperature=0`, some models show run-to-run variance. Take numbers as an estimate, not a point value. Run the same eval 3× and report a range if this matters.
3. **Compliance oracle bias**: The compliance detector is itself an LLM. Garbage in, garbage out. For serious comparisons, consider running two different compliance detectors and only counting "complied" when both agree.
4. **Rate-limit induced errors**: Free tier will throw rate-limit errors under sustained load. The harness marks rate-limited calls as `errored` and reports them as compliance=false (conservative).

## What this is NOT

- **Not a production-readiness test.** A 50-payload corpus can't prove generalization.
- **Not a competitor benchmark.** For that, see `docs/eval-plans/04-differential-harness.md`.
- **Not a judge-accuracy test.** The compliance detector is the eval's own oracle, not the defense. If it systematically misjudges, both baseline and Aegis numbers drift together.

## Next step

Run one baseline eval, commit the summary JSON, wire a regression-style comparison so future changes can be measured against a known-good run.

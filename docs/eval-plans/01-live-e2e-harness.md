# Plan #1 — Live LLM End-to-End Harness

## The gap

Current tests prove `InputScanner` flags patterns. They do not prove that an injection sent through a real LLM with Aegis wrapped around it actually fails to reach the user.

A scanner that flags 100% of inputs but whose kill switch misses half the outputs is less useful than the headline TPR suggests. These are separate guarantees and need separate evidence.

## What to build

A full-pipeline harness under `tests/live/` that exercises the whole library against real models:

- Real provider (Anthropic Haiku + gpt-4o-mini + a small open model via Ollama for offline cases)
- Real `Aegis` instance, real streaming flow (`streamText`-like)
- Feed the existing 76-payload adversarial corpus through
- Record per-payload:
  - Did the model actually comply with the injection (ASR baseline)?
  - Did Aegis's scanner catch it at input time?
  - Did the stream monitor catch it during output if input slipped?
  - Did the kill switch fire before the bad token reached stdout?

## The metric that matters

**Attack Success Rate (ASR) with Aegis on vs off**, not raw TPR.
- ASR-baseline: % of payloads where the unwrapped model complied with the injection
- ASR-with-aegis: % of payloads where the Aegis-wrapped model produced output the user could actually see
- Reduction: `(ASR-baseline − ASR-with-aegis) / ASR-baseline`

This is the number to publish. "Aegis reduces attack success by X%" is defensible; "scanner TPR is 100%" is a distraction.

## Cost & gating

- Haiku + gpt-4o-mini @ 76 payloads × 3 sensitivity profiles ≈ 230 calls/run
- At current pricing, roughly $0.50–$2 per run
- Gate behind `AEGIS_LIVE_E2E=1` so CI doesn't pay on every push
- Run nightly or on release-candidate builds

## Files to create

- `tests/live/e2e-harness.test.ts` — the main suite
- `tests/live/providers.ts` — provider adapters (Anthropic, OpenAI, Ollama)
- `tests/live/payloads.ts` — reuse the adversarial corpus from the existing benchmark
- `tests/live/README.md` — env setup, cost expectations, how to run
- `.github/workflows/e2e-nightly.yml` — scheduled runner with API keys as secrets

## Definition of success

Published ASR reduction number, per provider, per sensitivity. Results checked into `evals/e2e-results/<date>-<provider>.json` so trends over time are visible.

# Aegis Eval Plans

Index of test-harness ideas for proving Aegis actually works as a defense layer, not just as a pattern matcher.

The existing `tests/` tree proves the scanner *detects* known patterns. These plans are for closing the gap between "detection fired" and "user was actually protected."

## Plans

1. [Live LLM end-to-end harness](./docs/eval-plans/01-live-e2e-harness.md) — the gap in the current test suite
2. [External academic corpora](./docs/eval-plans/02-external-corpora.md) — TensorTrust / CyberSecEval / AdvBench **← starting here**
3. [Red-team LLM harness](./docs/eval-plans/03-red-team-loop.md) — point a capable model at Aegis and tell it to break it
4. [Differential harness vs. competitors](./docs/eval-plans/04-differential-harness.md) — Aegis vs. Rebuff, LLM Guard, Lakera, etc.
5. [Production shadow mode](./docs/eval-plans/05-production-shadow-mode.md) — observe-only pilots with real apps
6. [Pipeline-level fuzzing](./docs/eval-plans/06-pipeline-fuzzing.md) — orchestrator-level property testing

## Current status

- Unit + adversarial + benign corpus + fuzz coverage: **in place**
- Live E2E harness: **partial** (gated LLMJudge test at `tests/integration/judge-live.test.ts`)
- Everything below that line: **planned**

## Priority

Start: **#2** (external corpora). Cheap, defensible, no live LLM cost.
Then: **#1** (live E2E harness). Closes the "scanner flagged ≠ user protected" gap.
Then: **#3** (red-team loop). Generates corpus material faster than hand-curation.

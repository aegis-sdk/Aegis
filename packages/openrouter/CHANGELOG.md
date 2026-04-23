# @aegis-sdk/openrouter

## 1.0.0

### Minor Changes

- df62e24: LLMJudge wired into the defense pipeline (input + output), OpenRouter adapter,
  and a live end-to-end eval harness that measures real attack-success-rate
  reduction.

  **Core (`@aegis-sdk/core`)**
  - `LLMJudge` grew a grey-band config (`band: { low, high }`) and a
    3-way `classify(score)` method returning `pass | judge | block`.
    Scanner-unsafe inputs below `band.low` pass without a judge call;
    above `band.high` block without a judge call; in between, the judge
    decides. Default band `[0.25, 0.75]`.
  - Legacy `triggerThreshold` still works and maps to a one-sided band for
    back-compat.
  - New `LLMJudge.evaluateInput(userInput, context)` method — evaluates
    an input before the model runs (complement to `evaluate`, which judges
    model output).
  - `Aegis.guardInput` now routes scanner-unsafe-but-grey-band inputs
    through the judge. A judge-approved verdict overrides the scanner's
    unsafe verdict, letting legitimate borderline requests through.
  - `Aegis.createJudgedStreamTransform(userRequest, options)` — new
    `TransformStream` that buffers LLM output, asks the judge whether it
    aligns with the user's original request, and either emits the approved
    output or a redaction marker. Supports `mode: "buffer"` (default,
    safe — user sees nothing until approved) and `mode: "passthrough"`
    (live streaming + post-hoc judge audit).
  - Audit events gain a `phase: "input" | "output"` field on
    `judge_evaluation` entries.

  **OpenRouter adapter (`@aegis-sdk/openrouter`) — new package**
  - `createJudgeCall(config)` returns an `LLMJudgeCallFn` for `new LLMJudge({ llmCall })`.
  - `createChatCall(config)` returns a general chat-completion function for
    victim-model testing in eval harnesses.
  - Retry-with-exponential-backoff on 429 / 5xx responses (free-tier rate
    limits are real).
  - `FREE_MODELS` constant lists known-good free model ids; `DEFAULT_FREE_MODEL`
    picks a small-and-fast default.

  **Live E2E harness (`evals/live-e2e/`)**
  - `pnpm eval:live` runs adversarial payloads through a real victim model
    twice (direct + with Aegis) and uses a separate "compliance detector"
    model to label each response as complied/refused.
  - Measures **ASR reduction** — the actual outcome-level metric, not just
    scanner TPR.
  - Three model slots (victim, Aegis judge, compliance detector) are
    independently configurable via CLI flags.
  - Gated behind `AEGIS_LIVE_E2E=1` + `OPENROUTER_API_KEY`; refuses to run
    without explicit opt-in.
  - Per-payload JSONL streams (gitignored) + aggregate summary JSON
    (committed) written to `evals/external-results/live/`.

  **First recorded run** — 10-payload TensorTrust smoke, all three roles
  on `openai/gpt-oss-20b:free`:
  - Baseline ASR (no Aegis): 80%
  - Aegis ASR (balanced): 20% (8 blocked at input, 2 "Access granted"
    outcome-coercion leaked through — the known-hard category from the
    external-corpora evaluation)
  - Reduction: 60 percentage points absolute, 75% relative

  Numbers are smoke-test scale, not publication-ready. Larger runs and
  model-independence are the next validation steps.

  **Tests**
  - 55 judge unit tests (was 48 — added `evaluateInput`, grey-band
    `classify`, legacy `triggerThreshold` back-compat, scanner-context
    propagation, async-error fallback).
  - 32 orchestrator tests (was 21 — added input-judge wiring cases and
    7 `createJudgedStreamTransform` tests covering buffer+passthrough
    modes, empty output, OOM cap, missing-judge error).
  - Total: **6,013 passing**, 3 skipped, 6 todo.
  - Internal benchmark unchanged (balanced TPR 100%, FPR 0.24%).

### Patch Changes

- Updated dependencies [d82b3e4]
- Updated dependencies [8748c08]
- Updated dependencies [d548a7b]
- Updated dependencies [df62e24]
  - @aegis-sdk/core@0.6.0

# @aegis-sdk/core

## 0.6.0

### Minor Changes

- d82b3e4: Phase 1 audit remediation — hardening the core detection pipeline.

  **Scanner**
  - Wire `tryDecodeBase64` into `normalizeEncoding()`. Base64-wrapped injection payloads containing suspicious keywords are now surfaced to pattern matching via an appended `[base64-decoded: …]` view. Innocuous base64 payloads pass through untouched.
  - Add error boundaries around both the built-in and custom pattern-match loops. If a regex throws, the scanner emits a `scanner_error` detection at `critical` severity — the scan result fails closed instead of bubbling an uncaught exception.
  - Tighten role-play patterns that previously used unbounded `.*` before an alternation. Replaced with `[\s\S]{0,200}?` to cap worst-case backtracking on pathological inputs.
  - Expand the Unicode homoglyph map from ~25 entries to ~140 entries. Coverage now includes Cyrillic, Greek, Armenian, Latin Extended / IPA, Mathematical Alphanumerics (Bold + Italic), Fullwidth Latin, and smart quotes.
  - Add a configurable `contextFloodingThreshold` (default 50,000 chars, raised from a hard-coded 10,000). Long legitimate RAG contexts no longer falsely trip the flood detector.

  **Stream Monitor**
  - `onViolation` callbacks are now awaited inside the TransformStream. Audit-log writes have a chance to flush before `controller.terminate()` runs.
  - Rejections inside `onViolation` are caught and logged to stderr via a new `safeNotify` helper — an audit-log failure no longer crashes the stream.
  - The `onViolation` callback type now explicitly permits `Promise<void>` return values.

  **Sandbox**
  - Add `SANDBOX_EXTRACTION_FAILED` symbol and `didExtractionFail()` helper. When `failMode: "open"` returns schema defaults after exhausted retries, the result is now tagged with a non-enumerable sentinel so callers can distinguish a genuinely-empty extraction from a post-failure fallback.

  **Types**
  - New `DetectionType` variant: `scanner_error`.
  - New `InputScannerConfig.contextFloodingThreshold` field.
  - `StreamMonitorConfig.onViolation` widened to `(v) => void | Promise<void>`.

- 8748c08: Phase 5 — smaller improvements surfaced during the audit.
  - **`maxInputLength` cap**: `InputScanner` now short-circuits oversized inputs (default: 1,000,000 chars) with a critical `context_flooding` detection before normalization or pattern matching. Set to 0 to disable.
  - **Shared injection-keyword list**: `packages/core/src/scanner/keywords.ts` owns the canonical keyword set used both by the base64 decoder's suspicion gate and by any future shared detection code. Prevents drift between hand-rolled copies.
  - **`replaceHomoglyphs` single-pass regex**: swapped char-by-char iteration for a precompiled `/…/gu` regex built from the homoglyph map. 100k-char inputs normalize in <4ms.

- d548a7b: External-corpus evaluation and pattern expansion.

  Added `evals/external-corpora/` — fetchers and runners for TensorTrust,
  AdvBench, and CyberSecEval 2 (Meta PurpleLlama). Each run produces a
  reproducible JSON with TPR, FPR, per-category breakdown, and latency stats.
  Raw corpora are pulled from upstream on first run and cached in
  `.cache/corpora/` (gitignored); we do not redistribute raw data.

  Running the initial matrix exposed real gaps in the pattern set. Expanded:
  - **Instruction override**: `ignore/disregard/forget` patterns now cover
    `directives|orders|commands|directions|training` in addition to the
    existing `instructions|prompts|rules`. Added a shorter `forget <object>`
    shape so "forget previous instructions" matches — previously only the
    rigid "forget everything you were told" shape was caught.
  - **Instead-of substitution**: new pattern catches task-hijack attempts
    framed as "instead of doing X, do Y."
  - **Output-reflection attacks**: new pattern for "repeat/echo/print the
    above/preceding/previous [text|content|message|conversation]." Scoped
    narrowly to avoid tripping "could you repeat that" in normal
    conversation.
  - **Credential extraction**: new pattern for
    "tell me|reveal|show me <the|your> secret|password|passphrase|access
    code|api key|auth token|credentials." Scoped to secret-ish nouns to
    avoid matching "tell me the answer" / "show me the code."
  - **Output coercion**: new pattern for
    "say|respond|reply|answer|output|print|write + only|exactly|verbatim|
    just|literally|nothing but" — forces model to emit attacker-controlled
    text.
  - **Output-prefix hijack**: new pattern for
    "start|begin|prefix|preface|prepend|open your response|output|answer|
    reply|message with."

  Detection deltas on full external corpora:

  | Corpus               | Sensitivity | Before |  After |
  | -------------------- | ----------- | -----: | -----: |
  | TensorTrust (1,346)  | balanced    | 42.27% | 66.05% |
  | TensorTrust (1,346)  | paranoid    | 54.83% | 70.73% |
  | CyberSecEval 2 (251) | balanced    | 11.16% | 16.73% |
  | CyberSecEval 2 (251) | paranoid    | 11.95% | 17.53% |

  Internal benchmark unchanged: balanced TPR 100%, balanced FPR 0.24%,
  mean latency 0.017ms. Permissive TPR on the internal 76-payload corpus
  went from 52.6% → 55.3% as a small side effect of the expanded patterns.
  No new false positives on the 5,000-query benign corpus.

  The regression gate only enforces the balanced profile, so the permissive
  TPR bump does not require a baseline update. `accuracy-baseline.json`
  remains at the previously-frozen values.

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

## 0.5.0

### Minor Changes

- ## v0.5.0 — Launch Prep Release

  ### @aegis-sdk/core

  **New features:**
  - **Sandbox module**: Full implementation with provider-agnostic `llmCall` function, schema enforcement, type coercion, retry logic, timeout, and fail-open/fail-closed modes
  - **Policy file loading**: `loadPolicyFile()` for async JSON/YAML loading, `validatePolicySchema()` for validation, `parseSimpleYaml()` zero-dependency YAML parser
  - **Detection benchmarks**: 100% TPR on 76 adversarial payloads, 0.24% FPR on 5,000 benign corpus at `balanced` sensitivity

  **New exports:** `SandboxCallFn`, `loadPolicyFile`, `validatePolicySchema`, `parseSimpleYaml`

  ### All packages
  - Added npm-facing README with installation, quick start, and API reference
  - 5,943 tests passing across 43 test files
  - Published detection accuracy benchmarks (`pnpm benchmark:accuracy`)

## 0.2.0

### Minor Changes

- Phase 2 release — agentic defense, framework adapters, and false-positive elimination.

  ### @aegis-sdk/core
  - ActionValidator: human-in-the-loop approval gates, MCP parameter scanning, denial-of-wallet detection, data exfiltration prevention
  - `guardChainStep()`: agentic loop protection with step budgets, cumulative risk tracking, and privilege decay
  - StreamMonitor: PII redaction mode (12 patterns — SSN, CC, email, phone, IP, passport, DOB, IBAN, routing number, driver's license, MRN)
  - False positive elimination: 17 → 0 FPs from benign corpus (refined role manipulation patterns, CJK entropy boosting, code block stripping, Cyrillic mixing thresholds)
  - New types: `ActionValidatorConfig`, `DenialOfWalletConfig`, `ChainStepOptions`, `ChainStepResult`, `AgentLoopConfig`

  ### @aegis-sdk/vercel
  - Fixed `createAegisTransform()` to return proper `StreamTextTransform` function compatible with Vercel AI SDK `experimental_transform`

  ### @aegis-sdk/anthropic (NEW)
  - `guardMessages()` — scan Anthropic MessageParam[] for injection
  - `createStreamTransform()` — monitor streaming responses
  - `wrapAnthropicClient()` — Proxy-based client wrapper with automatic input/output protection

  ### @aegis-sdk/openai (NEW)
  - `guardMessages()` — scan OpenAI ChatCompletionMessageParam[] for injection
  - `createStreamTransform()` — monitor streaming responses
  - `wrapOpenAIClient()` — Proxy-based client wrapper with nested proxy for chat.completions.create()

  ### @aegis-sdk/langchain (NEW)
  - `createAegisCallback()` — LangChain callback handler (handleLLMStart, handleLLMEnd, handleToolStart, handleToolEnd)
  - `AegisChainGuard` — agentic chain protection with step budgets and cumulative risk

  ### @aegis-sdk/hono (NEW)
  - `aegisMiddleware()` — Hono middleware with context injection
  - `aegisStreamTransform()` — output stream monitoring
  - `guardMessages()` — standalone guard

  ### @aegis-sdk/next (NEW)
  - `withAegis()` — App Router handler wrapper
  - `aegisMiddleware()` — Edge-compatible middleware with route matching

  ### @aegis-sdk/testing
  - `generateFuzzPayloads()` — combinatorial payload generator
  - Template-based fuzz testing infrastructure with fast-check (10 property-based tests)

## 0.1.0

### Minor Changes

- Initial v0.1.0 release — streaming-first prompt injection defense for JavaScript/TypeScript.

  ### @aegis-sdk/core
  - InputScanner with 60+ detection patterns across all 19 OWASP-aligned threat categories (T1-T19)
  - Quarantine type system with taint tracking and `unsafeUnwrap()` escape hatch
  - PromptBuilder with delimiter injection, canary tokens, and role-locked sections
  - StreamMonitor with sliding-window cross-chunk pattern detection via TransformStream
  - AuditLog with pluggable transports, alerting rules, and structured event logging
  - ActionValidator for tool-call allow/deny enforcement
  - Sandbox for structured data extraction with schema validation
  - Policy engine with 3 presets (strict, balanced, permissive) and full customization
  - Shannon entropy analysis for adversarial suffix detection (GCG attacks)
  - Unicode script detection for language-switching attacks (T18)
  - Encoding normalization (base64, Unicode escapes, zero-width characters, homoglyphs)
  - Many-shot jailbreak detection
  - Trajectory analysis for multi-turn Crescendo attack detection (T7)
  - Recovery modes: continue, reset-last, quarantine-session, terminate-session

  ### @aegis-sdk/vercel
  - `createAegisTransform()` for Vercel AI SDK `experimental_transform`
  - `guardMessages()` convenience wrapper for input scanning
  - `createAegisMiddleware()` for `wrapLanguageModel()` integration

  ### @aegis-sdk/express
  - `aegisMiddleware()` — Express 4/5 middleware with configurable message scanning
  - `aegisStreamTransform()` — output stream monitoring helper
  - `guardMessages()` — standalone guard function for non-middleware use
  - Custom `onBlocked` handler support
  - Global `req.aegis` type augmentation

  ### @aegis-sdk/testing
  - 20 attack suites with 56+ payloads covering all 19 threat categories
  - Benign corpus (200 entries) for false positive validation
  - `scannerAccuracy()` benchmark utility
  - `generateEvasion()` for automated evasion variant generation

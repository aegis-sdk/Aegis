# @aegis-sdk/express

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

### Patch Changes

- Updated dependencies
  - @aegis-sdk/core@0.4.0

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

### Patch Changes

- Updated dependencies
  - @aegis-sdk/core@0.2.0

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

### Patch Changes

- Updated dependencies
  - @aegis-sdk/core@0.1.0

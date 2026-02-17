# @aegis-sdk/next

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

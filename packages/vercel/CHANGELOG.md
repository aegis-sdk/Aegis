# @aegis-sdk/vercel

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

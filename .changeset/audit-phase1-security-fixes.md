---
"@aegis-sdk/core": minor
---

Phase 1 audit remediation — hardening the core detection pipeline.

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

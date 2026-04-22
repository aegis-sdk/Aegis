---
"@aegis-sdk/core": minor
---

Phase 5 — smaller improvements surfaced during the audit.

- **`maxInputLength` cap**: `InputScanner` now short-circuits oversized inputs (default: 1,000,000 chars) with a critical `context_flooding` detection before normalization or pattern matching. Set to 0 to disable.
- **Shared injection-keyword list**: `packages/core/src/scanner/keywords.ts` owns the canonical keyword set used both by the base64 decoder's suspicion gate and by any future shared detection code. Prevents drift between hand-rolled copies.
- **`replaceHomoglyphs` single-pass regex**: swapped char-by-char iteration for a precompiled `/…/gu` regex built from the homoglyph map. 100k-char inputs normalize in <4ms.

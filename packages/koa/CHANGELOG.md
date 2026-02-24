# @aegis-sdk/koa

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

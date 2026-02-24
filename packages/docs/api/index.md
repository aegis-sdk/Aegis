# API Reference

## Package Imports

```ts
// Recommended: import from @aegis-sdk/core
import { Aegis, aegis } from "@aegis-sdk/core";

// Individual modules
import {
  InputScanner,
  StreamMonitor,
  PromptBuilder,
  AuditLog,
  ActionValidator,
  Sandbox,
  MessageSigner,
  AlertingEngine,
  TrajectoryAnalyzer,
  PerplexityAnalyzer,
  AutoRetryHandler,
  LLMJudge,
  MultiModalScanner,
} from "@aegis-sdk/core";

// Policy utilities
import { resolvePolicy, getPreset, isActionAllowed } from "@aegis-sdk/core";

// Quarantine
import { quarantine, isQuarantined } from "@aegis-sdk/core";

// Analysis utilities
import {
  normalizeEncoding,
  tryDecodeBase64,
  shannonEntropy,
  analyzeEntropy,
  detectLanguageSwitches,
} from "@aegis-sdk/core";

// Transports
import { FileTransport, OTelTransport } from "@aegis-sdk/core";
```

## Classes

| Class | Description | Page |
|-------|-------------|------|
| [`Aegis`](/api/aegis) | Main entry point — orchestrates the full defense pipeline | [Aegis](/api/aegis) |
| [`InputScanner`](/api/input-scanner) | Pattern matching + heuristic injection detection | [InputScanner](/api/input-scanner) |
| [`StreamMonitor`](/api/stream-monitor) | Real-time output scanning via TransformStream | [StreamMonitor](/api/stream-monitor) |
| [`PromptBuilder`](/api/prompt-builder) | Sandwich pattern prompt construction | [PromptBuilder](/api/prompt-builder) |
| [`ActionValidator`](/api/action-validator) | Tool call validation, rate limiting, DoW detection | [ActionValidator](/api/action-validator) |
| [`AuditLog`](/api/audit-log) | Security event logging (console, file, OTel, custom) | [AuditLog](/api/audit-log) |
| `Sandbox` | Zero-capability model for untrusted content | — |
| `MessageSigner` | HMAC conversation integrity (T15) | — |
| `AlertingEngine` | Real-time alerting (rate-spike, session-kills) | — |
| `TrajectoryAnalyzer` | Crescendo / multi-turn attack detection (T7) | — |
| `PerplexityAnalyzer` | Character-level n-gram perplexity estimation | — |
| `AutoRetryHandler` | Retry-with-escalation for blocked input | — |
| `LLMJudge` | Intent alignment verification using a second LLM | — |
| `MultiModalScanner` | Text extraction + scanning for images, PDFs, audio | — |

## Error Classes

| Error | Description |
|-------|-------------|
| `AegisInputBlocked` | Thrown when input is blocked by the scanner. Carries `scanResult: ScanResult`. |
| `AegisSessionQuarantined` | Thrown when a quarantined session receives further input. |
| `AegisSessionTerminated` | Thrown on critical violation. Session cannot be recovered. Carries `scanResult: ScanResult`. |
| `MultiModalFileTooLarge` | Thrown when media content exceeds `maxFileSize`. |
| `MultiModalUnsupportedType` | Thrown when the media type is not in `allowedMediaTypes`. |
| `MultiModalExtractionFailed` | Thrown when text extraction returns empty text. |

## Policy Functions

| Function | Description |
|----------|-------------|
| [`resolvePolicy(input)`](/api/policy-engine) | Resolve a preset name or policy object into an `AegisPolicy` |
| [`getPreset(name)`](/api/policy-engine) | Get a built-in policy preset by name |
| [`isActionAllowed(policy, toolName)`](/api/policy-engine) | Check if a tool is allowed/denied/requires-approval |

## Quarantine Functions

| Function | Description |
|----------|-------------|
| [`quarantine(value, options)`](/api/quarantine) | Wrap content in a `Quarantined<T>` container |
| [`isQuarantined(value)`](/api/quarantine) | Type guard — returns `true` if value is quarantined |

## Utility Functions

| Function | Description |
|----------|-------------|
| `normalizeEncoding(text)` | Normalize Unicode, homoglyphs, zero-width characters, and base64 |
| `tryDecodeBase64(text)` | Attempt to decode a base64 string; returns original on failure |
| `shannonEntropy(text)` | Calculate Shannon entropy in bits per character |
| `analyzeEntropy(text, options?)` | Sliding-window entropy analysis with anomaly detection |
| `detectLanguageSwitches(text)` | Detect script/language switches in text |
| `parseWindow(window)` | Parse a duration string (`"5m"`, `"1h"`) into milliseconds |

## Type Exports

All types are exported from `@aegis-sdk/core`. See the [Types Reference](/api/types) for the full list.

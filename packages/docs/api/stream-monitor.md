# StreamMonitor

Real-time output watchdog. Implements a `TransformStream` pass-through that monitors LLM output tokens in parallel with delivery. Uses a sliding window buffer to catch patterns that span chunk boundaries.

This is the core of the **Optimistic Defense** pattern: stream tokens immediately while scanning in parallel, using `controller.terminate()` to abort the moment a violation is detected.

```ts
import { StreamMonitor } from "@aegis-sdk/core";
```

## Constructor

```ts
new StreamMonitor(config?: StreamMonitorConfig)
```

### StreamMonitorConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `canaryTokens` | `string[]` | `[]` | Tokens to detect in output (system prompt leak detection) |
| `detectPII` | `boolean` | `true` | Scan for PII patterns (SSN, CC, email, phone, etc.) |
| `piiRedaction` | `boolean` | `false` | When `true` + `detectPII`, redact PII instead of terminating |
| `detectSecrets` | `boolean` | `true` | Scan for API keys, AWS keys, bearer tokens |
| `detectInjectionPayloads` | `boolean` | `false` | Scan for injection patterns in output |
| `sanitizeMarkdown` | `boolean` | `false` | Sanitize dangerous markdown in output |
| `customPatterns` | `RegExp[]` | `[]` | Additional regex patterns to match |
| `chunkStrategy` | `ChunkStrategy` | `"sentence"` | `"sentence"`, `"tokens"`, or `"fixed"` |
| `chunkSize` | `number` | `50` | Chunk size for fixed/token strategies |
| `onViolation` | `(v: StreamViolation) => void` | no-op | Callback invoked when a violation is detected |

## Methods

### createTransform()

Create a `TransformStream` that monitors text chunks for violations.

```ts
createTransform(): TransformStream<string, string>
```

**Returns:** A `TransformStream<string, string>`.

Pipe your LLM output stream through this transform. Tokens pass through with zero delay. When a violation is detected, the stream is terminated via `controller.terminate()` and the `onViolation` callback fires.

When `piiRedaction` is enabled, PII matches are replaced with `[REDACTED-SSN]`, `[REDACTED-CC]`, etc., instead of terminating. Non-PII violations (canary leaks, secrets) still terminate immediately.

### Built-in PII Patterns

| Label | Pattern |
|-------|---------|
| `SSN` | US Social Security Number (`123-45-6789`) |
| `CC` | Credit card numbers (4 groups of 4 digits) |
| `EMAIL` | Email addresses |
| `PHONE` | US phone numbers |
| `IP_ADDRESS` | IPv4 addresses (excludes `0.0.0.0`, `127.0.0.1`) |
| `PASSPORT` | Passport numbers (1-2 letters + 6-8 digits) |
| `DOB` | Date of birth (contextual: "DOB:", "born on", etc.) |
| `IBAN` | International Bank Account Numbers |
| `ROUTING_NUMBER` | US bank routing numbers (ABA) |
| `DRIVERS_LICENSE` | Generic alphanumeric driver's license patterns |
| `MRN` | Medical record numbers |

### StreamViolation

```ts
interface StreamViolation {
  type: "canary_leak" | "pii_detected" | "secret_detected"
      | "injection_payload" | "policy_violation" | "custom_pattern";
  matched: string;
  position: number;
  description: string;
}
```

## Example

```ts
import { StreamMonitor } from "@aegis-sdk/core";

const monitor = new StreamMonitor({
  canaryTokens: ["CANARY_7f3a9b"],
  detectPII: true,
  piiRedaction: true,
  onViolation: (v) => {
    console.warn(`Stream violation: ${v.type} — ${v.description}`);
  },
});

const transform = monitor.createTransform();

// With Vercel AI SDK
const result = streamText({
  model: openai("gpt-4o"),
  messages,
  experimental_transform: transform,
});

// Or pipe manually
const outputStream = llmStream.pipeThrough(transform);
```

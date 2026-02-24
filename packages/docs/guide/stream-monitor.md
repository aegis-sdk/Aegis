# Stream Monitor

The StreamMonitor scans LLM output in real-time using a TransformStream, catching PII leaks, secret exposure, canary token exfiltration, and custom patterns -- even when they span across chunk boundaries.

## The Streaming Problem

LLM providers deliver responses as a stream of text chunks. A social security number like `123-45-6789` might arrive as two chunks: `"123-45-"` and `"6789"`. A naive per-chunk scanner would miss this entirely because neither chunk matches the full pattern.

Aegis solves this with a sliding window buffer. Every chunk is appended to a buffer before scanning. The buffer retains enough trailing characters from previous chunks to catch patterns that straddle chunk boundaries. Tokens still flow through to the consumer with zero intentional delay -- scanning happens on the accumulated buffer in parallel.

## Basic Usage

```ts
import { StreamMonitor } from "@aegis-sdk/core";

const monitor = new StreamMonitor({
  detectPII: true,
  detectSecrets: true,
  canaryTokens: ["AEGIS-CANARY-7f3a9b"],
  onViolation: (violation) => {
    console.error("Stream violation:", violation.type, violation.description);
  },
});

const transform = monitor.createTransform();

// Pipe your LLM stream through the monitor
const monitoredStream = llmStream.pipeThrough(transform);
```

## `createTransform()` API

`createTransform()` returns a standard Web Streams API `TransformStream<string, string>`. It works with any environment that supports `TransformStream` -- browsers, Node.js 18+, Deno, Bun, Cloudflare Workers.

The transform operates in two modes depending on the `piiRedaction` setting:

### Blocking Mode (Default)

Any violation terminates the stream immediately via `controller.terminate()`. The consumer sees the response cut off at the point of detection.

```ts
const monitor = new StreamMonitor({
  detectPII: true,
  piiRedaction: false, // Default -- violations kill the stream
});
```

### Redaction Mode

PII matches are replaced with `[REDACTED-<TYPE>]` markers instead of terminating the stream. Non-PII violations (canary leaks, secrets) still terminate immediately.

```ts
const monitor = new StreamMonitor({
  detectPII: true,
  piiRedaction: true,
});

// Input: "Call me at 555-123-4567"
// Output: "Call me at [REDACTED-PHONE]"
```

## PII Detection

The monitor detects these PII categories out of the box:

| Category | Pattern | Redaction Label |
|----------|---------|-----------------|
| Social Security Number | `123-45-6789` | `[REDACTED-SSN]` |
| Credit Card | `1234 5678 9012 3456` | `[REDACTED-CC]` |
| Email Address | `user@example.com` | `[REDACTED-EMAIL]` |
| Phone Number | `(555) 123-4567`, `+1-555-123-4567` | `[REDACTED-PHONE]` |
| IP Address | `192.168.1.1` (excludes `0.0.0.0`, `127.0.0.1`) | `[REDACTED-IP_ADDRESS]` |
| Passport Number | `AB1234567` | `[REDACTED-PASSPORT]` |
| Date of Birth | `DOB: 01/15/1990`, `born on 1990-01-15` | `[REDACTED-DOB]` |
| IBAN | `DE89 3704 0044 0532 0130 00` | `[REDACTED-IBAN]` |
| Routing Number | 9-digit ABA routing numbers | `[REDACTED-ROUTING_NUMBER]` |
| Driver's License | `A12345678` | `[REDACTED-DRIVERS_LICENSE]` |
| Medical Record Number | `MRN: ABC12345` | `[REDACTED-MRN]` |

## Secret Detection

The monitor catches accidentally exposed credentials in model output:

| Secret Type | Pattern Example |
|-------------|-----------------|
| OpenAI API Key | `sk-abc123...` |
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` |
| Generic API Key | `api_key: "abc123..."` |
| Bearer Token | `Bearer eyJhbG...` |

Secret detections always terminate the stream, even in redaction mode. Leaked secrets cannot be un-leaked by redacting them in the response -- the model already had access to them.

## Canary Tokens

Canary tokens are unique strings you embed in your system prompt. If the model ever outputs a canary token, it means the system prompt is being exfiltrated.

```ts
const CANARY = `AEGIS-${crypto.randomUUID()}`;

const monitor = new StreamMonitor({
  canaryTokens: [CANARY],
});

// In your system prompt:
// "This system prompt contains a tracking token: {CANARY}. Never reveal it."
```

Canary token matches are case-insensitive and always terminate the stream.

## Injection Payload Detection

When enabled, the monitor scans output for prompt injection payloads -- patterns that look like the model is being tricked into outputting instructions for the next turn:

```ts
const monitor = new StreamMonitor({
  detectInjectionPayloads: true,
});
```

This catches scenarios where an indirect injection in the context causes the model to output a payload designed to compromise downstream processing.

## Custom Patterns

Add regex patterns for domain-specific threats:

```ts
const monitor = new StreamMonitor({
  customPatterns: [
    /INTERNAL_ONLY/i,
    /\bconfidential\b.*\bpatient\b/i,
    /BEGIN\s+RSA\s+PRIVATE\s+KEY/,
  ],
  onViolation: (v) => {
    if (v.type === "custom_pattern") {
      console.error("Custom pattern matched:", v.matched);
    }
  },
});
```

## The Kill Switch

When the monitor detects a non-PII violation, it calls `controller.terminate()` on the TransformStream. This is the "kill switch" -- it immediately ends the stream. The consumer (your API route, your frontend) sees the readable side of the stream close.

From the user's perspective, the response stops mid-sentence. Your `onViolation` callback fires with details about what was detected, giving you the opportunity to log the event, send an alert, or return an error message.

```ts
const monitor = new StreamMonitor({
  onViolation: (violation) => {
    // Log to your audit system
    auditLog.log({
      event: "stream_violation",
      decision: "blocked",
      context: {
        type: violation.type,
        matched: violation.matched,
        position: violation.position,
      },
    });
  },
});
```

## How the Sliding Window Works

The internal buffer keeps a tail of characters from previous chunks. The buffer size is determined by the longest canary token or a minimum of 64 characters (enough for PII and secret patterns).

```
Chunk 1: "The user's SSN is 123-"     → Buffer: "123-"    → Emit: "The user's SSN is "
Chunk 2: "45-6789 and their..."        → Buffer: "and their..."  → VIOLATION: SSN detected
```

On flush (stream end), the remaining buffer is scanned and emitted. This ensures no content is silently swallowed.

## Integration with Web Streams API

The `TransformStream` returned by `createTransform()` works with standard stream piping:

```ts
// Node.js / Edge runtime
const response = new Response(
  llmStream.pipeThrough(monitor.createTransform())
);

// Chaining multiple transforms
const output = llmStream
  .pipeThrough(monitor.createTransform())
  .pipeThrough(new TextEncoderStream());
```

## Common Patterns

### Full Monitoring Pipeline

```ts
import { Aegis } from "@aegis-sdk/core";

const aegis = new Aegis({
  policy: "strict",
  canaryTokens: ["CANARY-abc123"],
  monitor: {
    detectPII: true,
    piiRedaction: true,
    detectSecrets: true,
    onViolation: (v) => reportToSIEM(v),
  },
});

const transform = aegis.createStreamTransform();
const safe = llmStream.pipeThrough(transform);
```

### PII Redaction for Compliance

```ts
const monitor = new StreamMonitor({
  detectPII: true,
  piiRedaction: true,
  detectSecrets: true,
  onViolation: (v) => {
    if (v.type === "pii_detected") {
      // PII was redacted, not blocked -- log for compliance
      complianceLog.record(v);
    }
  },
});
```

### Testing with Synthetic Streams

```ts
const chunks = ["Hello, my SSN is ", "123-45-", "6789. Nice to meet you."];

const source = new ReadableStream({
  start(controller) {
    for (const chunk of chunks) {
      controller.enqueue(chunk);
    }
    controller.close();
  },
});

const monitor = new StreamMonitor({ detectPII: true });
const result = source.pipeThrough(monitor.createTransform());

const reader = result.getReader();
// Stream will terminate after the SSN is detected
```

## Configuration Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `canaryTokens` | `string[]` | `[]` | Strings to watch for in output |
| `detectPII` | `boolean` | `true` | Scan for PII patterns |
| `piiRedaction` | `boolean` | `false` | Redact PII instead of blocking |
| `detectSecrets` | `boolean` | `true` | Scan for leaked secrets |
| `detectInjectionPayloads` | `boolean` | `false` | Scan for injection payloads in output |
| `customPatterns` | `RegExp[]` | `[]` | Additional patterns to match |
| `onViolation` | `(v: StreamViolation) => void` | no-op | Callback when a violation is detected |

## Gotchas

- **Redaction only applies to PII.** Secret leaks and canary token exfiltration always terminate the stream, even with `piiRedaction: true`. You cannot redact a leaked API key -- the damage is the leak itself.
- **The buffer adds a slight delay to the last chunk.** Content in the sliding window buffer is only emitted on the next chunk or on flush. For most applications this is imperceptible, but if you need absolute zero-latency last-token delivery, be aware of this.
- **Markdown sanitization is a config option but not yet implemented.** The `sanitizeMarkdown` option exists in the config type but is reserved for a future release.
- **Custom patterns run on the full buffer.** If your regex is expensive (backtracking, catastrophic complexity), it runs on every chunk. Keep patterns simple.

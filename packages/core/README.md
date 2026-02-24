# @aegis-sdk/core

Streaming-first prompt injection defense for JavaScript/TypeScript AI applications.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/core
```

## Quick Start

```typescript
import { Aegis } from '@aegis-sdk/core';

const aegis = new Aegis({ policy: 'strict' });

// Scan input messages before sending to the LLM
const safeMessages = await aegis.guardInput(messages);

// Monitor the output stream in real-time (kills on violation)
const transform = aegis.createStreamTransform();
```

With the Vercel AI SDK:

```typescript
import { streamText } from 'ai';
import { openai } from '@ai-sdk/openai';
import { Aegis } from '@aegis-sdk/core';

const aegis = new Aegis({ policy: 'strict' });

export async function POST(req: Request) {
  const { messages } = await req.json();

  const safeMessages = await aegis.guardInput(messages);

  const result = streamText({
    model: openai('gpt-4o'),
    messages: safeMessages,
    experimental_transform: aegis.createStreamTransform(),
  });

  return result.toDataStreamResponse();
}
```

## API

### `Aegis` class

The main entry point. Accepts an `AegisConfig` with a policy preset (`'strict'`, `'balanced'`, `'permissive'`) or a custom policy object.

- **`guardInput(messages, options?)`** -- Scan messages for prompt injection. Returns messages if safe, throws `AegisInputBlocked` if blocked.
- **`createStreamTransform()`** -- Returns a `TransformStream<string, string>` that monitors output tokens and kills the stream on violation.
- **`guardChainStep(output, options)`** -- Guard a single step in an agentic loop. Tracks cumulative risk, enforces step budgets, and applies privilege decay.
- **`scanMedia(content, mediaType)`** -- Scan images, audio, or documents for injection attempts (requires `multiModal` config).
- **`judgeOutput(userRequest, modelOutput, context?)`** -- Evaluate model output against original user intent using an LLM-Judge (requires `judge` config).
- **`getAuditLog()`** -- Access the audit log for querying security events.
- **`getValidator()`** -- Access the action validator for tool call validation.
- **`getPolicy()`** -- Access the resolved policy.
- **`getMessageSigner()`** -- Access the HMAC message signer (returns `null` if integrity is not configured).
- **`isSessionQuarantined()`** -- Check whether the current session has been quarantined.

### `aegis` singleton

Convenience singleton for the "simple path" API:

```typescript
import { aegis } from '@aegis-sdk/core';

aegis.configure({ policy: 'strict' });
const instance = aegis.getInstance();
```

### Core modules

Each module is exported individually for standalone use:

| Export | Purpose |
|--------|---------|
| `quarantine(content, options?)` | Wrap content as `Quarantined<T>` to track trust |
| `isQuarantined(value)` | Check if a value is quarantined |
| `InputScanner` | Pattern matching + heuristic injection detection |
| `PerplexityAnalyzer` | Character n-gram perplexity for adversarial suffix detection |
| `TrajectoryAnalyzer` | Multi-turn escalation detection (Crescendo attacks) |
| `PromptBuilder` | Sandwich-pattern prompt construction with delimiters |
| `StreamMonitor` | Real-time output scanning via `TransformStream` |
| `ActionValidator` | Tool call validation + rate limiting |
| `Sandbox` | Zero-capability model for untrusted content |
| `LLMJudge` | Provider-agnostic intent alignment verification |
| `MultiModalScanner` | Extract + scan text from images/audio/documents |
| `AutoRetryHandler` | Retry with escalated security after a block |
| `AuditLog` | Security event logging |
| `FileTransport` | JSONL file transport with rotation |
| `OTelTransport` | OpenTelemetry spans/metrics/logs transport |
| `AlertingEngine` | Real-time alerting (rate-spike, session-kills) |
| `MessageSigner` | HMAC conversation integrity |

### Policy helpers

```typescript
import { resolvePolicy, getPreset, isActionAllowed, loadPolicyFile } from '@aegis-sdk/core';

const policy = resolvePolicy('strict');
const preset = getPreset('balanced');
const allowed = isActionAllowed(policy, 'search_kb');
const filePolicy = await loadPolicyFile('./aegis-policy.yaml');
```

### Error classes

- **`AegisInputBlocked`** -- Thrown when input is blocked. Contains `scanResult` with detections and score.
- **`AegisSessionQuarantined`** -- Thrown when a quarantined session attempts input.
- **`AegisSessionTerminated`** -- Thrown on critical violations. Session must be recreated.

## Canary Tokens

Embed canary tokens in your system prompt to detect when the model leaks it:

```typescript
const aegis = new Aegis({
  policy: 'strict',
  canaryTokens: ['AEGIS_CANARY_7f3a9b'],
});
```

If the model outputs a canary token, the stream monitor kills the stream immediately.

## Preset Policies

```typescript
new Aegis({ policy: 'strict' });      // High security, tighter thresholds
new Aegis({ policy: 'balanced' });    // Default -- good for most apps
new Aegis({ policy: 'permissive' });  // Lower friction, wider thresholds
```

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

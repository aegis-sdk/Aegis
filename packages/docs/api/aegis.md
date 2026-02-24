# Aegis Class

The main entry point for streaming-first prompt injection defense. Orchestrates input scanning, output monitoring, policy enforcement, and audit logging.

```ts
import { Aegis } from "@aegis-sdk/core";
```

## Constructor

```ts
new Aegis(config?: AegisConfig)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | [`AegisConfig`](/api/types#aegisconfig) | `{}` | Full configuration object |

When no config is provided, Aegis uses the `"balanced"` policy preset with default scanner, monitor, and audit settings.

## Methods

### guardInput()

Scan and validate input messages before sending to the LLM. Quarantines user messages, runs the input scanner, and returns the messages if they pass. Throws if a blocking violation is detected.

```ts
async guardInput(
  messages: PromptMessage[],
  options?: GuardInputOptions
): Promise<PromptMessage[]>
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `messages` | `PromptMessage[]` | Conversation messages (`{ role, content }`) |
| `options.scanStrategy` | `ScanStrategy` | `"last-user"` (default), `"all-user"`, or `"full-history"` |

**Returns:** The original `messages` array if they pass validation.

**Throws:**
- `AegisInputBlocked` — input blocked by the scanner
- `AegisSessionQuarantined` — session was previously quarantined
- `AegisSessionTerminated` — critical violation, session is dead

**Recovery modes** (configured via `config.recovery.mode`):
- `"continue"` — throw immediately (default)
- `"reset-last"` — strip the offending message and return the rest
- `"quarantine-session"` — lock the session; all future input blocked
- `"terminate-session"` — throw a terminal error
- `"auto-retry"` — re-scan with escalated security; throw if exhausted

### createStreamTransform()

Create a `TransformStream` for monitoring LLM output in real-time.

```ts
createStreamTransform(): TransformStream<string, string>
```

**Returns:** A `TransformStream<string, string>` that scans output tokens and terminates the stream on violation.

### guardChainStep()

Guard a single step in an agentic loop. Provides multi-layer protection: quarantines model output, scans for injection, tracks cumulative risk, enforces step budget, and applies privilege decay.

```ts
async guardChainStep(
  output: string,
  options: ChainStepOptions
): Promise<ChainStepResult>
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `output` | `string` | Raw model output text to scan |
| `options.step` | `number` | Current step number (1-based, required) |
| `options.maxSteps` | `number` | Max steps before halt. Default: `25` |
| `options.cumulativeRisk` | `number` | Risk score from previous steps. Default: `0` |
| `options.riskBudget` | `number` | Risk threshold for halt. Default: `3.0` |
| `options.initialTools` | `string[]` | Full tool list available at step 1 |
| `options.sessionId` | `string` | Session ID for audit correlation |
| `options.requestId` | `string` | Request ID for audit correlation |

**Returns:** `ChainStepResult` with `safe`, `reason`, `cumulativeRisk`, `scanResult`, `availableTools`, and `budgetExhausted`.

### judgeOutput()

Evaluate model output against original user intent using the LLM-Judge.

```ts
async judgeOutput(
  userRequest: string,
  modelOutput: string,
  context?: JudgeEvaluationContext
): Promise<JudgeVerdict>
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `userRequest` | `string` | The original user request |
| `modelOutput` | `string` | The model's generated response |
| `context` | `JudgeEvaluationContext` | Optional risk score, detections, messages |

**Returns:** `JudgeVerdict` with `decision`, `confidence`, `reasoning`, `approved`, `executionTimeMs`.

**Throws:** `Error` if the judge is not configured.

### scanMedia()

Scan media content (images, PDFs, audio) for prompt injection.

```ts
async scanMedia(
  content: Uint8Array | string,
  mediaType: MediaType
): Promise<MultiModalScanResult>
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `content` | `Uint8Array \| string` | Raw media content or base64-encoded string |
| `mediaType` | `MediaType` | `"image"`, `"audio"`, `"video"`, `"pdf"`, or `"document"` |

**Returns:** `MultiModalScanResult` with `extracted`, `scanResult`, `fileSize`, `safe`.

**Throws:** `Error` if multi-modal scanning is not configured.

### isSessionQuarantined()

```ts
isSessionQuarantined(): boolean
```

Returns `true` if the session has been quarantined by a previous `"quarantine-session"` recovery action.

## Accessor Methods

| Method | Return Type | Description |
|--------|-------------|-------------|
| `getPolicy()` | `AegisPolicy` | The resolved policy object |
| `getValidator()` | `ActionValidator` | The action validator instance |
| `getAuditLog()` | `AuditLog` | The audit log instance |
| `getMessageSigner()` | `MessageSigner \| null` | HMAC signer, or `null` if not configured |
| `getRetryHandler()` | `AutoRetryHandler \| null` | Retry handler, or `null` if not enabled |
| `getJudge()` | `LLMJudge \| null` | LLM-Judge, or `null` if not configured |
| `getMultiModalScanner()` | `MultiModalScanner \| null` | Media scanner, or `null` if not configured |

## Singleton API

For simpler setups, use the `aegis` singleton:

```ts
import { aegis } from "@aegis-sdk/core";

// Configure once
const instance = aegis.configure({ policy: "strict" });

// Retrieve anywhere
const instance = aegis.getInstance();
```

| Method | Return Type | Description |
|--------|-------------|-------------|
| `aegis.configure(config)` | `Aegis` | Create and set the default instance |
| `aegis.getInstance()` | `Aegis` | Get or lazily create the default instance |

## Example

```ts
import { Aegis, AegisInputBlocked } from "@aegis-sdk/core";
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";

const aegis = new Aegis({
  policy: "strict",
  recovery: { mode: "quarantine-session" },
});

// Guard input
try {
  const safeMessages = await aegis.guardInput(messages);

  // Monitor output stream
  const result = streamText({
    model: openai("gpt-4o"),
    messages: safeMessages,
    experimental_transform: aegis.createStreamTransform(),
  });
} catch (err) {
  if (err instanceof AegisInputBlocked) {
    console.warn("Blocked:", err.scanResult.detections);
  }
}
```

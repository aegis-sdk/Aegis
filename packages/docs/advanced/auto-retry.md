# Auto-Retry

When the InputScanner blocks an input, the default behavior is to throw `AegisInputBlocked` and stop. But blocking is not always the right call — a legitimate input may trigger a borderline detection, or a noisy scanner configuration may produce false positives. The auto-retry system provides a structured path for re-evaluating blocked input with escalating security measures.

## The Kill Switch Recovery Problem

Aegis uses an optimistic defense model: stream tokens to the user while monitoring for violations, then kill the stream if a violation is detected. But what happens after the kill?

Without auto-retry:
1. Input triggers a detection with score 0.52 (just above the 0.5 threshold)
2. `AegisInputBlocked` is thrown
3. The user sees an error message
4. Legitimate users are frustrated; attackers try a different approach

With auto-retry:
1. Input triggers a detection with score 0.52
2. The input is **re-scanned with paranoid sensitivity** — a stricter scan
3. If the paranoid scan passes, the input was likely a false positive and is allowed through
4. If it still fails, the input is routed to a **sandbox** for safe data extraction
5. Only if all retry attempts fail is the input blocked

This provides graceful degradation: legitimate edge cases get a second chance, while actual attacks face progressively tighter scrutiny.

## Escalation Strategies

### `stricter_scanner`

Re-scans the input with `sensitivity: "paranoid"` — the strictest scanner configuration. If the input passes the paranoid scan, it survives a stricter check than the original and is considered safe.

```ts
const aegis = new Aegis({
  recovery: { mode: 'auto-retry' },
  autoRetry: {
    enabled: true,
    escalationPath: 'stricter_scanner',
    maxAttempts: 3,
  },
});
```

This is the default strategy. It is fast (no external calls) and catches false positives from the balanced scanner that do not trigger under paranoid rules.

### `sandbox`

Flags the input for routing to the Aegis Sandbox — a zero-capability model that extracts structured data from the input without executing any instructions it may contain.

```ts
const aegis = new Aegis({
  recovery: { mode: 'auto-retry' },
  autoRetry: {
    enabled: true,
    escalationPath: 'sandbox',
  },
});
```

The sandbox escalation always returns `succeeded: true` because it provides a safe execution path — the caller is responsible for actually invoking the Sandbox with the quarantined input.

### `combined`

Tries the stricter scanner first. If that still fails, falls back to sandbox routing.

```ts
const aegis = new Aegis({
  recovery: { mode: 'auto-retry' },
  autoRetry: {
    enabled: true,
    escalationPath: 'combined',
    maxAttempts: 3,
  },
});
```

This is the most comprehensive strategy: it gives legitimate inputs two chances to pass deterministic checks before falling back to the safe extraction path.

## Configuration

### Through Aegis

```ts
import { Aegis } from '@aegis-sdk/core';

const aegis = new Aegis({
  recovery: { mode: 'auto-retry' },  // Enable auto-retry recovery mode
  autoRetry: {
    enabled: true,
    maxAttempts: 3,                   // Default: 3
    escalationPath: 'combined',       // Default: 'stricter_scanner'
    onRetry: (context) => {
      console.log(`Retry attempt ${context.attempt}/${context.totalAttempts}`, {
        escalation: context.escalation,
        originalScore: context.originalScore,
      });
    },
  },
});
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | `boolean` | — | Whether auto-retry is active |
| `maxAttempts` | `number` | `3` | Maximum retry attempts before giving up |
| `escalationPath` | `'stricter_scanner' \| 'sandbox' \| 'combined'` | `'stricter_scanner'` | Which escalation strategy to use |
| `onRetry` | `(context: RetryContext) => void` | — | Callback invoked before each retry attempt |

## Max Attempts and Exhaustion

When all retry attempts are exhausted without success, `guardInput()` throws `AegisInputBlocked` — the same error as without auto-retry. The auto-retry system is transparent: callers only see the final outcome.

```ts
try {
  const messages = await aegis.guardInput([
    { role: 'user', content: suspiciousInput },
  ]);
  // Input passed (either on first scan or after retry)
} catch (err) {
  if (err.name === 'AegisInputBlocked') {
    // All retry attempts exhausted — input is definitively blocked
    console.warn('Blocked after retries:', err.scanResult);
  }
}
```

## The `onRetry` Callback

The `onRetry` callback fires before each retry attempt, giving you visibility into the retry process:

```ts
const aegis = new Aegis({
  recovery: { mode: 'auto-retry' },
  autoRetry: {
    enabled: true,
    maxAttempts: 3,
    escalationPath: 'combined',
    onRetry: async (context) => {
      console.log('Retry attempt', {
        attempt: context.attempt,
        totalAttempts: context.totalAttempts,
        escalation: context.escalation,
        originalScore: context.originalScore,
        detectionCount: context.originalDetections.length,
      });

      // Optional: send metrics
      await metrics.increment('aegis.retry', {
        attempt: context.attempt,
        escalation: context.escalation,
      });
    },
  },
});
```

### `RetryContext`

| Field | Type | Description |
|-------|------|-------------|
| `attempt` | `number` | Current attempt number (1-based) |
| `totalAttempts` | `number` | Total configured attempts |
| `escalation` | `AutoRetryEscalation` | Strategy applied for this attempt |
| `originalDetections` | `Detection[]` | Detections from the original failed scan |
| `originalScore` | `number` | Composite score from the original scan |

## `RetryResult`

Each retry attempt produces a `RetryResult`:

| Field | Type | Description |
|-------|------|-------------|
| `attempt` | `number` | The attempt number |
| `succeeded` | `boolean` | Whether this attempt succeeded |
| `escalation` | `AutoRetryEscalation` | The strategy that was applied |
| `scanResult` | `ScanResult \| undefined` | Scan result if a re-scan was performed |
| `exhausted` | `boolean` | Whether all attempts are now exhausted |

## Integration with Recovery Modes

Auto-retry is one of five recovery modes available in Aegis. Set `recovery.mode` to `'auto-retry'` and provide the `autoRetry` configuration:

```ts
const aegis = new Aegis({
  // The recovery mode determines what happens when a scan blocks input
  recovery: { mode: 'auto-retry' },

  // The auto-retry config controls the retry behavior
  autoRetry: {
    enabled: true,
    maxAttempts: 2,
    escalationPath: 'stricter_scanner',
  },
});
```

If `recovery.mode` is `'auto-retry'` but no `autoRetry` config is provided (or `enabled` is `false`), the system falls back to throwing `AegisInputBlocked` immediately — equivalent to the `'continue'` recovery mode.

## Audit Trail

Every retry attempt is logged to the audit log with full context:

```json
{
  "event": "scan_block",
  "decision": "blocked",
  "context": {
    "recovery": "auto-retry",
    "attempt": 1,
    "maxAttempts": 3,
    "escalation": "stricter_scanner",
    "succeeded": false,
    "exhausted": false,
    "score": 0.52
  }
}
```

When a retry succeeds:

```json
{
  "event": "scan_block",
  "decision": "allowed",
  "context": {
    "recovery": "auto-retry",
    "attempt": 2,
    "maxAttempts": 3,
    "escalation": "stricter_scanner",
    "succeeded": true,
    "exhausted": false,
    "score": 0.0
  }
}
```

## Standalone Usage

You can use the `AutoRetryHandler` directly without the Aegis class:

```ts
import { AutoRetryHandler, InputScanner, quarantine } from '@aegis-sdk/core';

const handler = new AutoRetryHandler({
  enabled: true,
  maxAttempts: 3,
  escalationPath: 'combined',
  onRetry: (ctx) => console.log(`Attempt ${ctx.attempt}`),
});

const scanner = new InputScanner();
const input = quarantine(userText, { source: 'user_input' });
const initialResult = scanner.scan(input);

if (!initialResult.safe) {
  for (let attempt = 1; attempt <= handler.getMaxAttempts(); attempt++) {
    const retryResult = await handler.attemptRetry(
      input,
      initialResult.detections,
      attempt,
      scanner,
    );

    if (retryResult.succeeded) {
      console.log('Input passed on retry');
      break;
    }

    if (retryResult.exhausted) {
      console.warn('All retries exhausted — blocking input');
      break;
    }
  }
}
```

## Related

- [Input Scanner](/guide/input-scanner) — The scanner that triggers retries
- [Sandbox](/guide/sandbox) — Zero-capability model for safe data extraction
- [Agentic Defense](/advanced/) — Recovery modes in agent loops
- [Alerting](/advanced/alerting) — Monitor retry rates for attack pattern detection

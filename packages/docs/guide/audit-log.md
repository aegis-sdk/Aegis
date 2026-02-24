# Audit Log

The AuditLog records every security decision in the Aegis pipeline -- scans, blocks, approvals, violations, and custom events -- with pluggable transports for console, file, OpenTelemetry, and custom destinations.

## Why Audit Everything?

Security without observability is guessing. When an attack is detected, you need to know: what was the input, what pattern matched, what was the model's response, and what action was blocked. When a false positive frustrates a user, you need the same data to tune your sensitivity. The audit log provides this trail for every decision Aegis makes.

## Basic Usage

```ts
import { AuditLog } from "@aegis-sdk/core";

const audit = new AuditLog({
  transports: ["console"],
  level: "all",
});

audit.log({
  event: "scan_block",
  decision: "blocked",
  context: { score: 0.87, detections: ["instruction_override"] },
});
```

When using the `Aegis` class, the audit log is created and wired up automatically based on your configuration.

## Audit Event Types

Every event in the pipeline has a corresponding audit event type:

| Event | Description | Typical Decision |
|-------|-------------|------------------|
| `scan_pass` | Input passed the scanner | `allowed` |
| `scan_block` | Input blocked by scanner | `blocked` |
| `scan_trajectory` | Trajectory analysis completed | `info` / `flagged` |
| `quarantine_create` | Content was quarantined | `info` |
| `quarantine_release` | Content released from quarantine | `info` |
| `unsafe_unwrap` | `unsafeUnwrap()` was called | `flagged` |
| `excessive_unwrap` | Too many unwrap calls | `flagged` |
| `sandbox_trigger` | Content sent to sandbox for processing | `info` |
| `sandbox_result` | Sandbox returned a result | `info` |
| `stream_violation` | Stream monitor detected a violation | `blocked` |
| `action_block` | Tool call blocked by validator | `blocked` |
| `action_approve` | Tool call approved (possibly after human review) | `allowed` |
| `kill_switch` | Stream terminated by kill switch | `blocked` |
| `session_quarantine` | Session moved to quarantine mode | `blocked` |
| `message_integrity_fail` | HMAC signature verification failed | `blocked` |
| `chain_step_scan` | Agentic chain step scanned | `info` / `blocked` |
| `denial_of_wallet` | DoW threshold exceeded | `blocked` |
| `policy_violation` | Policy rule violated | `blocked` |
| `judge_evaluation` | LLM judge evaluated input | `info` / `blocked` |
| `custom_check` | Custom check event | varies |

## The `AuditEntry` Object

```ts
interface AuditEntry {
  timestamp: Date;                    // When the event occurred
  event: AuditEventType;             // Event type from the table above
  decision: "allowed" | "blocked" | "flagged" | "info";
  sessionId?: string;                // Session correlation ID
  requestId?: string;                // Request correlation ID
  context: Record<string, unknown>;  // Event-specific details
}
```

## Transport System

The audit log supports multiple simultaneous transports. Enable any combination:

```ts
const audit = new AuditLog({
  transports: ["console", "json-file", "otel", "custom"],
  level: "all",
});
```

Every entry is dispatched to all active transports in parallel.

### Console Transport

Writes human-readable log lines to `console.log` (for info/allowed events) or `console.warn` (for blocked/flagged events):

```
[AEGIS BLOCK] scan_block { score: 0.87, detections: ['instruction_override'] }
[AEGIS FLAG] unsafe_unwrap { reason: 'Passing to display layer' }
[AEGIS] scan_pass { score: 0.05 }
```

### JSON File Transport (`json-file`)

Appends each entry as a JSON line to a `.jsonl` file. Requires Node.js runtime (uses `fs` module internally).

```ts
import { AuditLog, FileTransport } from "@aegis-sdk/core";

const file = new FileTransport({
  path: "./aegis-audit.jsonl",
  rotate: true,
  maxSizeMB: 100,
});

const audit = new AuditLog({
  transports: ["json-file"],
  level: "all",
});

audit.setFileTransport(file);
```

#### File Rotation

When `rotate: true`, the transport checks the file size before each write. If the file exceeds `maxSizeMB`, it renames the current file to `aegis-audit.<timestamp>.jsonl` and starts writing to a fresh file.

```ts
const file = new FileTransport({
  path: "./logs/aegis-audit.jsonl",
  rotate: true,
  maxSizeMB: 50, // Default: 50 MB
});
```

#### Edge/Browser Environments

`FileTransport` throws a descriptive error if instantiated outside Node.js. For edge runtimes and browsers, use the console transport or a custom transport that sends entries to your logging service.

### OpenTelemetry Transport (`otel`)

Forwards audit entries to OpenTelemetry as spans, metrics, and logs. Does not depend on `@opentelemetry/*` packages -- you pass your own OTel API objects:

```ts
import { trace, metrics } from "@opentelemetry/api";
import { AuditLog, OTelTransport } from "@aegis-sdk/core";

const otel = new OTelTransport({
  tracer: trace.getTracer("aegis"),
  meter: metrics.getMeter("aegis"),
  prefix: "aegis",
});

const audit = new AuditLog({
  transports: ["otel"],
  level: "all",
});

audit.setOTelTransport(otel);
```

#### What Gets Exported

**Traces:** `blocked` and `flagged` events create spans with attributes:
- `aegis.event` -- the event type
- `aegis.decision` -- allowed/blocked/flagged
- `aegis.sessionId`, `aegis.requestId` -- correlation IDs
- `aegis.score` -- scan score (when present)
- Status code: `ERROR` for blocked, `OK` for flagged

**Metrics:**
- `aegis.events.total` -- counter of all events
- `aegis.events.blocked` -- counter of blocked events
- `aegis.events.flagged` -- counter of flagged events
- `aegis.scan.score` -- histogram of scan scores

**Logs:** All events are forwarded to the OTel logger with severity:
- `ERROR` for blocked events
- `WARN` for flagged events
- `INFO` for everything else

#### Partial OTel Setup

All OTel config fields are optional. You can use just tracing, just metrics, or just logging:

```ts
// Metrics only
const otel = new OTelTransport({
  meter: metrics.getMeter("aegis"),
});

// Traces only
const otel = new OTelTransport({
  tracer: trace.getTracer("aegis"),
});
```

### Custom Transport

Write entries to any destination -- Datadog, Splunk, a database, a webhook:

```ts
const audit = new AuditLog({
  transports: ["custom"],
  level: "all",
});

// Add one or more custom transport functions
audit.addTransport((entry) => {
  fetch("https://logs.example.com/ingest", {
    method: "POST",
    body: JSON.stringify(entry),
  });
});

audit.addTransport((entry) => {
  if (entry.decision === "blocked") {
    sendSlackAlert(`Aegis blocked: ${entry.event}`, entry.context);
  }
});
```

Custom transports can be async (return a Promise). Errors in custom transports are swallowed to avoid breaking the pipeline.

#### Removing a Custom Transport

```ts
const myTransport = (entry: AuditEntry) => sendToDatadog(entry);

audit.addTransport(myTransport);
// ... later ...
audit.removeTransport(myTransport); // Uses reference equality
```

## Log Levels

Control which events are recorded:

| Level | Records |
|-------|---------|
| `violations-only` | Only `blocked` and `flagged` decisions |
| `actions` | Everything except `info` decisions |
| `all` | Every event (default) |

```ts
// Production: only record security-relevant events
const audit = new AuditLog({
  transports: ["json-file"],
  level: "violations-only",
});

// Development: record everything for debugging
const audit = new AuditLog({
  transports: ["console"],
  level: "all",
});
```

## Content Redaction

For compliance or privacy, redact string values from the context object:

```ts
const audit = new AuditLog({
  transports: ["json-file"],
  level: "all",
  redactContent: true,
});

// Context values become:
// { reason: "Injection detected", input: "[REDACTED]", matched: "[REDACTED]" }
// Note: "reason" and "event" keys are NOT redacted
```

## Querying Audit Entries

The audit log keeps entries in memory for querying:

```ts
// Get all blocked events in the last hour
const blocked = audit.query({
  event: "scan_block",
  since: new Date(Date.now() - 3600_000),
});

// Get the last 10 entries for a session
const session = audit.query({
  sessionId: "sess_abc123",
  limit: 10,
});

// Get all entries (for testing/debugging)
const all = audit.getEntries();
```

## Alerting Integration

The audit log integrates with the AlertingEngine to fire alerts based on patterns in the event stream:

```ts
const audit = new AuditLog({
  transports: ["console"],
  level: "all",
  alerting: {
    enabled: true,
    rules: [
      {
        id: "high-block-rate",
        condition: { type: "rate-spike", event: "scan_block", threshold: 10, windowMs: 60_000 },
        action: "callback",
        callback: (alert) => sendPagerDutyAlert(alert),
        cooldownMs: 300_000, // 5-minute cooldown between alerts
      },
      {
        id: "session-kills",
        condition: { type: "session-kills", threshold: 3, windowMs: 300_000 },
        action: "webhook",
        webhookUrl: "https://hooks.slack.com/services/...",
      },
    ],
  },
});
```

Access active alerts:

```ts
const activeAlerts = audit.getActiveAlerts();
const engine = audit.getAlertingEngine();
```

See the [Alerting](/advanced/alerting) guide for full alerting configuration.

## Common Patterns

### Multi-Transport Production Setup

```ts
import { AuditLog, FileTransport, OTelTransport } from "@aegis-sdk/core";
import { trace, metrics } from "@opentelemetry/api";

const file = new FileTransport({
  path: "/var/log/aegis/audit.jsonl",
  rotate: true,
  maxSizeMB: 200,
});

const otel = new OTelTransport({
  tracer: trace.getTracer("aegis"),
  meter: metrics.getMeter("aegis"),
});

const audit = new AuditLog({
  transports: ["json-file", "otel", "custom"],
  level: "violations-only",
  redactContent: true,
});

audit.setFileTransport(file);
audit.setOTelTransport(otel);
audit.addTransport((entry) => {
  if (entry.decision === "blocked") {
    sendToSIEM(entry);
  }
});
```

### Testing with In-Memory Queries

```ts
const audit = new AuditLog({ level: "all" });

// Run your test...
aegis.guardInput(messages);

// Assert on audit entries
const blocks = audit.query({ event: "scan_block" });
expect(blocks).toHaveLength(1);
expect(blocks[0].context.score).toBeGreaterThan(0.4);

// Clean up
audit.clear();
```

## Gotchas

- **In-memory entries grow unbounded.** The audit log stores entries in an array with no built-in eviction. For long-running servers, use `violations-only` level or periodically call `audit.clear()`. The file and OTel transports persist entries externally, so clearing in-memory entries does not lose data.
- **Custom transports swallow errors.** If your custom transport throws, the error is caught silently to avoid breaking the Aegis pipeline. Add try/catch and logging inside your transport function if you need error visibility.
- **FileTransport uses synchronous writes.** `appendFileSync` is used for reliability (no data loss on crash). For high-throughput scenarios, consider a custom async transport with batching.
- **The `transport` option (singular) is deprecated.** Use `transports` (plural) instead. Both are accepted and merged if both are present, but `transport` may be removed in a future major version.
- **OTelTransport does not install OpenTelemetry.** You must install and configure `@opentelemetry/api` and your exporters separately. Aegis only calls the interfaces you pass in.

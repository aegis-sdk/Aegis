# AuditLog

Records every decision, action, and violation in the Aegis pipeline. Supports multiple simultaneous transports: console, JSON file, OpenTelemetry, or any number of custom transport functions.

```ts
import { AuditLog } from "@aegis-sdk/core";
```

## Constructor

```ts
new AuditLog(config?: AuditLogConfig)
```

### AuditLogConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `transport` | `AuditTransport` | — | Single transport (legacy, merged with `transports`) |
| `transports` | `AuditTransport[]` | `["console"]` | Multiple active transports |
| `path` | `string` | `"./aegis-audit.jsonl"` | File path for `"json-file"` transport |
| `level` | `AuditLevel` | `"all"` | Filtering level |
| `redactContent` | `boolean` | `false` | Redact string values in context |
| `alerting` | `AlertingConfig` | — | Alerting engine configuration |

### AuditTransport

```ts
type AuditTransport = "json-file" | "console" | "otel" | "custom";
```

### AuditLevel

| Value | Logs |
|-------|------|
| `"violations-only"` | Only `"blocked"` and `"flagged"` decisions |
| `"actions"` | Everything except `"info"` decisions |
| `"all"` | All entries |

## Methods

### log()

Log an audit entry. The `timestamp` is auto-populated.

```ts
log(entry: {
  event: AuditEventType;
  decision?: "allowed" | "blocked" | "flagged" | "info";
  sessionId?: string;
  requestId?: string;
  context?: Record<string, unknown>;
}): void
```

### query()

Query stored audit entries with optional filters.

```ts
query(filters: {
  event?: AuditEventType;
  since?: Date;
  limit?: number;
  sessionId?: string;
}): AuditEntry[]
```

### getEntries()

Get all stored entries (read-only).

```ts
getEntries(): readonly AuditEntry[]
```

### clear()

Clear all stored entries.

```ts
clear(): void
```

### Transport Management

```ts
// Add a custom transport function
addTransport(fn: TransportFn): void

// Remove a previously-added custom transport (by reference)
removeTransport(fn: TransportFn): void

// Wire an OTelTransport instance
setOTelTransport(otel: OTelTransport): void

// Wire a FileTransport instance for JSONL logging
setFileTransport(file: FileTransport): void

// Legacy: replace all custom transports with a single function
setCustomTransport(fn: TransportFn): void  // @deprecated — use addTransport()
```

### Alerting

```ts
// Get the alerting engine (null if not configured)
getAlertingEngine(): AlertingEngine | null

// Get all active (unresolved) alerts
getActiveAlerts(): Alert[]
```

## AuditEntry

```ts
interface AuditEntry {
  timestamp: Date;
  event: AuditEventType;
  decision: "allowed" | "blocked" | "flagged" | "info";
  sessionId?: string;
  requestId?: string;
  context: Record<string, unknown>;
}
```

## AuditEventType

```ts
type AuditEventType =
  | "scan_pass"              // Input passed scanning
  | "scan_block"             // Input blocked by scanner
  | "scan_trajectory"        // Trajectory analysis flagged escalation
  | "quarantine_create"      // Content quarantined
  | "quarantine_release"     // Content released from quarantine
  | "unsafe_unwrap"          // unsafeUnwrap() called
  | "excessive_unwrap"       // unsafeUnwrap() exceeded threshold
  | "sandbox_trigger"        // Sandbox invoked
  | "sandbox_result"         // Sandbox extraction result
  | "stream_violation"       // Stream monitor detected violation
  | "action_block"           // Action validator blocked a tool call
  | "action_approve"         // Action approved (possibly after human review)
  | "kill_switch"            // Kill switch triggered
  | "session_quarantine"     // Session quarantined
  | "message_integrity_fail" // HMAC verification failed
  | "chain_step_scan"        // Agentic loop step scanned
  | "denial_of_wallet"       // DoW threshold exceeded
  | "policy_violation"       // Generic policy violation
  | "judge_evaluation"       // LLM-Judge evaluated output
  | "custom_check";          // Custom user-defined check
```

## TransportFn

```ts
type TransportFn = (entry: AuditEntry) => void | Promise<void>;
```

Async transports are fire-and-forget — errors are swallowed to avoid blocking the pipeline.

## Example

```ts
import { AuditLog, FileTransport } from "@aegis-sdk/core";

const audit = new AuditLog({
  transports: ["console", "json-file", "custom"],
  level: "all",
  path: "./logs/aegis.jsonl",
});

// Wire file transport
audit.setFileTransport(new FileTransport({ path: "./logs/aegis.jsonl" }));

// Add custom transport
audit.addTransport((entry) => {
  sendToDatadog(entry);
});

// Query recent blocks
const blocks = audit.query({
  event: "scan_block",
  since: new Date(Date.now() - 3600_000),
});
```

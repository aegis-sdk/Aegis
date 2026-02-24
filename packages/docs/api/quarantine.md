# Quarantine

Taint-tracking for untrusted content. Quarantined content cannot be used directly in system prompts or tool parameters — the type system and runtime guards prevent accidental use of untrusted data in trusted contexts.

```ts
import { quarantine, isQuarantined } from "@aegis-sdk/core";
```

## quarantine()

Wrap content in a `Quarantined<T>` container.

```ts
function quarantine<T>(content: T, options: QuarantineOptions): Quarantined<T>
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `content` | `T` | The untrusted content to quarantine |
| `options.source` | `ContentSource` | Where the content came from |
| `options.risk` | `RiskLevel` | Override auto-inferred risk level |

**Returns:** A frozen `Quarantined<T>` object.

Risk level is auto-inferred from `source` if not explicitly set:
- **high**: `user_input`, `web_content`, `email`, `file_upload`, `unknown`
- **medium**: `api_response`, `tool_output`, `mcp_tool_output`, `model_output`
- **low**: `database`, `rag_retrieval`

### ContentSource

```ts
type ContentSource =
  | "user_input" | "api_response" | "web_content" | "email"
  | "file_upload" | "database" | "rag_retrieval" | "tool_output"
  | "mcp_tool_output" | "model_output" | "unknown";
```

## isQuarantined()

Type guard that returns `true` if the value is a `Quarantined<T>` container.

```ts
function isQuarantined<T>(value: unknown): value is Quarantined<T>
```

## Quarantined\<T\>

```ts
interface Quarantined<T> {
  readonly __quarantined: true;
  readonly value: T;
  readonly metadata: QuarantineMetadata;
  unsafeUnwrap(options: UnsafeUnwrapOptions): T;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `__quarantined` | `true` | Brand field for type guarding |
| `value` | `T` | The raw content (accessible but type-guarded) |
| `metadata` | `QuarantineMetadata` | Source, risk, timestamp, unique ID |

### QuarantineMetadata

```ts
interface QuarantineMetadata {
  readonly source: ContentSource;
  readonly risk: RiskLevel;
  readonly timestamp: Date;
  readonly id: string;        // e.g., "q_m1abc23_x7y9z0"
}
```

## unsafeUnwrap()

Extract the raw value from quarantine. Requires a documented reason. Emits a console warning and tracks the global unwrap count.

```ts
unsafeUnwrap(options: UnsafeUnwrapOptions): T
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `options.reason` | `string` | **Required.** Why this is safe to unwrap. |
| `options.audit` | `boolean` | Whether to emit a console warning. Default: `true`. |

**Throws:** `Error` if `reason` is not provided.

If `unsafeUnwrap()` is called more than 10 times globally, an excessive-unwrap handler fires (if registered).

## Runtime Safety

Quarantined objects prevent accidental string coercion:

```ts
const q = quarantine("hello", { source: "user_input" });

// These throw at runtime:
`${q}`;           // Error: Cannot coerce Quarantined content to string
String(q);        // Error: Cannot coerce Quarantined content to a primitive
q + " world";     // Error: Cannot coerce Quarantined content to a primitive
```

## Example

```ts
import { quarantine, isQuarantined } from "@aegis-sdk/core";

// Quarantine user input
const input = quarantine(req.body.message, { source: "user_input" });

// Check if something is quarantined
if (isQuarantined(input)) {
  console.log(`Source: ${input.metadata.source}, Risk: ${input.metadata.risk}`);
}

// Pass to InputScanner (accepts Quarantined<string>)
const result = scanner.scan(input);

// If you must access the raw value (escape hatch):
const raw = input.unsafeUnwrap({
  reason: "Validated by scanner, passing to logging",
});
```

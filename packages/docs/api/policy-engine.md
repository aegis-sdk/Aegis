# Policy Engine

The policy engine provides declarative security policies — think "CSP for AI." Policies control which tools are allowed, rate limits, input/output constraints, PII handling, and alignment enforcement.

```ts
import { resolvePolicy, getPreset, isActionAllowed } from "@aegis-sdk/core";
```

## Functions

### resolvePolicy()

Resolve a policy from a preset name, an `AegisPolicy` object, or a file path string.

```ts
function resolvePolicy(
  input: PresetPolicy | AegisPolicy | string
): AegisPolicy
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `input` | `PresetPolicy \| AegisPolicy \| string` | A preset name, a full policy object, or a path |

**Returns:** A resolved `AegisPolicy` object (deep-cloned from presets).

**Throws:** `Error` if the string is not a recognized preset name.

### getPreset()

Get a built-in policy preset by name.

```ts
function getPreset(name: PresetPolicy): AegisPolicy
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `PresetPolicy` | One of the preset names |

**Returns:** A deep-cloned `AegisPolicy` object.

### isActionAllowed()

Check if a tool name is allowed by the policy's capability rules.

```ts
function isActionAllowed(
  policy: AegisPolicy,
  toolName: string
): { allowed: boolean; requiresApproval: boolean; reason: string }
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `policy` | `AegisPolicy` | The resolved policy to check against |
| `toolName` | `string` | The tool name to validate |

**Returns:**

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | `boolean` | Whether the tool is permitted |
| `requiresApproval` | `boolean` | Whether human-in-the-loop approval is required |
| `reason` | `string` | Human-readable explanation |

Evaluation order: deny list (checked first, overrides allow) -> requireApproval list -> allow list -> default deny if allow list is non-empty.

Glob matching is supported: `"*"` matches everything, `"delete_*"` matches `"delete_user"`, `"delete_file"`, etc.

## PresetPolicy

```ts
type PresetPolicy =
  | "strict"
  | "balanced"
  | "permissive"
  | "customer-support"
  | "code-assistant"
  | "paranoid";
```

| Preset | Allow | Deny | Input Max | Output Max | PII | Exfiltration |
|--------|-------|------|-----------|------------|-----|--------------|
| `strict` | none | `*` | 4,000 | 8,000 | block | blocked |
| `balanced` | `*` | none | 8,000 | 16,000 | redact | blocked |
| `permissive` | `*` | none | 32,000 | 64,000 | allow | allowed |
| `customer-support` | specific tools | `delete_*`, `admin_*` | 4,000 | 8,000 | redact | blocked |
| `code-assistant` | specific tools | `execute_shell`, etc. | 32,000 | 64,000 | allow | blocked |
| `paranoid` | none | `*` | 2,000 | 4,000 | block | blocked |

## AegisPolicy

```ts
interface AegisPolicy {
  version: 1;
  capabilities: {
    allow: string[];           // Glob patterns for allowed tools
    deny: string[];            // Glob patterns for denied tools
    requireApproval: string[]; // Tools requiring human approval
  };
  limits: Record<string, { max: number; window: string }>;
  input: {
    maxLength: number;
    blockPatterns: string[];
    requireQuarantine: boolean;
    encodingNormalization: boolean;
  };
  output: {
    maxLength: number;
    blockPatterns: string[];
    redactPatterns: string[];
    detectPII: boolean;
    detectCanary: boolean;
    blockOnLeak: boolean;
    detectInjectionPayloads: boolean;
    sanitizeMarkdown: boolean;
  };
  alignment: {
    enabled: boolean;
    strictness: "low" | "medium" | "high";
  };
  dataFlow: {
    piiHandling: PiiHandling;          // "block" | "redact" | "allow"
    externalDataSources: string[];
    noExfiltration: boolean;
  };
}
```

## Example

```ts
import { resolvePolicy, isActionAllowed } from "@aegis-sdk/core";

const policy = resolvePolicy("customer-support");

const result = isActionAllowed(policy, "search_kb");
// { allowed: true, requiresApproval: false, reason: "Allowed by policy" }

const result2 = isActionAllowed(policy, "delete_user");
// { allowed: false, requiresApproval: false, reason: 'Tool "delete_user" is in the deny list' }

const result3 = isActionAllowed(policy, "issue_refund");
// { allowed: true, requiresApproval: true, reason: 'Tool "issue_refund" requires human approval' }
```

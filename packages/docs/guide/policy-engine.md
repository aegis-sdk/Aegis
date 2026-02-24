# Policy Engine

The PolicyEngine is a declarative security policy system -- think Content Security Policy (CSP) but for AI tool use, data handling, and I/O constraints.

## The "CSP for AI" Concept

Web applications use Content Security Policy headers to declare what resources a page can load. The Aegis PolicyEngine applies the same idea to AI agents: declare what tools the model can use, what data it can access, and how it handles PII -- all in a single policy object. The enforcement happens automatically throughout the pipeline.

A policy is a plain JSON object. You can check it into version control, diff it in code review, and audit it with standard tooling. No magic, no hidden configuration.

## Policy Presets

Aegis ships with six presets for common use cases:

### `strict`

Maximum security. All tools denied by default, short I/O limits, PII blocked, markdown sanitized.

```ts
import { Aegis } from "@aegis-sdk/core";

const aegis = new Aegis({ policy: "strict" });
```

- Capabilities: all denied (`deny: ["*"]`)
- Input max: 4,000 characters
- Output max: 8,000 characters
- PII handling: block
- Injection payload detection: on
- Exfiltration prevention: on

### `balanced`

Sensible defaults for most applications. All tools allowed, moderate limits, PII redacted.

```ts
const aegis = new Aegis({ policy: "balanced" });
```

- Capabilities: all allowed (`allow: ["*"]`)
- Input max: 8,000 characters
- Output max: 16,000 characters
- PII handling: redact
- Injection payload detection: off
- Exfiltration prevention: on

### `permissive`

Minimal restrictions. Useful for internal tools, development, or applications where users are trusted.

```ts
const aegis = new Aegis({ policy: "permissive" });
```

- Capabilities: all allowed
- Input max: 32,000 characters
- Output max: 64,000 characters
- PII handling: allow
- Quarantine not required
- Exfiltration prevention: off

### `customer-support`

Tailored for support chatbots. Allows knowledge base search and ticket creation, denies destructive operations, requires approval for refunds.

```ts
const aegis = new Aegis({ policy: "customer-support" });
```

- Allowed: `search_kb`, `create_ticket`, `lookup_order`, `check_status`
- Denied: `delete_*`, `admin_*`, `modify_user`
- Requires approval: `issue_refund`, `escalate_to_human`
- Rate limits: 3 tickets/hour, 1 refund/hour
- PII handling: redact

### `code-assistant`

For code generation and review tools. Allows file read/write and search, denies shell execution and network access.

```ts
const aegis = new Aegis({ policy: "code-assistant" });
```

- Allowed: `read_file`, `search_code`, `write_file`, `run_tests`
- Denied: `execute_shell`, `network_request`, `install_package`
- Requires approval: `write_file`, `run_tests`
- Rate limits: 20 writes/hour, 10 test runs/hour
- PII handling: allow (code may contain test data)

### `paranoid`

Maximum lockdown. Even stricter than `strict` -- shorter limits, all tools denied, everything monitored.

```ts
const aegis = new Aegis({ policy: "paranoid" });
```

- Capabilities: all denied
- Input max: 2,000 characters
- Output max: 4,000 characters
- PII handling: block
- All detection features enabled

## Custom Policies

Start from a preset and override specific fields, or write a policy from scratch:

```ts
import { getPreset } from "@aegis-sdk/core";

// Start from balanced, customize capabilities
const policy = {
  ...getPreset("balanced"),
  capabilities: {
    allow: ["search_*", "read_*", "create_ticket"],
    deny: ["delete_*", "admin_*", "execute_*"],
    requireApproval: ["send_email", "create_ticket"],
  },
  limits: {
    create_ticket: { max: 5, window: "1h" },
    send_email: { max: 3, window: "1h" },
  },
};

const aegis = new Aegis({ policy });
```

### Policy Object Structure

```ts
interface AegisPolicy {
  version: 1;
  capabilities: {
    allow: string[];          // Tools the model can use
    deny: string[];           // Tools that are blocked (overrides allow)
    requireApproval: string[];// Tools that need human approval
  };
  limits: Record<string, {    // Per-tool rate limits
    max: number;              // Maximum calls allowed
    window: string;           // Time window ("30s", "5m", "1h", "1d")
  }>;
  input: {
    maxLength: number;        // Maximum input character count
    blockPatterns: string[];  // Regex patterns to block in input
    requireQuarantine: boolean;// Force quarantine on all inputs
    encodingNormalization: boolean; // Normalize encoded content
  };
  output: {
    maxLength: number;        // Maximum output character count
    blockPatterns: string[];  // Regex patterns to block in output
    redactPatterns: string[]; // Regex patterns to redact in output
    detectPII: boolean;       // Scan output for PII
    detectCanary: boolean;    // Watch for canary token leaks
    blockOnLeak: boolean;     // Kill stream on canary leak
    detectInjectionPayloads: boolean; // Scan output for injection
    sanitizeMarkdown: boolean;// Sanitize markdown in output
  };
  alignment: {
    enabled: boolean;         // Enable alignment checking
    strictness: "low" | "medium" | "high";
  };
  dataFlow: {
    piiHandling: "block" | "redact" | "allow";
    externalDataSources: string[];
    noExfiltration: boolean;  // Prevent read-then-send attacks
  };
}
```

## `resolvePolicy()`

Resolves a policy from a preset name or a policy object:

```ts
import { resolvePolicy } from "@aegis-sdk/core";

// From a preset name
const policy = resolvePolicy("strict");

// From a policy object (returns it as-is)
const policy = resolvePolicy(customPolicyObject);
```

Throws an error if the string is not a recognized preset name.

## `getPreset()`

Returns a deep clone of a preset policy:

```ts
import { getPreset } from "@aegis-sdk/core";

const base = getPreset("customer-support");
base.capabilities.allow.push("send_notification");
// The original preset is not modified
```

## `isActionAllowed()`

Checks whether a tool call is permitted by the policy:

```ts
import { isActionAllowed, getPreset } from "@aegis-sdk/core";

const policy = getPreset("customer-support");

const result = isActionAllowed(policy, "search_kb");
// { allowed: true, requiresApproval: false, reason: "Allowed by policy" }

const result2 = isActionAllowed(policy, "delete_user");
// { allowed: false, requiresApproval: false, reason: 'Tool "delete_user" is in the deny list' }

const result3 = isActionAllowed(policy, "issue_refund");
// { allowed: true, requiresApproval: true, reason: 'Tool "issue_refund" requires human approval' }
```

### Evaluation Order

1. **Deny list checked first.** If the tool matches any deny pattern, it is blocked regardless of the allow list.
2. **Approval list checked second.** If the tool matches a requireApproval pattern, it is allowed but flagged for human review.
3. **Allow list checked third.** If the tool matches an allow pattern, it is allowed.
4. **Default deny.** If the allow list is non-empty and the tool does not match any pattern, it is denied.

## Glob Pattern Matching

Capability lists support glob patterns with `*` as a wildcard suffix:

| Pattern | Matches |
|---------|---------|
| `"*"` | All tools |
| `"search_*"` | `search_kb`, `search_docs`, `search_users` |
| `"delete_*"` | `delete_user`, `delete_record`, `delete_file` |
| `"admin_*"` | `admin_panel`, `admin_settings` |
| `"send_email"` | Only `send_email` (exact match) |

```ts
const policy = {
  // ...
  capabilities: {
    allow: ["read_*", "search_*"],     // All read and search tools
    deny: ["read_secrets", "admin_*"], // But not secrets or admin
    requireApproval: ["write_*"],      // All writes need approval
  },
};
```

## Rate Limits

Rate limits are configured per tool with a maximum count and time window:

```ts
const policy = {
  // ...
  limits: {
    create_ticket: { max: 3, window: "1h" },  // 3 per hour
    send_email: { max: 10, window: "1d" },     // 10 per day
    search_kb: { max: 100, window: "5m" },     // 100 per 5 minutes
    issue_refund: { max: 1, window: "1h" },    // 1 per hour
  },
};
```

Supported window formats: `"30s"`, `"5m"`, `"1h"`, `"1d"` (seconds, minutes, hours, days).

## PII Handling Modes

The `dataFlow.piiHandling` field controls how PII is handled across the pipeline:

| Mode | Behavior |
|------|----------|
| `"block"` | Any PII detected in output terminates the stream |
| `"redact"` | PII is replaced with `[REDACTED-TYPE]` markers |
| `"allow"` | PII passes through without intervention |

This setting propagates to the StreamMonitor configuration automatically when using the `Aegis` class.

## Data Flow Policies

### No Exfiltration

When `dataFlow.noExfiltration` is `true`, the ActionValidator tracks data read by tool calls and blocks subsequent tool calls that would send that data to external destinations:

```ts
const policy = {
  // ...
  dataFlow: {
    noExfiltration: true,
    piiHandling: "redact",
    externalDataSources: [],
  },
};
```

This prevents attacks where an injected instruction causes the model to read sensitive data and then email or webhook it to an attacker.

## Common Patterns

### Starting from a Preset and Customizing

```ts
import { getPreset } from "@aegis-sdk/core";

const policy = getPreset("balanced");

// Add specific rate limits
policy.limits = {
  create_order: { max: 5, window: "1h" },
  send_notification: { max: 20, window: "1d" },
};

// Tighten output scanning
policy.output.detectInjectionPayloads = true;
policy.output.sanitizeMarkdown = true;

// Lock down data flow
policy.dataFlow.noExfiltration = true;
policy.dataFlow.piiHandling = "redact";

const aegis = new Aegis({ policy });
```

### Environment-Specific Policies

```ts
const policy =
  process.env.NODE_ENV === "production"
    ? getPreset("strict")
    : getPreset("permissive");

const aegis = new Aegis({ policy });
```

### Multi-Tenant Policies

```ts
function getPolicyForTier(tier: "free" | "pro" | "enterprise") {
  switch (tier) {
    case "free":
      return {
        ...getPreset("strict"),
        limits: { search: { max: 10, window: "1h" } },
      };
    case "pro":
      return getPreset("balanced");
    case "enterprise":
      return {
        ...getPreset("balanced"),
        input: { ...getPreset("balanced").input, maxLength: 32000 },
      };
  }
}
```

## Gotchas

- **Deny overrides allow.** If a tool matches both a deny pattern and an allow pattern, it is denied. Design your patterns with this in mind.
- **Empty allow list means allow all.** If `capabilities.allow` is `[]` (empty array), the default behavior is to allow all tools that are not in the deny list. If you want to deny everything by default, use `deny: ["*"]`.
- **Rate limits are per-instance.** The ActionValidator stores rate limit counters in memory. If you have multiple server instances, each tracks rates independently. For distributed rate limiting, use a custom validator with a shared store.
- **Presets return deep clones.** Calling `getPreset()` returns a new copy every time. Mutating the returned object does not affect the preset definition.
- **Policy file loading is not yet implemented.** The `resolvePolicy()` function accepts a file path string but the YAML/JSON file loading is planned for a future release. Currently only preset names and policy objects are supported.

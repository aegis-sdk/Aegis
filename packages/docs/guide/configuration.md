# Configuration

Aegis is configured through a single `AegisConfig` object passed to the constructor. Every field is optional — sensible defaults are applied automatically.

```ts
import { Aegis } from "@aegis-sdk/core";

const aegis = new Aegis({
  policy: "balanced",
  scanner: { sensitivity: "balanced" },
  recovery: { mode: "continue" },
  audit: { transport: "console", level: "violations-only" },
});
```

## Full Config Shape

```ts
interface AegisConfig {
  /** Policy preset name or a full policy object */
  policy?: PresetPolicy | AegisPolicy | string;

  /** Input scanner configuration */
  scanner?: InputScannerConfig;

  /** Stream monitor configuration */
  monitor?: StreamMonitorConfig;

  /** Recovery behavior when input is blocked */
  recovery?: RecoveryConfig;

  /** Audit log configuration */
  audit?: AuditLogConfig;

  /** Canary tokens to detect in output streams */
  canaryTokens?: string[];

  /** Action validator configuration */
  validator?: ActionValidatorConfig;

  /** Agent loop / chain step configuration */
  agentLoop?: AgentLoopConfig;

  /** HMAC message integrity for detecting history manipulation */
  integrity?: MessageIntegrityConfig;
}
```

## Policy Presets

Aegis ships with six policy presets. Pass the name as a string to `policy`:

| Preset | Input Max | Output Max | PII Handling | Tool Access | Use Case |
|--------|-----------|------------|--------------|-------------|----------|
| `strict` | 4,000 | 8,000 | Block | Deny all | High-security applications |
| `balanced` | 8,000 | 16,000 | Redact | Allow all | General-purpose (default) |
| `permissive` | 32,000 | 64,000 | Allow | Allow all | Internal tools, low-risk |
| `customer-support` | 4,000 | 8,000 | Redact | Allowlist | Customer-facing chatbots |
| `code-assistant` | 32,000 | 64,000 | Allow | Allowlist | Code generation tools |
| `paranoid` | 2,000 | 4,000 | Block | Deny all | Maximum security |

### Preset Details

::: details strict
- All tools denied by default
- PII detection and blocking enabled
- Injection payload detection in output streams
- Markdown sanitization enabled
- High alignment strictness
- No exfiltration allowed
:::

::: details balanced (default)
- All tools allowed
- PII detected and redacted (not blocked)
- Output injection detection disabled (input scanning handles it)
- Medium alignment strictness
- No exfiltration allowed
:::

::: details customer-support
- Specific tools allowlisted: `search_kb`, `create_ticket`, `lookup_order`, `check_status`
- Tools requiring approval: `issue_refund`, `escalate_to_human`
- Rate limits: max 3 tickets/hour, max 1 refund/hour
- Dangerous tools denied: `delete_*`, `admin_*`, `modify_user`
:::

::: details code-assistant
- Specific tools allowlisted: `read_file`, `search_code`, `write_file`, `run_tests`
- Tools requiring approval: `write_file`, `run_tests`
- Dangerous tools denied: `execute_shell`, `network_request`, `install_package`
- Rate limits: max 20 file writes/hour, max 10 test runs/hour
- Long input/output allowed for code context
:::

### Custom Policy

Pass a full `AegisPolicy` object for complete control:

```ts
const aegis = new Aegis({
  policy: {
    version: 1,
    capabilities: {
      allow: ["search", "read_file"],
      deny: ["delete_*", "admin_*"],
      requireApproval: ["write_file"],
    },
    limits: {
      write_file: { max: 10, window: "1h" },
    },
    input: {
      maxLength: 8000,
      blockPatterns: [],
      requireQuarantine: true,
      encodingNormalization: true,
    },
    output: {
      maxLength: 16000,
      blockPatterns: [],
      redactPatterns: [],
      detectPII: true,
      detectCanary: true,
      blockOnLeak: true,
      detectInjectionPayloads: false,
      sanitizeMarkdown: false,
    },
    alignment: { enabled: true, strictness: "medium" },
    dataFlow: {
      piiHandling: "redact",
      externalDataSources: [],
      noExfiltration: true,
    },
  },
});
```

## Scanner Configuration

Control how the input scanner detects injection attempts:

```ts
interface InputScannerConfig {
  /** Detection sensitivity: 'paranoid' | 'balanced' | 'permissive' */
  sensitivity?: Sensitivity;

  /** Additional regex patterns to match against input */
  customPatterns?: RegExp[];

  /** Normalize Unicode, Base64, and other encodings before scanning */
  encodingNormalization?: boolean;

  /** Detect high-entropy adversarial suffixes */
  entropyAnalysis?: boolean;

  /** Detect language switching attacks */
  languageDetection?: boolean;

  /** Detect many-shot jailbreaking patterns */
  manyShotDetection?: boolean;

  /** Entropy threshold for adversarial suffix detection */
  entropyThreshold?: number;

  /** Number of example/response pairs to trigger many-shot detection */
  manyShotThreshold?: number;
}
```

### Sensitivity Levels

- **`paranoid`** — Lowest thresholds, most false positives. Use when security is paramount.
- **`balanced`** — Default. Good trade-off between security and usability.
- **`permissive`** — Highest thresholds, fewest false positives. Use for trusted environments.

## Recovery Modes

Control what happens when an injection is detected:

```ts
interface RecoveryConfig {
  /** Recovery strategy */
  mode: RecoveryMode;

  /** Automatically retry with the offending message removed */
  autoRetry?: boolean;

  /** Maximum auto-retry attempts */
  autoRetryMaxAttempts?: number;

  /** Notify the user about the blocked input */
  notifyUser?: boolean;
}
```

| Mode | Behavior |
|------|----------|
| `continue` | Throw `AegisInputBlocked` immediately (default) |
| `reset-last` | Strip the offending message and return remaining history |
| `quarantine-session` | Lock the session — all future input is blocked |
| `terminate-session` | Throw a terminal error — session must be recreated |

```ts
// Example: strip the bad message instead of throwing
const aegis = new Aegis({
  recovery: { mode: "reset-last" },
});
```

## Audit Configuration

```ts
interface AuditLogConfig {
  /** Transport: 'console' | 'json-file' | 'otel' | 'custom' */
  transport?: AuditTransport;

  /** Multiple transports simultaneously */
  transports?: AuditTransport[];

  /** File path for json-file transport */
  path?: string;

  /** Log level: 'violations-only' | 'actions' | 'all' */
  level?: AuditLevel;

  /** Redact message content from audit entries */
  redactContent?: boolean;

  /** Alerting rules */
  alerting?: AlertingConfig;
}
```

### Audit Levels

- **`violations-only`** — Only log blocked/flagged events
- **`actions`** — Log violations and tool call validations
- **`all`** — Log everything including allowed scans

## Agent Loop Configuration

For agentic systems with multi-step tool calling:

```ts
const aegis = new Aegis({
  agentLoop: {
    /** Maximum steps before halting. Default: 25 */
    defaultMaxSteps: 25,

    /** Cumulative risk score threshold. Default: 3.0 */
    defaultRiskBudget: 3.0,

    /** Privilege decay: reduce available tools as steps increase */
    privilegeDecay: {
      10: 0.75, // At step 10, 75% of tools remain
      15: 0.5, // At step 15, 50% of tools remain
      20: 0.25, // At step 20, 25% of tools remain
    },
  },
});
```

## Message Integrity

Detect conversation history manipulation using HMAC signatures:

```ts
const aegis = new Aegis({
  integrity: {
    /** HMAC secret key (required) */
    secret: process.env.AEGIS_HMAC_SECRET!,

    /** Hash algorithm. Default: 'SHA-256' */
    algorithm: "SHA-256",

    /** Only sign assistant messages. Default: true */
    assistantOnly: true,
  },
});
```

## Environment Variables

Aegis does not read environment variables directly — all configuration is explicit. However, a common pattern is:

```ts
const aegis = new Aegis({
  policy: process.env.AEGIS_POLICY ?? "balanced",
  integrity: process.env.AEGIS_HMAC_SECRET
    ? { secret: process.env.AEGIS_HMAC_SECRET }
    : undefined,
  audit: {
    transport: process.env.NODE_ENV === "production" ? "otel" : "console",
    level: process.env.NODE_ENV === "production" ? "violations-only" : "all",
  },
});
```

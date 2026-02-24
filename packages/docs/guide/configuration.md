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

  /** Auto-retry with escalated security on blocked input (v0.4.0) */
  autoRetry?: AutoRetryConfig;

  /** Multi-modal content scanning — images, PDFs, audio, etc. (v0.4.0) */
  multiModal?: MultiModalConfig;

  /** LLM-Judge intent alignment verification (v0.4.0) */
  judge?: LLMJudgeConfig;
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

  /** Enable character-level perplexity estimation (v0.4.0). Default: false */
  perplexityEstimation?: boolean;

  /** Perplexity anomaly threshold in bits per character. Default: 4.5 */
  perplexityThreshold?: number;

  /** Full perplexity analyzer configuration (overrides perplexityThreshold). */
  perplexityConfig?: PerplexityConfig;
}
```

### Sensitivity Levels

- **`paranoid`** — Lowest thresholds, most false positives. Use when security is paramount.
- **`balanced`** — Default. Good trade-off between security and usability.
- **`permissive`** — Highest thresholds, fewest false positives. Use for trusted environments.

### Perplexity Estimation <Badge type="tip" text="v0.4.0" />

Character-level n-gram perplexity analysis detects adversarial inputs that are statistically unusual — GCG adversarial suffixes, encoded payloads, random gibberish — without requiring ML models or bundled weights.

Natural English text clusters around 3.0-4.0 bits/char. Adversarial suffixes from gradient-based attacks typically exceed 5.0 bits/char.

```ts
const aegis = new Aegis({
  scanner: {
    perplexityEstimation: true,
    perplexityThreshold: 4.5, // Default — raise to reduce false positives on technical content
  },
});
```

For fine-grained control, use the full `perplexityConfig`:

```ts
const aegis = new Aegis({
  scanner: {
    perplexityEstimation: true,
    perplexityConfig: {
      enabled: true,
      threshold: 4.5,    // Bits per character anomaly threshold
      windowSize: 50,    // Characters per sliding window
      ngramOrder: 3,     // Trigram analysis (character-level)
      languageProfiles: {
        english: {
          name: "English",
          expectedRange: { min: 2.5, max: 4.0 },
          commonNgrams: ["the", "ing", "and", "ent", "ion"],
        },
      },
    },
  },
});
```

The `ScanResult` includes a `perplexity` field when enabled:

```ts
const result = scanner.scan(quarantinedInput);
if (result.perplexity?.anomalous) {
  console.log("Perplexity:", result.perplexity.perplexity);
  console.log("Max window:", result.perplexity.maxWindowPerplexity);
  // result.perplexity.windowScores has per-window breakdown
}
```

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
| `auto-retry` | Re-scan with escalated security; throw only if all retries fail (v0.4.0) |

```ts
// Example: strip the bad message instead of throwing
const aegis = new Aegis({
  recovery: { mode: "reset-last" },
});
```

```ts
// Example: auto-retry with escalated scanning before giving up
const aegis = new Aegis({
  recovery: { mode: "auto-retry" },
  autoRetry: {
    enabled: true,
    maxAttempts: 3,
    escalationPath: "stricter_scanner",
  },
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

## Auto-Retry Configuration <Badge type="tip" text="v0.4.0" />

When `recovery.mode` is set to `"auto-retry"`, the `autoRetry` config controls how Aegis re-scans blocked input with escalated security before giving up.

```ts
interface AutoRetryConfig {
  /** Whether auto-retry is enabled. */
  enabled: boolean;

  /** Maximum number of retry attempts before giving up. Default: 3 */
  maxAttempts?: number;

  /** Escalation strategy to apply on retry. Default: "stricter_scanner" */
  escalationPath?: AutoRetryEscalation;

  /** Callback invoked before each retry attempt. */
  onRetry?: (context: RetryContext) => void | Promise<void>;
}
```

### Escalation Strategies

| Strategy | Behavior |
|----------|----------|
| `stricter_scanner` | Re-scan the input with `sensitivity: "paranoid"` (default) |
| `sandbox` | Flag the input for sandbox extraction — defers to the caller |
| `combined` | Try paranoid scan first, then sandbox if still failing |

```ts
const aegis = new Aegis({
  recovery: { mode: "auto-retry" },
  autoRetry: {
    enabled: true,
    maxAttempts: 3,
    escalationPath: "combined",
    onRetry: (ctx) => {
      console.log(
        `Retry ${ctx.attempt}/${ctx.totalAttempts} — ` +
        `escalation: ${ctx.escalation}, ` +
        `original score: ${ctx.originalScore.toFixed(2)}`
      );
    },
  },
});
```

If all retry attempts fail, `guardInput()` throws `AegisInputBlocked` as usual. The audit log records each retry attempt with its result.

## LLM Judge Configuration <Badge type="tip" text="v0.4.0" />

The LLM Judge uses a secondary LLM call to verify whether model output aligns with the original user intent. This catches subtle manipulation that deterministic pattern matching cannot detect.

```ts
interface LLMJudgeConfig {
  /** Whether the judge is active. Default: true */
  enabled?: boolean;

  /**
   * Risk score threshold above which the judge is invoked (0-1).
   * The judge only fires when the input scanner produces a score at or above
   * this value. Default: 0.5
   */
  triggerThreshold?: number;

  /** Timeout for the judge LLM call in milliseconds. Default: 5000 */
  timeout?: number;

  /** Custom system prompt for the judge. Overrides the built-in default. */
  systemPrompt?: string;

  /**
   * The LLM call function — provided by you or a provider adapter.
   * Takes a prompt string, returns the raw model response string.
   * This is the only required field.
   */
  llmCall: (prompt: string) => Promise<string>;
}
```

### Basic Setup

```ts
import OpenAI from "openai";

const openai = new OpenAI();

const aegis = new Aegis({
  judge: {
    triggerThreshold: 0.5,
    timeout: 5000,
    llmCall: async (prompt) => {
      const res = await openai.chat.completions.create({
        model: "gpt-4o-mini", // Fast and cheap — the judge prompt is small
        messages: [{ role: "user", content: prompt }],
        temperature: 0,
      });
      return res.choices[0].message.content ?? "";
    },
  },
});
```

### Using the Judge

The judge is invoked automatically during `guardInput()` when the scanner's risk score exceeds the `triggerThreshold`. You can also invoke it manually:

```ts
const verdict = await aegis.judgeOutput(
  "What is the weather in Tokyo?",
  modelResponseText,
  {
    riskScore: 0.6,
    detections: scanResult.detections,
  },
);

if (!verdict.approved) {
  console.log("Judge rejected:", verdict.reasoning);
  console.log("Decision:", verdict.decision); // "rejected" | "flagged"
  console.log("Confidence:", verdict.confidence);
}
```

### Cost/Latency Tips

- Set `triggerThreshold` to 0.7+ so the judge only fires on already-suspicious inputs
- Use `gpt-4o-mini`, `claude-haiku`, or another fast model — the judge prompt is small
- Set `timeout` to 3000ms to cap worst-case latency
- The judge falls back to `"flagged"` on timeout or error — it never silently approves on failure

## Multi-Modal Scanning Configuration <Badge type="tip" text="v0.4.0" />

The multi-modal scanner extracts text from images, PDFs, audio, and documents, then runs the full input scanner pipeline on the extracted content.

```ts
interface MultiModalConfig {
  /** Whether multi-modal scanning is enabled. Default: true */
  enabled?: boolean;

  /** Maximum file size in bytes. Default: 10,485,760 (10 MB) */
  maxFileSize?: number;

  /** Allowed media types. Default: all types. */
  allowedMediaTypes?: MediaType[];

  /**
   * The text extraction function — provided by you or an adapter.
   * This is the only required field.
   */
  extractText: (
    content: Uint8Array | string,
    mediaType: MediaType,
  ) => Promise<{ text: string; confidence: number }>;

  /** Scanner sensitivity for extracted text. Inherits from main scanner if omitted. */
  scannerSensitivity?: Sensitivity;
}
```

Supported media types: `"image"`, `"audio"`, `"video"`, `"pdf"`, `"document"`.

### Basic Setup

Aegis does not bundle OCR or speech-to-text — you provide the extraction function. This keeps the core library dependency-free and lets you use any extraction service.

```ts
import Tesseract from "tesseract.js";

const aegis = new Aegis({
  multiModal: {
    maxFileSize: 5 * 1024 * 1024, // 5 MB limit
    allowedMediaTypes: ["image", "pdf"],
    extractText: async (content, mediaType) => {
      if (mediaType === "image") {
        const result = await Tesseract.recognize(
          content instanceof Uint8Array ? Buffer.from(content) : content,
          "eng",
        );
        return { text: result.data.text, confidence: result.data.confidence / 100 };
      }
      // Handle other types...
      return { text: "", confidence: 0 };
    },
  },
});
```

### Scanning Media

```ts
const imageBytes = await fs.readFile("uploaded-image.png");

const result = await aegis.scanMedia(imageBytes, "image");

if (!result.safe) {
  console.log("Injection detected in image!");
  console.log("Extracted text:", result.extracted.text);
  console.log("Scan detections:", result.scanResult.detections);
}
```

The `MultiModalScanResult` includes the extracted text, extraction confidence, the full `ScanResult`, and the file size.

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

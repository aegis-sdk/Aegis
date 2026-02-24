---
title: Policy Examples
description: Complete, domain-specific Aegis policy configurations for financial services, customer support, code assistants, and healthcare applications.
---

# Policy Examples

This page provides complete `AegisConfig` configurations for common application types. Each example is ready to copy into your project and adjust. Every field is shown explicitly so you can see exactly what is configured -- no hidden defaults.

For an explanation of what each field does, see [Policy Engine](/guide/policy-engine) and [Configuration](/guide/configuration).

## Financial Services Chatbot

A strict configuration for banking, trading, or financial advisory applications. The priority is preventing any data leakage or unauthorized actions. PII is blocked outright rather than redacted -- in financial services, the safest approach is to never let sensitive data reach the output stream.

```ts
import { Aegis } from "@aegis-sdk/core";

const aegis = new Aegis({
  policy: {
    version: 1,
    capabilities: {
      allow: ["lookup_account", "check_balance", "get_transaction_history", "search_faq"],
      deny: ["transfer_*", "delete_*", "admin_*", "modify_*", "execute_*"],
      requireApproval: ["initiate_transfer", "close_account", "update_profile"],
    },
    limits: {
      lookup_account: { max: 20, window: "1h" },
      check_balance: { max: 30, window: "1h" },
      get_transaction_history: { max: 10, window: "1h" },
      initiate_transfer: { max: 2, window: "1h" },
    },
    input: {
      maxLength: 4000,
      blockPatterns: [],
      requireQuarantine: true,
      encodingNormalization: true,
    },
    output: {
      maxLength: 8000,
      blockPatterns: [],
      redactPatterns: [
        "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b",   // Credit card numbers
        "\\b\\d{3}-\\d{2}-\\d{4}\\b",                        // SSN format
        "\\b[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}([A-Z0-9]?){0,16}\\b", // IBAN
      ],
      detectPII: true,
      detectCanary: true,
      blockOnLeak: true,
      detectInjectionPayloads: true,
      sanitizeMarkdown: true,
    },
    alignment: { enabled: true, strictness: "high" },
    dataFlow: {
      piiHandling: "block",
      externalDataSources: [],
      noExfiltration: true,
    },
  },

  scanner: {
    sensitivity: "balanced",
    encodingNormalization: true,
    entropyAnalysis: true,
    languageDetection: true,
    manyShotDetection: true,
    perplexityEstimation: true,
    perplexityThreshold: 4.5,
  },

  monitor: {
    detectPII: true,
    piiRedaction: true,
    detectSecrets: true,
    detectInjectionPayloads: true,
  },

  integrity: {
    secret: process.env.AEGIS_HMAC_SECRET!,
    algorithm: "SHA-256",
  },

  canaryTokens: [process.env.AEGIS_CANARY_TOKEN!],

  recovery: { mode: "continue" },

  audit: {
    transports: ["otel", "json-file"],
    path: "/var/log/aegis/financial-audit.jsonl",
    level: "all",  // Log everything for compliance
    redactContent: true,
    alerting: {
      enabled: true,
      rules: [
        {
          id: "injection-burst",
          condition: { type: "rate-spike", event: "scan_block", threshold: 5, windowMs: 60_000 },
          action: "webhook",
          webhookUrl: process.env.SECURITY_WEBHOOK_URL!,
          cooldownMs: 300_000,
        },
        {
          id: "repeated-attacker",
          condition: { type: "repeated-attacker", threshold: 3, windowMs: 300_000 },
          action: "callback",
          callback: async (alert) => {
            await banSession(alert.context.sessionId as string);
          },
        },
      ],
    },
  },

  validator: {
    scanMcpParams: true,
    denialOfWallet: {
      maxOperations: 50,
      window: "5m",
      maxSandboxTriggers: 5,
      maxToolCalls: 30,
    },
  },
});
```

**Why these choices:**

- `piiHandling: "block"` -- In financial applications, leaking account numbers or SSNs is unacceptable. Blocking is safer than redacting because redaction can fail on novel PII formats.
- `audit.level: "all"` -- Financial regulators often require complete audit trails. Log everything and use `redactContent: true` to avoid storing raw customer messages.
- `output.redactPatterns` -- Even with `detectPII`, explicit regex patterns for credit cards, SSNs, and IBANs add a deterministic safety net.
- `recovery: { mode: "continue" }` -- Throw immediately on injection. Do not attempt to strip or retry -- in finance, a false negative is far more costly than a false positive.

---

## Customer Support Bot

A balanced configuration for customer-facing support chatbots. The bot can search a knowledge base, create tickets, and look up orders, but destructive operations are blocked and refunds require human approval.

```ts
import { Aegis } from "@aegis-sdk/core";

const aegis = new Aegis({
  policy: {
    version: 1,
    capabilities: {
      allow: ["search_kb", "create_ticket", "lookup_order", "check_status", "get_faq"],
      deny: ["delete_*", "admin_*", "modify_user", "execute_*", "send_email"],
      requireApproval: ["issue_refund", "escalate_to_human", "update_order"],
    },
    limits: {
      create_ticket: { max: 3, window: "1h" },
      issue_refund: { max: 1, window: "1h" },
      search_kb: { max: 50, window: "5m" },
      lookup_order: { max: 20, window: "1h" },
    },
    input: {
      maxLength: 4000,
      blockPatterns: [],
      requireQuarantine: true,
      encodingNormalization: true,
    },
    output: {
      maxLength: 8000,
      blockPatterns: [],
      redactPatterns: [],
      detectPII: true,
      detectCanary: true,
      blockOnLeak: true,
      detectInjectionPayloads: true,
      sanitizeMarkdown: true,
    },
    alignment: { enabled: true, strictness: "high" },
    dataFlow: {
      piiHandling: "redact",
      externalDataSources: [],
      noExfiltration: true,
    },
  },

  scanner: {
    sensitivity: "balanced",
    encodingNormalization: true,
    entropyAnalysis: true,
    languageDetection: true,
    manyShotDetection: true,
    perplexityEstimation: false, // Customer messages are informal -- perplexity causes more false positives
  },

  monitor: {
    detectPII: true,
    piiRedaction: true,
    detectSecrets: false,
    detectInjectionPayloads: true,
  },

  integrity: {
    secret: process.env.AEGIS_HMAC_SECRET!,
    algorithm: "SHA-256",
  },

  canaryTokens: [process.env.AEGIS_CANARY_TOKEN!],

  recovery: { mode: "reset-last" }, // Strip the offending message rather than terminating

  audit: {
    transports: ["otel"],
    level: "violations-only",
    redactContent: true,
    alerting: {
      enabled: true,
      rules: [
        {
          id: "block-rate-spike",
          condition: { type: "rate-spike", event: "scan_block", threshold: 15, windowMs: 60_000 },
          action: "webhook",
          webhookUrl: process.env.SLACK_WEBHOOK_URL!,
          cooldownMs: 300_000,
        },
        {
          id: "session-abuse",
          condition: { type: "repeated-attacker", threshold: 5, windowMs: 600_000 },
          action: "callback",
          callback: async (alert) => {
            await quarantineSession(alert.context.sessionId as string);
          },
        },
      ],
    },
  },

  validator: {
    scanMcpParams: true,
    denialOfWallet: {
      maxOperations: 100,
      window: "5m",
      maxSandboxTriggers: 10,
      maxToolCalls: 50,
    },
  },
});
```

**Why these choices:**

- `recovery: { mode: "reset-last" }` -- Support bots should be forgiving. If a message is blocked, strip it and continue the conversation rather than throwing an error. The user can rephrase.
- `perplexityEstimation: false` -- Customer messages often contain misspellings, slang, mixed languages, and pasted error logs. Perplexity analysis tends to flag these as anomalous, producing false positives.
- `piiHandling: "redact"` -- Customers often share their own PII voluntarily (order numbers, email addresses). Redaction is less disruptive than blocking.
- `languageDetection: true` -- Support bots often serve multilingual users. Language detection catches language-switching attacks without blocking legitimate multilingual conversations.

---

## Code Assistant

A permissive configuration for code generation and review tools. Code naturally contains patterns that look like injection attacks (SQL queries, shell commands, HTML tags), so output scanning must be relaxed. The focus is on preventing the assistant from executing code or making network requests, not on content classification.

```ts
import { Aegis } from "@aegis-sdk/core";

const aegis = new Aegis({
  policy: {
    version: 1,
    capabilities: {
      allow: ["read_file", "search_code", "write_file", "run_tests", "list_directory", "get_diff"],
      deny: ["execute_shell", "network_request", "install_package", "delete_*", "admin_*"],
      requireApproval: ["write_file", "run_tests"],
    },
    limits: {
      write_file: { max: 30, window: "1h" },
      run_tests: { max: 15, window: "1h" },
      search_code: { max: 200, window: "1h" },
      read_file: { max: 500, window: "1h" },
    },
    input: {
      maxLength: 32000,    // Code context is long
      blockPatterns: [],
      requireQuarantine: true,
      encodingNormalization: true,
    },
    output: {
      maxLength: 64000,    // Code output is long
      blockPatterns: [],
      redactPatterns: [],
      detectPII: false,    // Code contains test data that looks like PII
      detectCanary: true,
      blockOnLeak: true,
      detectInjectionPayloads: false, // Code *is* injection payloads (SQL, shell, etc.)
      sanitizeMarkdown: false,        // Code blocks need raw markdown
    },
    alignment: { enabled: true, strictness: "medium" },
    dataFlow: {
      piiHandling: "allow",           // Code may contain test fixtures with fake PII
      externalDataSources: [],
      noExfiltration: true,           // Still prevent read-then-exfiltrate attacks
    },
  },

  scanner: {
    sensitivity: "permissive",        // Reduce false positives on code-like input
    encodingNormalization: true,
    entropyAnalysis: true,
    languageDetection: false,         // Code mixes natural language and programming syntax
    manyShotDetection: true,
    perplexityEstimation: false,      // Code has naturally high perplexity
  },

  monitor: {
    detectPII: false,
    piiRedaction: false,
    detectSecrets: true,              // Catch accidentally leaked API keys
    detectInjectionPayloads: false,
  },

  canaryTokens: [process.env.AEGIS_CANARY_TOKEN!],

  recovery: { mode: "continue" },

  audit: {
    transports: ["otel"],
    level: "violations-only",
    redactContent: false, // Code content is useful for debugging false positives
  },

  validator: {
    scanMcpParams: true,
    denialOfWallet: {
      maxOperations: 200,
      window: "5m",
      maxSandboxTriggers: 20,
      maxToolCalls: 100,
    },
  },
});
```

**Why these choices:**

- `sensitivity: "permissive"` -- Code input routinely contains strings like `DROP TABLE`, `rm -rf`, `<script>`, and base64-encoded data. Permissive sensitivity raises thresholds so these are not flagged.
- `detectInjectionPayloads: false` -- Injection payloads in output are the *point* of a code assistant. A user asking "write me a SQL injection test" should get one.
- `detectPII: false` -- Code often contains test fixtures with realistic-looking names, emails, and phone numbers. PII detection would constantly false-positive.
- `detectSecrets: true` -- Even in a code assistant, you do not want the model to echo back real API keys or passwords from the codebase.
- `perplexityEstimation: false` -- Programming languages, minified code, base64 strings, and UUIDs all have high character-level perplexity. Enabling this would produce constant false positives.
- `noExfiltration: true` -- Even though we are permissive on content, we still want to prevent an attack where the model reads a secrets file and then writes its contents to a network endpoint.

---

## Healthcare / HIPAA-Aware

A strict configuration for healthcare applications handling protected health information (PHI). The priority is preventing any PHI from leaking through the LLM output, maintaining a complete audit trail for compliance, and logging every interaction for potential regulatory review.

::: warning
Aegis is a security library, not a HIPAA compliance product. Using this configuration helps meet security requirements, but HIPAA compliance involves organizational policies, physical security, employee training, and business associate agreements that are outside the scope of a software library. Consult your compliance team.
:::

```ts
import { Aegis } from "@aegis-sdk/core";

const aegis = new Aegis({
  policy: {
    version: 1,
    capabilities: {
      allow: ["search_medical_kb", "lookup_patient_record", "check_appointment", "get_guidelines"],
      deny: ["delete_*", "admin_*", "modify_*", "export_*", "send_*", "execute_*"],
      requireApproval: ["update_patient_record", "schedule_appointment", "prescribe_medication"],
    },
    limits: {
      lookup_patient_record: { max: 10, window: "1h" },
      search_medical_kb: { max: 50, window: "1h" },
      update_patient_record: { max: 5, window: "1h" },
      schedule_appointment: { max: 10, window: "1h" },
      prescribe_medication: { max: 3, window: "1h" },
    },
    input: {
      maxLength: 4000,
      blockPatterns: [],
      requireQuarantine: true,
      encodingNormalization: true,
    },
    output: {
      maxLength: 8000,
      blockPatterns: [],
      redactPatterns: [
        "\\b\\d{3}-\\d{2}-\\d{4}\\b",                    // SSN
        "\\b[A-Z]{3}\\d{9}\\b",                           // MRN (medical record number) format
        "\\b\\d{10,11}\\b",                                // NPI (National Provider Identifier)
      ],
      detectPII: true,
      detectCanary: true,
      blockOnLeak: true,
      detectInjectionPayloads: true,
      sanitizeMarkdown: true,
    },
    alignment: { enabled: true, strictness: "high" },
    dataFlow: {
      piiHandling: "block",          // PHI must never appear in output
      externalDataSources: [],
      noExfiltration: true,
    },
  },

  scanner: {
    sensitivity: "balanced",
    encodingNormalization: true,
    entropyAnalysis: true,
    languageDetection: true,
    manyShotDetection: true,
    perplexityEstimation: true,
    perplexityThreshold: 4.5,
  },

  monitor: {
    detectPII: true,
    piiRedaction: true,
    detectSecrets: true,
    detectInjectionPayloads: true,
  },

  integrity: {
    secret: process.env.AEGIS_HMAC_SECRET!,
    algorithm: "SHA-256",
  },

  canaryTokens: [process.env.AEGIS_CANARY_TOKEN!],

  recovery: { mode: "continue" }, // Throw immediately -- do not attempt recovery with PHI at stake

  autoRetry: {
    enabled: false, // Do not retry with PHI -- better to block and let a human review
  },

  audit: {
    transports: ["json-file", "otel"],
    path: "/var/log/aegis/hipaa-audit.jsonl",
    level: "all",                  // HIPAA requires comprehensive access logs
    redactContent: true,           // Do not store PHI in audit logs
    alerting: {
      enabled: true,
      rules: [
        {
          id: "phi-leak-attempt",
          condition: { type: "rate-spike", event: "stream_violation", threshold: 3, windowMs: 60_000 },
          action: "webhook",
          webhookUrl: process.env.SECURITY_WEBHOOK_URL!,
          cooldownMs: 60_000,
        },
        {
          id: "injection-burst",
          condition: { type: "rate-spike", event: "scan_block", threshold: 5, windowMs: 60_000 },
          action: "webhook",
          webhookUrl: process.env.SECURITY_WEBHOOK_URL!,
          cooldownMs: 300_000,
        },
        {
          id: "session-compromise",
          condition: { type: "session-kills", threshold: 2, windowMs: 300_000 },
          action: "callback",
          callback: async (alert) => {
            await notifyComplianceTeam(alert);
            await terminateSession(alert.context.sessionId as string);
          },
        },
      ],
    },
  },

  validator: {
    scanMcpParams: true,
    denialOfWallet: {
      maxOperations: 50,
      window: "5m",
      maxSandboxTriggers: 5,
      maxToolCalls: 25,
    },
  },
});
```

**Why these choices:**

- `piiHandling: "block"` -- PHI leakage is a HIPAA violation. Blocking is the only acceptable mode for healthcare applications. If the model generates content containing patient identifiers, the stream is terminated.
- `audit.level: "all"` with `redactContent: true` -- HIPAA requires access logging for all interactions with PHI. Logging everything provides the audit trail, while redacting content ensures the audit log itself does not become a PHI exposure vector.
- `autoRetry.enabled: false` -- Retrying a blocked input with escalated security risks processing PHI through a less-secure path. Better to block and let a human review the situation.
- `audit.transports: ["json-file", "otel"]` -- Dual transport ensures audit logs are persisted locally (for compliance archival) and forwarded to the observability platform (for real-time monitoring). The local JSONL file serves as a compliance record.
- Lower rate limits -- Healthcare interactions should be deliberate. Tight limits on patient record lookups and prescriptions prevent automated abuse.

---

## Choosing Between Presets and Custom Policies

For many applications, a built-in preset is sufficient:

```ts
// Simple: use a preset
const aegis = new Aegis({ policy: "strict" });
```

Use a custom policy when you need:

- **Specific tool allowlists** -- presets either allow all or deny all tools
- **Custom rate limits** -- presets do not include rate limits (except `customer-support` and `code-assistant`)
- **Domain-specific output patterns** -- custom `redactPatterns` for your data formats
- **Compliance requirements** -- explicit PII blocking, audit levels, and content redaction

You can also start from a preset and override specific fields:

```ts
import { getPreset } from "@aegis-sdk/core";

const policy = getPreset("strict");

// Add your specific tool allowlist
policy.capabilities.allow = ["search_kb", "lookup_record"];
policy.capabilities.deny = ["delete_*", "admin_*"];
policy.capabilities.requireApproval = ["update_record"];

// Add rate limits
policy.limits = {
  search_kb: { max: 50, window: "1h" },
  update_record: { max: 10, window: "1h" },
};

const aegis = new Aegis({ policy });
```

For more on policy mechanics (evaluation order, glob patterns, PII handling modes), see [Policy Engine](/guide/policy-engine).

For production deployment guidance (OTel setup, alerting, performance tuning, security checklist), see [Production Deployment](/guide/production).

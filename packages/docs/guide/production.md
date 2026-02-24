---
title: Production Deployment
description: Security checklist, monitoring, alerting, performance tuning, and operational guidance for deploying Aegis SDK in production.
---

# Production Deployment Guide

This guide covers what you need to configure, monitor, and harden before deploying Aegis to production.

## Security Checklist

Before going live, verify each of these items:

1. **Policy selection** — Use `strict` or `paranoid` for public-facing applications. `balanced` is acceptable for authenticated internal tools.
2. **HMAC integrity enabled** — Set `integrity.secret` from an environment variable to detect conversation history manipulation.
3. **Canary tokens deployed** — Embed unique canary tokens in your system prompts and configure the stream monitor to detect leaks.
4. **Audit logging active** — Enable at least `violations-only` level with a persistent transport (file or OpenTelemetry).
5. **Recovery mode chosen** — Pick a recovery mode that matches your UX. `continue` (throw) is safest; `reset-last` is more forgiving.
6. **PII handling configured** — Set `dataFlow.piiHandling` to `block` or `redact` based on compliance requirements.
7. **Action validator configured** — If the LLM can call tools, define `capabilities.allow` and `capabilities.deny` lists.
8. **Rate limiting active** — Set `limits` in your policy for expensive or destructive tools.
9. **Secrets rotated** — The HMAC secret and any API keys for the LLM Judge should be rotated regularly.
10. **Red team tests passing** — Run `npx aegis red-team --policy <your-policy>` and verify your detection rate is acceptable.

---

## Policy Selection by Use Case

Choosing the right policy preset (or building a custom policy) is the most impactful decision for balancing security and usability. Here is a guide for common application types.

| Application Type | Recommended Policy | PII Handling | Key Considerations |
|------------------|-------------------|-------------|-------------------|
| Banking / financial services | `strict` or custom | `block` | Block all PII in output, deny all tools except explicitly approved ones, enable injection payload detection, audit everything |
| Customer support chatbot | `customer-support` | `redact` | Allowlist safe tools (KB search, ticket creation), require approval for refunds, rate limit ticket creation |
| Creative writing / content generation | `permissive` or `balanced` | `allow` | Users intentionally write long, unusual text -- raise scanner thresholds to reduce false positives, use permissive sensitivity |
| Code assistant | `code-assistant` | `allow` | Code contains patterns that look like injections (SQL, shell commands) -- disable injection payload detection in output, raise perplexity threshold |
| Healthcare / HIPAA-aware | `strict` or custom | `block` | Block all PII, enable full audit logging with file transport for compliance records, enable content redaction in audit entries |
| Internal tool / admin dashboard | `balanced` | `redact` | Users are authenticated employees -- `balanced` is sufficient, but still enable exfiltration prevention and tool rate limits |

For complete, copy-paste-ready policy configurations for each of these use cases, see [Policy Examples](/guide/policy-examples).

---

## Environment-Specific Configuration

Use environment variables to vary configuration across environments without changing code.

```ts
import { Aegis } from "@aegis-sdk/core";
import type { AegisConfig } from "@aegis-sdk/core";

function createAegisConfig(): AegisConfig {
  const env = process.env.NODE_ENV ?? "development";

  const base: AegisConfig = {
    policy: "balanced",
    scanner: {
      sensitivity: "balanced",
      encodingNormalization: true,
      entropyAnalysis: true,
    },
  };

  if (env === "production") {
    return {
      ...base,
      policy: "strict",
      scanner: {
        ...base.scanner,
        sensitivity: "balanced", // "paranoid" if you can tolerate more false positives
        perplexityEstimation: true,
      },
      integrity: {
        secret: process.env.AEGIS_HMAC_SECRET!,
      },
      canaryTokens: [process.env.AEGIS_CANARY_TOKEN!],
      audit: {
        transports: ["otel"],
        level: "violations-only",
        redactContent: true, // Do not log raw user content in production
      },
      recovery: { mode: "continue" },
    };
  }

  if (env === "staging") {
    return {
      ...base,
      policy: "strict",
      audit: {
        transports: ["console", "json-file"],
        path: "./aegis-staging-audit.jsonl",
        level: "all", // Log everything in staging for debugging
      },
      recovery: { mode: "continue" },
    };
  }

  // Development
  return {
    ...base,
    audit: {
      transport: "console",
      level: "all",
    },
    recovery: { mode: "continue" },
  };
}

const aegis = new Aegis(createAegisConfig());
```

---

## Secrets Management

### HMAC Secret

The HMAC secret is used by the `MessageSigner` to detect conversation history manipulation. It must be:

- At least 32 characters long
- Generated with a cryptographically secure random number generator
- Stored in your secrets manager (AWS Secrets Manager, Vault, Doppler, etc.)
- Never committed to source control

```bash
# Generate a secure HMAC secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

```ts
const aegis = new Aegis({
  integrity: {
    secret: process.env.AEGIS_HMAC_SECRET!,
    algorithm: "SHA-256",
  },
});
```

### LLM Judge API Keys

If you are using the LLM Judge, the API key for the judge model is managed through your LLM provider's client — not through Aegis directly. Make sure the provider client reads the key from environment variables:

```ts
import OpenAI from "openai";

// The OpenAI client reads OPENAI_API_KEY from env automatically
const judgeClient = new OpenAI();

const aegis = new Aegis({
  judge: {
    triggerThreshold: 0.7,
    timeout: 3000,
    llmCall: async (prompt) => {
      const res = await judgeClient.chat.completions.create({
        model: "gpt-4o-mini", // Use a fast, cheap model for judging
        messages: [{ role: "user", content: prompt }],
        temperature: 0,
      });
      return res.choices[0].message.content ?? "";
    },
  },
});
```

---

## Monitoring Setup (OpenTelemetry)

Aegis integrates with OpenTelemetry for production observability. Every security event (scans, blocks, violations, tool validations) emits spans, metrics, and log entries.

### Step 1: Install the OTel SDK

```bash
pnpm add @opentelemetry/sdk-node @opentelemetry/auto-instrumentations-node \
  @opentelemetry/exporter-trace-otlp-http @opentelemetry/exporter-metrics-otlp-http
```

### Step 2: Initialize OTel before Aegis

```ts
// tracing.ts — import this FIRST in your entry point
import { NodeSDK } from "@opentelemetry/sdk-node";
import { getNodeAutoInstrumentations } from "@opentelemetry/auto-instrumentations-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-http";
import { PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";

const sdk = new NodeSDK({
  serviceName: "my-ai-app",
  traceExporter: new OTLPTraceExporter({
    url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? "http://localhost:4318/v1/traces",
  }),
  metricReader: new PeriodicExportingMetricReader({
    exporter: new OTLPMetricExporter({
      url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? "http://localhost:4318/v1/metrics",
    }),
    exportIntervalMillis: 15_000,
  }),
  instrumentations: [getNodeAutoInstrumentations()],
});

sdk.start();
```

### Step 3: Wire Aegis to OTel

```ts
import { Aegis, OTelTransport } from "@aegis-sdk/core";
import { trace, metrics } from "@opentelemetry/api";

const aegis = new Aegis({
  audit: {
    transports: ["otel"],
    level: "violations-only",
    redactContent: true,
  },
});

const otelTransport = new OTelTransport({
  tracer: trace.getTracer("aegis-sdk"),
  meter: metrics.getMeter("aegis-sdk"),
});

aegis.getAuditLog().setOTelTransport(otelTransport);
```

### What gets exported

| OTel Signal | Aegis Events |
|-------------|-------------|
| **Spans** | `scan_pass`, `scan_block`, `stream_violation`, `action_block`, `judge_evaluation` |
| **Metrics** | `aegis.scans.total`, `aegis.scans.blocked`, `aegis.violations.total`, `aegis.judge.latency_ms` |
| **Logs** | All audit entries at the configured level |

---

## Alerting Setup

The `AlertingEngine` monitors audit events in real time and triggers alerts when conditions are met.

### Webhook Alerts

```ts
const aegis = new Aegis({
  audit: {
    transport: "console",
    level: "all",
    alerting: {
      enabled: true,
      rules: [
        {
          id: "block-rate-spike",
          condition: {
            type: "rate-spike",
            event: "scan_block",
            threshold: 10,     // More than 10 blocks...
            windowMs: 60_000,  // ...within 1 minute
          },
          action: "webhook",
          webhookUrl: "https://hooks.slack.com/services/T.../B.../xxx",
          cooldownMs: 300_000, // Don't re-fire for 5 minutes
        },
        {
          id: "session-kills",
          condition: {
            type: "session-kills",
            threshold: 3,
            windowMs: 300_000, // 3 session kills in 5 minutes
          },
          action: "webhook",
          webhookUrl: "https://hooks.slack.com/services/T.../B.../xxx",
        },
      ],
    },
  },
});
```

### Callback Alerts

For custom alert handling (PagerDuty, Datadog Events, email, etc.):

```ts
const aegis = new Aegis({
  audit: {
    transport: "console",
    level: "all",
    alerting: {
      enabled: true,
      rules: [
        {
          id: "cost-anomaly",
          condition: {
            type: "cost-anomaly",
            threshold: 100,     // More than 100 sandbox triggers...
            windowMs: 3600_000, // ...within 1 hour
          },
          action: "callback",
          callback: async (alert) => {
            await pagerduty.createIncident({
              title: `Aegis Alert: ${alert.ruleId}`,
              body: JSON.stringify(alert.context),
              severity: "warning",
            });
          },
        },
        {
          id: "repeated-attacker",
          condition: {
            type: "repeated-attacker",
            threshold: 5,
            windowMs: 600_000, // Same session blocked 5 times in 10 minutes
          },
          action: "callback",
          callback: async (alert) => {
            // Automatically ban the session or IP
            await banSession(alert.context.sessionId as string);
          },
        },
      ],
    },
  },
});
```

### Available Alert Conditions

| Condition | Description |
|-----------|-------------|
| `rate-spike` | A specific audit event exceeds a count threshold within a time window |
| `session-kills` | Session quarantines or terminations exceed a threshold |
| `cost-anomaly` | Expensive operations (sandbox, judge) exceed a threshold |
| `scan-block-rate` | Block rate exceeds a threshold (proportion of blocked vs total scans) |
| `repeated-attacker` | A single session triggers blocks repeatedly |

---

## Performance Tuning

Not every feature needs to be enabled in every environment. Here is a guide for balancing security and performance at different load levels.

### Low traffic (< 100 req/s)

Enable everything. The overhead is negligible.

```ts
const aegis = new Aegis({
  policy: "strict",
  scanner: {
    sensitivity: "balanced",
    encodingNormalization: true,
    entropyAnalysis: true,
    languageDetection: true,
    manyShotDetection: true,
    perplexityEstimation: true,
  },
  judge: {
    triggerThreshold: 0.5,
    timeout: 5000,
    llmCall: judgeLlmCall,
  },
});
```

### Medium traffic (100-1000 req/s)

Disable the most expensive optional features. Keep the core pipeline.

```ts
const aegis = new Aegis({
  policy: "balanced",
  scanner: {
    sensitivity: "balanced",
    encodingNormalization: true,
    entropyAnalysis: true,
    languageDetection: false,    // Skip if monolingual app
    manyShotDetection: true,
    perplexityEstimation: false, // O(n) but with higher constant factor
  },
  judge: {
    triggerThreshold: 0.8, // Only judge highly suspicious inputs
    timeout: 3000,
    llmCall: judgeLlmCall,
  },
  audit: {
    transports: ["otel"],
    level: "violations-only", // Don't log every passing scan
    redactContent: true,
  },
});
```

### High traffic (> 1000 req/s)

Minimize per-request overhead. Use the LLM Judge only for the riskiest inputs, or disable it entirely.

```ts
const aegis = new Aegis({
  policy: "balanced",
  scanner: {
    sensitivity: "balanced",
    encodingNormalization: false, // Skip for known-clean inputs
    entropyAnalysis: true,
    languageDetection: false,
    manyShotDetection: false,
    perplexityEstimation: false,
  },
  // No judge at high traffic — too expensive per-call
  audit: {
    transports: ["otel"],
    level: "violations-only",
    redactContent: true,
  },
});
```

---

## Rate Limiting

Rate limits are configured in the policy's `limits` field. They apply to tool calls validated by the `ActionValidator`.

```ts
const aegis = new Aegis({
  policy: {
    version: 1,
    capabilities: {
      allow: ["search", "read_file", "send_email"],
      deny: ["delete_*", "admin_*"],
      requireApproval: ["send_email"],
    },
    limits: {
      search: { max: 50, window: "1h" },
      read_file: { max: 100, window: "1h" },
      send_email: { max: 5, window: "1h" },
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
    alignment: { enabled: true, strictness: "high" },
    dataFlow: {
      piiHandling: "redact",
      externalDataSources: [],
      noExfiltration: true,
    },
  },
});
```

### Denial-of-Wallet Protection

Configure the `ActionValidator` to detect and prevent cost-based abuse:

```ts
const aegis = new Aegis({
  validator: {
    denialOfWallet: {
      maxOperations: 100,     // Max total operations per window
      window: "5m",           // 5-minute sliding window
      maxSandboxTriggers: 10, // Max sandbox invocations
      maxToolCalls: 50,       // Max tool calls
    },
  },
});
```

---

## Audit Log Rotation

When using the `json-file` transport in production, configure log rotation to prevent unbounded disk growth.

### Using FileTransport with rotation

```ts
import { Aegis, FileTransport } from "@aegis-sdk/core";

const aegis = new Aegis({
  audit: {
    transports: ["json-file"],
    path: "./logs/aegis-audit.jsonl",
    level: "violations-only",
  },
});

const fileTransport = new FileTransport({
  path: "./logs/aegis-audit.jsonl",
  // FileTransport writes JSONL — use external rotation tools
});

aegis.getAuditLog().setFileTransport(fileTransport);
```

### External rotation with logrotate

For Linux/macOS production deployments, use `logrotate`:

```
# /etc/logrotate.d/aegis
/var/log/aegis/aegis-audit.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 app app
    postrotate
        # Signal your app to reopen the log file if needed
        kill -USR1 $(cat /var/run/myapp.pid)
    endscript
}
```

For production, prefer the OTel transport (which delegates storage to your observability platform) over raw file logging.

---

## High-Availability Patterns

### Stateless Aegis instances

Each `Aegis` instance is stateless by default (except for session quarantine state). You can create a new instance per request if needed:

```ts
// Per-request Aegis — no shared state, no session quarantine issues
export async function handleRequest(req: Request) {
  const aegis = new Aegis(productionConfig);
  const { messages } = await req.json();
  const safeMessages = await aegis.guardInput(messages);
  // ...
}
```

### Shared instance with session isolation

For session-based quarantine, maintain one Aegis instance per user session (not globally):

```ts
const sessionInstances = new Map<string, Aegis>();

function getAegisForSession(sessionId: string): Aegis {
  if (!sessionInstances.has(sessionId)) {
    sessionInstances.set(sessionId, new Aegis(productionConfig));
  }
  return sessionInstances.get(sessionId)!;
}

// Clean up expired sessions
setInterval(() => {
  for (const [id, instance] of sessionInstances) {
    if (instance.isSessionQuarantined()) {
      sessionInstances.delete(id);
    }
  }
}, 60_000);
```

### Audit log aggregation

When running multiple instances (horizontal scaling), route audit events to a centralized destination via OpenTelemetry or a custom transport:

```ts
const aegis = new Aegis({
  audit: {
    transports: ["otel", "custom"],
    level: "violations-only",
  },
});

// Custom transport sends events to a central log aggregator
aegis.getAuditLog().addTransport(async (entry) => {
  await fetch("https://logs.internal.example.com/aegis", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ...entry,
      instanceId: process.env.INSTANCE_ID,
      region: process.env.AWS_REGION,
    }),
  });
});
```

---

## Complete Production Configuration

A full production config pulling everything together:

```ts
import { Aegis, OTelTransport } from "@aegis-sdk/core";
import { trace, metrics } from "@opentelemetry/api";
import OpenAI from "openai";

const judgeClient = new OpenAI();

const aegis = new Aegis({
  policy: "strict",

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
    onViolation: (violation) => {
      console.error(`[aegis] Stream violation: ${violation.type}`);
    },
  },

  canaryTokens: [process.env.AEGIS_CANARY_TOKEN!],

  integrity: {
    secret: process.env.AEGIS_HMAC_SECRET!,
    algorithm: "SHA-256",
  },

  recovery: { mode: "continue" },

  autoRetry: {
    enabled: true,
    maxAttempts: 2,
    escalationPath: "stricter_scanner",
  },

  judge: {
    triggerThreshold: 0.7,
    timeout: 3000,
    llmCall: async (prompt) => {
      const res = await judgeClient.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
        temperature: 0,
      });
      return res.choices[0].message.content ?? "";
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

  agentLoop: {
    defaultMaxSteps: 25,
    defaultRiskBudget: 3.0,
    privilegeDecay: { 10: 0.75, 15: 0.5, 20: 0.25 },
  },

  audit: {
    transports: ["otel"],
    level: "violations-only",
    redactContent: true,
    alerting: {
      enabled: true,
      rules: [
        {
          id: "block-rate-spike",
          condition: { type: "rate-spike", event: "scan_block", threshold: 20, windowMs: 60_000 },
          action: "webhook",
          webhookUrl: process.env.SLACK_WEBHOOK_URL!,
          cooldownMs: 300_000,
        },
        {
          id: "session-kill-spike",
          condition: { type: "session-kills", threshold: 5, windowMs: 300_000 },
          action: "webhook",
          webhookUrl: process.env.SLACK_WEBHOOK_URL!,
          cooldownMs: 600_000,
        },
      ],
    },
  },
});

// Wire up OTel transport
const otel = new OTelTransport({
  tracer: trace.getTracer("aegis-sdk"),
  meter: metrics.getMeter("aegis-sdk"),
});
aegis.getAuditLog().setOTelTransport(otel);
```

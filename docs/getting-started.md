# Getting Started with Aegis

## What is Aegis?

Aegis is a streaming-first prompt injection defense library for JavaScript and TypeScript. It provides defense-in-depth against prompt injection attacks --- scanning input before it reaches the LLM, monitoring output streams in real time, and validating tool calls before they execute. Aegis is designed to add security without sacrificing streaming latency.

## Installation

```bash
# pnpm (recommended)
pnpm add @aegis-sdk/core

# npm
npm install @aegis-sdk/core

# yarn
yarn add @aegis-sdk/core
```

## Quick Start (5 minutes)

The fastest way to add prompt injection defense is to create an `Aegis` instance and call `guardInput()` on your messages before sending them to the LLM.

```ts
import { Aegis, AegisInputBlocked } from "@aegis-sdk/core";

const aegis = new Aegis({ policy: "balanced" });

const messages = [
  { role: "system", content: "You are a helpful assistant." },
  { role: "user", content: userInput },
];

try {
  // Scan messages for injection attempts
  const safeMessages = await aegis.guardInput(messages);

  // Pass safe messages to your LLM
  const response = await llm.chat(safeMessages);
} catch (error) {
  if (error instanceof AegisInputBlocked) {
    console.warn("Blocked:", error.scanResult.detections);
    // Respond with a safe fallback
  }
}
```

`guardInput()` quarantines user messages, runs them through the input scanner, and either returns the messages unchanged (if they pass) or throws `AegisInputBlocked` with detailed detection information.

### Singleton API

If you prefer a simpler setup without managing instances, use the `aegis` singleton:

```ts
import { aegis } from "@aegis-sdk/core";

// Configure once at startup
aegis.configure({ policy: "strict" });

// Use anywhere
const instance = aegis.getInstance();
const safeMessages = await instance.guardInput(messages);
```

## Framework Integration

Aegis provides framework-specific adapters that automatically scan request bodies, add security headers, and integrate with each framework's middleware or plugin system.

### Vercel AI SDK

The Vercel adapter is the primary integration path. It works with `streamText()` and `generateText()`.

```bash
pnpm add @aegis-sdk/core @aegis-sdk/vercel
```

```ts
import { Aegis } from "@aegis-sdk/core";
import { withAegis } from "@aegis-sdk/vercel";
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";

const aegis = new Aegis({ policy: "balanced" });

// streamText with input scanning and output monitoring
const result = await streamText({
  model: openai("gpt-4o"),
  messages: await aegis.guardInput(messages),
  experimental_transform: aegis.createStreamTransform(),
});
```

### Next.js

```bash
pnpm add @aegis-sdk/core @aegis-sdk/next
```

```ts
// app/api/chat/route.ts
import { Aegis, AegisInputBlocked } from "@aegis-sdk/core";
import { aegisMiddleware } from "@aegis-sdk/next";
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";

const aegis = new Aegis({ policy: "balanced" });

export const POST = aegisMiddleware(aegis, async (req) => {
  const { messages } = await req.json();

  const safeMessages = await aegis.guardInput(messages);

  const result = streamText({
    model: openai("gpt-4o"),
    messages: safeMessages,
    experimental_transform: aegis.createStreamTransform(),
  });

  return result.toDataStreamResponse();
});
```

### Express

```bash
pnpm add @aegis-sdk/core @aegis-sdk/express
```

```ts
import express from "express";
import { Aegis } from "@aegis-sdk/core";
import { aegisMiddleware } from "@aegis-sdk/express";

const app = express();
const aegis = new Aegis({ policy: "strict" });

// Apply Aegis middleware to all /api/chat routes
app.use("/api/chat", aegisMiddleware(aegis));

app.post("/api/chat", async (req, res) => {
  // req.body.messages has already been scanned by the middleware
  const response = await llm.chat(req.body.messages);
  res.json(response);
});
```

### SvelteKit

```bash
pnpm add @aegis-sdk/core @aegis-sdk/sveltekit
```

```ts
// src/hooks.server.ts
import { Aegis } from "@aegis-sdk/core";
import { aegisHandle } from "@aegis-sdk/sveltekit";

const aegis = new Aegis({ policy: "balanced" });

export const handle = aegisHandle(aegis);
```

```ts
// src/routes/api/chat/+server.ts
import { json } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";

export const POST: RequestHandler = async ({ request, locals }) => {
  const { messages } = await request.json();
  // locals.aegis is injected by the handle hook
  const safeMessages = await locals.aegis.guardInput(messages);
  const response = await llm.chat(safeMessages);
  return json(response);
};
```

### Hono

```bash
pnpm add @aegis-sdk/core @aegis-sdk/hono
```

```ts
import { Hono } from "hono";
import { Aegis } from "@aegis-sdk/core";
import { aegisMiddleware } from "@aegis-sdk/hono";

const app = new Hono();
const aegis = new Aegis({ policy: "balanced" });

app.use("/api/chat/*", aegisMiddleware(aegis));

app.post("/api/chat", async (c) => {
  const { messages } = await c.req.json();
  const response = await llm.chat(messages);
  return c.json(response);
});
```

### Fastify

```bash
pnpm add @aegis-sdk/core @aegis-sdk/fastify
```

```ts
import Fastify from "fastify";
import { Aegis } from "@aegis-sdk/core";
import { aegisPlugin } from "@aegis-sdk/fastify";

const fastify = Fastify();
const aegis = new Aegis({ policy: "balanced" });

fastify.register(aegisPlugin, { aegis, routes: ["/api/chat"] });

fastify.post("/api/chat", async (request, reply) => {
  const { messages } = request.body;
  const response = await llm.chat(messages);
  return response;
});
```

## Provider Adapters

Provider adapters wrap the native LLM client with a `Proxy` that automatically scans input and monitors output. This gives you defense without changing your existing LLM call patterns.

### OpenAI

```bash
pnpm add @aegis-sdk/core @aegis-sdk/openai
```

```ts
import { Aegis } from "@aegis-sdk/core";
import { wrapOpenAIClient } from "@aegis-sdk/openai";
import OpenAI from "openai";

const aegis = new Aegis({ policy: "balanced" });
const openai = wrapOpenAIClient(new OpenAI(), aegis);

// Use the wrapped client exactly like the original
const response = await openai.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: userInput }],
});
```

### Anthropic

```bash
pnpm add @aegis-sdk/core @aegis-sdk/anthropic
```

```ts
import { Aegis } from "@aegis-sdk/core";
import { wrapAnthropicClient } from "@aegis-sdk/anthropic";
import Anthropic from "@anthropic-ai/sdk";

const aegis = new Aegis({ policy: "balanced" });
const anthropic = wrapAnthropicClient(new Anthropic(), aegis);

const response = await anthropic.messages.create({
  model: "claude-sonnet-4-20250514",
  max_tokens: 1024,
  messages: [{ role: "user", content: userInput }],
});
```

### Google Gemini

```bash
pnpm add @aegis-sdk/core @aegis-sdk/google
```

```ts
import { Aegis } from "@aegis-sdk/core";
import { wrapGoogleClient } from "@aegis-sdk/google";
import { GoogleGenerativeAI } from "@google/generative-ai";

const aegis = new Aegis({ policy: "balanced" });
const google = wrapGoogleClient(new GoogleGenerativeAI(apiKey), aegis);

const model = google.getGenerativeModel({ model: "gemini-pro" });
const result = await model.generateContent(userInput);
```

### Mistral

```bash
pnpm add @aegis-sdk/core @aegis-sdk/mistral
```

```ts
import { Aegis } from "@aegis-sdk/core";
import { wrapMistralClient } from "@aegis-sdk/mistral";
import { Mistral } from "@mistralai/mistralai";

const aegis = new Aegis({ policy: "balanced" });
const mistral = wrapMistralClient(new Mistral({ apiKey }), aegis);

const response = await mistral.chat.complete({
  model: "mistral-large-latest",
  messages: [{ role: "user", content: userInput }],
});
```

### Ollama

```bash
pnpm add @aegis-sdk/core @aegis-sdk/ollama
```

```ts
import { Aegis } from "@aegis-sdk/core";
import { wrapOllamaClient } from "@aegis-sdk/ollama";
import { Ollama } from "ollama";

const aegis = new Aegis({ policy: "balanced" });
const ollama = wrapOllamaClient(new Ollama(), aegis);

const response = await ollama.chat({
  model: "llama3",
  messages: [{ role: "user", content: userInput }],
});
```

### LangChain.js

```bash
pnpm add @aegis-sdk/core @aegis-sdk/langchain
```

```ts
import { Aegis } from "@aegis-sdk/core";
import { AegisCallbackHandler } from "@aegis-sdk/langchain";
import { ChatOpenAI } from "@langchain/openai";

const aegis = new Aegis({ policy: "balanced" });

const model = new ChatOpenAI({
  modelName: "gpt-4o",
  callbacks: [new AegisCallbackHandler(aegis)],
});

const response = await model.invoke(userInput);
```

## Configuration

### Policy Presets

Aegis ships with six built-in policy presets. Pass a preset name as a string, or provide a full `AegisPolicy` object for custom configuration.

| Preset | Description | Use Case |
|--------|-------------|----------|
| `balanced` | Moderate protection, allows all tools, PII redaction | General-purpose chatbots |
| `strict` | Tight limits, denies all tools by default, PII blocking | Financial services, healthcare |
| `permissive` | Relaxed scanning, larger input/output limits | Internal tools, development |
| `customer-support` | Scoped tool allowlist, refund approval gates | Support chatbots |
| `code-assistant` | Code-oriented limits, shell/network denied | AI coding tools |
| `paranoid` | Maximum restrictions, smallest limits | High-security environments |

### Full Configuration

```ts
import { Aegis } from "@aegis-sdk/core";
import type { AegisConfig } from "@aegis-sdk/core";

const config: AegisConfig = {
  // Policy: preset name or full AegisPolicy object
  policy: "balanced",

  // Scanner configuration
  scanner: {
    sensitivity: "balanced",       // "paranoid" | "balanced" | "permissive"
    customPatterns: [/my-custom-regex/i],
    encodingNormalization: true,
    entropyAnalysis: true,
    languageDetection: true,
    manyShotDetection: true,
  },

  // Stream monitor configuration
  monitor: {
    canaryTokens: ["SECRET_CANARY_TOKEN_12345"],
    detectPII: true,
    detectSecrets: true,
    detectInjectionPayloads: false,
    sanitizeMarkdown: false,
    onViolation: (violation) => {
      console.error("Stream violation:", violation.type, violation.matched);
    },
  },

  // Recovery mode when input is blocked
  recovery: {
    mode: "continue",  // "continue" | "reset-last" | "quarantine-session" | "terminate-session"
  },

  // Audit logging
  audit: {
    transports: ["console", "json-file"],
    level: "all",              // "violations-only" | "actions" | "all"
    path: "./aegis-audit.jsonl",
    redactContent: false,
  },

  // Action validator for tool calls
  validator: {
    scanMcpParams: true,
    onApprovalNeeded: async (request) => {
      // Your human-in-the-loop logic
      return confirm(`Allow ${request.proposedAction.tool}?`);
    },
  },

  // Agent loop protection
  agentLoop: {
    defaultMaxSteps: 25,
    defaultRiskBudget: 3.0,
    privilegeDecay: { 10: 0.75, 15: 0.5, 20: 0.25 },
  },

  // Canary tokens for output monitoring
  canaryTokens: ["CANARY_abc123"],

  // HMAC integrity for conversation history
  integrity: {
    secret: process.env.AEGIS_HMAC_SECRET!,
    algorithm: "SHA-256",
  },
};

const aegis = new Aegis(config);
```

## Scanner Sensitivity

The input scanner's `sensitivity` controls how aggressively it flags potential injection attempts. Each level adjusts scoring thresholds and detection heuristics.

| Sensitivity | Threshold | Behavior |
|-------------|-----------|----------|
| `paranoid` | Very low threshold | Catches more attacks but may produce more false positives. Best for high-security applications. |
| `balanced` | Moderate threshold | Good balance between detection and false positive rates. Recommended for most applications. |
| `permissive` | Higher threshold | Only blocks the most obvious attacks. Use when false positives are unacceptable. |

```ts
const aegis = new Aegis({
  scanner: {
    sensitivity: "paranoid",
    encodingNormalization: true,  // Decode Base64, Unicode escapes, etc.
    entropyAnalysis: true,        // Flag high-entropy adversarial suffixes
    manyShotDetection: true,      // Detect many-shot jailbreak patterns
  },
});
```

## Stream Monitoring

`createStreamTransform()` returns a `TransformStream<string, string>` that monitors LLM output tokens in real time. It uses a sliding-window buffer to catch patterns that span across stream chunks. If a violation is detected, the stream can be terminated immediately.

```ts
import { Aegis } from "@aegis-sdk/core";
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";

const aegis = new Aegis({
  canaryTokens: ["CANARY_secret_12345"],
  monitor: {
    detectPII: true,
    detectSecrets: true,
    onViolation: (violation) => {
      console.error(`Output violation: ${violation.type} — "${violation.matched}"`);
    },
  },
});

const safeMessages = await aegis.guardInput(messages);

const result = streamText({
  model: openai("gpt-4o"),
  messages: safeMessages,
  experimental_transform: aegis.createStreamTransform(),
});
```

The monitor checks for:

- **Canary token leaks** --- detects if the model outputs tokens you embedded in the system prompt
- **PII detection** --- catches email addresses, phone numbers, SSNs, and other personal data
- **Secret detection** --- flags API keys, tokens, and credential patterns
- **Injection payloads** --- identifies prompt injection patterns in model output (chain injection)
- **Custom patterns** --- your own regex patterns for domain-specific content

## Recovery Modes

When `guardInput()` detects an injection, the recovery mode determines what happens next.

| Mode | Behavior |
|------|----------|
| `continue` | Throws `AegisInputBlocked` immediately. The caller handles the error. This is the default. |
| `reset-last` | Removes the offending message from the conversation and returns the remaining history. The caller can retry with the cleaned messages. |
| `quarantine-session` | Locks the Aegis instance. All subsequent `guardInput()` calls throw `AegisSessionQuarantined`. A new `Aegis` instance must be created to resume. |
| `terminate-session` | Throws `AegisSessionTerminated`. The session is permanently over. |

```ts
import {
  Aegis,
  AegisInputBlocked,
  AegisSessionQuarantined,
  AegisSessionTerminated,
} from "@aegis-sdk/core";

const aegis = new Aegis({
  recovery: { mode: "quarantine-session" },
});

try {
  const safeMessages = await aegis.guardInput(messages);
} catch (error) {
  if (error instanceof AegisInputBlocked) {
    // Single message was blocked (recovery: "continue" mode)
    console.warn("Input blocked:", error.scanResult);
  } else if (error instanceof AegisSessionQuarantined) {
    // Session is locked — no more input accepted
    console.warn("Session quarantined");
  } else if (error instanceof AegisSessionTerminated) {
    // Session is terminated — must create a new Aegis instance
    console.error("Session terminated:", error.scanResult);
  }
}
```

### Scan Strategies

`guardInput()` accepts a `scanStrategy` option that controls which messages are scanned:

| Strategy | Behavior |
|----------|----------|
| `last-user` | Scan only the most recent user message. (Default) |
| `all-user` | Scan all user messages in the conversation. Also runs trajectory analysis. |
| `full-history` | Scan every message (system, user, assistant). Also runs trajectory analysis. |

```ts
const safeMessages = await aegis.guardInput(messages, {
  scanStrategy: "all-user",
});
```

## Audit Logging

Every security decision flows through the audit log. Aegis supports multiple simultaneous transports.

### Console Logging (default)

```ts
const aegis = new Aegis({
  audit: {
    transport: "console",
    level: "all",
  },
});
```

### File Logging (JSON Lines)

```ts
import { Aegis, FileTransport } from "@aegis-sdk/core";

const aegis = new Aegis({
  audit: {
    transports: ["console", "json-file"],
    path: "./aegis-audit.jsonl",
    level: "all",
  },
});

// Wire up the file transport
const fileTransport = new FileTransport({ path: "./aegis-audit.jsonl" });
aegis.getAuditLog().setFileTransport(fileTransport);
```

### OpenTelemetry

```ts
import { Aegis, OTelTransport } from "@aegis-sdk/core";

const aegis = new Aegis({
  audit: {
    transports: ["console", "otel"],
    level: "all",
  },
});

// Wire up your OTel provider
const otel = new OTelTransport({
  tracer: trace.getTracer("aegis"),
  meter: metrics.getMeter("aegis"),
});
aegis.getAuditLog().setOTelTransport(otel);
```

### Custom Transports

```ts
const aegis = new Aegis({
  audit: {
    transports: ["console", "custom"],
    level: "all",
  },
});

// Add any number of custom transport functions
aegis.getAuditLog().addTransport((entry) => {
  sendToDatadog(entry);
});

aegis.getAuditLog().addTransport(async (entry) => {
  await sendToSplunk(entry);
});
```

### Querying the Audit Log

```ts
const auditLog = aegis.getAuditLog();

// Get all blocked events
const blocked = auditLog.query({ event: "scan_block" });

// Get events from the last hour
const recent = auditLog.query({
  since: new Date(Date.now() - 3600_000),
  limit: 100,
});

// Get events for a specific session
const sessionEvents = auditLog.query({ sessionId: "sess_abc123" });
```

### Audit Levels

| Level | What gets logged |
|-------|------------------|
| `violations-only` | Only `blocked` and `flagged` decisions |
| `actions` | All decisions except `info` |
| `all` | Every event, including informational ones |

## Red Team Testing

Aegis ships with a testing package for validating your defenses against known attack patterns.

```bash
pnpm add -D @aegis-sdk/testing
```

```ts
import { Aegis } from "@aegis-sdk/core";
import { AttackSuite, runRedTeam } from "@aegis-sdk/testing";

const aegis = new Aegis({ policy: "balanced" });

// Run the built-in attack suite against your configuration
const results = await runRedTeam(aegis, {
  suites: [AttackSuite.INSTRUCTION_OVERRIDE, AttackSuite.ROLE_MANIPULATION],
});

for (const result of results) {
  console.log(`${result.attack}: ${result.blocked ? "BLOCKED" : "MISSED"}`);
}
```

### CLI

The Aegis CLI provides a command-line interface for scanning inputs and running red team tests:

```bash
pnpm add -D @aegis-sdk/cli

# Scan a single input
npx aegis scan "Ignore previous instructions and..."

# Run the full red team suite
npx aegis red-team --policy balanced --output results.json
```

## Next Steps

- **API Reference** --- Detailed documentation for every class, method, and type in `docs/api-reference/`
- **MCP Integration** --- Protecting MCP tool calls and agentic loops in `docs/mcp-integration.md`
- **Testing Guide** --- Writing adversarial and benign test cases in `docs/guides/testing.md`
- **Policy Authoring** --- Creating custom policies for your domain in `docs/guides/policies.md`
- **Architecture** --- How the defense pipeline works internally in `docs/guides/architecture.md`

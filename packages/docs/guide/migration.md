---
title: Migration Guides
description: Migrate to Aegis from other prompt injection defense tools
---

# Migration Guides

## Adding Aegis to an Existing Vercel AI SDK App

If you already have a Next.js app using the Vercel AI SDK, adding Aegis takes about 5 minutes.

### Step 1: Install

```bash
npm install @aegis-sdk/core @aegis-sdk/vercel
```

### Step 2: Create an Aegis Instance

```typescript
// lib/aegis.ts
import { Aegis } from '@aegis-sdk/core';

export const aegis = new Aegis({
  policy: 'balanced',
  canaryTokens: ['YOUR_CANARY_TOKEN_HERE'],
});
```

### Step 3: Guard Your Route

```typescript
// app/api/chat/route.ts
import { streamText } from 'ai';
import { openai } from '@ai-sdk/openai';
import { aegis } from '@/lib/aegis';

export async function POST(req: Request) {
  const { messages } = await req.json();

  // Add this line — scans input for injection
  const safeMessages = await aegis.guardInput(messages);

  const result = streamText({
    model: openai('gpt-4o'),
    messages: safeMessages,
    // Add this line — monitors output stream
    experimental_transform: aegis.createStreamTransform(),
  });

  return result.toDataStreamResponse();
}
```

### Step 4: Handle Blocked Input (Optional)

```typescript
import { AegisInputBlocked } from '@aegis-sdk/core';

try {
  const safeMessages = await aegis.guardInput(messages);
  // ...
} catch (err) {
  if (err instanceof AegisInputBlocked) {
    return new Response(
      JSON.stringify({ error: 'blocked', score: err.scanResult.score }),
      { status: 403 },
    );
  }
  throw err;
}
```

That's it. Your existing `useChat` client code requires zero changes.

---

## Coming from LLM Guard (Python)

LLM Guard is a Python library. Aegis is TypeScript-first. Here's how concepts map:

| LLM Guard | Aegis |
|-----------|-------|
| `ScanPrompt(scanners)` | `aegis.guardInput(messages)` |
| `ScanOutput(scanners)` | `aegis.createStreamTransform()` |
| `BanSubstrings` scanner | `canaryTokens` config + `customPatterns` |
| `Anonymize` scanner | `monitor: { detectPII: true, piiRedaction: true }` |
| `TokenLimit` scanner | `input: { maxLength }` in policy |
| `Regex` scanner | `scanner: { customPatterns: [/regex/] }` |
| `Secrets` scanner | `monitor: { detectSecrets: true }` |
| Custom scanner class | `scanner: { customPatterns }` + `monitor: { onViolation }` |
| `PromptInjection` scanner | Built into `InputScanner` (no extra config) |
| Vault for PII | `monitor: { piiRedaction: true }` replaces with `[REDACTED-TYPE]` |

### Key Differences

1. **Streaming**: LLM Guard scans complete text. Aegis scans streams in real-time.
2. **Type Safety**: Aegis provides `Quarantined<T>` for taint tracking at compile time.
3. **Policy Engine**: Aegis uses declarative policies instead of scanner composition.
4. **Action Validation**: Aegis validates tool calls — LLM Guard doesn't cover this.

---

## Coming from NeMo Guardrails

NeMo Guardrails uses Colang (a custom DSL) for defining conversation flows. Aegis uses declarative JSON/YAML policies.

| NeMo Guardrails | Aegis |
|----------------|-------|
| Colang flow definitions | `AegisPolicy` object or `.yaml` file |
| `define user greeting` | Not needed — Aegis doesn't constrain conversation flow |
| `define bot refuse` | `recovery: { mode: 'terminate-session' }` |
| Input rails | `aegis.guardInput()` |
| Output rails | `aegis.createStreamTransform()` |
| Dialog rails | `aegis.guardChainStep()` for agentic loops |
| KnowledgeBase | Not covered — use with your existing RAG pipeline |
| LLM call interception | `wrapOpenAIClient()` / `wrapAnthropicClient()` |

### Key Differences

1. **No DSL**: Aegis doesn't require learning Colang. Configuration is JSON/YAML/TypeScript.
2. **Streaming-first**: NeMo buffers; Aegis streams.
3. **Provider-agnostic**: Aegis works with any LLM provider. NeMo is tied to LangChain.
4. **JS/TS native**: NeMo requires a Python runtime. Aegis runs anywhere Node.js runs.

### Migration Steps

1. Replace Colang input rails with `aegis.guardInput()` calls
2. Replace output rails with `aegis.createStreamTransform()`
3. Convert your NeMo config to an Aegis policy:

```typescript
const aegis = new Aegis({
  policy: {
    version: 1,
    capabilities: {
      allow: ['search', 'lookup'],
      deny: ['delete_*', 'admin_*'],
      requireApproval: ['purchase'],
    },
    limits: { purchase: { max: 1, window: '1h' } },
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
      detectInjectionPayloads: false,
      sanitizeMarkdown: false,
    },
    alignment: { enabled: true, strictness: 'medium' },
    dataFlow: {
      piiHandling: 'redact',
      externalDataSources: [],
      noExfiltration: true,
    },
  },
});
```

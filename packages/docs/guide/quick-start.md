# Quick Start

Get Aegis protecting your AI application in under 5 minutes.

## 1. Install

::: code-group

```sh [pnpm]
pnpm add @aegis-sdk/core
```

```sh [npm]
npm install @aegis-sdk/core
```

```sh [yarn]
yarn add @aegis-sdk/core
```

```sh [bun]
bun add @aegis-sdk/core
```

:::

## 2. Create an Aegis Instance

```ts
import { Aegis } from "@aegis-sdk/core";

const aegis = new Aegis({
  policy: "balanced", // 'strict' | 'balanced' | 'permissive' | 'paranoid'
});
```

## 3. Guard Input

Scan user messages before sending them to the LLM:

```ts
import { Aegis, AegisInputBlocked } from "@aegis-sdk/core";

const aegis = new Aegis({ policy: "balanced" });

const messages = [
  { role: "system" as const, content: "You are a helpful assistant." },
  { role: "user" as const, content: userInput },
];

try {
  const safeMessages = await aegis.guardInput(messages);
  // safeMessages passed validation — send to your LLM
} catch (error) {
  if (error instanceof AegisInputBlocked) {
    console.warn("Input blocked:", error.scanResult.detections);
    // Handle blocked input (show error to user, log, etc.)
  }
}
```

## 4. Monitor Output Streams

Scan LLM output in real-time using a `TransformStream`:

```ts
const transform = aegis.createStreamTransform();

// Pipe your LLM stream through the Aegis transform
const monitoredStream = llmStream.pipeThrough(transform);
```

## 5. With Vercel AI SDK

The most common integration. Install the Vercel adapter:

::: code-group

```sh [pnpm]
pnpm add @aegis-sdk/core @aegis-sdk/vercel
```

```sh [npm]
npm install @aegis-sdk/core @aegis-sdk/vercel
```

:::

Then use it in your API route:

```ts
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { Aegis } from "@aegis-sdk/core";
import { createAegisTransform, guardMessages } from "@aegis-sdk/vercel";

const aegis = new Aegis({ policy: "strict" });

export async function POST(req: Request) {
  const { messages } = await req.json();

  // Step 1: Guard input
  const safeMessages = await guardMessages(aegis, messages);

  // Step 2: Stream with output monitoring
  const result = streamText({
    model: openai("gpt-4o"),
    messages: safeMessages,
    experimental_transform: createAegisTransform(aegis),
  });

  return result.toDataStreamResponse();
}
```

## What Happens When an Attack is Detected?

**On input scan:** Aegis throws an `AegisInputBlocked` error with details about the detected violations. Your application catches this and decides how to respond — typically by returning an error message to the user.

**On output monitoring:** The stream transform terminates the stream immediately via the kill switch. The user sees the response cut off at the point of violation. The audit log records what was detected.

## Next Steps

- [Installation](/guide/installation) — All package managers and framework adapters
- [Configuration](/guide/configuration) — Policy presets, scanner sensitivity, recovery modes
- [Vercel AI SDK Guide](/guide/vercel-ai) — Deep dive into Vercel integration

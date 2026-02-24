# @aegis-sdk/vercel

Vercel AI SDK adapter for Aegis prompt injection defense. Integrates directly with `streamText()` via `experimental_transform` for real-time output monitoring.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/vercel @aegis-sdk/core ai
```

## Quick Start

```typescript
import { streamText } from 'ai';
import { openai } from '@ai-sdk/openai';
import { Aegis } from '@aegis-sdk/core';
import { createAegisTransform, guardMessages } from '@aegis-sdk/vercel';

const aegis = new Aegis({ policy: 'strict' });

export async function POST(req: Request) {
  const { messages } = await req.json();

  // Scan input messages
  const safeMessages = await guardMessages(aegis, messages);

  // Stream with real-time output monitoring
  const result = streamText({
    model: openai('gpt-4o'),
    messages: safeMessages,
    experimental_transform: createAegisTransform(aegis),
  });

  return result.toDataStreamResponse();
}
```

## API

### `createAegisTransform(aegis, options?)`

Create a stream transform compatible with the Vercel AI SDK's `experimental_transform` option on `streamText()`. Returns a function (not a TransformStream directly) that accepts `{ tools, stopStream }` from the SDK.

The transform processes `TextStreamPart` objects:
- `text-delta` parts have their `textDelta` scanned by the Aegis StreamMonitor. On violation, the stream is terminated via `stopStream()`.
- All other part types pass through unchanged.

```typescript
const result = streamText({
  model: openai('gpt-4o'),
  messages: safeMessages,
  experimental_transform: createAegisTransform(aegis),
});
```

### `createAegisMiddleware(aegis)`

Create model middleware for use with `wrapLanguageModel()`. An alternative to `experimental_transform` that wraps the model itself -- all streams through the wrapped model are monitored.

```typescript
import { wrapLanguageModel } from 'ai';
import { createAegisMiddleware } from '@aegis-sdk/vercel';

const protectedModel = wrapLanguageModel({
  model: openai('gpt-4o'),
  middleware: createAegisMiddleware(aegis),
});
```

### `guardMessages(aegis, messages, options?)`

Scan Vercel AI SDK format messages (`{ role: string, content: string }[]`) for prompt injection. Converts to Aegis format and runs `aegis.guardInput()`. Returns the original messages if safe, throws `AegisInputBlocked` if blocked.

Options:
- **`scanStrategy`** -- `'last-user'` (default), `'all-user'`, or `'full-history'`

### `getAuditLog(aegis)`

Convenience accessor for the Aegis audit log.

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

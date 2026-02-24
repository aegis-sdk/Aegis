# @aegis-sdk/hono

Hono middleware for scanning LLM chat messages against prompt injection attacks.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/hono @aegis-sdk/core
```

## Quick Start

```ts
import { Hono } from 'hono';
import { Aegis } from '@aegis-sdk/core';
import { aegisMiddleware } from '@aegis-sdk/hono';

const app = new Hono();
const aegis = new Aegis({ policy: 'strict' });

app.post('/api/chat', aegisMiddleware({ aegis }), async (c) => {
  const { messages, instance } = c.get('aegis');
  // messages are scanned and safe to forward to your LLM
  return c.json({ reply: '...' });
});

export default app;
```

## API

### `aegisMiddleware(options?)`

Creates Hono middleware that reads messages from the request body, runs them through `aegis.guardInput()`, and sets the result on the context via `c.set('aegis', ...)`. Returns 403 with violation details if input is blocked.

Accepts either an `AegisConfig` directly or an `AegisMiddlewareOptions` object:

| Option | Type | Default | Description |
|---|---|---|---|
| `aegis` | `AegisConfig \| Aegis` | `{}` | Aegis configuration or pre-constructed instance |
| `messagesProperty` | `string` | `"messages"` | Property on the request body to read messages from |
| `scanStrategy` | `ScanStrategy` | `"last-user"` | Which messages to scan |
| `onBlocked` | `(c, error) => Response` | -- | Custom error handler. Return a `Response` to take over |

Access scan results in your handler via `c.get('aegis')`, which returns `{ messages, instance, auditLog }`.

### `aegisStreamTransform(configOrInstance?)`

Returns a `TransformStream<string, string>` that monitors LLM output tokens for injection payloads, PII leaks, and canary token leaks.

```ts
app.post('/chat', aegisMiddleware({ aegis }), async (c) => {
  const transform = aegisStreamTransform(aegis);
  const monitoredStream = llmStream.pipeThrough(transform);
  return new Response(monitoredStream, {
    headers: { 'Content-Type': 'text/event-stream' },
  });
});
```

### `guardMessages(aegis, messages, options?)`

Scans messages directly without using the middleware. Throws `AegisInputBlocked` if input is blocked.

### Re-exports

`Aegis`, `AegisInputBlocked`, `AegisSessionQuarantined`, `AegisSessionTerminated`, and all core types are re-exported for convenience.

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

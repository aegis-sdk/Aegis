# @aegis-sdk/express

Express middleware for scanning LLM chat messages against prompt injection attacks.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/express @aegis-sdk/core
```

## Quick Start

```ts
import express from 'express';
import { aegisMiddleware } from '@aegis-sdk/express';

const app = express();
app.use(express.json());

app.post('/api/chat', aegisMiddleware({ policy: 'strict' }), (req, res) => {
  const { messages, instance } = req.aegis; // scanned messages
  // pass messages to your LLM
  res.json({ reply: '...' });
});

app.listen(3000);
```

## API

### `aegisMiddleware(options?)`

Creates Express middleware that reads `req.body.messages`, runs them through `aegis.guardInput()`, and attaches the safe messages to `req.aegis`. Returns 403 with violation details if input is blocked.

Accepts either an `AegisConfig` directly or an `AegisMiddlewareOptions` object:

| Option | Type | Default | Description |
|---|---|---|---|
| `aegis` | `AegisConfig \| Aegis` | `{}` | Aegis configuration or pre-constructed instance |
| `messagesProperty` | `string` | `"messages"` | Property on `req.body` to read messages from |
| `scanStrategy` | `ScanStrategy` | `"last-user"` | Which messages to scan |
| `onBlocked` | `(req, res, error) => boolean` | -- | Custom error handler. Return `true` to take over the response |

### `aegisStreamTransform(configOrInstance?)`

Returns a `TransformStream<string, string>` that monitors LLM output tokens for injection payloads, PII leaks, and canary token leaks.

```ts
const transform = aegisStreamTransform(aegis);
const monitoredStream = llmStream.pipeThrough(transform);
```

### `guardMessages(aegis, messages, options?)`

Scans messages directly without using the middleware. Useful for WebSocket handlers or custom middleware chains. Throws `AegisInputBlocked` if input is blocked.

```ts
import { Aegis } from '@aegis-sdk/core';
import { guardMessages } from '@aegis-sdk/express';

const aegis = new Aegis({ policy: 'strict' });
const safe = await guardMessages(aegis, messages);
```

### Re-exports

`Aegis`, `AegisInputBlocked`, `AegisSessionQuarantined`, `AegisSessionTerminated`, and all core types are re-exported for convenience.

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

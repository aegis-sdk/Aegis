# @aegis-sdk/fastify

Fastify plugin for scanning LLM chat messages against prompt injection attacks.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/fastify @aegis-sdk/core
```

## Quick Start

```ts
import Fastify from 'fastify';
import { aegisPlugin } from '@aegis-sdk/fastify';

const app = Fastify();

app.register(aegisPlugin, {
  aegis: { policy: 'strict' },
  routes: ['/api/chat'],
});

app.post('/api/chat', async (request, reply) => {
  const { messages, instance } = request.aegis; // scanned messages
  // pass messages to your LLM
  return { reply: '...' };
});

app.listen({ port: 3000 });
```

## API

### `aegisPlugin`

Fastify plugin that registers a `preHandler` hook. The hook reads messages from the request body, runs them through `aegis.guardInput()`, and attaches the safe messages to `request.aegis`. Returns 403 with violation details if input is blocked.

Register it with `app.register(aegisPlugin, options)`:

| Option | Type | Default | Description |
|---|---|---|---|
| `aegis` | `AegisConfig \| Aegis` | `{}` | Aegis configuration or pre-constructed instance |
| `routes` | `(string \| RegExp)[]` | -- | Routes to protect. If omitted, all POST requests are scanned |
| `methods` | `string[]` | `["POST"]` | HTTP methods to scan |
| `messagesProperty` | `string` | `"messages"` | Property on the request body to read messages from |
| `scanStrategy` | `ScanStrategy` | `"last-user"` | Which messages to scan |
| `onBlocked` | `(request, reply, error) => unknown` | -- | Custom error handler. Return truthy to take over the response |

Access scan results in your handler via `request.aegis`, which returns `{ messages, instance, auditLog }`.

### `aegisStreamTransform(configOrInstance?)`

Returns a `TransformStream<string, string>` that monitors LLM output tokens for injection payloads, PII leaks, and canary token leaks.

### `guardMessages(aegis, messages, options?)`

Scans messages directly without using the plugin. Throws `AegisInputBlocked` if input is blocked.

### Re-exports

`Aegis`, `AegisInputBlocked`, `AegisSessionQuarantined`, `AegisSessionTerminated`, and all core types are re-exported for convenience.

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

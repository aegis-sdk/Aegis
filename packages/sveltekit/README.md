# @aegis-sdk/sveltekit

SvelteKit handle hook for scanning LLM chat messages against prompt injection attacks.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/sveltekit @aegis-sdk/core
```

## Quick Start

```ts
// src/hooks.server.ts
import { sequence } from '@sveltejs/kit/hooks';
import { aegisHandle } from '@aegis-sdk/sveltekit';

const aegis = aegisHandle({
  aegis: { policy: 'strict' },
  routes: ['/api/chat'],
});

export const handle = sequence(aegis);
```

Then access the scanned messages in your API route:

```ts
// src/routes/api/chat/+server.ts
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ locals }) => {
  const { messages, instance, auditLog } = locals.aegis;
  // messages are scanned and safe to forward to your LLM
  return new Response(JSON.stringify({ reply: '...' }));
};
```

## API

### `aegisHandle(options?)`

Creates a SvelteKit `Handle` function that scans incoming POST request bodies through `aegis.guardInput()` and attaches safe messages to `event.locals.aegis`. Returns 403 with violation details if input is blocked. Non-POST requests and routes not matching the filter are passed through without scanning.

Accepts either an `AegisConfig` directly or an `AegisHandleOptions` object:

| Option | Type | Default | Description |
|---|---|---|---|
| `aegis` | `AegisConfig \| Aegis` | `{}` | Aegis configuration or pre-constructed instance |
| `routes` | `(string \| RegExp)[]` | -- | Routes to protect. If omitted, all POST requests are scanned |
| `messagesProperty` | `string` | `"messages"` | Property on the request body to read messages from |
| `scanStrategy` | `ScanStrategy` | `"last-user"` | Which messages to scan |
| `onBlocked` | `(event, error) => Response` | -- | Custom error handler. Return a `Response` to take over |

### `aegisStreamTransform(configOrInstance?)`

Returns a `TransformStream<string, string>` that monitors LLM output tokens for injection payloads, PII leaks, and canary token leaks.

```ts
// src/routes/api/chat/+server.ts
import { aegisStreamTransform } from '@aegis-sdk/sveltekit';

export const POST: RequestHandler = async ({ locals }) => {
  const transform = aegisStreamTransform(locals.aegis.instance);
  const monitoredStream = llmStream.pipeThrough(transform);
  return new Response(monitoredStream, {
    headers: { 'Content-Type': 'text/event-stream' },
  });
};
```

### `guardMessages(aegis, messages, options?)`

Scans messages directly without using the handle hook. Useful in form actions, WebSocket handlers, or custom server routes. Throws `AegisInputBlocked` if input is blocked.

### Re-exports

`Aegis`, `AegisInputBlocked`, `AegisSessionQuarantined`, `AegisSessionTerminated`, and all core types are re-exported for convenience.

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

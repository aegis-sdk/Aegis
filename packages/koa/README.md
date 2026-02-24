# @aegis-sdk/koa

Koa middleware for scanning LLM chat messages against prompt injection attacks.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/koa @aegis-sdk/core
```

## Quick Start

```ts
import Koa from 'koa';
import bodyParser from 'koa-bodyparser';
import { aegisMiddleware } from '@aegis-sdk/koa';

const app = new Koa();
app.use(bodyParser());
app.use(aegisMiddleware({ policy: 'strict' }));

app.use(async (ctx) => {
  const { messages, instance } = ctx.state.aegis; // scanned messages
  // pass messages to your LLM
  ctx.body = { reply: '...' };
});

app.listen(3000);
```

## API

### `aegisMiddleware(options?)`

Creates Koa middleware that reads `ctx.request.body.messages`, runs them through `aegis.guardInput()`, and attaches the safe messages to `ctx.state.aegis`. Returns 403 with violation details if input is blocked.

Requires a body parsing middleware (e.g., `koa-bodyparser`) to be applied first.

Accepts either an `AegisConfig` directly or an `AegisMiddlewareOptions` object:

| Option | Type | Default | Description |
|---|---|---|---|
| `aegis` | `AegisConfig \| Aegis` | `{}` | Aegis configuration or pre-constructed instance |
| `messagesProperty` | `string` | `"messages"` | Property on `ctx.request.body` to read messages from |
| `scanStrategy` | `ScanStrategy` | `"last-user"` | Which messages to scan |
| `onBlocked` | `(ctx, detections, error) => boolean` | -- | Custom error handler. Return `true` to take over the response |

Access scan results in downstream middleware via `ctx.state.aegis`, which returns `{ messages, instance, auditLog }`.

### `aegisStreamTransform(configOrInstance?)`

Returns a `TransformStream<string, string>` that monitors LLM output tokens for injection payloads, PII leaks, and canary token leaks.

```ts
app.use(async (ctx) => {
  const transform = aegisStreamTransform(ctx.state.aegis.instance);
  const monitoredStream = llmStream.pipeThrough(transform);
  // pipe the monitored stream to the response
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

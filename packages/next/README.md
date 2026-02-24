# @aegis-sdk/next

Next.js integration for scanning LLM chat messages against prompt injection attacks.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/next @aegis-sdk/core
```

## Quick Start

```ts
// app/api/chat/route.ts
import { Aegis } from '@aegis-sdk/core';
import { withAegis } from '@aegis-sdk/next';
import { streamText } from 'ai';
import { openai } from '@ai-sdk/openai';

const aegis = new Aegis({ policy: 'strict' });

export const POST = withAegis(aegis, async (req, safeMessages) => {
  const result = streamText({
    model: openai('gpt-4o'),
    messages: safeMessages,
  });
  return result.toDataStreamResponse();
});
```

## API

### `withAegis(aegisOrConfig, handler, options?)`

Higher-order function that wraps a Next.js App Router route handler. Parses the request body, scans messages through `aegis.guardInput()`, and passes safe messages to your handler. Returns 403 with violation details if input is blocked.

| Option | Type | Default | Description |
|---|---|---|---|
| `messagesProperty` | `string` | `"messages"` | Property on the request body to read messages from |
| `scanStrategy` | `ScanStrategy` | `"last-user"` | Which messages to scan |
| `onBlocked` | `(req, error) => Response` | -- | Custom error handler. Return a `Response` to take over |

Your handler receives `(req, safeMessages, { instance, auditLog })`.

### `aegisMiddleware(options?)`

Creates a Next.js Edge Middleware function for request-level scanning. Designed for use in `middleware.ts` at the project root.

```ts
// middleware.ts
import { aegisMiddleware } from '@aegis-sdk/next';

const aegisMw = aegisMiddleware({
  aegis: { policy: 'strict' },
  matchRoutes: ['/api/chat', '/api/ai'],
});

export async function middleware(req: Request) {
  return aegisMw(req);
}

export const config = {
  matcher: ['/api/chat/:path*', '/api/ai/:path*'],
};
```

| Option | Type | Default | Description |
|---|---|---|---|
| `aegis` | `AegisConfig \| Aegis` | `{}` | Aegis configuration or pre-constructed instance |
| `matchRoutes` | `(string \| RegExp)[]` | -- | Route patterns to scan. If omitted, all POST requests are scanned |
| `messagesProperty` | `string` | `"messages"` | Property on the request body to read messages from |
| `scanStrategy` | `ScanStrategy` | `"last-user"` | Which messages to scan |
| `onBlocked` | `(req, error) => Response` | -- | Custom error handler |

### `guardMessages(aegis, messages, options?)`

Scans messages directly without using `withAegis` or Edge Middleware. Useful in Server Actions, custom API routes, or WebSocket handlers. Throws `AegisInputBlocked` if input is blocked.

### Re-exports

`Aegis`, `AegisInputBlocked`, `AegisSessionQuarantined`, `AegisSessionTerminated`, and all core types are re-exported for convenience.

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

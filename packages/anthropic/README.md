# @aegis-sdk/anthropic

Anthropic Claude SDK adapter for Aegis prompt injection defense. Scans messages, monitors streams, and validates tool_use blocks in Anthropic's content block format.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/anthropic @aegis-sdk/core @anthropic-ai/sdk
```

## Quick Start

Wrap the Anthropic client for automatic protection on every call:

```typescript
import Anthropic from '@anthropic-ai/sdk';
import { Aegis } from '@aegis-sdk/core';
import { wrapAnthropicClient } from '@aegis-sdk/anthropic';

const aegis = new Aegis({ policy: 'strict' });
const client = wrapAnthropicClient(new Anthropic(), aegis);

// Messages are scanned before sending.
// Streaming responses are monitored in real-time.
// tool_use blocks are validated against the policy.
const response = await client.messages.create({
  model: 'claude-sonnet-4-20250514',
  max_tokens: 1024,
  messages: [{ role: 'user', content: 'Hello!' }],
});
```

Or scan messages manually:

```typescript
import { Aegis } from '@aegis-sdk/core';
import { guardMessages } from '@aegis-sdk/anthropic';

const aegis = new Aegis({ policy: 'strict' });

const messages = [
  {
    role: 'user' as const,
    content: [
      { type: 'text' as const, text: userInput },
    ],
  },
];

// Throws AegisInputBlocked if injection is detected
const safe = await guardMessages(aegis, messages);
```

## API

### `wrapAnthropicClient(client, aegis, options?)`

Proxy the Anthropic client to automatically guard all `messages.create()` calls. Input messages are scanned before sending, streaming responses are monitored, and `tool_use` content blocks are validated against the Aegis policy. All other client methods pass through unchanged.

### `guardMessages(aegis, messages, options?)`

Scan an array of `AnthropicMessageParam[]` for prompt injection. Handles Anthropic's message format -- string content, arrays of content blocks (text, tool_use, tool_result, image), and nested text within tool_result blocks. Optionally validates `tool_use` blocks against the policy (enabled by default). Returns the original messages if safe, throws `AegisInputBlocked` if blocked.

### `createStreamTransform(aegis)`

Create a `TransformStream<string, string>` for monitoring extracted text deltas. Feed `text_delta` values from Anthropic streaming events through this transform for real-time output scanning.

### `getAuditLog(aegis)`

Convenience accessor for the Aegis audit log.

## Options

`guardMessages` and the client wrapper accept `AnthropicGuardOptions`:

- **`scanStrategy`** -- `'last-user'` (default), `'all-user'`, or `'full-history'`
- **`validateToolUse`** -- Whether to validate tool_use blocks against the policy (default: `true`)

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

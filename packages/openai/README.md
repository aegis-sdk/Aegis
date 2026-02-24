# @aegis-sdk/openai

OpenAI SDK adapter for Aegis prompt injection defense. Scans messages, monitors streams, and validates tool calls in the OpenAI chat completion format.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/openai @aegis-sdk/core openai
```

## Quick Start

Wrap the OpenAI client for automatic protection on every call:

```typescript
import OpenAI from 'openai';
import { Aegis } from '@aegis-sdk/core';
import { wrapOpenAIClient } from '@aegis-sdk/openai';

const aegis = new Aegis({ policy: 'strict' });
const client = wrapOpenAIClient(new OpenAI(), aegis);

// Messages are scanned before sending.
// Streaming responses are monitored in real-time.
// Tool calls are validated against the policy.
const stream = await client.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Hello!' }],
  stream: true,
});
```

Or scan messages manually:

```typescript
import { Aegis } from '@aegis-sdk/core';
import { guardMessages } from '@aegis-sdk/openai';

const aegis = new Aegis({ policy: 'strict' });

const messages = [
  { role: 'system' as const, content: 'You are a helpful assistant.' },
  { role: 'user' as const, content: userInput },
];

// Throws AegisInputBlocked if injection is detected
const safe = await guardMessages(aegis, messages);
```

## API

### `wrapOpenAIClient(client, aegis, options?)`

Proxy the OpenAI client to automatically guard all `chat.completions.create()` calls. Input messages are scanned before sending, streaming responses are monitored, and tool/function calls are validated against the Aegis policy. All other client methods pass through unchanged.

### `guardMessages(aegis, messages, options?)`

Scan an array of `OpenAIChatCompletionMessageParam[]` for prompt injection. Extracts text from all message formats (string content, multi-modal content parts, tool/function messages) and runs them through `aegis.guardInput()`. Optionally validates `tool_calls` and `function_call` blocks against the policy (enabled by default). Returns the original messages if safe, throws `AegisInputBlocked` if blocked.

### `createStreamTransform(aegis)`

Create a `TransformStream<string, string>` for monitoring extracted text deltas. Feed `delta.content` values from OpenAI streaming chunks through this transform for real-time output scanning.

### `getAuditLog(aegis)`

Convenience accessor for the Aegis audit log.

## Options

`guardMessages` and the client wrapper accept `OpenAIGuardOptions`:

- **`scanStrategy`** -- `'last-user'` (default), `'all-user'`, or `'full-history'`
- **`validateToolCalls`** -- Whether to validate tool/function calls against the policy (default: `true`)

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

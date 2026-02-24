# @aegis-sdk/mistral

Mistral AI SDK adapter for Aegis prompt injection defense. Scans messages and monitors streaming responses in Mistral's chat completion format.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/mistral @aegis-sdk/core @mistralai/mistralai
```

## Quick Start

Wrap the Mistral client for automatic protection:

```typescript
import { Mistral } from '@mistralai/mistralai';
import { Aegis } from '@aegis-sdk/core';
import { wrapMistralClient } from '@aegis-sdk/mistral';

const aegis = new Aegis({ policy: 'strict' });
const client = wrapMistralClient(new Mistral({ apiKey: process.env.MISTRAL_API_KEY! }), aegis);

// Messages are scanned before sending.
// Streaming responses are monitored in real-time.
const response = await client.chat.complete({
  model: 'mistral-large-latest',
  messages: [{ role: 'user', content: 'Hello!' }],
});
```

Or scan messages manually:

```typescript
import { Aegis } from '@aegis-sdk/core';
import { guardMessages } from '@aegis-sdk/mistral';

const aegis = new Aegis({ policy: 'strict' });

const messages = [
  { role: 'system' as const, content: 'You are a helpful assistant.' },
  { role: 'user' as const, content: userInput },
];

// Throws AegisInputBlocked if injection is detected
const safe = await guardMessages(aegis, messages);
```

## API

### `wrapMistralClient(client, aegis, options?)`

Proxy the Mistral client to automatically guard `chat.complete()` and `chat.stream()` calls. Input messages are scanned before sending and streaming responses are monitored. All other client methods pass through unchanged.

### `guardMessages(aegis, messages, options?)`

Scan an array of `MistralMessage[]` for prompt injection. Extracts text content from Mistral's message format (system, user, assistant, tool roles) and runs them through `aegis.guardInput()`. Tool messages are treated as user-provided content for scanning purposes since they can carry injection payloads. Returns the original messages if safe, throws `AegisInputBlocked` if blocked.

### `createStreamTransform(aegis)`

Create a `TransformStream<string, string>` for monitoring extracted text deltas from Mistral streaming chunks.

### `getAuditLog(aegis)`

Convenience accessor for the Aegis audit log.

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

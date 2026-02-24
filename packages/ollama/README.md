# @aegis-sdk/ollama

Ollama adapter for Aegis prompt injection defense. Scans messages and monitors streaming responses for local model usage via Ollama.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/ollama @aegis-sdk/core ollama
```

## Quick Start

Wrap the Ollama client for automatic protection:

```typescript
import { Ollama } from 'ollama';
import { Aegis } from '@aegis-sdk/core';
import { wrapOllamaClient } from '@aegis-sdk/ollama';

const aegis = new Aegis({ policy: 'strict' });
const client = wrapOllamaClient(new Ollama(), aegis);

// Messages are scanned before sending.
// Streaming responses are monitored in real-time.
const response = await client.chat({
  model: 'llama3',
  messages: [{ role: 'user', content: 'Hello!' }],
});
```

Or scan messages manually:

```typescript
import { Aegis } from '@aegis-sdk/core';
import { guardMessages } from '@aegis-sdk/ollama';

const aegis = new Aegis({ policy: 'strict' });

const messages = [
  { role: 'system' as const, content: 'You are a helpful assistant.' },
  { role: 'user' as const, content: userInput },
];

// Throws AegisInputBlocked if injection is detected
const safe = await guardMessages(aegis, messages);
```

## API

### `wrapOllamaClient(client, aegis, options?)`

Proxy the Ollama client to automatically guard `chat()` calls. Input messages are scanned before sending, and streaming responses (when `stream: true`) are monitored in real-time. All other client methods pass through unchanged.

### `guardMessages(aegis, messages, options?)`

Scan an array of `OllamaMessage[]` for prompt injection. Ollama uses the standard system/user/assistant roles, which map directly to the Aegis three-role model. Returns the original messages if safe, throws `AegisInputBlocked` if blocked.

### `createStreamTransform(aegis)`

Create a `TransformStream<string, string>` for monitoring extracted `message.content` values from Ollama streaming chunks.

### `getAuditLog(aegis)`

Convenience accessor for the Aegis audit log.

## Why protect local models?

Local models running through Ollama still process untrusted user input. Prompt injection attacks work regardless of where the model runs. If your application takes user input and passes it to a local LLM that has access to tools, files, or databases, the same attack vectors apply.

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

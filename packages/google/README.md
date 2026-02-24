# @aegis-sdk/google

Google Gemini SDK adapter for Aegis prompt injection defense. Scans messages in Gemini's `parts[]` content format and monitors streaming responses.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/google @aegis-sdk/core @google/generative-ai
```

## Quick Start

Wrap the Gemini model client for automatic protection:

```typescript
import { GoogleGenerativeAI } from '@google/generative-ai';
import { Aegis } from '@aegis-sdk/core';
import { wrapGoogleClient } from '@aegis-sdk/google';

const aegis = new Aegis({ policy: 'strict' });
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY!);
const model = genAI.getGenerativeModel({ model: 'gemini-pro' });
const wrapped = wrapGoogleClient(model, aegis);

// Contents are scanned before sending.
// Streaming responses are monitored in real-time.
const result = await wrapped.generateContent({
  contents: [{ role: 'user', parts: [{ text: 'Hello!' }] }],
});
```

Or scan messages manually:

```typescript
import { Aegis } from '@aegis-sdk/core';
import { guardMessages } from '@aegis-sdk/google';

const aegis = new Aegis({ policy: 'strict' });

const contents = [
  { role: 'user' as const, parts: [{ text: userInput }] },
];

const systemInstruction = {
  parts: [{ text: 'You are a helpful assistant.' }],
};

// Throws AegisInputBlocked if injection is detected
const safe = await guardMessages(aegis, contents, systemInstruction);
```

## API

### `wrapGoogleClient(client, aegis, options?)`

Proxy a Gemini model instance (from `getGenerativeModel()`) to automatically guard `generateContent()` and `generateContentStream()`. Input contents are scanned before sending and streaming responses are monitored. All other methods pass through unchanged.

### `guardMessages(aegis, contents, systemInstruction?, options?)`

Scan an array of `GeminiContent[]` for prompt injection. Extracts text from Gemini's `parts[]` format (text parts, function responses) and runs them through `aegis.guardInput()`. An optional `systemInstruction` is included as a system-role message during scanning. Returns the original contents if safe, throws `AegisInputBlocked` if blocked.

### `createStreamTransform(aegis)`

Create a `TransformStream<string, string>` for monitoring extracted text content from Gemini streaming chunks.

### `getAuditLog(aegis)`

Convenience accessor for the Aegis audit log.

## Gemini message format

Gemini uses `role: 'model'` instead of `'assistant'`. The adapter handles this mapping automatically. Gemini's `systemInstruction` is provided separately from `contents` and is scanned as a system-role message.

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

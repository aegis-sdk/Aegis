# Message Integrity

Conversation history is stored client-side in many AI applications — in browser `localStorage`, in a database the user controls, or in an API request body. This creates an opportunity for attackers to tamper with the conversation history before the model processes it.

The `MessageSigner` module provides HMAC-based cryptographic signing and verification of conversation messages. It detects both content tampering (changing what a message says) and ordering manipulation (reordering, inserting, or deleting messages).

## The Threat: History Tampering (T15)

Consider a chatbot that stores conversation history client-side. An attacker can:

1. **Modify assistant messages** to make it look like the model previously agreed to something it did not.
2. **Insert fake messages** to create a false context that steers the model's behavior.
3. **Reorder messages** to change the conversation's logical flow.
4. **Delete messages** — particularly system warnings or refusals — to remove guardrails the model previously established.

All of these manipulations happen before the tampered history reaches the LLM, so the model has no way to know it is operating on falsified context.

## How It Works

The `MessageSigner` uses HMAC-SHA256 (via the Web Crypto API) to create cryptographic signatures for messages. Each signature incorporates the previous signature in a chain, so any change to any message — or to the order of messages — invalidates the chain from that point forward.

```
Message 1: "Hello"
  → HMAC("assistant:Hello")                      = sig_1

Message 2: "How are you?"
  → HMAC("sig_1|user:How are you?")              = sig_2

Message 3: "I'm fine, thanks!"
  → HMAC("sig_2|assistant:I'm fine, thanks!")     = sig_3

Chain Hash = sig_3
```

If message 2 is tampered with, `sig_2` changes, which cascades to `sig_3` and the chain hash — all become invalid.

## Configuration

Enable integrity checking through the `integrity` config:

```ts
import { Aegis } from '@aegis-sdk/core';

const aegis = new Aegis({
  integrity: {
    secret: process.env.HMAC_SECRET,  // Required: your signing secret
    algorithm: 'SHA-256',              // Default: 'SHA-256'
    assistantOnly: true,               // Default: true
  },
});

const signer = aegis.getMessageSigner();
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `secret` | `string` | (required) | HMAC signing secret. Keep this server-side. |
| `algorithm` | `string` | `'SHA-256'` | Hash algorithm for HMAC. Passed to `SubtleCrypto`. |
| `assistantOnly` | `boolean` | `true` | When true, only assistant messages get explicit signatures. User messages still contribute to the chain hash for ordering integrity. |

## API Reference

### `sign(message)`

Sign a single message and return its HMAC hex signature.

```ts
const signer = new MessageSigner({ secret: 'my-secret' });

const signature = await signer.sign({
  role: 'assistant',
  content: 'The weather in Tokyo is 22°C and sunny.',
});
// → "a1b2c3d4e5f6..."
```

### `verify(message, signature)`

Verify that a signature matches the message content.

```ts
const valid = await signer.verify(
  { role: 'assistant', content: 'The weather in Tokyo is 22°C and sunny.' },
  'a1b2c3d4e5f6...',
);
// → true
```

### `signConversation(messages)`

Sign an entire conversation, returning a `SignedConversation` with per-message signatures and a chain hash.

```ts
const messages = [
  { role: 'system', content: 'You are a helpful assistant.' },
  { role: 'user', content: 'What is the weather in Tokyo?' },
  { role: 'assistant', content: 'The weather in Tokyo is 22°C and sunny.' },
];

const signed = await signer.signConversation(messages);

// signed.messages → [
//   { message: {...}, signature: "" },       // system (not signed when assistantOnly)
//   { message: {...}, signature: "" },       // user (not signed when assistantOnly)
//   { message: {...}, signature: "a1b2..." }, // assistant (signed)
// ]
// signed.chainHash → "f9e8d7c6..."
```

### `verifyConversation(signed)`

Verify the integrity of a previously signed conversation. Returns detailed results about which messages (if any) were tampered with.

```ts
const result = await signer.verifyConversation(signed);

// result.valid → true (all signatures match)
// result.tamperedIndices → [] (no tampered messages)
// result.chainValid → true (ordering is intact)
```

### `IntegrityResult`

| Field | Type | Description |
|-------|------|-------------|
| `valid` | `boolean` | `true` when all signatures match and chain is intact |
| `tamperedIndices` | `number[]` | Indices of messages with invalid signatures |
| `chainValid` | `boolean` | Whether the chain hash ordering is intact |

## Detecting Tampering

When a message is modified, the verification pinpoints exactly which messages were tampered with:

```ts
// Tamper with message 2 (the assistant response)
signed.messages[2].message.content = 'TAMPERED CONTENT';

const result = await signer.verifyConversation(signed);

// result.valid → false
// result.tamperedIndices → [2]  ← the tampered message
// result.chainValid → false     ← chain is broken from index 2 onward
```

## Chain Hashing and Ordering

The chain hash mechanism ensures that even reordering messages is detected. Each message's signature incorporates the previous message's signature, creating a cryptographic chain:

```ts
// Original order: [system, user, assistant]
const signed = await signer.signConversation(messages);

// Swap user and assistant messages
const reordered = {
  messages: [signed.messages[0], signed.messages[2], signed.messages[1]],
  chainHash: signed.chainHash,
};

const result = await signer.verifyConversation(reordered);
// result.valid → false
// result.chainValid → false
```

## Integration with Aegis

A typical flow: sign the conversation after each model response, store the signed version, and verify it when the conversation is resumed.

```ts
import { Aegis } from '@aegis-sdk/core';

const aegis = new Aegis({
  policy: 'strict',
  integrity: { secret: process.env.HMAC_SECRET },
});

const signer = aegis.getMessageSigner();

// After each model response, sign and store
async function afterModelResponse(messages) {
  const signed = await signer.signConversation(messages);
  await saveToDatabase(signed);
}

// Before processing a resumed conversation, verify
async function beforeProcessing(signed) {
  const result = await signer.verifyConversation(signed);

  if (!result.valid) {
    console.warn('Conversation tampered!', {
      tamperedIndices: result.tamperedIndices,
      chainValid: result.chainValid,
    });
    throw new Error('Conversation integrity check failed');
  }

  // Safe to proceed — extract the messages
  return signed.messages.map(entry => entry.message);
}
```

## Runtime Compatibility

The `MessageSigner` uses the Web Crypto API (`SubtleCrypto`) for HMAC operations, making it compatible with:

- Node.js 16+
- Deno
- Cloudflare Workers
- Vercel Edge Functions
- Modern browsers

When `SubtleCrypto` is not available (rare in modern runtimes), the signer falls back to a simple FNV-based hash. This fallback is **not cryptographically secure** — it provides basic integrity detection only. Production deployments should always use a runtime with `SubtleCrypto` support.

## Security Considerations

- **Keep the secret server-side.** If the secret is exposed to the client, an attacker can forge valid signatures.
- **Rotate secrets periodically.** When rotating, verify conversations with both old and new secrets during the transition period.
- **The `assistantOnly` option** (default: `true`) signs only assistant messages but still includes user messages in the chain hash. This is sufficient for most use cases because the attack vector is modifying what the assistant "said" to manipulate future model behavior.
- **Set `assistantOnly: false`** if you need to detect tampering of user messages as well. This adds signatures to every message in the conversation.

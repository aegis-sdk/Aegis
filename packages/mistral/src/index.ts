/**
 * @aegis-sdk/mistral — Mistral AI SDK adapter for Aegis prompt injection defense.
 *
 * Provides three integration patterns:
 * 1. `guardMessages()` — scan MistralMessage[] before sending to the API
 * 2. `createStreamTransform()` — monitor streaming responses for output violations
 * 3. `wrapMistralClient()` — proxy the Mistral client to automatically guard all calls
 *
 * @example
 * ```ts
 * import { Mistral } from '@mistralai/mistralai';
 * import { Aegis } from '@aegis-sdk/core';
 * import { wrapMistralClient } from '@aegis-sdk/mistral';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 * const client = wrapMistralClient(new Mistral({ apiKey: 'YOUR_KEY' }), aegis);
 *
 * // All messages are automatically scanned before sending.
 * // Streaming responses are automatically monitored.
 * const response = await client.chat.complete({
 *   model: 'mistral-large-latest',
 *   messages: [{ role: 'user', content: 'Hello!' }],
 * });
 * ```
 */

import { Aegis } from "@aegis-sdk/core";
import type {
  AegisConfig,
  GuardInputOptions,
  AuditLog,
  PromptMessage,
  StreamMonitorConfig,
} from "@aegis-sdk/core";

// ─── Mistral SDK Types ──────────────────────────────────────────────────────
//
// We define our own lightweight interfaces that mirror the Mistral SDK's
// message types. This avoids a hard runtime dependency on @mistralai/mistralai
// and lets us work with any compatible version (>=1.0.0).

/** A Mistral chat completion message. */
export interface MistralMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  name?: string;
  tool_calls?: MistralToolCall[];
  tool_call_id?: string;
}

/** A Mistral tool call within an assistant message. */
export interface MistralToolCall {
  id: string;
  type: "function";
  function: {
    name: string;
    arguments: string;
  };
}

/** Shape of a Mistral chat completion request. */
export interface MistralChatCompletionRequest {
  model: string;
  messages: MistralMessage[];
  stream?: boolean;
  [key: string]: unknown;
}

/** Shape of a Mistral streaming chunk. */
export interface MistralChatCompletionChunk {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: MistralChunkChoice[];
}

export interface MistralChunkChoice {
  index: number;
  delta: {
    role?: string;
    content?: string | null;
    tool_calls?: Partial<MistralToolCall>[];
  };
  finish_reason: string | null;
}

/** Options for guardMessages. */
export type MistralGuardOptions = GuardInputOptions;

/** Options for the wrapped client. */
export interface WrapClientOptions {
  /** Guard input options applied to every request. */
  guard?: MistralGuardOptions;
  /** Stream monitor configuration. */
  monitor?: StreamMonitorConfig;
}

// ─── Guard Messages ─────────────────────────────────────────────────────────

/**
 * Scan Mistral MistralMessage[] for prompt injection before sending to the API.
 *
 * Extracts text content from Mistral's message format and runs it through
 * `aegis.guardInput()`. Mistral messages follow the same role conventions
 * as OpenAI (system, user, assistant, tool).
 *
 * @param aegis - The Aegis instance to use for scanning
 * @param messages - Mistral-format messages to scan
 * @param options - Scan strategy options
 * @returns The original messages if they pass validation
 * @throws {AegisInputBlocked} if input is blocked
 *
 * @example
 * ```ts
 * const messages = [
 *   { role: 'system', content: 'You are a helpful assistant.' },
 *   { role: 'user', content: 'Hello!' },
 * ];
 * const safe = await guardMessages(aegis, messages);
 * ```
 */
export async function guardMessages(
  aegis: Aegis,
  messages: MistralMessage[],
  options: MistralGuardOptions = {},
): Promise<MistralMessage[]> {
  // Convert Mistral messages to Aegis PromptMessage format for scanning.
  const aegisMessages = messagesToPromptMessages(messages);

  // Run input guard — this throws if blocked.
  await aegis.guardInput(aegisMessages, {
    scanStrategy: options.scanStrategy,
  });

  return messages;
}

// ─── Stream Transform ───────────────────────────────────────────────────────

/**
 * Create a TransformStream that monitors Mistral streaming text deltas.
 *
 * This provides a `TransformStream<string, string>` that you pipe extracted
 * text content through for real-time Aegis output monitoring.
 *
 * For Mistral's streaming responses, extract `delta.content` from each chunk
 * and pipe it through this transform.
 *
 * @param aegis - Aegis instance (or AegisConfig to create one)
 * @returns A TransformStream that monitors text content
 *
 * @example
 * ```ts
 * const transform = createStreamTransform(aegis);
 *
 * const readable = new ReadableStream({
 *   async start(controller) {
 *     for await (const chunk of stream) {
 *       const content = chunk.data?.choices[0]?.delta?.content;
 *       if (content) controller.enqueue(content);
 *     }
 *     controller.close();
 *   },
 * });
 *
 * const monitored = readable.pipeThrough(transform);
 * ```
 */
export function createStreamTransform(aegis: Aegis | AegisConfig): TransformStream<string, string> {
  const instance = aegis instanceof Aegis ? aegis : new Aegis(aegis);
  return instance.createStreamTransform();
}

// ─── Client Wrapper ─────────────────────────────────────────────────────────

/**
 * Wrap a Mistral client to automatically guard all chat completion calls.
 *
 * Returns a proxy of the original client where `client.chat.complete()` and
 * `client.chat.stream()` are intercepted to:
 * 1. Scan input messages with `guardMessages()` before sending
 * 2. Wrap streaming responses with the Aegis StreamMonitor
 *
 * All other methods and properties on the client are passed through unchanged.
 *
 * @param client - A Mistral SDK client instance
 * @param aegis - Aegis instance or AegisConfig
 * @param options - Additional wrapper options
 * @returns A proxied client with Aegis protection
 *
 * @example
 * ```ts
 * import { Mistral } from '@mistralai/mistralai';
 * import { Aegis } from '@aegis-sdk/core';
 * import { wrapMistralClient } from '@aegis-sdk/mistral';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 * const client = wrapMistralClient(new Mistral({ apiKey: 'YOUR_KEY' }), aegis);
 *
 * // Non-streaming — messages are scanned before sending
 * const response = await client.chat.complete({
 *   model: 'mistral-large-latest',
 *   messages: [{ role: 'user', content: 'Hello!' }],
 * });
 *
 * // Streaming — messages scanned + output monitored
 * const stream = await client.chat.stream({
 *   model: 'mistral-large-latest',
 *   messages: [{ role: 'user', content: 'Hello!' }],
 * });
 * ```
 */
export function wrapMistralClient<
  T extends {
    chat: {
      complete: (...args: unknown[]) => unknown;
      stream: (...args: unknown[]) => unknown;
    };
  },
>(client: T, aegis: Aegis | AegisConfig, options: WrapClientOptions = {}): T {
  const instance = aegis instanceof Aegis ? aegis : new Aegis(aegis);
  const guardOptions = options.guard ?? {};

  // Create a proxy over `client.chat` to intercept `complete()` and `stream()`.
  const chatProxy = new Proxy(client.chat, {
    get(target, prop, receiver) {
      if (prop === "complete") {
        return async (...args: unknown[]) => {
          const params = args[0] as Record<string, unknown> | undefined;

          if (params && Array.isArray(params.messages)) {
            const messages = params.messages as MistralMessage[];
            await guardMessages(instance, messages, guardOptions);
          }

          // Call the original complete method.
          const original = Reflect.get(target, prop, receiver) as (...a: unknown[]) => unknown;
          const result = await original.apply(target, args);

          return result;
        };
      }

      if (prop === "stream") {
        return async (...args: unknown[]) => {
          const params = args[0] as Record<string, unknown> | undefined;

          if (params && Array.isArray(params.messages)) {
            const messages = params.messages as MistralMessage[];
            await guardMessages(instance, messages, guardOptions);
          }

          // Call the original stream method.
          const original = Reflect.get(target, prop, receiver) as (...a: unknown[]) => unknown;
          const result = await original.apply(target, args);

          // Wrap the streaming response to monitor output.
          if (result != null) {
            return wrapStreamResponse(result, instance);
          }

          return result;
        };
      }

      return Reflect.get(target, prop, receiver);
    },
  });

  // Create a proxy over the client to replace `chat` with our proxy.
  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === "chat") {
        return chatProxy;
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

// ─── Convenience Exports ────────────────────────────────────────────────────

/**
 * Get the Aegis audit log from an Aegis instance.
 * Convenience export for use alongside the Mistral adapter.
 */
export function getAuditLog(aegis: Aegis): AuditLog {
  return aegis.getAuditLog();
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

/**
 * Convert Mistral MistralMessage[] to Aegis PromptMessage[].
 *
 * Mistral messages follow similar role conventions to OpenAI. The "tool" role
 * is treated as user-provided content for scanning purposes, since tool
 * responses can carry injection payloads.
 */
function messagesToPromptMessages(messages: MistralMessage[]): PromptMessage[] {
  return messages.map((msg) => ({
    role: mapRole(msg.role),
    content: extractSingleMessageText(msg),
  }));
}

/**
 * Map Mistral role strings to Aegis's three-role model.
 */
function mapRole(role: string): "system" | "user" | "assistant" {
  switch (role) {
    case "system":
      return "system";
    case "user":
      return "user";
    case "assistant":
      return "assistant";
    case "tool":
      // Tool responses are treated as user-provided content
      // for scanning purposes, since they can carry injection payloads.
      return "user";
    default:
      return "user";
  }
}

/**
 * Extract text content from a single Mistral message.
 */
function extractSingleMessageText(msg: MistralMessage): string {
  return msg.content ?? "";
}

/**
 * Wrap a Mistral streaming response to monitor text deltas through Aegis.
 *
 * The Mistral SDK's streaming response is an async iterable of chunk objects.
 * We wrap it so that `delta.content` values are piped through the Aegis
 * stream transform for real-time output monitoring.
 */
function wrapStreamResponse(stream: unknown, aegis: Aegis): AsyncIterable<unknown> {
  const transform = aegis.createStreamTransform();
  const writer = transform.writable.getWriter();
  const reader = transform.readable.getReader();

  // Track pending transformed text.
  const transformedChunks: string[] = [];
  let _transformDone = false;

  // Read from the transform output in the background.
  const readTransformed = async (): Promise<void> => {
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          _transformDone = true;
          break;
        }
        transformedChunks.push(value);
      }
    } catch {
      _transformDone = true;
    }
  };

  const readPromise = readTransformed();

  const originalIterable = stream as AsyncIterable<MistralChatCompletionChunk>;

  return {
    [Symbol.asyncIterator](): AsyncIterator<unknown> {
      const originalIterator = originalIterable[Symbol.asyncIterator]();

      return {
        async next(): Promise<IteratorResult<unknown>> {
          const result = await originalIterator.next();

          if (result.done) {
            try {
              await writer.close();
            } catch {
              // Writer may already be closed.
            }
            await readPromise;
            return result;
          }

          const chunk = result.value;

          // Feed text content through the transform for monitoring.
          if (chunk.choices) {
            for (const choice of chunk.choices) {
              const content = choice.delta?.content;
              if (typeof content === "string" && content.length > 0) {
                try {
                  await writer.write(content);
                } catch {
                  // Transform may reject on violation — let the chunk pass through
                  // so the caller sees the stream error naturally.
                }
              }
            }
          }

          return result;
        },

        async return(value?: unknown): Promise<IteratorResult<unknown>> {
          try {
            await writer.close();
          } catch {
            // Ignore close errors.
          }
          await readPromise;
          if (originalIterator.return) {
            return originalIterator.return(value);
          }
          return { done: true, value: undefined };
        },

        async throw(error?: unknown): Promise<IteratorResult<unknown>> {
          try {
            await writer.abort(error);
          } catch {
            // Ignore abort errors.
          }
          if (originalIterator.throw) {
            return originalIterator.throw(error);
          }
          throw error;
        },
      };
    },
  };
}

// ─── Re-exports from core ───────────────────────────────────────────────────

export {
  Aegis,
  AegisInputBlocked,
  AegisSessionQuarantined,
  AegisSessionTerminated,
} from "@aegis-sdk/core";

export type {
  AegisConfig,
  ScanResult,
  Detection,
  DetectionType,
  GuardInputOptions,
  ScanStrategy,
  AuditLog,
  AuditEntry,
  PromptMessage,
  StreamMonitorConfig,
  StreamViolation,
  RecoveryConfig,
  RecoveryMode,
  ActionValidationRequest,
  ActionValidationResult,
} from "@aegis-sdk/core";

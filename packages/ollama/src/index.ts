/**
 * @aegis-sdk/ollama — Ollama SDK adapter for Aegis prompt injection defense.
 *
 * Provides three integration patterns:
 * 1. `guardMessages()` — scan OllamaMessage[] before sending to the API
 * 2. `createStreamTransform()` — monitor streaming responses for output violations
 * 3. `wrapOllamaClient()` — proxy the Ollama client to automatically guard all calls
 *
 * @example
 * ```ts
 * import { Ollama } from 'ollama';
 * import { Aegis } from '@aegis-sdk/core';
 * import { wrapOllamaClient } from '@aegis-sdk/ollama';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 * const client = wrapOllamaClient(new Ollama(), aegis);
 *
 * // All messages are automatically scanned before sending.
 * // Streaming responses are automatically monitored.
 * const response = await client.chat({
 *   model: 'llama3',
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

// ─── Ollama SDK Types ───────────────────────────────────────────────────────
//
// We define our own lightweight interfaces that mirror the Ollama SDK's
// message types. This avoids a hard runtime dependency on the `ollama`
// package and lets us work with any compatible version (>=0.5.0).

/** An Ollama chat message. */
export interface OllamaMessage {
  role: "system" | "user" | "assistant";
  content: string;
  images?: string[];
}

/** Shape of an Ollama chat request. */
export interface OllamaChatRequest {
  model: string;
  messages: OllamaMessage[];
  stream?: boolean;
  [key: string]: unknown;
}

/** Shape of an Ollama chat response (non-streaming). */
export interface OllamaChatResponse {
  model: string;
  created_at: string;
  message: OllamaMessage;
  done: boolean;
  total_duration?: number;
  load_duration?: number;
  prompt_eval_count?: number;
  prompt_eval_duration?: number;
  eval_count?: number;
  eval_duration?: number;
}

/** Shape of an Ollama streaming chunk. */
export interface OllamaChatStreamChunk {
  model: string;
  created_at: string;
  message: {
    role: string;
    content: string;
  };
  done: boolean;
}

/** Options for guardMessages. */
export type OllamaGuardOptions = GuardInputOptions;

/** Options for the wrapped client. */
export interface WrapClientOptions {
  /** Guard input options applied to every request. */
  guard?: OllamaGuardOptions;
  /** Stream monitor configuration. */
  monitor?: StreamMonitorConfig;
}

// ─── Guard Messages ─────────────────────────────────────────────────────────

/**
 * Scan Ollama OllamaMessage[] for prompt injection before sending to the API.
 *
 * Extracts text content from Ollama's message format and runs it through
 * `aegis.guardInput()`. Ollama uses the standard system/user/assistant roles.
 *
 * @param aegis - The Aegis instance to use for scanning
 * @param messages - Ollama-format messages to scan
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
  messages: OllamaMessage[],
  options: OllamaGuardOptions = {},
): Promise<OllamaMessage[]> {
  // Convert Ollama messages to Aegis PromptMessage format for scanning.
  const aegisMessages = messagesToPromptMessages(messages);

  // Run input guard — this throws if blocked.
  await aegis.guardInput(aegisMessages, {
    scanStrategy: options.scanStrategy,
  });

  return messages;
}

// ─── Stream Transform ───────────────────────────────────────────────────────

/**
 * Create a TransformStream that monitors Ollama streaming text content.
 *
 * This provides a `TransformStream<string, string>` that you pipe extracted
 * text content through for real-time Aegis output monitoring.
 *
 * For Ollama's streaming responses, extract `message.content` from each chunk
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
 *     const stream = await ollama.chat({ model: 'llama3', messages, stream: true });
 *     for await (const chunk of stream) {
 *       if (chunk.message?.content) controller.enqueue(chunk.message.content);
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
 * Wrap an Ollama client to automatically guard all chat calls.
 *
 * Returns a proxy of the original client where `client.chat()` is intercepted
 * to:
 * 1. Scan input messages with `guardMessages()` before sending
 * 2. Wrap streaming responses with the Aegis StreamMonitor
 *
 * All other methods and properties on the client are passed through unchanged.
 *
 * @param client - An Ollama SDK client instance
 * @param aegis - Aegis instance or AegisConfig
 * @param options - Additional wrapper options
 * @returns A proxied client with Aegis protection
 *
 * @example
 * ```ts
 * import { Ollama } from 'ollama';
 * import { Aegis } from '@aegis-sdk/core';
 * import { wrapOllamaClient } from '@aegis-sdk/ollama';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 * const client = wrapOllamaClient(new Ollama(), aegis);
 *
 * // Non-streaming — messages are scanned before sending
 * const response = await client.chat({
 *   model: 'llama3',
 *   messages: [{ role: 'user', content: 'Hello!' }],
 * });
 *
 * // Streaming — messages scanned + output monitored
 * const stream = await client.chat({
 *   model: 'llama3',
 *   messages: [{ role: 'user', content: 'Hello!' }],
 *   stream: true,
 * });
 * for await (const chunk of stream) {
 *   process.stdout.write(chunk.message.content);
 * }
 * ```
 */
export function wrapOllamaClient<
  T extends {
    chat: (...args: unknown[]) => unknown;
  },
>(client: T, aegis: Aegis | AegisConfig, options: WrapClientOptions = {}): T {
  const instance = aegis instanceof Aegis ? aegis : new Aegis(aegis);
  const guardOptions = options.guard ?? {};

  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === "chat") {
        return async (...args: unknown[]) => {
          const params = args[0] as Record<string, unknown> | undefined;

          if (params && Array.isArray(params.messages)) {
            const messages = params.messages as OllamaMessage[];
            await guardMessages(instance, messages, guardOptions);
          }

          // Call the original chat method.
          const original = Reflect.get(target, prop, receiver) as (...a: unknown[]) => unknown;
          const result = await original.apply(target, args);

          // If the request was streaming, wrap the async iterator.
          if (params && params.stream === true && result != null) {
            return wrapStreamResponse(result, instance);
          }

          return result;
        };
      }

      return Reflect.get(target, prop, receiver);
    },
  });
}

// ─── Convenience Exports ────────────────────────────────────────────────────

/**
 * Get the Aegis audit log from an Aegis instance.
 * Convenience export for use alongside the Ollama adapter.
 */
export function getAuditLog(aegis: Aegis): AuditLog {
  return aegis.getAuditLog();
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

/**
 * Convert Ollama OllamaMessage[] to Aegis PromptMessage[].
 *
 * Ollama uses the standard system/user/assistant roles, which map directly
 * to the Aegis three-role model.
 */
function messagesToPromptMessages(messages: OllamaMessage[]): PromptMessage[] {
  return messages.map((msg) => ({
    role: msg.role as "system" | "user" | "assistant",
    content: msg.content ?? "",
  }));
}

/**
 * Wrap an Ollama streaming response to monitor text content through Aegis.
 *
 * The Ollama SDK's streaming response is an async iterable of chunk objects.
 * We wrap it so that `message.content` values are piped through the Aegis
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

  const originalIterable = stream as AsyncIterable<OllamaChatStreamChunk>;

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
          const content = chunk.message?.content;
          if (typeof content === "string" && content.length > 0) {
            try {
              await writer.write(content);
            } catch {
              // Transform may reject on violation — let the chunk pass through
              // so the caller sees the stream error naturally.
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

/**
 * @aegis-sdk/anthropic — Anthropic Claude SDK adapter for Aegis prompt injection defense.
 *
 * Provides three integration patterns:
 * 1. `guardMessages()` — scan Anthropic MessageParam[] before sending to the API
 * 2. `createStreamTransform()` — monitor streaming responses for output violations
 * 3. `wrapAnthropicClient()` — proxy the Anthropic client to automatically guard all calls
 *
 * @example
 * ```ts
 * import Anthropic from '@anthropic-ai/sdk';
 * import { Aegis } from '@aegis-sdk/core';
 * import { wrapAnthropicClient } from '@aegis-sdk/anthropic';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 * const client = wrapAnthropicClient(new Anthropic(), aegis);
 *
 * // All messages are automatically scanned before sending.
 * // Streaming responses are automatically monitored.
 * const stream = await client.messages.create({
 *   model: 'claude-sonnet-4-20250514',
 *   max_tokens: 1024,
 *   messages: [{ role: 'user', content: 'Hello!' }],
 *   stream: true,
 * });
 * ```
 */

import { Aegis, AegisInputBlocked } from "@aegis-sdk/core";
import type {
  AegisConfig,
  DetectionType,
  GuardInputOptions,
  AuditLog,
  PromptMessage,
  StreamMonitorConfig,
} from "@aegis-sdk/core";

// ─── Anthropic SDK Types ────────────────────────────────────────────────────
//
// We define our own lightweight interfaces that mirror the Anthropic SDK's
// message types. This avoids a hard runtime dependency on @anthropic-ai/sdk
// and lets us work with any compatible version.

/** A content block within an Anthropic message (text or tool use). */
export interface AnthropicTextBlock {
  type: "text";
  text: string;
}

export interface AnthropicToolUseBlock {
  type: "tool_use";
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export interface AnthropicToolResultBlock {
  type: "tool_result";
  tool_use_id: string;
  content: string | AnthropicContentBlock[];
}

export interface AnthropicImageBlock {
  type: "image";
  source: {
    type: "base64" | "url";
    media_type?: string;
    data?: string;
    url?: string;
  };
}

export type AnthropicContentBlock =
  | AnthropicTextBlock
  | AnthropicToolUseBlock
  | AnthropicToolResultBlock
  | AnthropicImageBlock;

/** An Anthropic message parameter (compatible with MessageParam from the SDK). */
export interface AnthropicMessageParam {
  role: "user" | "assistant";
  content: string | AnthropicContentBlock[];
}

/** Shape of an Anthropic streaming event with a content_block delta. */
export interface AnthropicContentBlockDelta {
  type: "content_block_delta";
  index: number;
  delta: {
    type: "text_delta" | "input_json_delta";
    text?: string;
    partial_json?: string;
  };
}

/** Shape of an Anthropic streaming event with a content_block start. */
export interface AnthropicContentBlockStart {
  type: "content_block_start";
  index: number;
  content_block: {
    type: "text" | "tool_use";
    id?: string;
    name?: string;
    text?: string;
    input?: Record<string, unknown>;
  };
}

/** Union of Anthropic streaming event types we inspect. */
export type AnthropicStreamEvent =
  | AnthropicContentBlockDelta
  | AnthropicContentBlockStart
  | { type: string; [key: string]: unknown };

/** Options for guardMessages and the client wrapper. */
export interface AnthropicGuardOptions extends GuardInputOptions {
  /** Whether to also validate tool_use blocks against the Aegis policy. Default: true. */
  validateToolUse?: boolean;
}

/** Options for the wrapped client. */
export interface WrapClientOptions {
  /** Guard input options applied to every request. */
  guard?: AnthropicGuardOptions;
  /** Stream monitor configuration. */
  monitor?: StreamMonitorConfig;
}

// ─── Guard Messages ─────────────────────────────────────────────────────────

/**
 * Scan Anthropic MessageParam[] for prompt injection before sending to the API.
 *
 * Extracts text content from Anthropic's message format (which can contain
 * string content or arrays of content blocks) and runs it through
 * `aegis.guardInput()`.
 *
 * @param aegis - The Aegis instance to use for scanning
 * @param messages - Anthropic-format messages to scan
 * @param options - Scan strategy and tool-use validation options
 * @returns The original messages if they pass validation
 * @throws {AegisInputBlocked} if input is blocked
 *
 * @example
 * ```ts
 * const messages = [
 *   { role: 'user', content: 'Summarize this document for me.' },
 * ];
 * const safe = await guardMessages(aegis, messages);
 * ```
 */
export async function guardMessages(
  aegis: Aegis,
  messages: AnthropicMessageParam[],
  options: AnthropicGuardOptions = {},
): Promise<AnthropicMessageParam[]> {
  const validateToolUse = options.validateToolUse ?? true;

  // Convert Anthropic messages to Aegis PromptMessage format for scanning.
  const aegisMessages = messagesToPromptMessages(messages);

  // Run input guard — this throws if blocked.
  await aegis.guardInput(aegisMessages, {
    scanStrategy: options.scanStrategy,
  });

  // Optionally validate tool_use blocks against the action policy.
  if (validateToolUse) {
    const validator = aegis.getValidator();
    for (const msg of messages) {
      const blocks = getContentBlocks(msg);
      for (const block of blocks) {
        if (block.type === "tool_use") {
          const result = await validator.check({
            originalRequest: extractTextContent(messages),
            proposedAction: {
              tool: block.name,
              params: block.input,
            },
          });

          if (!result.allowed) {
            // Log the tool-use block and throw.
            aegis.getAuditLog().log({
              event: "action_block",
              decision: "blocked",
              context: {
                tool: block.name,
                reason: result.reason,
                source: "anthropic-adapter",
              },
            });
            throw new AegisInputBlocked({
              safe: false,
              score: 1.0,
              detections: [
                {
                  type: "tool_abuse" as DetectionType,
                  pattern: `tool_use:${block.name}`,
                  matched: block.name,
                  severity: "high",
                  position: { start: 0, end: 0 },
                  description: `Tool use blocked by policy: ${result.reason}`,
                },
              ],
              normalized: "",
              language: { primary: "en", switches: [] },
              entropy: { mean: 0, maxWindow: 0, anomalous: false },
            });
          }
        }
      }
    }
  }

  return messages;
}

// ─── Stream Transform ───────────────────────────────────────────────────────

/**
 * Create a TransformStream that monitors Anthropic streaming text deltas.
 *
 * This extracts text content from Anthropic's streaming format and pipes it
 * through the Aegis StreamMonitor for real-time violation detection.
 *
 * Returns a `TransformStream<string, string>` compatible with the Web Streams API.
 * For Anthropic's streaming responses, you should extract text deltas and pipe
 * them through this transform.
 *
 * @param aegis - Aegis instance (or AegisConfig to create one)
 * @returns A TransformStream that monitors text content
 *
 * @example
 * ```ts
 * const transform = createStreamTransform(aegis);
 *
 * // Pipe extracted text deltas through the transform
 * const readable = new ReadableStream({
 *   async start(controller) {
 *     for await (const event of stream) {
 *       if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
 *         controller.enqueue(event.delta.text);
 *       }
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
 * Wrap an Anthropic client to automatically guard all message creation calls.
 *
 * Returns a proxy of the original client where `client.messages.create()` is
 * intercepted to:
 * 1. Scan input messages with `guardMessages()` before sending
 * 2. Wrap streaming responses with the Aegis StreamMonitor
 * 3. Validate tool_use content blocks against the policy
 *
 * Non-messages methods and properties are passed through unchanged.
 *
 * @param client - An Anthropic SDK client instance
 * @param aegis - Aegis instance or AegisConfig
 * @param options - Additional wrapper options
 * @returns A proxied client with Aegis protection
 *
 * @example
 * ```ts
 * import Anthropic from '@anthropic-ai/sdk';
 * import { Aegis } from '@aegis-sdk/core';
 * import { wrapAnthropicClient } from '@aegis-sdk/anthropic';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 * const client = wrapAnthropicClient(new Anthropic(), aegis);
 *
 * // Non-streaming — messages are scanned before sending
 * const response = await client.messages.create({
 *   model: 'claude-sonnet-4-20250514',
 *   max_tokens: 1024,
 *   messages: [{ role: 'user', content: 'Hello!' }],
 * });
 *
 * // Streaming — messages scanned + output monitored
 * const stream = await client.messages.create({
 *   model: 'claude-sonnet-4-20250514',
 *   max_tokens: 1024,
 *   messages: [{ role: 'user', content: 'Hello!' }],
 *   stream: true,
 * });
 * ```
 */
export function wrapAnthropicClient<
  T extends { messages: { create: (...args: unknown[]) => unknown } },
>(client: T, aegis: Aegis | AegisConfig, options: WrapClientOptions = {}): T {
  const instance = aegis instanceof Aegis ? aegis : new Aegis(aegis);
  const guardOptions = options.guard ?? {};

  // Create a proxy over `client.messages` to intercept `create()`.
  const messagesProxy = new Proxy(client.messages, {
    get(target, prop, receiver) {
      if (prop === "create") {
        return async (...args: unknown[]) => {
          const params = args[0] as Record<string, unknown> | undefined;

          if (params && Array.isArray(params.messages)) {
            // Guard the messages before forwarding.
            const messages = params.messages as AnthropicMessageParam[];
            await guardMessages(instance, messages, guardOptions);
          }

          // Call the original create method.
          const originalCreate = Reflect.get(target, prop, receiver) as (
            ...a: unknown[]
          ) => unknown;
          const result = await originalCreate.apply(target, args);

          // If the request was streaming, wrap the async iterator.
          if (params && params.stream === true && result != null) {
            return wrapStreamResponse(result, instance);
          }

          // For non-streaming responses, validate tool_use blocks in the output.
          if (result != null && typeof result === "object" && "content" in result) {
            const response = result as {
              content: AnthropicContentBlock[];
              [key: string]: unknown;
            };
            await validateOutputToolUse(instance, response.content);
          }

          return result;
        };
      }

      return Reflect.get(target, prop, receiver);
    },
  });

  // Create a proxy over the client to replace `messages` with our proxy.
  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === "messages") {
        return messagesProxy;
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

// ─── Convenience Exports ────────────────────────────────────────────────────

/**
 * Get the Aegis audit log from an Aegis instance.
 * Convenience export for use alongside the Anthropic adapter.
 */
export function getAuditLog(aegis: Aegis): AuditLog {
  return aegis.getAuditLog();
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

/**
 * Convert Anthropic MessageParam[] to Aegis PromptMessage[].
 *
 * Anthropic messages can have string content or arrays of content blocks.
 * We extract all text content and flatten it into the simple role/content
 * format that Aegis expects.
 */
function messagesToPromptMessages(messages: AnthropicMessageParam[]): PromptMessage[] {
  return messages.map((msg) => ({
    role: msg.role as "user" | "assistant",
    content: extractSingleMessageText(msg),
  }));
}

/**
 * Extract text content from a single Anthropic message.
 */
function extractSingleMessageText(msg: AnthropicMessageParam): string {
  if (typeof msg.content === "string") {
    return msg.content;
  }

  // Array of content blocks — extract text blocks and tool_result text.
  return msg.content
    .map((block) => {
      if (block.type === "text") return block.text;
      if (block.type === "tool_result") {
        if (typeof block.content === "string") return block.content;
        if (Array.isArray(block.content)) {
          return block.content
            .filter((b): b is AnthropicTextBlock => b.type === "text")
            .map((b) => b.text)
            .join("\n");
        }
      }
      return "";
    })
    .filter(Boolean)
    .join("\n");
}

/**
 * Extract a combined text representation of all messages (for action validation context).
 */
function extractTextContent(messages: AnthropicMessageParam[]): string {
  return messages.map(extractSingleMessageText).filter(Boolean).join("\n");
}

/**
 * Get content blocks from a message, normalizing string content to a text block array.
 */
function getContentBlocks(msg: AnthropicMessageParam): AnthropicContentBlock[] {
  if (typeof msg.content === "string") {
    return [{ type: "text", text: msg.content }];
  }
  return msg.content;
}

/**
 * Validate tool_use blocks in a non-streaming API response against the Aegis policy.
 */
async function validateOutputToolUse(
  aegis: Aegis,
  content: AnthropicContentBlock[],
): Promise<void> {
  const validator = aegis.getValidator();

  for (const block of content) {
    if (block.type === "tool_use") {
      const result = await validator.check({
        originalRequest: "",
        proposedAction: {
          tool: block.name,
          params: block.input,
        },
      });

      if (!result.allowed) {
        aegis.getAuditLog().log({
          event: "action_block",
          decision: "blocked",
          context: {
            tool: block.name,
            reason: result.reason,
            source: "anthropic-adapter-output",
          },
        });
      }
    }
  }
}

/**
 * Wrap an Anthropic streaming response to monitor text deltas through Aegis.
 *
 * The Anthropic SDK's streaming response is an async iterable. We wrap it
 * so that text_delta events are piped through the Aegis stream transform
 * for real-time output monitoring.
 */
function wrapStreamResponse(stream: unknown, aegis: Aegis): AsyncIterable<unknown> {
  const transform = aegis.createStreamTransform();
  const writer = transform.writable.getWriter();
  const reader = transform.readable.getReader();

  // Track pending transformed text to inject back into events.
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

  // Start reading transformed output.
  const readPromise = readTransformed();

  const originalIterable = stream as AsyncIterable<AnthropicStreamEvent>;

  return {
    [Symbol.asyncIterator](): AsyncIterator<unknown> {
      const originalIterator = originalIterable[Symbol.asyncIterator]();

      return {
        async next(): Promise<IteratorResult<unknown>> {
          const result = await originalIterator.next();

          if (result.done) {
            // Signal end to the transform.
            try {
              await writer.close();
            } catch {
              // Writer may already be closed.
            }
            await readPromise;
            return result;
          }

          const event = result.value;

          // Feed text deltas through the transform for monitoring.
          if (
            event.type === "content_block_delta" &&
            typeof event.delta === "object" &&
            event.delta !== null &&
            "type" in event.delta &&
            event.delta.type === "text_delta" &&
            "text" in event.delta &&
            typeof event.delta.text === "string"
          ) {
            try {
              await writer.write(event.delta.text);
            } catch {
              // Transform may reject on violation — let the event pass through
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

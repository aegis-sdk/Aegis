/**
 * @aegis-sdk/openai — OpenAI SDK adapter for Aegis prompt injection defense.
 *
 * Provides three integration patterns:
 * 1. `guardMessages()` — scan OpenAI ChatCompletionMessageParam[] before sending
 * 2. `createStreamTransform()` — monitor streaming responses for output violations
 * 3. `wrapOpenAIClient()` — proxy the OpenAI client to automatically guard all calls
 *
 * @example
 * ```ts
 * import OpenAI from 'openai';
 * import { Aegis } from '@aegis-sdk/core';
 * import { wrapOpenAIClient } from '@aegis-sdk/openai';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 * const client = wrapOpenAIClient(new OpenAI(), aegis);
 *
 * // All messages are automatically scanned before sending.
 * // Streaming responses are automatically monitored.
 * const stream = await client.chat.completions.create({
 *   model: 'gpt-4o',
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

// ─── OpenAI SDK Types ───────────────────────────────────────────────────────
//
// Lightweight interfaces that mirror the OpenAI SDK's chat completion types.
// This avoids a hard runtime dependency on the `openai` package and lets us
// work with any compatible version (>=4.0.0).

/** A text content part in an OpenAI message. */
export interface OpenAITextContentPart {
  type: "text";
  text: string;
}

/** An image content part in an OpenAI message. */
export interface OpenAIImageContentPart {
  type: "image_url";
  image_url: { url: string; detail?: "auto" | "low" | "high" };
}

export type OpenAIContentPart = OpenAITextContentPart | OpenAIImageContentPart;

/** An OpenAI function call within an assistant message. */
export interface OpenAIFunctionCall {
  name: string;
  arguments: string;
}

/** An OpenAI tool call within an assistant message. */
export interface OpenAIToolCall {
  id: string;
  type: "function";
  function: OpenAIFunctionCall;
}

/** System message. */
export interface OpenAISystemMessage {
  role: "system";
  content: string;
  name?: string;
}

/** User message (string or multi-modal content parts). */
export interface OpenAIUserMessage {
  role: "user";
  content: string | OpenAIContentPart[];
  name?: string;
}

/** Assistant message (may include tool calls). */
export interface OpenAIAssistantMessage {
  role: "assistant";
  content?: string | null;
  tool_calls?: OpenAIToolCall[];
  function_call?: OpenAIFunctionCall;
  name?: string;
}

/** Tool response message. */
export interface OpenAIToolMessage {
  role: "tool";
  content: string;
  tool_call_id: string;
}

/** Function response message (legacy). */
export interface OpenAIFunctionMessage {
  role: "function";
  content: string;
  name: string;
}

/** Union of all OpenAI chat completion message types. */
export type OpenAIChatCompletionMessageParam =
  | OpenAISystemMessage
  | OpenAIUserMessage
  | OpenAIAssistantMessage
  | OpenAIToolMessage
  | OpenAIFunctionMessage;

/** Shape of a streaming chunk from OpenAI. */
export interface OpenAIChatCompletionChunk {
  id: string;
  object: "chat.completion.chunk";
  created: number;
  model: string;
  choices: OpenAIChunkChoice[];
}

export interface OpenAIChunkChoice {
  index: number;
  delta: {
    role?: string;
    content?: string | null;
    tool_calls?: Partial<OpenAIToolCall>[];
    function_call?: Partial<OpenAIFunctionCall>;
  };
  finish_reason: string | null;
}

/** Options for guardMessages and the client wrapper. */
export interface OpenAIGuardOptions extends GuardInputOptions {
  /** Whether to also validate tool/function calls against the Aegis policy. Default: true. */
  validateToolCalls?: boolean;
}

/** Options for the wrapped client. */
export interface WrapClientOptions {
  /** Guard input options applied to every request. */
  guard?: OpenAIGuardOptions;
  /** Stream monitor configuration. */
  monitor?: StreamMonitorConfig;
}

// ─── Guard Messages ─────────────────────────────────────────────────────────

/**
 * Scan OpenAI ChatCompletionMessageParam[] for prompt injection before sending.
 *
 * Extracts text content from OpenAI's message format (which supports string
 * content, multi-modal content parts, and tool/function messages) and runs it
 * through `aegis.guardInput()`.
 *
 * @param aegis - The Aegis instance to use for scanning
 * @param messages - OpenAI-format messages to scan
 * @param options - Scan strategy and tool-call validation options
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
  messages: OpenAIChatCompletionMessageParam[],
  options: OpenAIGuardOptions = {},
): Promise<OpenAIChatCompletionMessageParam[]> {
  const validateToolCalls = options.validateToolCalls ?? true;

  // Convert OpenAI messages to Aegis PromptMessage format for scanning.
  const aegisMessages = messagesToPromptMessages(messages);

  // Run input guard — this throws if blocked.
  await aegis.guardInput(aegisMessages, {
    scanStrategy: options.scanStrategy,
  });

  // Optionally validate tool_calls in assistant messages against the policy.
  if (validateToolCalls) {
    const validator = aegis.getValidator();
    for (const msg of messages) {
      if (msg.role === "assistant") {
        const assistantMsg = msg as OpenAIAssistantMessage;

        // Modern tool_calls format.
        if (assistantMsg.tool_calls) {
          for (const toolCall of assistantMsg.tool_calls) {
            let parsedArgs: Record<string, unknown> = {};
            try {
              parsedArgs = JSON.parse(toolCall.function.arguments) as Record<string, unknown>;
            } catch {
              // If arguments can't be parsed, pass empty object.
            }

            const result = await validator.check({
              originalRequest: extractTextContent(messages),
              proposedAction: {
                tool: toolCall.function.name,
                params: parsedArgs,
              },
            });

            if (!result.allowed) {
              aegis.getAuditLog().log({
                event: "action_block",
                decision: "blocked",
                context: {
                  tool: toolCall.function.name,
                  reason: result.reason,
                  source: "openai-adapter",
                },
              });
              throw new AegisInputBlocked({
                safe: false,
                score: 1.0,
                detections: [
                  {
                    type: "tool_abuse" as DetectionType,
                    pattern: `tool_call:${toolCall.function.name}`,
                    matched: toolCall.function.name,
                    severity: "high",
                    position: { start: 0, end: 0 },
                    description: `Tool call blocked by policy: ${result.reason}`,
                  },
                ],
                normalized: "",
                language: { primary: "en", switches: [] },
                entropy: { mean: 0, maxWindow: 0, anomalous: false },
              });
            }
          }
        }

        // Legacy function_call format.
        if (assistantMsg.function_call) {
          let parsedArgs: Record<string, unknown> = {};
          try {
            parsedArgs = JSON.parse(assistantMsg.function_call.arguments) as Record<
              string,
              unknown
            >;
          } catch {
            // If arguments can't be parsed, pass empty object.
          }

          const result = await validator.check({
            originalRequest: extractTextContent(messages),
            proposedAction: {
              tool: assistantMsg.function_call.name,
              params: parsedArgs,
            },
          });

          if (!result.allowed) {
            aegis.getAuditLog().log({
              event: "action_block",
              decision: "blocked",
              context: {
                tool: assistantMsg.function_call.name,
                reason: result.reason,
                source: "openai-adapter",
              },
            });
            throw new AegisInputBlocked({
              safe: false,
              score: 1.0,
              detections: [
                {
                  type: "tool_abuse" as DetectionType,
                  pattern: `function_call:${assistantMsg.function_call.name}`,
                  matched: assistantMsg.function_call.name,
                  severity: "high",
                  position: { start: 0, end: 0 },
                  description: `Function call blocked by policy: ${result.reason}`,
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
 * Create a TransformStream that monitors OpenAI streaming text deltas.
 *
 * This provides a `TransformStream<string, string>` that you pipe extracted
 * text content through for real-time Aegis output monitoring.
 *
 * For OpenAI's streaming responses, extract `delta.content` from each chunk
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
 *       const content = chunk.choices[0]?.delta?.content;
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
 * Wrap an OpenAI client to automatically guard all chat completion calls.
 *
 * Returns a proxy of the original client where `client.chat.completions.create()`
 * is intercepted to:
 * 1. Scan input messages with `guardMessages()` before sending
 * 2. Wrap streaming responses with the Aegis StreamMonitor
 * 3. Validate tool/function calls in responses against the policy
 *
 * All other methods and properties on the client are passed through unchanged.
 *
 * @param client - An OpenAI SDK client instance
 * @param aegis - Aegis instance or AegisConfig
 * @param options - Additional wrapper options
 * @returns A proxied client with Aegis protection
 *
 * @example
 * ```ts
 * import OpenAI from 'openai';
 * import { Aegis } from '@aegis-sdk/core';
 * import { wrapOpenAIClient } from '@aegis-sdk/openai';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 * const client = wrapOpenAIClient(new OpenAI(), aegis);
 *
 * // Non-streaming — messages are scanned before sending
 * const response = await client.chat.completions.create({
 *   model: 'gpt-4o',
 *   messages: [{ role: 'user', content: 'Hello!' }],
 * });
 *
 * // Streaming — messages scanned + output monitored
 * const stream = await client.chat.completions.create({
 *   model: 'gpt-4o',
 *   messages: [{ role: 'user', content: 'Hello!' }],
 *   stream: true,
 * });
 * ```
 */
export function wrapOpenAIClient<
  T extends {
    chat: {
      completions: { create: (...args: unknown[]) => unknown };
    };
  },
>(client: T, aegis: Aegis | AegisConfig, options: WrapClientOptions = {}): T {
  const instance = aegis instanceof Aegis ? aegis : new Aegis(aegis);
  const guardOptions = options.guard ?? {};

  // Create a proxy over `client.chat.completions` to intercept `create()`.
  const completionsProxy = new Proxy(client.chat.completions, {
    get(target, prop, receiver) {
      if (prop === "create") {
        return async (...args: unknown[]) => {
          const params = args[0] as Record<string, unknown> | undefined;

          if (params && Array.isArray(params.messages)) {
            // Guard the messages before forwarding.
            const messages = params.messages as OpenAIChatCompletionMessageParam[];
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

          // For non-streaming responses, validate tool/function calls in output.
          if (result != null && typeof result === "object") {
            const response = result as {
              choices?: {
                message?: {
                  tool_calls?: OpenAIToolCall[];
                  function_call?: OpenAIFunctionCall;
                };
              }[];
              [key: string]: unknown;
            };

            if (response.choices) {
              for (const choice of response.choices) {
                if (choice.message) {
                  await validateOutputToolCalls(
                    instance,
                    choice.message.tool_calls,
                    choice.message.function_call,
                  );
                }
              }
            }
          }

          return result;
        };
      }

      return Reflect.get(target, prop, receiver);
    },
  });

  // Create a proxy over `client.chat` to replace `completions` with our proxy.
  const chatProxy = new Proxy(client.chat, {
    get(target, prop, receiver) {
      if (prop === "completions") {
        return completionsProxy;
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
 * Convenience export for use alongside the OpenAI adapter.
 */
export function getAuditLog(aegis: Aegis): AuditLog {
  return aegis.getAuditLog();
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

/**
 * Convert OpenAI ChatCompletionMessageParam[] to Aegis PromptMessage[].
 *
 * OpenAI messages can have various roles (system, user, assistant, tool, function)
 * and content types. We extract all text content and map it to the simple
 * role/content format that Aegis expects.
 */
function messagesToPromptMessages(messages: OpenAIChatCompletionMessageParam[]): PromptMessage[] {
  return messages.map((msg) => ({
    role: mapRole(msg.role),
    content: extractSingleMessageText(msg),
  }));
}

/**
 * Map OpenAI role strings to Aegis's three-role model.
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
    case "function":
      // Tool and function responses are treated as user-provided content
      // for scanning purposes, since they can carry injection payloads.
      return "user";
    default:
      return "user";
  }
}

/**
 * Extract text content from a single OpenAI message.
 */
function extractSingleMessageText(msg: OpenAIChatCompletionMessageParam): string {
  switch (msg.role) {
    case "system":
      return msg.content;
    case "user": {
      if (typeof msg.content === "string") return msg.content;
      // Multi-modal content parts — extract text parts.
      return (msg.content as OpenAIContentPart[])
        .filter((part): part is OpenAITextContentPart => part.type === "text")
        .map((part) => part.text)
        .join("\n");
    }
    case "assistant":
      return msg.content ?? "";
    case "tool":
      return msg.content;
    case "function":
      return msg.content;
    default:
      return "";
  }
}

/**
 * Extract a combined text representation of all messages (for action validation context).
 */
function extractTextContent(messages: OpenAIChatCompletionMessageParam[]): string {
  return messages.map(extractSingleMessageText).filter(Boolean).join("\n");
}

/**
 * Validate tool_calls and function_call in a non-streaming API response.
 */
async function validateOutputToolCalls(
  aegis: Aegis,
  toolCalls?: OpenAIToolCall[],
  functionCall?: OpenAIFunctionCall,
): Promise<void> {
  const validator = aegis.getValidator();

  if (toolCalls) {
    for (const toolCall of toolCalls) {
      let parsedArgs: Record<string, unknown> = {};
      try {
        parsedArgs = JSON.parse(toolCall.function.arguments) as Record<string, unknown>;
      } catch {
        // If arguments can't be parsed, use empty object.
      }

      const result = await validator.check({
        originalRequest: "",
        proposedAction: {
          tool: toolCall.function.name,
          params: parsedArgs,
        },
      });

      if (!result.allowed) {
        aegis.getAuditLog().log({
          event: "action_block",
          decision: "blocked",
          context: {
            tool: toolCall.function.name,
            reason: result.reason,
            source: "openai-adapter-output",
          },
        });
      }
    }
  }

  if (functionCall) {
    let parsedArgs: Record<string, unknown> = {};
    try {
      parsedArgs = JSON.parse(functionCall.arguments) as Record<string, unknown>;
    } catch {
      // If arguments can't be parsed, use empty object.
    }

    const result = await validator.check({
      originalRequest: "",
      proposedAction: {
        tool: functionCall.name,
        params: parsedArgs,
      },
    });

    if (!result.allowed) {
      aegis.getAuditLog().log({
        event: "action_block",
        decision: "blocked",
        context: {
          tool: functionCall.name,
          reason: result.reason,
          source: "openai-adapter-output",
        },
      });
    }
  }
}

/**
 * Wrap an OpenAI streaming response to monitor text deltas through Aegis.
 *
 * The OpenAI SDK's streaming response is an async iterable of chunk objects.
 * We wrap it so that `delta.content` values are piped through the Aegis
 * stream transform for real-time output monitoring.
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

  const originalIterable = stream as AsyncIterable<OpenAIChatCompletionChunk>;

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

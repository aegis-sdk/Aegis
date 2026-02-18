/**
 * @aegis-sdk/google — Google Gemini SDK adapter for Aegis prompt injection defense.
 *
 * Provides three integration patterns:
 * 1. `guardMessages()` — scan GeminiContent[] before sending to the API
 * 2. `createStreamTransform()` — monitor streaming responses for output violations
 * 3. `wrapGoogleClient()` — proxy the Google Generative AI client to automatically guard all calls
 *
 * @example
 * ```ts
 * import { GoogleGenerativeAI } from '@google/generative-ai';
 * import { Aegis } from '@aegis-sdk/core';
 * import { wrapGoogleClient } from '@aegis-sdk/google';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 * const genAI = new GoogleGenerativeAI('YOUR_API_KEY');
 * const model = genAI.getGenerativeModel({ model: 'gemini-pro' });
 * const wrapped = wrapGoogleClient(model, aegis);
 *
 * // All messages are automatically scanned before sending.
 * // Streaming responses are automatically monitored.
 * const result = await wrapped.generateContent({
 *   contents: [{ role: 'user', parts: [{ text: 'Hello!' }] }],
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

// ─── Google Gemini SDK Types ────────────────────────────────────────────────
//
// We define our own lightweight interfaces that mirror the Google Generative AI
// SDK's types. This avoids a hard runtime dependency on @google/generative-ai
// and lets us work with any compatible version (>=0.21.0).

/** A single part within a Gemini content message. */
export interface GeminiPart {
  text?: string;
  inlineData?: { mimeType: string; data: string };
  functionCall?: { name: string; args: Record<string, unknown> };
  functionResponse?: { name: string; response: Record<string, unknown> };
}

/** A content message in the Gemini format. */
export interface GeminiContent {
  role: "user" | "model";
  parts: GeminiPart[];
}

/** A system instruction for Gemini (provided separately from contents). */
export interface GeminiSystemInstruction {
  parts: { text: string }[];
}

/** The request shape for generateContent / generateContentStream. */
export interface GeminiGenerateContentRequest {
  contents: GeminiContent[];
  systemInstruction?: GeminiSystemInstruction;
}

/** Shape of a streaming chunk from Gemini. */
export interface GeminiGenerateContentStreamChunk {
  candidates?: {
    content?: {
      role?: string;
      parts?: GeminiPart[];
    };
    finishReason?: string;
  }[];
  text?: () => string;
}

/** Options for guardMessages. */
export type GoogleGuardOptions = GuardInputOptions;

/** Options for the wrapped client. */
export interface WrapClientOptions {
  /** Guard input options applied to every request. */
  guard?: GoogleGuardOptions;
  /** Stream monitor configuration. */
  monitor?: StreamMonitorConfig;
}

// ─── Guard Messages ─────────────────────────────────────────────────────────

/**
 * Scan Gemini GeminiContent[] for prompt injection before sending to the API.
 *
 * Extracts text content from Gemini's message format (which contains arrays
 * of parts with optional text fields) and runs it through `aegis.guardInput()`.
 *
 * An optional `systemInstruction` can be provided — its text parts are scanned
 * as a system-role message.
 *
 * @param aegis - The Aegis instance to use for scanning
 * @param contents - Gemini-format content messages to scan
 * @param systemInstruction - Optional system instruction to include in scanning
 * @param options - Scan strategy options
 * @returns The original contents if they pass validation
 * @throws {AegisInputBlocked} if input is blocked
 *
 * @example
 * ```ts
 * const contents = [
 *   { role: 'user', parts: [{ text: 'Summarize this document for me.' }] },
 * ];
 * const safe = await guardMessages(aegis, contents);
 * ```
 */
export async function guardMessages(
  aegis: Aegis,
  contents: GeminiContent[],
  systemInstruction?: GeminiSystemInstruction,
  options: GoogleGuardOptions = {},
): Promise<GeminiContent[]> {
  // Convert Gemini messages to Aegis PromptMessage format for scanning.
  const aegisMessages = contentsToPromptMessages(contents, systemInstruction);

  // Run input guard — this throws if blocked.
  await aegis.guardInput(aegisMessages, {
    scanStrategy: options.scanStrategy,
  });

  return contents;
}

// ─── Stream Transform ───────────────────────────────────────────────────────

/**
 * Create a TransformStream that monitors Gemini streaming text content.
 *
 * This provides a `TransformStream<string, string>` that you pipe extracted
 * text content through for real-time Aegis output monitoring.
 *
 * For Gemini's streaming responses, extract text from each chunk's candidates
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
 *     const stream = await model.generateContentStream({ contents });
 *     for await (const chunk of stream.stream) {
 *       const text = chunk.text();
 *       if (text) controller.enqueue(text);
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
 * Wrap a Google Generative AI model client to automatically guard all content generation calls.
 *
 * Returns a proxy of the original model where `generateContent()` and
 * `generateContentStream()` are intercepted to:
 * 1. Scan input contents with `guardMessages()` before sending
 * 2. Wrap streaming responses with the Aegis StreamMonitor
 *
 * All other methods and properties on the model are passed through unchanged.
 *
 * @param client - A Google Generative AI model instance (from `getGenerativeModel()`)
 * @param aegis - Aegis instance or AegisConfig
 * @param options - Additional wrapper options
 * @returns A proxied model with Aegis protection
 *
 * @example
 * ```ts
 * import { GoogleGenerativeAI } from '@google/generative-ai';
 * import { Aegis } from '@aegis-sdk/core';
 * import { wrapGoogleClient } from '@aegis-sdk/google';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 * const genAI = new GoogleGenerativeAI('YOUR_API_KEY');
 * const model = genAI.getGenerativeModel({ model: 'gemini-pro' });
 * const wrapped = wrapGoogleClient(model, aegis);
 *
 * // Non-streaming — contents are scanned before sending
 * const response = await wrapped.generateContent({
 *   contents: [{ role: 'user', parts: [{ text: 'Hello!' }] }],
 * });
 *
 * // Streaming — contents scanned + output monitored
 * const stream = await wrapped.generateContentStream({
 *   contents: [{ role: 'user', parts: [{ text: 'Hello!' }] }],
 * });
 * ```
 */
export function wrapGoogleClient<
  T extends {
    generateContent: (...args: unknown[]) => unknown;
    generateContentStream: (...args: unknown[]) => unknown;
  },
>(client: T, aegis: Aegis | AegisConfig, options: WrapClientOptions = {}): T {
  const instance = aegis instanceof Aegis ? aegis : new Aegis(aegis);
  const guardOptions = options.guard ?? {};

  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === "generateContent") {
        return async (...args: unknown[]) => {
          const params = normalizeRequest(args);

          if (params && Array.isArray(params.contents)) {
            await guardMessages(
              instance,
              params.contents as GeminiContent[],
              params.systemInstruction as GeminiSystemInstruction | undefined,
              guardOptions,
            );
          }

          // Call the original method.
          const original = Reflect.get(target, prop, receiver) as (...a: unknown[]) => unknown;
          const result = await original.apply(target, args);

          return result;
        };
      }

      if (prop === "generateContentStream") {
        return async (...args: unknown[]) => {
          const params = normalizeRequest(args);

          if (params && Array.isArray(params.contents)) {
            await guardMessages(
              instance,
              params.contents as GeminiContent[],
              params.systemInstruction as GeminiSystemInstruction | undefined,
              guardOptions,
            );
          }

          // Call the original method.
          const original = Reflect.get(target, prop, receiver) as (...a: unknown[]) => unknown;
          const result = await original.apply(target, args);

          // Wrap the streaming response to monitor output.
          if (result != null && typeof result === "object") {
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
 * Convenience export for use alongside the Google adapter.
 */
export function getAuditLog(aegis: Aegis): AuditLog {
  return aegis.getAuditLog();
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

/**
 * Normalize a generateContent call's arguments to a request object.
 *
 * The Google Generative AI SDK accepts either a string, an array of parts,
 * or a full request object. We normalize all forms to the request shape.
 */
function normalizeRequest(args: unknown[]): GeminiGenerateContentRequest | null {
  const first = args[0];

  if (first == null) return null;

  // String shorthand: generateContent("Hello")
  if (typeof first === "string") {
    return {
      contents: [{ role: "user", parts: [{ text: first }] }],
    };
  }

  // Array of parts shorthand: generateContent([{ text: "Hello" }])
  if (Array.isArray(first)) {
    return {
      contents: [{ role: "user", parts: first as GeminiPart[] }],
    };
  }

  // Full request object: generateContent({ contents: [...] })
  if (typeof first === "object" && "contents" in first) {
    return first as GeminiGenerateContentRequest;
  }

  // Single part shorthand: generateContent({ text: "Hello" })
  if (typeof first === "object" && "text" in first) {
    return {
      contents: [{ role: "user", parts: [first as GeminiPart] }],
    };
  }

  return null;
}

/**
 * Convert Gemini GeminiContent[] to Aegis PromptMessage[].
 *
 * Gemini messages use "model" role for assistant responses. We map this
 * to "assistant" for Aegis's three-role model (system, user, assistant).
 * An optional system instruction is prepended as a system message.
 */
function contentsToPromptMessages(
  contents: GeminiContent[],
  systemInstruction?: GeminiSystemInstruction,
): PromptMessage[] {
  const messages: PromptMessage[] = [];

  // Add system instruction as the first message if present.
  if (systemInstruction && systemInstruction.parts.length > 0) {
    const systemText = systemInstruction.parts
      .map((p) => p.text)
      .filter(Boolean)
      .join("\n");
    if (systemText) {
      messages.push({ role: "system", content: systemText });
    }
  }

  // Convert each content message.
  for (const content of contents) {
    const text = extractContentText(content);
    if (text || content.parts.length === 0) {
      messages.push({
        role: mapRole(content.role),
        content: text,
      });
    }
  }

  return messages;
}

/**
 * Map Gemini role strings to Aegis's three-role model.
 */
function mapRole(role: string): "system" | "user" | "assistant" {
  switch (role) {
    case "user":
      return "user";
    case "model":
      return "assistant";
    default:
      return "user";
  }
}

/**
 * Extract text content from a single Gemini content message.
 *
 * Concatenates all text parts, including function response text
 * representations.
 */
function extractContentText(content: GeminiContent): string {
  return content.parts
    .map((part) => {
      if (part.text != null) return part.text;
      if (part.functionResponse) {
        // Serialize function response for scanning.
        return JSON.stringify(part.functionResponse.response);
      }
      return "";
    })
    .filter(Boolean)
    .join("\n");
}

/**
 * Wrap a Gemini streaming response to monitor text content through Aegis.
 *
 * The Google Generative AI SDK's streaming response has a `stream` property
 * that is an async iterable of chunks. We wrap it so that text content from
 * each chunk is piped through the Aegis stream transform for real-time
 * output monitoring.
 */
function wrapStreamResponse(response: unknown, aegis: Aegis): unknown {
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

  const original = response as {
    stream: AsyncIterable<GeminiGenerateContentStreamChunk>;
    response: Promise<unknown>;
    [key: string]: unknown;
  };

  // If there's no stream property, return as-is.
  if (!original.stream) {
    return response;
  }

  const originalStream = original.stream;

  const wrappedStream: AsyncIterable<GeminiGenerateContentStreamChunk> = {
    [Symbol.asyncIterator](): AsyncIterator<GeminiGenerateContentStreamChunk> {
      const originalIterator = originalStream[Symbol.asyncIterator]();

      return {
        async next(): Promise<IteratorResult<GeminiGenerateContentStreamChunk>> {
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

          // Extract text from the chunk and feed through transform.
          if (chunk.candidates) {
            for (const candidate of chunk.candidates) {
              if (candidate.content?.parts) {
                for (const part of candidate.content.parts) {
                  if (part.text != null && part.text.length > 0) {
                    try {
                      await writer.write(part.text);
                    } catch {
                      // Transform may reject on violation.
                    }
                  }
                }
              }
            }
          }

          return result;
        },

        async return(value?: unknown): Promise<IteratorResult<GeminiGenerateContentStreamChunk>> {
          try {
            await writer.close();
          } catch {
            // Ignore close errors.
          }
          await readPromise;
          if (originalIterator.return) {
            return originalIterator.return(value) as Promise<
              IteratorResult<GeminiGenerateContentStreamChunk>
            >;
          }
          return { done: true, value: undefined as unknown as GeminiGenerateContentStreamChunk };
        },

        async throw(error?: unknown): Promise<IteratorResult<GeminiGenerateContentStreamChunk>> {
          try {
            await writer.abort(error);
          } catch {
            // Ignore abort errors.
          }
          if (originalIterator.throw) {
            return originalIterator.throw(error) as Promise<
              IteratorResult<GeminiGenerateContentStreamChunk>
            >;
          }
          throw error;
        },
      };
    },
  };

  // Return a new object that replaces the stream but preserves everything else.
  return new Proxy(original, {
    get(target, prop, receiver) {
      if (prop === "stream") {
        return wrappedStream;
      }
      return Reflect.get(target, prop, receiver);
    },
  });
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

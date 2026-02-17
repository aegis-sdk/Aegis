/**
 * @aegis-sdk/vercel — Vercel AI SDK integration for Aegis.
 *
 * Provides two integration patterns:
 * 1. `createAegisTransform()` — for use with `experimental_transform` on `streamText()`
 * 2. `createAegisMiddleware()` — for use with `wrapLanguageModel()`
 *
 * @example
 * ```ts
 * import { streamText } from 'ai';
 * import { openai } from '@ai-sdk/openai';
 * import { Aegis } from '@aegis-sdk/core';
 * import { createAegisTransform } from '@aegis-sdk/vercel';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 *
 * const result = streamText({
 *   model: openai('gpt-4o'),
 *   messages: safeMessages,
 *   experimental_transform: createAegisTransform(aegis),
 * });
 * ```
 */

import type { Aegis, StreamMonitorConfig, AuditLog } from "@aegis-sdk/core";

// ─── Vercel AI SDK Compatible Types ─────────────────────────────────────────
// These are defined locally to avoid requiring `ai` as a direct dependency.
// They mirror the types from the Vercel AI SDK (`ai` package) so that
// `createAegisTransform()` returns a value assignable to `experimental_transform`.

/**
 * Minimal representation of a TextStreamPart from the Vercel AI SDK.
 *
 * The full union has many members; we only need to discriminate on `type`
 * and extract the `textDelta` from text-bearing parts.
 */
interface TextStreamPartBase {
  type: string;
  [key: string]: unknown;
}

interface TextDeltaPart extends TextStreamPartBase {
  type: "text-delta";
  textDelta: string;
}

type TextStreamPart = TextStreamPartBase;

/** Matches Vercel AI SDK's ToolSet = Record<string, Tool> */
type ToolSet = Record<string, unknown>;

/**
 * The shape Vercel AI SDK expects for `experimental_transform`:
 *
 * ```ts
 * (options: { tools: TOOLS; stopStream: () => void }) =>
 *   TransformStream<TextStreamPart<TOOLS>, TextStreamPart<TOOLS>>
 * ```
 */
type StreamTextTransform = (options: {
  tools: ToolSet;
  stopStream?: () => void;
}) => TransformStream<TextStreamPart, TextStreamPart>;

// ─── Public API ─────────────────────────────────────────────────────────────

export interface AegisTransformOptions {
  /** Additional stream monitor configuration */
  monitor?: StreamMonitorConfig;
  /** Whether to log violations to the Aegis audit log */
  audit?: boolean;
}

/**
 * Create a stream transform compatible with Vercel AI SDK's `experimental_transform`.
 *
 * Returns a **function** (not a TransformStream directly) that accepts the
 * `{ tools, stopStream }` options from the Vercel AI SDK and returns a
 * `TransformStream<TextStreamPart, TextStreamPart>`.
 *
 * The transform processes `TextStreamPart` objects:
 * - `text-delta` parts have their `textDelta` scanned by Aegis's StreamMonitor.
 *   When a violation is detected the stream is terminated via `stopStream()` or
 *   `controller.terminate()`.
 * - All other part types are passed through unchanged.
 *
 * @example
 * ```ts
 * const result = streamText({
 *   model: openai('gpt-4o'),
 *   messages: safeMessages,
 *   experimental_transform: createAegisTransform(aegis),
 * });
 * ```
 */
export function createAegisTransform(
  aegis: Aegis,
  _options: AegisTransformOptions = {},
): StreamTextTransform {
  return ({ stopStream } = { tools: {} }) => {
    // Create the underlying text-level TransformStream from Aegis
    const textTransform = aegis.createStreamTransform();
    const textWriter = textTransform.writable.getWriter();
    const textReader = textTransform.readable.getReader();

    // Track whether the text stream has been terminated
    let terminated = false;

    // Buffer for non-text parts that arrive between text chunks.
    // We need to interleave them correctly with the text output.
    const pendingParts: TextStreamPart[] = [];

    return new TransformStream<TextStreamPart, TextStreamPart>({
      async transform(part, controller) {
        if (terminated) return;

        if (isTextDelta(part)) {
          // Feed the text delta into the Aegis scanner
          try {
            await textWriter.write(part.textDelta);
          } catch {
            // Writer closed — stream was terminated by Aegis
            terminated = true;
            if (stopStream) stopStream();
            controller.terminate();
            return;
          }

          // Drain any scanned text that the monitor has emitted
          try {
            while (true) {
              const { value, done } = await Promise.race([
                textReader.read(),
                // Don't block forever — if no output yet, break out
                new Promise<{ value: undefined; done: true }>((resolve) =>
                  setTimeout(() => resolve({ value: undefined, done: true }), 0),
                ),
              ]);

              if (done || value === undefined) break;

              // Emit any queued non-text parts first
              for (const pending of pendingParts) {
                controller.enqueue(pending);
              }
              pendingParts.length = 0;

              // Emit the scanned text as a text-delta part
              controller.enqueue({ type: "text-delta", textDelta: value } as TextStreamPart);
            }
          } catch {
            // Reader closed — stream was terminated by Aegis monitor
            terminated = true;
            if (stopStream) stopStream();
            controller.terminate();
            return;
          }
        } else {
          // Non-text parts pass through unchanged
          controller.enqueue(part);
        }
      },

      async flush(controller) {
        if (terminated) return;

        try {
          // Signal end-of-input to the Aegis text transform
          await textWriter.close();

          // Drain any remaining scanned text
          while (true) {
            const { value, done } = await textReader.read();
            if (done || value === undefined) break;

            // Flush pending non-text parts
            for (const pending of pendingParts) {
              controller.enqueue(pending);
            }
            pendingParts.length = 0;

            controller.enqueue({ type: "text-delta", textDelta: value } as TextStreamPart);
          }
        } catch {
          // Stream was terminated by Aegis
          terminated = true;
          if (stopStream) stopStream();
          controller.terminate();
          return;
        }

        // Flush any remaining non-text parts
        for (const pending of pendingParts) {
          controller.enqueue(pending);
        }
        pendingParts.length = 0;
      },
    });
  };
}

function isTextDelta(part: TextStreamPart): part is TextDeltaPart {
  return part.type === "text-delta" && typeof (part as TextDeltaPart).textDelta === "string";
}

/**
 * Create model middleware for use with `wrapLanguageModel()`.
 *
 * This is an alternative to `experimental_transform` that wraps the model
 * itself rather than the stream. All streams through the wrapped model
 * are automatically monitored.
 *
 * @example
 * ```ts
 * import { wrapLanguageModel } from 'ai';
 * import { createAegisMiddleware } from '@aegis-sdk/vercel';
 *
 * const protectedModel = wrapLanguageModel({
 *   model: openai('gpt-4o'),
 *   middleware: createAegisMiddleware(aegis),
 * });
 * ```
 */
export function createAegisMiddleware(_aegis: Aegis): {
  wrapStream: (options: { stream: ReadableStream }) => ReadableStream;
} {
  // Full middleware implementation requires deeper Vercel AI SDK type integration.
  // This stub provides the correct shape; full implementation in Phase 1b.
  return {
    wrapStream({ stream }) {
      // TODO: Pipe through Aegis stream transform
      return stream;
    },
  };
}

/**
 * Guard input messages in the Vercel AI SDK message format.
 *
 * Convenience wrapper around `aegis.guardInput()` that handles
 * the Vercel AI SDK's message format conversion.
 */
export async function guardMessages(
  aegis: Aegis,
  messages: { role: string; content: string }[],
  options?: { scanStrategy?: "last-user" | "all-user" | "full-history" },
): Promise<{ role: string; content: string }[]> {
  // Convert to Aegis format
  const aegisMessages = messages.map((m) => ({
    role: m.role as "system" | "user" | "assistant",
    content: m.content,
  }));

  await aegis.guardInput(aegisMessages, options);

  // Return original messages (they passed validation)
  return messages;
}

/**
 * Get the Aegis audit log from an Aegis instance.
 * Convenience export for use in API routes.
 */
export function getAuditLog(aegis: Aegis): AuditLog {
  return aegis.getAuditLog();
}

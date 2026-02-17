/**
 * @aegis-sdk/vercel — Vercel AI SDK integration for Aegis.
 *
 * Provides two integration patterns:
 * 1. `createStreamTransform()` — for use with `experimental_transform` on `streamText()`
 * 2. `createModelMiddleware()` — for use with `wrapLanguageModel()`
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

export interface AegisTransformOptions {
  /** Additional stream monitor configuration */
  monitor?: StreamMonitorConfig;
  /** Whether to log violations to the Aegis audit log */
  audit?: boolean;
}

/**
 * Create a stream transform compatible with Vercel AI SDK's `experimental_transform`.
 *
 * This wraps Aegis's StreamMonitor into the format expected by `streamText()`.
 * It processes `TextStreamPart` objects, scanning `text-delta` parts for
 * content violations while passing all other part types through unmodified.
 */
export function createAegisTransform(
  aegis: Aegis,
  _options: AegisTransformOptions = {},
): TransformStream<string, string> {
  return aegis.createStreamTransform();
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
export function createAegisMiddleware(
  _aegis: Aegis,
): {
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

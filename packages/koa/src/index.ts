/**
 * @aegis-sdk/koa — Koa middleware adapter for Aegis prompt injection defense.
 *
 * Provides two integration patterns:
 * 1. `aegisMiddleware()` — Koa middleware that scans `ctx.request.body.messages` before they reach your route handler
 * 2. `aegisStreamTransform()` — helper to wrap response streams with Aegis output monitoring
 *
 * Compatible with Koa 2+ (requires koa-bodyparser or similar body parsing middleware).
 *
 * @example
 * ```ts
 * import Koa from 'koa';
 * import bodyParser from 'koa-bodyparser';
 * import { aegisMiddleware } from '@aegis-sdk/koa';
 *
 * const app = new Koa();
 * app.use(bodyParser());
 *
 * // Apply to all AI chat routes
 * app.use(aegisMiddleware({ policy: 'strict' }));
 *
 * app.use(async (ctx) => {
 *   const { messages } = ctx.state.aegis; // scanned messages
 *   // ... pass to your LLM
 * });
 * ```
 */

import {
  Aegis,
  AegisInputBlocked,
  AegisSessionQuarantined,
  AegisSessionTerminated,
} from "@aegis-sdk/core";
import type { AegisConfig, Detection, GuardInputOptions, AuditLog } from "@aegis-sdk/core";

// Use type-only imports for Koa types so we don't create a runtime dependency.
import type { Context, Next, Middleware } from "koa";

// ─── Types ──────────────────────────────────────────────────────────────────

/** Scan results attached to `ctx.state.aegis` by the middleware. */
export interface AegisRequestData {
  /** The messages after passing through Aegis guardInput (safe to forward to LLM). */
  messages: { role: string; content: string }[];
  /** The Aegis instance used for this request (useful for stream transforms, audit log, etc). */
  instance: Aegis;
  /** The audit log for this request's Aegis instance. */
  auditLog: AuditLog;
}

/** Violation details returned in the 403 response body. */
export interface AegisViolationResponse {
  error: "aegis_blocked";
  message: string;
  detections: Detection[];
  score?: number;
}

/** Configuration for the aegisMiddleware. */
export interface AegisMiddlewareOptions {
  /** Aegis configuration. Accepts a config object or a pre-constructed Aegis instance. */
  aegis?: AegisConfig | Aegis;
  /** Property path on ctx.request.body to read messages from. Defaults to "messages". */
  messagesProperty?: string;
  /** Scan strategy passed to guardInput. */
  scanStrategy?: GuardInputOptions["scanStrategy"];
  /**
   * Custom error handler. If provided, called instead of the default 403 response.
   * Return `true` to indicate you have handled the response; return `false` or
   * `undefined` to fall through to the default handler.
   */
  onBlocked?: (
    ctx: Context,
    detections: Detection[],
    error: AegisInputBlocked | AegisSessionQuarantined | AegisSessionTerminated,
  ) => boolean | undefined | Promise<boolean | undefined>;
}

// ─── Middleware ──────────────────────────────────────────────────────────────

/**
 * Create Koa middleware that scans incoming messages for prompt injection.
 *
 * Reads messages from `ctx.request.body.messages` (configurable via `messagesProperty`),
 * runs them through `aegis.guardInput()`, and either:
 * - Attaches the safe messages to `ctx.state.aegis` and calls `next()`, or
 * - Responds with 403 and violation details if input is blocked.
 *
 * Requires a body parsing middleware (e.g., `koa-bodyparser`) to be applied before this middleware.
 *
 * @param options - Middleware configuration. Can also accept a plain AegisConfig
 *                  for the simple case: `aegisMiddleware({ policy: 'strict' })`.
 * @returns Koa middleware function
 *
 * @example
 * ```ts
 * // Simple usage with AegisConfig
 * app.use(aegisMiddleware({ policy: 'strict' }));
 *
 * // Advanced usage with options
 * app.use(aegisMiddleware({
 *   aegis: { policy: 'strict', recovery: { mode: 'quarantine-session' } },
 *   scanStrategy: 'all-user',
 *   messagesProperty: 'conversation',
 *   onBlocked: (ctx, detections, err) => {
 *     ctx.status = 400;
 *     ctx.body = { blocked: true };
 *     return true;
 *   },
 * }));
 *
 * // Usage with pre-constructed Aegis instance
 * const aegis = new Aegis({ policy: 'strict' });
 * app.use(aegisMiddleware({ aegis }));
 * ```
 */
export function aegisMiddleware(options: AegisMiddlewareOptions | AegisConfig = {}): Middleware {
  // Distinguish between AegisMiddlewareOptions and a plain AegisConfig.
  // If the object has an `aegis` key, `messagesProperty` key, `scanStrategy` key,
  // or `onBlocked` key, treat it as AegisMiddlewareOptions. Otherwise treat it as AegisConfig.
  const opts = isMiddlewareOptions(options) ? options : { aegis: options };

  const messagesProperty = opts.messagesProperty ?? "messages";
  const scanStrategy = opts.scanStrategy ?? "last-user";
  const onBlocked = opts.onBlocked;

  // Resolve the Aegis instance: either use the provided one or create from config.
  const aegisInstance =
    opts.aegis instanceof Aegis ? opts.aegis : new Aegis(opts.aegis as AegisConfig | undefined);

  return async (ctx: Context, next: Next): Promise<void> => {
    // Extract messages from the configured body property.
    // koa-bodyparser augments ctx.request with a `body` property.
    // Cast through `unknown` because Koa's Request type lacks an index signature.
    const body = (ctx.request as unknown as { body?: Record<string, unknown> }).body;

    if (!body || typeof body !== "object") {
      // No body — nothing to scan. Let the route handler decide what to do.
      ctx.state.aegis = {
        messages: [],
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisRequestData;
      await next();
      return;
    }

    const rawMessages = body[messagesProperty];

    if (!Array.isArray(rawMessages)) {
      // No messages array found — attach empty result and continue.
      ctx.state.aegis = {
        messages: [],
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisRequestData;
      await next();
      return;
    }

    // Normalize messages to the format Aegis expects.
    const messages = rawMessages.map((m: Record<string, unknown>) => ({
      role: String(m.role ?? "user") as "system" | "user" | "assistant",
      content: String(m.content ?? ""),
    }));

    try {
      // Run the guard.
      const safeMessages = await aegisInstance.guardInput(messages, { scanStrategy });

      ctx.state.aegis = {
        messages: safeMessages,
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisRequestData;

      await next();
    } catch (error: unknown) {
      if (
        error instanceof AegisInputBlocked ||
        error instanceof AegisSessionQuarantined ||
        error instanceof AegisSessionTerminated
      ) {
        // Build detections array for the callback.
        let detections: Detection[] = [];
        if (error instanceof AegisInputBlocked) {
          detections = error.scanResult.detections;
        }
        if (error instanceof AegisSessionTerminated) {
          detections = error.scanResult.detections;
        }

        // Allow custom handler to take over.
        if (onBlocked) {
          try {
            const handled = await onBlocked(ctx, detections, error);
            if (handled === true) return;
          } catch {
            // If custom handler throws, fall through to default.
          }
        }

        // Default response: 403 with violation details.
        const response: AegisViolationResponse = {
          error: "aegis_blocked",
          message: error.message,
          detections: [],
        };

        if (error instanceof AegisInputBlocked) {
          response.detections = error.scanResult.detections;
          response.score = error.scanResult.score;
        }

        if (error instanceof AegisSessionTerminated) {
          response.detections = error.scanResult.detections;
          response.score = error.scanResult.score;
        }

        ctx.status = 403;
        ctx.body = response;
        return;
      }

      // Unknown error — rethrow so Koa's error handling picks it up.
      throw error;
    }
  };
}

// ─── Stream Transform Helper ────────────────────────────────────────────────

/**
 * Create an Aegis stream transform for monitoring LLM output in Koa responses.
 *
 * Returns a `TransformStream<string, string>` that can be piped through
 * to scan output tokens for prompt injection payloads, PII leaks, canary
 * token leaks, and other violations.
 *
 * @param configOrInstance - AegisConfig object or a pre-constructed Aegis instance.
 * @returns A TransformStream that scans output content.
 *
 * @example
 * ```ts
 * import { aegisMiddleware, aegisStreamTransform } from '@aegis-sdk/koa';
 * import { Aegis } from '@aegis-sdk/core';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 *
 * app.use(aegisMiddleware({ aegis }));
 *
 * app.use(async (ctx) => {
 *   const transform = aegisStreamTransform(aegis);
 *
 *   // Pipe your LLM stream through the transform
 *   const llmStream = getStreamFromLLM(ctx.state.aegis.messages);
 *   const reader = llmStream.pipeThrough(transform).getReader();
 *
 *   ctx.set('Content-Type', 'text/event-stream');
 *   ctx.set('Cache-Control', 'no-cache');
 *   ctx.set('Connection', 'keep-alive');
 *
 *   const { PassThrough } = await import('node:stream');
 *   const stream = new PassThrough();
 *   ctx.body = stream;
 *
 *   while (true) {
 *     const { done, value } = await reader.read();
 *     if (done) break;
 *     stream.write(`data: ${value}\n\n`);
 *   }
 *   stream.end();
 * });
 * ```
 *
 * @example
 * ```ts
 * // Using the Aegis instance from the middleware via ctx.state.aegis
 * app.use(async (ctx) => {
 *   const transform = aegisStreamTransform(ctx.state.aegis.instance);
 *   // ... use transform to pipe LLM output
 * });
 * ```
 */
export function aegisStreamTransform(
  configOrInstance?: AegisConfig | Aegis,
): TransformStream<string, string> {
  const instance =
    configOrInstance instanceof Aegis ? configOrInstance : new Aegis(configOrInstance);

  return instance.createStreamTransform();
}

// ─── Convenience Exports ────────────────────────────────────────────────────

/**
 * Guard messages directly without using the middleware.
 *
 * Useful when you need to scan messages outside of the standard middleware flow,
 * e.g., in WebSocket handlers or custom middleware chains.
 *
 * @param aegis - Aegis instance
 * @param messages - Messages in the standard AI chat format
 * @param options - Scan strategy options
 * @returns The original messages if they pass validation
 * @throws {AegisInputBlocked} if input is blocked
 */
export async function guardMessages(
  aegis: Aegis,
  messages: { role: string; content: string }[],
  options?: GuardInputOptions,
): Promise<{ role: string; content: string }[]> {
  const aegisMessages = messages.map((m) => ({
    role: m.role as "system" | "user" | "assistant",
    content: m.content,
  }));

  await aegis.guardInput(aegisMessages, options);
  return messages;
}

/**
 * Get the Aegis audit log from an Aegis instance.
 * Convenience export for use in Koa routes.
 */
export function getAuditLog(aegis: Aegis): AuditLog {
  return aegis.getAuditLog();
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

/** Type guard to distinguish AegisMiddlewareOptions from a plain AegisConfig. */
function isMiddlewareOptions(
  value: AegisMiddlewareOptions | AegisConfig,
): value is AegisMiddlewareOptions {
  return (
    "aegis" in value ||
    "messagesProperty" in value ||
    "scanStrategy" in value ||
    "onBlocked" in value
  );
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
} from "@aegis-sdk/core";

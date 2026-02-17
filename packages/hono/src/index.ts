/**
 * @aegis-sdk/hono — Hono middleware adapter for Aegis prompt injection defense.
 *
 * Provides three integration patterns:
 * 1. `aegisMiddleware()` — Hono middleware that scans request body messages before they reach your handler
 * 2. `aegisStreamTransform()` — helper to wrap response streams with Aegis output monitoring
 * 3. `guardMessages()` — standalone guard function for scanning messages outside middleware
 *
 * Compatible with Hono >=4.0.0.
 *
 * @example
 * ```ts
 * import { Hono } from 'hono';
 * import { Aegis } from '@aegis-sdk/core';
 * import { aegisMiddleware } from '@aegis-sdk/hono';
 *
 * const app = new Hono();
 * const aegis = new Aegis({ policy: 'strict' });
 *
 * app.post('/api/chat', aegisMiddleware({ aegis }), async (c) => {
 *   const { messages, instance } = c.get('aegis');
 *   // messages are already scanned and safe to forward to your LLM
 *   return c.json({ response: '...' });
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

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * Minimal Hono context type.
 * We define this locally to avoid a runtime dependency on hono.
 * The shape matches hono's Context interface for the methods we use.
 */
interface HonoContext {
  req: {
    json: () => Promise<unknown>;
  };
  get: (key: string) => unknown;
  set: (key: string, value: unknown) => void;
  json: (data: unknown, status?: number) => Response;
}

/** A Hono middleware function. */
type HonoMiddleware = (c: HonoContext, next: () => Promise<void>) => Promise<Response | undefined>;

/** Scan results attached to the Hono context by the middleware. */
export interface AegisContextData {
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
  /** Property path on the request body to read messages from. Defaults to "messages". */
  messagesProperty?: string;
  /** Scan strategy passed to guardInput. */
  scanStrategy?: GuardInputOptions["scanStrategy"];
  /**
   * Custom error handler. If provided, called instead of the default 403 response.
   * Return a Response to take over the response; return `undefined` or `null`
   * to fall through to the default handler.
   */
  onBlocked?: (
    c: HonoContext,
    error: AegisInputBlocked | AegisSessionQuarantined | AegisSessionTerminated,
  ) => Response | undefined | null | Promise<Response | undefined | null>;
}

// ─── Middleware ──────────────────────────────────────────────────────────────

/**
 * Create Hono middleware that scans incoming messages for prompt injection.
 *
 * Reads messages from the request body's `messages` property (configurable),
 * runs them through `aegis.guardInput()`, and either:
 * - Attaches the safe messages to `c.set('aegis', ...)` and calls `next()`, or
 * - Responds with 403 and violation details if input is blocked.
 *
 * @param options - Middleware configuration. Can also accept a plain AegisConfig
 *                  for the simple case: `aegisMiddleware({ policy: 'strict' })`.
 * @returns Hono middleware function
 *
 * @example
 * ```ts
 * // Simple usage with AegisConfig
 * app.post('/chat', aegisMiddleware({ policy: 'strict' }), handler);
 *
 * // Advanced usage with options
 * app.post('/chat', aegisMiddleware({
 *   aegis: { policy: 'strict', recovery: { mode: 'quarantine-session' } },
 *   scanStrategy: 'all-user',
 *   messagesProperty: 'conversation',
 *   onBlocked: (c, err) => {
 *     return c.json({ blocked: true }, 400);
 *   },
 * }), handler);
 *
 * // Usage with pre-constructed Aegis instance
 * const aegis = new Aegis({ policy: 'strict' });
 * app.post('/chat', aegisMiddleware({ aegis }), handler);
 * ```
 */
export function aegisMiddleware(
  options: AegisMiddlewareOptions | AegisConfig = {},
): HonoMiddleware {
  // Distinguish between AegisMiddlewareOptions and a plain AegisConfig.
  const opts = isMiddlewareOptions(options) ? options : { aegis: options };

  const messagesProperty = opts.messagesProperty ?? "messages";
  const scanStrategy = opts.scanStrategy ?? "last-user";
  const onBlocked = opts.onBlocked;

  // Resolve the Aegis instance: either use the provided one or create from config.
  const aegisInstance =
    opts.aegis instanceof Aegis ? opts.aegis : new Aegis(opts.aegis as AegisConfig | undefined);

  return async (c: HonoContext, next: () => Promise<void>): Promise<Response | undefined> => {
    // Parse the request body
    let body: Record<string, unknown> | undefined;
    try {
      body = (await c.req.json()) as Record<string, unknown>;
    } catch {
      // No valid JSON body — nothing to scan.
      c.set("aegis", {
        messages: [],
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisContextData);
      await next();
      return;
    }

    if (!body || typeof body !== "object") {
      c.set("aegis", {
        messages: [],
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisContextData);
      await next();
      return;
    }

    const rawMessages = body[messagesProperty];

    if (!Array.isArray(rawMessages)) {
      // No messages array found — attach empty result and continue.
      c.set("aegis", {
        messages: [],
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisContextData);
      await next();
      return;
    }

    // Normalize messages to the format Aegis expects.
    const messages = rawMessages.map((m: Record<string, unknown>) => ({
      role: String(m.role ?? "user") as "system" | "user" | "assistant",
      content: String(m.content ?? ""),
    }));

    // Run the async guard and handle the result.
    try {
      const safeMessages = await aegisInstance.guardInput(messages, { scanStrategy });

      c.set("aegis", {
        messages: safeMessages,
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisContextData);

      await next();
    } catch (error: unknown) {
      if (
        error instanceof AegisInputBlocked ||
        error instanceof AegisSessionQuarantined ||
        error instanceof AegisSessionTerminated
      ) {
        // Allow custom handler to take over.
        if (onBlocked) {
          try {
            const customResponse = await onBlocked(c, error);
            if (customResponse) return customResponse;
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

        return c.json(response, 403);
      }

      // Unknown error — rethrow for Hono's error handling.
      throw error;
    }
  };
}

// ─── Stream Transform Helper ────────────────────────────────────────────────

/**
 * Create an Aegis stream transform for monitoring LLM output in Hono responses.
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
 * import { aegisMiddleware, aegisStreamTransform } from '@aegis-sdk/hono';
 * import { Aegis } from '@aegis-sdk/core';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 *
 * app.post('/chat', aegisMiddleware({ aegis }), async (c) => {
 *   const transform = aegisStreamTransform(aegis);
 *
 *   // Pipe your LLM stream through the transform
 *   const llmStream = getStreamFromLLM(c.get('aegis').messages);
 *   const monitoredStream = llmStream.pipeThrough(transform);
 *
 *   return new Response(monitoredStream, {
 *     headers: { 'Content-Type': 'text/event-stream' },
 *   });
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
 * Convenience export for use in Hono routes.
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

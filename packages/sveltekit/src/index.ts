/**
 * @aegis-sdk/sveltekit — SvelteKit hooks and handle adapter for Aegis.
 *
 * Provides three integration patterns:
 * 1. `aegisHandle()` — SvelteKit handle hook that scans request body messages
 * 2. `aegisStreamTransform()` — helper to wrap response streams
 * 3. `guardMessages()` — standalone guard function
 *
 * Compatible with SvelteKit >=2.0.0.
 *
 * @example
 * ```ts
 * // src/hooks.server.ts
 * import { aegisHandle } from '@aegis-sdk/sveltekit';
 *
 * export const handle = aegisHandle({ aegis: { policy: 'strict' } });
 * ```
 *
 * @example
 * ```ts
 * // src/hooks.server.ts — composing with other handles via sequence()
 * import { sequence } from '@sveltejs/kit/hooks';
 * import { aegisHandle } from '@aegis-sdk/sveltekit';
 *
 * const aegis = aegisHandle({
 *   aegis: { policy: 'strict' },
 *   routes: ['/api/chat', /^\/api\/ai\//],
 * });
 *
 * export const handle = sequence(aegis, yourOtherHandle);
 * ```
 *
 * @example
 * ```ts
 * // src/routes/api/chat/+server.ts — using event.locals.aegis
 * import type { RequestHandler } from './$types';
 *
 * export const POST: RequestHandler = async ({ locals }) => {
 *   const { messages, instance, auditLog } = locals.aegis;
 *   // messages are already scanned and safe to forward to your LLM
 *   return new Response(JSON.stringify({ response: '...' }));
 * };
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
 * Minimal SvelteKit RequestEvent type.
 * We define this locally to avoid a runtime dependency on @sveltejs/kit.
 * The shape matches SvelteKit's RequestEvent interface for the methods we use.
 */
interface RequestEvent {
  request: Request;
  locals: Record<string, unknown>;
  url: URL;
}

/** Promise or value. */
type MaybePromise<T> = T | Promise<T>;

/** SvelteKit Handle function shape. */
type Handle = (input: {
  event: RequestEvent;
  resolve: (event: RequestEvent) => MaybePromise<Response>;
}) => MaybePromise<Response>;

/** Scan results attached to event.locals.aegis by the handle hook. */
export interface AegisLocalsData {
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

/** Configuration for the aegisHandle hook. */
export interface AegisHandleOptions {
  /** Aegis configuration. Accepts a config object or a pre-constructed Aegis instance. */
  aegis?: AegisConfig | Aegis;
  /**
   * Routes to protect. Supports string prefixes and RegExp patterns.
   * If omitted, all POST requests are scanned.
   */
  routes?: string[] | RegExp[];
  /** Property path on the request body to read messages from. Defaults to "messages". */
  messagesProperty?: string;
  /** Scan strategy passed to guardInput. */
  scanStrategy?: GuardInputOptions["scanStrategy"];
  /**
   * Custom error handler. If provided, called instead of the default 403 response.
   * Return a Response to take over the response; return `null` or `undefined`
   * to fall through to the default handler.
   */
  onBlocked?: (
    event: RequestEvent,
    error: AegisInputBlocked | AegisSessionQuarantined | AegisSessionTerminated,
  ) => MaybePromise<Response | null>;
}

// ─── Handle Hook ─────────────────────────────────────────────────────────────

/**
 * Create a SvelteKit handle hook that scans incoming messages for prompt injection.
 *
 * Reads messages from the request body's `messages` property (configurable),
 * runs them through `aegis.guardInput()`, and either:
 * - Attaches the safe messages to `event.locals.aegis` and calls `resolve(event)`, or
 * - Responds with 403 and violation details if input is blocked.
 *
 * Non-POST requests and routes not matching the `routes` filter are passed through
 * without scanning.
 *
 * @param options - Handle hook configuration. Can also accept a plain AegisConfig
 *                  for the simple case: `aegisHandle({ policy: 'strict' })`.
 * @returns SvelteKit Handle function
 *
 * @example
 * ```ts
 * // Simple usage with AegisConfig
 * export const handle = aegisHandle({ policy: 'strict' });
 *
 * // Advanced usage with options
 * export const handle = aegisHandle({
 *   aegis: { policy: 'strict', recovery: { mode: 'quarantine-session' } },
 *   routes: ['/api/chat', /^\/api\/ai\//],
 *   scanStrategy: 'all-user',
 *   messagesProperty: 'conversation',
 *   onBlocked: (event, err) => {
 *     return new Response(JSON.stringify({ blocked: true }), { status: 400 });
 *   },
 * });
 *
 * // Usage with pre-constructed Aegis instance
 * const aegis = new Aegis({ policy: 'strict' });
 * export const handle = aegisHandle({ aegis });
 * ```
 */
export function aegisHandle(options: AegisHandleOptions | AegisConfig = {}): Handle {
  // Distinguish between AegisHandleOptions and a plain AegisConfig.
  const opts = isHandleOptions(options) ? options : { aegis: options };

  const messagesProperty = opts.messagesProperty ?? "messages";
  const scanStrategy = opts.scanStrategy ?? "last-user";
  const routes = opts.routes;
  const onBlocked = opts.onBlocked;

  // Resolve the Aegis instance: either use the provided one or create from config.
  const aegisInstance =
    opts.aegis instanceof Aegis ? opts.aegis : new Aegis(opts.aegis as AegisConfig | undefined);

  return async ({
    event,
    resolve,
  }: {
    event: RequestEvent;
    resolve: (event: RequestEvent) => MaybePromise<Response>;
  }): Promise<Response> => {
    // Only scan POST requests
    if (event.request.method !== "POST") {
      return resolve(event);
    }

    // Check route matching if configured
    if (routes && routes.length > 0) {
      const pathname = event.url.pathname;
      const matched = routes.some((route) => {
        if (typeof route === "string") {
          return pathname.startsWith(route);
        }
        return route.test(pathname);
      });

      if (!matched) {
        return resolve(event);
      }
    }

    // Parse the request body.
    // We clone the request so the body can be consumed again by downstream handlers.
    let body: Record<string, unknown> | undefined;
    try {
      body = (await event.request.clone().json()) as Record<string, unknown>;
    } catch {
      // No valid JSON body — nothing to scan.
      event.locals.aegis = {
        messages: [],
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisLocalsData;
      return resolve(event);
    }

    if (!body || typeof body !== "object") {
      event.locals.aegis = {
        messages: [],
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisLocalsData;
      return resolve(event);
    }

    const rawMessages = body[messagesProperty];

    if (!Array.isArray(rawMessages)) {
      // No messages array found — attach empty result and continue.
      event.locals.aegis = {
        messages: [],
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisLocalsData;
      return resolve(event);
    }

    // Normalize messages to the format Aegis expects.
    const messages = rawMessages.map((m: Record<string, unknown>) => ({
      role: String(m.role ?? "user") as "system" | "user" | "assistant",
      content: String(m.content ?? ""),
    }));

    // Run the async guard and handle the result.
    try {
      const safeMessages = await aegisInstance.guardInput(messages, { scanStrategy });

      event.locals.aegis = {
        messages: safeMessages,
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisLocalsData;

      return resolve(event);
    } catch (error: unknown) {
      if (
        error instanceof AegisInputBlocked ||
        error instanceof AegisSessionQuarantined ||
        error instanceof AegisSessionTerminated
      ) {
        // Allow custom handler to take over.
        if (onBlocked) {
          try {
            const customResponse = await onBlocked(event, error);
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

        return new Response(JSON.stringify(response), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Unknown error — rethrow for SvelteKit's error handling.
      throw error;
    }
  };
}

// ─── Stream Transform Helper ────────────────────────────────────────────────

/**
 * Create an Aegis stream transform for monitoring LLM output in SvelteKit responses.
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
 * // src/routes/api/chat/+server.ts
 * import { aegisStreamTransform } from '@aegis-sdk/sveltekit';
 * import { Aegis } from '@aegis-sdk/core';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 *
 * export const POST: RequestHandler = async ({ locals }) => {
 *   const transform = aegisStreamTransform(aegis);
 *
 *   // Pipe your LLM stream through the transform
 *   const llmStream = getStreamFromLLM(locals.aegis.messages);
 *   const monitoredStream = llmStream.pipeThrough(transform);
 *
 *   return new Response(monitoredStream, {
 *     headers: { 'Content-Type': 'text/event-stream' },
 *   });
 * };
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
 * Guard messages directly without using the handle hook.
 *
 * Useful when you need to scan messages outside of the standard hook flow,
 * e.g., in form actions, WebSocket handlers, or custom server routes.
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
 * Convenience export for use in SvelteKit routes.
 */
export function getAuditLog(aegis: Aegis): AuditLog {
  return aegis.getAuditLog();
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

/** Type guard to distinguish AegisHandleOptions from a plain AegisConfig. */
function isHandleOptions(value: AegisHandleOptions | AegisConfig): value is AegisHandleOptions {
  return (
    "aegis" in value ||
    "messagesProperty" in value ||
    "scanStrategy" in value ||
    "onBlocked" in value ||
    "routes" in value
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

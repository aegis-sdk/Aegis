/**
 * @aegis-sdk/fastify — Fastify plugin adapter for Aegis prompt injection defense.
 *
 * Provides three integration patterns:
 * 1. `aegisPlugin()` — Fastify plugin that scans request body messages via a preHandler hook
 * 2. `aegisStreamTransform()` — helper to wrap response streams with Aegis output monitoring
 * 3. `guardMessages()` — standalone guard function for scanning messages outside the plugin
 *
 * Compatible with Fastify >=4.0.0.
 *
 * @example
 * ```ts
 * import Fastify from 'fastify';
 * import { aegisPlugin } from '@aegis-sdk/fastify';
 *
 * const app = Fastify();
 *
 * app.register(aegisPlugin, {
 *   aegis: { policy: 'strict' },
 *   routes: ['/api/chat'],
 * });
 *
 * app.post('/api/chat', async (request, reply) => {
 *   const { messages, instance } = request.aegis;
 *   // messages are already scanned and safe to forward to your LLM
 *   return { response: '...' };
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

// ─── Minimal Fastify Types ──────────────────────────────────────────────────
// Defined locally to avoid a hard runtime dependency on fastify.

/** Minimal Fastify request shape. */
interface FastifyRequest {
  method: string;
  body: unknown;
  url: string;
  routeOptions?: { url?: string };
  aegis?: AegisRequestData;
}

/** Minimal Fastify reply shape. */
interface FastifyReply {
  status: (code: number) => FastifyReply;
  send: (payload: unknown) => FastifyReply;
  hijack: () => void;
}

/** Minimal Fastify instance shape for plugin registration. */
interface FastifyInstance {
  decorateRequest: (property: string, value: unknown) => void;
  addHook: (
    hook: string,
    handler: (request: FastifyRequest, reply: FastifyReply) => Promise<void>,
  ) => void;
}

/** Fastify plugin callback shape. */
type FastifyPluginCallback<T> = (
  instance: FastifyInstance,
  opts: T,
  done: (err?: Error) => void,
) => void;

// ─── Types ──────────────────────────────────────────────────────────────────

/** Scan results attached to `request.aegis` by the plugin's preHandler hook. */
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

/** Configuration for the aegisPlugin. */
export interface AegisPluginOptions {
  /** Aegis configuration. Accepts a config object or a pre-constructed Aegis instance. */
  aegis?: AegisConfig | Aegis;
  /**
   * Routes to protect. Supports string prefixes and RegExp patterns.
   * If omitted, all POST requests are scanned.
   */
  routes?: (string | RegExp)[];
  /** HTTP methods to scan. Defaults to `["POST"]`. */
  methods?: string[];
  /** Property path on the request body to read messages from. Defaults to "messages". */
  messagesProperty?: string;
  /** Scan strategy passed to guardInput. */
  scanStrategy?: GuardInputOptions["scanStrategy"];
  /**
   * Custom error handler. If provided, called instead of the default 403 response.
   * Return a truthy value to indicate the response has been handled; return
   * `undefined` or `null` to fall through to the default handler.
   */
  onBlocked?: (
    request: FastifyRequest,
    reply: FastifyReply,
    error: AegisInputBlocked | AegisSessionQuarantined | AegisSessionTerminated,
  ) => unknown | Promise<unknown>;
}

// ─── Plugin ─────────────────────────────────────────────────────────────────

/**
 * Fastify plugin that scans incoming messages for prompt injection.
 *
 * Registers a `preHandler` hook that reads messages from the request body's
 * `messages` property (configurable), runs them through `aegis.guardInput()`,
 * and either:
 * - Attaches the safe messages to `request.aegis` and continues, or
 * - Responds with 403 and violation details if input is blocked.
 *
 * Non-matching methods and routes are passed through without scanning.
 *
 * @param options - Plugin configuration. Can also accept a plain AegisConfig
 *                  for the simple case.
 *
 * @example
 * ```ts
 * // Simple usage
 * app.register(aegisPlugin, { aegis: { policy: 'strict' } });
 *
 * // Advanced usage with route filtering
 * app.register(aegisPlugin, {
 *   aegis: { policy: 'strict', recovery: { mode: 'quarantine-session' } },
 *   routes: ['/api/chat', /^\/api\/ai\//],
 *   scanStrategy: 'all-user',
 *   messagesProperty: 'conversation',
 *   onBlocked: (request, reply, err) => {
 *     reply.status(400).send({ blocked: true });
 *     return true;
 *   },
 * });
 *
 * // Usage with pre-constructed Aegis instance
 * const aegis = new Aegis({ policy: 'strict' });
 * app.register(aegisPlugin, { aegis });
 * ```
 */
export const aegisPlugin: FastifyPluginCallback<AegisPluginOptions | AegisConfig> = (
  fastify: FastifyInstance,
  options: AegisPluginOptions | AegisConfig,
  done: (err?: Error) => void,
) => {
  // Distinguish between AegisPluginOptions and a plain AegisConfig.
  const opts = isPluginOptions(options) ? options : ({ aegis: options } as AegisPluginOptions);

  const messagesProperty = opts.messagesProperty ?? "messages";
  const scanStrategy = opts.scanStrategy ?? "last-user";
  const routes = opts.routes;
  const methods = (opts.methods ?? ["POST"]).map((m) => m.toUpperCase());
  const onBlocked = opts.onBlocked;

  // Resolve the Aegis instance: either use the provided one or create from config.
  const aegisInstance =
    opts.aegis instanceof Aegis ? opts.aegis : new Aegis(opts.aegis as AegisConfig | undefined);

  // Decorate request with the aegis property so Fastify knows about it.
  fastify.decorateRequest("aegis", null);

  // Add preHandler hook to scan incoming messages.
  fastify.addHook("preHandler", async (request: FastifyRequest, reply: FastifyReply) => {
    // Only scan configured methods (default: POST).
    if (!methods.includes(request.method.toUpperCase())) {
      return;
    }

    // Check route matching if configured.
    if (routes && routes.length > 0) {
      const pathname = extractPathname(request.url);
      const matched = routes.some((route) => {
        if (typeof route === "string") {
          return pathname.startsWith(route);
        }
        return route.test(pathname);
      });

      if (!matched) {
        return;
      }
    }

    // Parse the request body.
    const body = request.body as Record<string, unknown> | undefined;

    if (!body || typeof body !== "object") {
      // No valid body — nothing to scan.
      request.aegis = {
        messages: [],
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisRequestData;
      return;
    }

    const rawMessages = body[messagesProperty];

    if (!Array.isArray(rawMessages)) {
      // No messages array found — attach empty result and continue.
      request.aegis = {
        messages: [],
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisRequestData;
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

      request.aegis = {
        messages: safeMessages,
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      } satisfies AegisRequestData;
    } catch (error: unknown) {
      if (
        error instanceof AegisInputBlocked ||
        error instanceof AegisSessionQuarantined ||
        error instanceof AegisSessionTerminated
      ) {
        // Allow custom handler to take over.
        if (onBlocked) {
          try {
            const customResult = await onBlocked(request, reply, error);
            if (customResult) return;
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

        reply.status(403).send(response);
        return;
      }

      // Unknown error — rethrow for Fastify's error handling.
      throw error;
    }
  });

  done();
};

// ─── Stream Transform Helper ────────────────────────────────────────────────

/**
 * Create an Aegis stream transform for monitoring LLM output in Fastify responses.
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
 * import { aegisPlugin, aegisStreamTransform } from '@aegis-sdk/fastify';
 * import { Aegis } from '@aegis-sdk/core';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 *
 * app.post('/chat', async (request, reply) => {
 *   const transform = aegisStreamTransform(aegis);
 *
 *   // Pipe your LLM stream through the transform
 *   const llmStream = getStreamFromLLM(request.aegis.messages);
 *   const monitoredStream = llmStream.pipeThrough(transform);
 *
 *   reply.send(monitoredStream);
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
 * Guard messages directly without using the plugin.
 *
 * Useful when you need to scan messages outside of the standard plugin flow,
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
 * Convenience export for use in Fastify routes.
 */
export function getAuditLog(aegis: Aegis): AuditLog {
  return aegis.getAuditLog();
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

/** Type guard to distinguish AegisPluginOptions from a plain AegisConfig. */
function isPluginOptions(value: AegisPluginOptions | AegisConfig): value is AegisPluginOptions {
  return (
    "aegis" in value ||
    "messagesProperty" in value ||
    "scanStrategy" in value ||
    "onBlocked" in value ||
    "routes" in value ||
    "methods" in value
  );
}

/**
 * Extract the pathname from a Fastify request URL.
 * Fastify's `request.url` is the raw URL string (e.g., "/api/chat?foo=bar"),
 * so we strip the query string if present.
 */
function extractPathname(url: string): string {
  const qIndex = url.indexOf("?");
  return qIndex === -1 ? url : url.slice(0, qIndex);
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

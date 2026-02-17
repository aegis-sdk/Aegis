/**
 * @aegis-sdk/next — Next.js integration for Aegis prompt injection defense.
 *
 * Provides three integration patterns:
 * 1. `withAegis()` — Higher-order function that wraps a Next.js API route handler
 * 2. `aegisMiddleware()` — Next.js Edge Middleware function for request-level scanning
 * 3. `guardMessages()` — Standalone guard function for scanning messages
 *
 * Compatible with Next.js >=13.0.0 (App Router and Pages Router).
 *
 * @example
 * ```ts
 * // app/api/chat/route.ts
 * import { Aegis } from '@aegis-sdk/core';
 * import { withAegis } from '@aegis-sdk/next';
 * import { streamText } from 'ai';
 * import { openai } from '@ai-sdk/openai';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 *
 * export const POST = withAegis(aegis, async (req, safeMessages) => {
 *   const result = streamText({
 *     model: openai('gpt-4o'),
 *     messages: safeMessages,
 *   });
 *   return result.toDataStreamResponse();
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
 * Minimal Next.js Request type.
 * We define this locally to avoid a runtime dependency on next.
 * Compatible with both standard Request (App Router) and NextRequest.
 */
interface NextLikeRequest {
  json: () => Promise<unknown>;
  url: string;
  method: string;
  headers: Headers;
}

/**
 * Minimal NextResponse shape for edge middleware.
 * We create standard Response objects instead of importing NextResponse
 * to avoid runtime dependency.
 */

/** Message format used throughout the adapters. */
export interface ChatMessage {
  role: string;
  content: string;
}

/** Violation details returned in the 403 response body. */
export interface AegisViolationResponse {
  error: "aegis_blocked";
  message: string;
  detections: Detection[];
  score?: number;
}

/** Configuration for `withAegis()`. */
export interface WithAegisOptions {
  /** Property path on the request body to read messages from. Defaults to "messages". */
  messagesProperty?: string;
  /** Scan strategy passed to guardInput. */
  scanStrategy?: GuardInputOptions["scanStrategy"];
  /**
   * Custom error handler. If provided, called instead of the default 403 response.
   * Return a Response to take over; return `undefined` to fall through to the default.
   */
  onBlocked?: (
    req: NextLikeRequest,
    error: AegisInputBlocked | AegisSessionQuarantined | AegisSessionTerminated,
  ) => Response | undefined | Promise<Response | undefined>;
}

/** Configuration for `aegisMiddleware()`. */
export interface AegisEdgeMiddlewareOptions {
  /** Aegis configuration. Accepts a config object or a pre-constructed Aegis instance. */
  aegis?: AegisConfig | Aegis;
  /** Property path on the request body to read messages from. Defaults to "messages". */
  messagesProperty?: string;
  /** Scan strategy passed to guardInput. */
  scanStrategy?: GuardInputOptions["scanStrategy"];
  /**
   * Route patterns to apply scanning to. If provided, only requests matching
   * one of these patterns will be scanned. Supports string prefixes and RegExp.
   * Defaults to scanning all POST requests.
   */
  matchRoutes?: (string | RegExp)[];
  /**
   * Custom error handler. If provided, called instead of the default 403 response.
   * Return a Response to take over; return `undefined` to fall through to the default.
   */
  onBlocked?: (
    req: NextLikeRequest,
    error: AegisInputBlocked | AegisSessionQuarantined | AegisSessionTerminated,
  ) => Response | undefined | Promise<Response | undefined>;
}

/** The handler function shape for `withAegis()`. */
type AegisRouteHandler = (
  req: NextLikeRequest,
  safeMessages: ChatMessage[],
  aegisData: { instance: Aegis; auditLog: AuditLog },
) => Response | Promise<Response>;

// ─── withAegis ──────────────────────────────────────────────────────────────

/**
 * Higher-order function that wraps a Next.js API route handler with Aegis protection.
 *
 * Reads messages from the request body, scans them through Aegis `guardInput()`,
 * and passes the safe messages to your handler function. If input is blocked,
 * responds with 403 and violation details.
 *
 * @param aegisOrConfig - Aegis instance or AegisConfig
 * @param handler - Your route handler that receives the request and safe messages
 * @param options - Additional configuration options
 * @returns A Next.js-compatible route handler function
 *
 * @example
 * ```ts
 * // app/api/chat/route.ts
 * import { Aegis } from '@aegis-sdk/core';
 * import { withAegis } from '@aegis-sdk/next';
 * import { streamText } from 'ai';
 * import { openai } from '@ai-sdk/openai';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 *
 * export const POST = withAegis(aegis, async (req, safeMessages) => {
 *   const result = streamText({
 *     model: openai('gpt-4o'),
 *     messages: safeMessages,
 *   });
 *   return result.toDataStreamResponse();
 * });
 * ```
 *
 * @example
 * ```ts
 * // With options
 * export const POST = withAegis(
 *   aegis,
 *   async (req, safeMessages, { instance, auditLog }) => {
 *     // Access the Aegis instance and audit log
 *     const transform = instance.createStreamTransform();
 *     // ...
 *     return new Response('ok');
 *   },
 *   {
 *     scanStrategy: 'all-user',
 *     messagesProperty: 'conversation',
 *     onBlocked: (req, err) => {
 *       return new Response(JSON.stringify({ blocked: true }), { status: 400 });
 *     },
 *   },
 * );
 * ```
 */
export function withAegis(
  aegisOrConfig: Aegis | AegisConfig,
  handler: AegisRouteHandler,
  options: WithAegisOptions = {},
): (req: NextLikeRequest) => Promise<Response> {
  const aegisInstance = aegisOrConfig instanceof Aegis ? aegisOrConfig : new Aegis(aegisOrConfig);

  const messagesProperty = options.messagesProperty ?? "messages";
  const scanStrategy = options.scanStrategy ?? "last-user";
  const onBlocked = options.onBlocked;

  return async (req: NextLikeRequest): Promise<Response> => {
    // Parse the request body
    let body: Record<string, unknown> | undefined;
    try {
      body = (await req.json()) as Record<string, unknown>;
    } catch {
      // No valid JSON body — pass empty messages to handler
      return handler(req, [], { instance: aegisInstance, auditLog: aegisInstance.getAuditLog() });
    }

    if (!body || typeof body !== "object") {
      return handler(req, [], { instance: aegisInstance, auditLog: aegisInstance.getAuditLog() });
    }

    const rawMessages = body[messagesProperty];

    if (!Array.isArray(rawMessages)) {
      return handler(req, [], { instance: aegisInstance, auditLog: aegisInstance.getAuditLog() });
    }

    // Normalize messages to the format Aegis expects.
    const messages: ChatMessage[] = rawMessages.map((m: Record<string, unknown>) => ({
      role: String(m.role ?? "user"),
      content: String(m.content ?? ""),
    }));

    const aegisMessages = messages.map((m) => ({
      role: m.role as "system" | "user" | "assistant",
      content: m.content,
    }));

    // Run the async guard
    try {
      const safeMessages = await aegisInstance.guardInput(aegisMessages, { scanStrategy });

      // Convert back to ChatMessage format for the handler
      const safeChat: ChatMessage[] = safeMessages.map((m) => ({
        role: m.role,
        content: m.content,
      }));

      return handler(req, safeChat, {
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      });
    } catch (error: unknown) {
      if (
        error instanceof AegisInputBlocked ||
        error instanceof AegisSessionQuarantined ||
        error instanceof AegisSessionTerminated
      ) {
        // Allow custom handler to take over.
        if (onBlocked) {
          try {
            const customResponse = await onBlocked(req, error);
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

      // Unknown error — return 500
      return new Response(
        JSON.stringify({ error: "internal_error", message: "An unexpected error occurred" }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
  };
}

// ─── Edge Middleware ─────────────────────────────────────────────────────────

/**
 * Create a Next.js Edge Middleware function for request-level scanning.
 *
 * This is designed for use in `middleware.ts` at the root of a Next.js project.
 * It scans incoming POST request bodies for prompt injection before the request
 * reaches your API route handlers.
 *
 * Note: Edge Middleware has limitations — it cannot access Node.js APIs.
 * This function uses only Web Standard APIs (fetch, Request, Response).
 *
 * @param options - Middleware configuration
 * @returns A middleware function compatible with Next.js Edge Middleware
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { aegisMiddleware } from '@aegis-sdk/next';
 * import { Aegis } from '@aegis-sdk/core';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 *
 * const aegisMw = aegisMiddleware({
 *   aegis,
 *   matchRoutes: ['/api/chat', '/api/ai'],
 * });
 *
 * export async function middleware(req: Request) {
 *   return aegisMw(req);
 * }
 *
 * export const config = {
 *   matcher: ['/api/chat/:path*', '/api/ai/:path*'],
 * };
 * ```
 */
export function aegisMiddleware(
  options: AegisEdgeMiddlewareOptions = {},
): (req: NextLikeRequest) => Promise<Response> {
  const aegisInstance =
    options.aegis instanceof Aegis
      ? options.aegis
      : new Aegis(options.aegis as AegisConfig | undefined);

  const messagesProperty = options.messagesProperty ?? "messages";
  const scanStrategy = options.scanStrategy ?? "last-user";
  const matchRoutes = options.matchRoutes;
  const onBlocked = options.onBlocked;

  return async (req: NextLikeRequest): Promise<Response> => {
    // Only scan POST requests
    if (req.method !== "POST") {
      // Let the request pass through (return a next()-equivalent response)
      return new Response(null, { status: 200, headers: { "x-aegis": "skipped" } });
    }

    // Check route matching if configured
    if (matchRoutes && matchRoutes.length > 0) {
      const url = new URL(req.url, "http://localhost");
      const pathname = url.pathname;
      const matched = matchRoutes.some((route) => {
        if (typeof route === "string") {
          return pathname.startsWith(route);
        }
        return route.test(pathname);
      });

      if (!matched) {
        return new Response(null, { status: 200, headers: { "x-aegis": "skipped" } });
      }
    }

    // Clone the request so the body can be read again by downstream handlers.
    // Edge Middleware needs to forward the request, so we need to preserve the body.
    let body: Record<string, unknown> | undefined;
    try {
      body = (await req.json()) as Record<string, unknown>;
    } catch {
      // No valid JSON body — let the request pass through
      return new Response(null, { status: 200, headers: { "x-aegis": "pass" } });
    }

    if (!body || typeof body !== "object") {
      return new Response(null, { status: 200, headers: { "x-aegis": "pass" } });
    }

    const rawMessages = body[messagesProperty];

    if (!Array.isArray(rawMessages)) {
      return new Response(null, { status: 200, headers: { "x-aegis": "pass" } });
    }

    // Normalize messages
    const messages = rawMessages.map((m: Record<string, unknown>) => ({
      role: String(m.role ?? "user") as "system" | "user" | "assistant",
      content: String(m.content ?? ""),
    }));

    // Run the guard
    try {
      await aegisInstance.guardInput(messages, { scanStrategy });

      // Input is safe — let the request pass through
      return new Response(null, { status: 200, headers: { "x-aegis": "pass" } });
    } catch (error: unknown) {
      if (
        error instanceof AegisInputBlocked ||
        error instanceof AegisSessionQuarantined ||
        error instanceof AegisSessionTerminated
      ) {
        // Allow custom handler to take over.
        if (onBlocked) {
          try {
            const customResponse = await onBlocked(req, error);
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

      // Unknown error — let it pass (don't break the middleware chain)
      return new Response(null, { status: 200, headers: { "x-aegis": "error" } });
    }
  };
}

// ─── Convenience Exports ────────────────────────────────────────────────────

/**
 * Guard messages directly without using middleware or withAegis.
 *
 * Useful when you need to scan messages outside of the standard patterns,
 * e.g., in Server Actions, API routes with custom body parsing, or WebSocket handlers.
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
 * Convenience export for use in Next.js routes.
 */
export function getAuditLog(aegis: Aegis): AuditLog {
  return aegis.getAuditLog();
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

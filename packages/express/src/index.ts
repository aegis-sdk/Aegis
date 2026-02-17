/**
 * @aegis-sdk/express — Express middleware adapter for Aegis prompt injection defense.
 *
 * Provides two integration patterns:
 * 1. `aegisMiddleware()` — Express middleware that scans `req.body.messages` before they reach your route handler
 * 2. `aegisStreamTransform()` — helper to wrap response streams with Aegis output monitoring
 *
 * Compatible with Express 4 and Express 5.
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { aegisMiddleware } from '@aegis-sdk/express';
 *
 * const app = express();
 * app.use(express.json());
 *
 * // Apply to all AI chat routes
 * app.post('/api/chat', aegisMiddleware({ policy: 'strict' }), (req, res) => {
 *   const { messages } = req.aegis; // scanned messages
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

// Use type-only imports for Express types so we don't create a runtime dependency.
// This works with both Express 4 and Express 5 since the middleware signature is the same.
import type { Request, Response, NextFunction } from "express";

// ─── Types ──────────────────────────────────────────────────────────────────

/** Scan results attached to the request by the middleware. */
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
  /** Property path on req.body to read messages from. Defaults to "messages". */
  messagesProperty?: string;
  /** Scan strategy passed to guardInput. */
  scanStrategy?: GuardInputOptions["scanStrategy"];
  /**
   * Custom error handler. If provided, called instead of the default 403 response.
   * Return `true` to indicate you have handled the response; return `false` or
   * `undefined` to fall through to the default handler.
   */
  onBlocked?: (
    req: Request,
    res: Response,
    error: AegisInputBlocked | AegisSessionQuarantined | AegisSessionTerminated,
  ) => boolean | undefined | Promise<boolean | undefined>;
}

// ─── Module Augmentation ────────────────────────────────────────────────────

// Extend the Express Request interface so `req.aegis` is typed.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      aegis?: AegisRequestData;
    }
  }
}

// ─── Middleware ──────────────────────────────────────────────────────────────

/**
 * Create Express middleware that scans incoming messages for prompt injection.
 *
 * Reads messages from `req.body.messages` (configurable via `messagesProperty`),
 * runs them through `aegis.guardInput()`, and either:
 * - Attaches the safe messages to `req.aegis` and calls `next()`, or
 * - Responds with 403 and violation details if input is blocked.
 *
 * @param options - Middleware configuration. Can also accept a plain AegisConfig
 *                  for the simple case: `aegisMiddleware({ policy: 'strict' })`.
 * @returns Express middleware function
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
 *   onBlocked: (req, res, err) => {
 *     res.status(400).json({ blocked: true });
 *     return true;
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
): (req: Request, res: Response, next: NextFunction) => void {
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

  return (req: Request, res: Response, next: NextFunction): void => {
    // Extract messages from the configured body property.
    const body = req.body as Record<string, unknown> | undefined;

    if (!body || typeof body !== "object") {
      // No body — nothing to scan. Let the route handler decide what to do.
      req.aegis = {
        messages: [],
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      };
      next();
      return;
    }

    const rawMessages = body[messagesProperty];

    if (!Array.isArray(rawMessages)) {
      // No messages array found — attach empty result and continue.
      req.aegis = {
        messages: [],
        instance: aegisInstance,
        auditLog: aegisInstance.getAuditLog(),
      };
      next();
      return;
    }

    // Normalize messages to the format Aegis expects.
    const messages = rawMessages.map((m: Record<string, unknown>) => ({
      role: String(m.role ?? "user") as "system" | "user" | "assistant",
      content: String(m.content ?? ""),
    }));

    // Run the async guard and handle the result.
    aegisInstance
      .guardInput(messages, { scanStrategy })
      .then((safeMessages) => {
        req.aegis = {
          messages: safeMessages,
          instance: aegisInstance,
          auditLog: aegisInstance.getAuditLog(),
        };
        next();
      })
      .catch(async (error: unknown) => {
        if (
          error instanceof AegisInputBlocked ||
          error instanceof AegisSessionQuarantined ||
          error instanceof AegisSessionTerminated
        ) {
          // Allow custom handler to take over.
          if (onBlocked) {
            try {
              const handled = await onBlocked(req, res, error);
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

          res.status(403).json(response);
          return;
        }

        // Unknown error — pass to Express error handling.
        next(error);
      });
  };
}

// ─── Stream Transform Helper ────────────────────────────────────────────────

/**
 * Create an Aegis stream transform for monitoring LLM output in Express responses.
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
 * import { aegisMiddleware, aegisStreamTransform } from '@aegis-sdk/express';
 * import { Aegis } from '@aegis-sdk/core';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 *
 * app.post('/chat', aegisMiddleware({ aegis }), async (req, res) => {
 *   const transform = aegisStreamTransform(aegis);
 *
 *   // Pipe your LLM stream through the transform
 *   const llmStream = getStreamFromLLM(req.aegis.messages);
 *   const reader = llmStream.pipeThrough(transform).getReader();
 *
 *   res.setHeader('Content-Type', 'text/event-stream');
 *   res.setHeader('Cache-Control', 'no-cache');
 *   res.setHeader('Connection', 'keep-alive');
 *
 *   while (true) {
 *     const { done, value } = await reader.read();
 *     if (done) break;
 *     res.write(`data: ${value}\n\n`);
 *   }
 *   res.end();
 * });
 * ```
 *
 * @example
 * ```ts
 * // Using the Aegis instance from the middleware via req.aegis
 * app.post('/chat', aegisMiddleware({ policy: 'strict' }), (req, res) => {
 *   const transform = aegisStreamTransform(req.aegis.instance);
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
 * Convenience export for use in Express routes.
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

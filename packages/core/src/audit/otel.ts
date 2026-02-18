import type { AuditEntry } from "../types.js";

// ─── Minimal OTel Interface Types ───────────────────────────────────────────
// Defined locally so @opentelemetry packages are NOT a hard dependency.
// Consumers pass in their own OTel API objects that satisfy these shapes.

/**
 * Minimal interface matching a subset of `@opentelemetry/api` Span.
 */
export interface OTelSpan {
  setAttribute(key: string, value: string | number | boolean): void;
  setStatus(status: { code: number; message?: string }): void;
  end(): void;
}

/**
 * Minimal interface matching a subset of `@opentelemetry/api` Counter.
 */
export interface OTelCounter {
  add(value: number, attributes?: Record<string, string>): void;
}

/**
 * Minimal interface matching a subset of `@opentelemetry/api` Histogram.
 */
export interface OTelHistogram {
  record(value: number, attributes?: Record<string, string>): void;
}

/**
 * Configuration for the OpenTelemetry audit transport.
 *
 * None of the fields are required -- the transport gracefully skips
 * any instrumentation channel that is not wired up.
 */
export interface OTelTransportConfig {
  /** OTel Tracer instance (from `@opentelemetry/api`). */
  tracer?: {
    startSpan(name: string, options?: unknown): OTelSpan;
  };
  /** OTel Meter instance (from `@opentelemetry/api`). */
  meter?: {
    createCounter(name: string, options?: unknown): OTelCounter;
    createHistogram(name: string, options?: unknown): OTelHistogram;
  };
  /** OTel Logger instance (from `@opentelemetry/api-logs`). */
  logger?: {
    emit(record: unknown): void;
  };
  /** Prefix for metric / span names. Default: `'aegis'`. */
  prefix?: string;
}

/**
 * OpenTelemetry-compatible transport for the Aegis audit log.
 *
 * This class does **not** depend on `@opentelemetry/*` packages at runtime.
 * Instead, it accepts OTel API objects through its constructor so the consumer
 * controls the OTel SDK version and configuration.
 *
 * @example
 * ```ts
 * import { trace, metrics } from '@opentelemetry/api';
 * import { OTelTransport } from '@aegis-sdk/core';
 *
 * const otel = new OTelTransport({
 *   tracer: trace.getTracer('aegis'),
 *   meter: metrics.getMeter('aegis'),
 *   prefix: 'aegis',
 * });
 *
 * auditLog.setOTelTransport(otel);
 * ```
 */
export class OTelTransport {
  private readonly prefix: string;
  private readonly tracer: OTelTransportConfig["tracer"];
  private readonly meter: OTelTransportConfig["meter"];
  private readonly logger: OTelTransportConfig["logger"];

  // Lazily-created metrics instruments
  private totalCounter?: OTelCounter;
  private blockedCounter?: OTelCounter;
  private flaggedCounter?: OTelCounter;
  private scoreHistogram?: OTelHistogram;

  constructor(config: OTelTransportConfig = {}) {
    this.prefix = config.prefix ?? "aegis";
    this.tracer = config.tracer;
    this.meter = config.meter;
    this.logger = config.logger;

    // Pre-create metric instruments if a meter was provided
    if (this.meter) {
      this.totalCounter = this.meter.createCounter(`${this.prefix}.events.total`, {
        description: "Total number of Aegis audit events",
      });
      this.blockedCounter = this.meter.createCounter(`${this.prefix}.events.blocked`, {
        description: "Number of blocked audit events",
      });
      this.flaggedCounter = this.meter.createCounter(`${this.prefix}.events.flagged`, {
        description: "Number of flagged audit events",
      });
      this.scoreHistogram = this.meter.createHistogram(`${this.prefix}.scan.score`, {
        description: "Distribution of scan scores",
      });
    }
  }

  /**
   * Emit an audit entry through all configured OTel channels.
   *
   * - **Tracing**: creates a span for `blocked` / `flagged` events.
   * - **Metrics**: increments counters and records histogram values.
   * - **Logging**: forwards the entry to the OTel logger.
   */
  emit(entry: AuditEntry): void {
    const attributes: Record<string, string> = {
      "aegis.event": entry.event,
      "aegis.decision": entry.decision,
    };

    if (entry.sessionId) {
      attributes["aegis.sessionId"] = entry.sessionId;
    }
    if (entry.requestId) {
      attributes["aegis.requestId"] = entry.requestId;
    }

    // ── Tracing ──────────────────────────────────────────────────────────
    if (this.tracer && (entry.decision === "blocked" || entry.decision === "flagged")) {
      const span = this.tracer.startSpan(`${this.prefix}.${entry.event}`);
      span.setAttribute("aegis.event", entry.event);
      span.setAttribute("aegis.decision", entry.decision);

      if (entry.sessionId) {
        span.setAttribute("aegis.sessionId", entry.sessionId);
      }
      if (entry.requestId) {
        span.setAttribute("aegis.requestId", entry.requestId);
      }

      // Score attribute for scan events
      const score = entry.context["score"];
      if (typeof score === "number") {
        span.setAttribute("aegis.score", score);
      }

      // OTel status code: 2 = ERROR for blocked, 1 = OK for flagged
      const statusCode = entry.decision === "blocked" ? 2 : 1;
      span.setStatus({
        code: statusCode,
        message: entry.decision === "blocked" ? `Blocked: ${entry.event}` : undefined,
      });

      span.end();
    }

    // ── Metrics ──────────────────────────────────────────────────────────
    this.totalCounter?.add(1, attributes);

    if (entry.decision === "blocked") {
      this.blockedCounter?.add(1, attributes);
    }
    if (entry.decision === "flagged") {
      this.flaggedCounter?.add(1, attributes);
    }

    // Record histogram for scan events that carry a score
    const score = entry.context["score"];
    if (typeof score === "number" && this.scoreHistogram) {
      this.scoreHistogram.record(score, attributes);
    }

    // ── Logging ──────────────────────────────────────────────────────────
    if (this.logger) {
      this.logger.emit({
        severityText:
          entry.decision === "blocked" ? "ERROR" : entry.decision === "flagged" ? "WARN" : "INFO",
        body: `[aegis] ${entry.event} — ${entry.decision}`,
        attributes: {
          ...attributes,
          "aegis.timestamp": entry.timestamp.toISOString(),
          "aegis.context": JSON.stringify(entry.context),
        },
      });
    }
  }
}

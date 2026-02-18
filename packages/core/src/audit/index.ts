import type {
  AuditEntry,
  AuditEventType,
  AuditLogConfig,
  AuditTransport,
  TransportFn,
  Alert,
} from "../types.js";
import type { OTelTransport } from "./otel.js";
import type { FileTransport } from "./file-transport.js";
import { AlertingEngine } from "../alerting/index.js";

/**
 * Resolved internal config — ensures `transports` is always an array and
 * all other fields have concrete defaults.
 */
interface ResolvedConfig {
  transports: AuditTransport[];
  path: string;
  level: NonNullable<AuditLogConfig["level"]>;
  redactContent: boolean;
  alerting: AuditLogConfig["alerting"];
}

/**
 * Merge the legacy single `transport` field with the new `transports` array,
 * deduplicating entries.
 */
function resolveTransports(config: AuditLogConfig): AuditTransport[] {
  const set = new Set<AuditTransport>();

  if (config.transports) {
    for (const t of config.transports) {
      set.add(t);
    }
  }

  // Legacy single-transport field: merge it in (but don't duplicate)
  if (config.transport) {
    set.add(config.transport);
  }

  // If nothing was specified at all, default to console
  if (set.size === 0) {
    set.add("console");
  }

  return [...set];
}

/**
 * Audit Log — records every decision, action, and violation in the pipeline.
 *
 * Supports multiple simultaneous transports: console, JSON file,
 * OpenTelemetry, or any number of custom transport functions.
 * Every security-relevant event in the Aegis pipeline creates an audit entry.
 *
 * @example
 * ```ts
 * // Multiple transports active at once
 * const audit = new AuditLog({
 *   transports: ['console', 'otel', 'custom'],
 *   level: 'all',
 * });
 *
 * // Wire OTel
 * audit.setOTelTransport(otel);
 *
 * // Add custom transports
 * audit.addTransport((entry) => sendToDatadog(entry));
 * audit.addTransport((entry) => sendToSplunk(entry));
 * ```
 */
export class AuditLog {
  private config: ResolvedConfig;
  private entries: AuditEntry[] = [];

  /** Registered custom transport functions. */
  private customTransports: TransportFn[] = [];

  /** OpenTelemetry transport instance (optional). */
  private otelTransport?: OTelTransport;

  /** JSON-Lines file transport instance (optional). */
  private fileTransport?: FileTransport;

  /** Alerting engine for evaluating rules against audit entries. */
  private alertingEngine?: AlertingEngine;

  constructor(config: AuditLogConfig = {}) {
    this.config = {
      transports: resolveTransports(config),
      path: config.path ?? "./aegis-audit.jsonl",
      level: config.level ?? "all",
      redactContent: config.redactContent ?? false,
      alerting: config.alerting,
    };

    // Initialize the alerting engine if alerting is configured and enabled
    if (this.config.alerting?.enabled && this.config.alerting.rules.length > 0) {
      this.alertingEngine = new AlertingEngine(this.config.alerting);
    }
  }

  // ── Transport management ────────────────────────────────────────────────

  /**
   * Set a custom transport function for audit entries.
   *
   * @deprecated Use {@link addTransport} instead for adding multiple custom
   * transports. This method is kept for backward compatibility and replaces
   * all existing custom transports with a single function.
   */
  setCustomTransport(fn: TransportFn): void {
    this.customTransports = [fn];
  }

  /**
   * Add a custom transport function.
   *
   * Multiple custom transports can be active simultaneously. Each one
   * receives every audit entry that passes level filtering.
   */
  addTransport(fn: TransportFn): void {
    this.customTransports.push(fn);
  }

  /**
   * Remove a previously-added custom transport function.
   *
   * Uses reference equality — pass the same function reference that was
   * originally added.
   */
  removeTransport(fn: TransportFn): void {
    const idx = this.customTransports.indexOf(fn);
    if (idx !== -1) {
      this.customTransports.splice(idx, 1);
    }
  }

  /**
   * Wire up an {@link OTelTransport} instance.
   *
   * When the `"otel"` transport is active, every audit entry is forwarded
   * to this transport's `emit()` method.
   */
  setOTelTransport(otel: OTelTransport): void {
    this.otelTransport = otel;
  }

  /**
   * Wire up a {@link FileTransport} instance for JSON-Lines file logging.
   *
   * When the `"json-file"` transport is active, every audit entry is
   * forwarded to this transport's `emit()` method.
   */
  setFileTransport(file: FileTransport): void {
    this.fileTransport = file;
  }

  // ── Logging ─────────────────────────────────────────────────────────────

  /**
   * Log an audit entry.
   */
  log(entry: {
    event: AuditEventType;
    decision?: AuditEntry["decision"];
    sessionId?: string;
    requestId?: string;
    context?: Record<string, unknown>;
  }): void {
    const full: AuditEntry = {
      timestamp: new Date(),
      event: entry.event,
      decision: entry.decision ?? "info",
      sessionId: entry.sessionId,
      requestId: entry.requestId,
      context: entry.context ?? {},
    };

    // Apply level filtering
    if (!this.shouldLog(full)) return;

    // Redact content if configured
    if (this.config.redactContent) {
      this.redact(full);
    }

    this.entries.push(full);
    this.emit(full);

    // Evaluate alerting rules against this entry
    if (this.alertingEngine) {
      this.alertingEngine.evaluate(full);
    }
  }

  // ── Querying ────────────────────────────────────────────────────────────

  /**
   * Query stored audit entries.
   */
  query(filters: {
    event?: AuditEventType;
    since?: Date;
    limit?: number;
    sessionId?: string;
  }): AuditEntry[] {
    let results = [...this.entries];

    if (filters.event) {
      results = results.filter((e) => e.event === filters.event);
    }
    if (filters.since) {
      const since = filters.since;
      results = results.filter((e) => e.timestamp >= since);
    }
    if (filters.sessionId) {
      results = results.filter((e) => e.sessionId === filters.sessionId);
    }
    if (filters.limit) {
      results = results.slice(-filters.limit);
    }

    return results;
  }

  /**
   * Get all entries (for testing/debugging).
   */
  getEntries(): readonly AuditEntry[] {
    return this.entries;
  }

  /**
   * Clear all entries (for testing).
   */
  clear(): void {
    this.entries = [];
  }

  /**
   * Get the alerting engine instance, if alerting is configured.
   *
   * @returns The AlertingEngine instance, or null if alerting is not enabled
   */
  getAlertingEngine(): AlertingEngine | null {
    return this.alertingEngine ?? null;
  }

  /**
   * Get all active (unresolved) alerts from the alerting engine.
   *
   * @returns Array of active alerts, or empty array if alerting is not enabled
   */
  getActiveAlerts(): Alert[] {
    return this.alertingEngine?.getActiveAlerts() ?? [];
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  private shouldLog(entry: AuditEntry): boolean {
    switch (this.config.level) {
      case "violations-only":
        return entry.decision === "blocked" || entry.decision === "flagged";
      case "actions":
        return entry.decision !== "info";
      case "all":
        return true;
    }
  }

  private redact(entry: AuditEntry): void {
    const ctx = entry.context;
    for (const key of Object.keys(ctx)) {
      if (typeof ctx[key] === "string" && key !== "reason" && key !== "event") {
        ctx[key] = "[REDACTED]";
      }
    }
  }

  /**
   * Dispatch an entry to every active transport.
   *
   * Multiple transports can fire simultaneously (e.g., console + otel + custom).
   */
  private emit(entry: AuditEntry): void {
    for (const transport of this.config.transports) {
      this.emitToTransport(transport, entry);
    }
  }

  /**
   * Route an entry to a single transport type.
   */
  private emitToTransport(transport: AuditTransport, entry: AuditEntry): void {
    switch (transport) {
      case "console":
        this.emitConsole(entry);
        break;

      case "json-file":
        if (this.fileTransport) {
          void this.fileTransport.emit(entry);
        } else {
          // Fallback: write JSON to console if no FileTransport is wired
          this.emitConsole(entry);
        }
        break;

      case "otel":
        if (this.otelTransport) {
          this.otelTransport.emit(entry);
        }
        break;

      case "custom":
        for (const fn of this.customTransports) {
          try {
            void fn(entry);
          } catch {
            // Swallow errors from custom transports to avoid breaking the pipeline.
          }
        }
        break;
    }
  }

  private emitConsole(entry: AuditEntry): void {
    const prefix =
      entry.decision === "blocked"
        ? "[AEGIS BLOCK]"
        : entry.decision === "flagged"
          ? "[AEGIS FLAG]"
          : "[AEGIS]";
    const msg = `${prefix} ${entry.event}`;

    if (entry.decision === "blocked" || entry.decision === "flagged") {
      console.warn(msg, entry.context);
    } else {
      console.log(msg, entry.context);
    }
  }
}

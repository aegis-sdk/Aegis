import type { AuditEntry, AuditEventType, AuditLogConfig } from "../types.js";

const DEFAULT_CONFIG: Required<Omit<AuditLogConfig, "alerting">> & { alerting: AuditLogConfig["alerting"] } = {
  transport: "console",
  path: "./aegis-audit.jsonl",
  level: "all",
  redactContent: false,
  alerting: undefined,
};

/**
 * Audit Log — records every decision, action, and violation in the pipeline.
 *
 * Supports multiple transports: console, JSON file, OpenTelemetry, or custom.
 * Every security-relevant event in the Aegis pipeline creates an audit entry.
 */
export class AuditLog {
  private config: typeof DEFAULT_CONFIG;
  private entries: AuditEntry[] = [];
  private customTransport?: (entry: AuditEntry) => void | Promise<void>;

  constructor(config: AuditLogConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Set a custom transport function for audit entries.
   */
  setCustomTransport(fn: (entry: AuditEntry) => void | Promise<void>): void {
    this.customTransport = fn;
  }

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
  }

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

  private emit(entry: AuditEntry): void {
    switch (this.config.transport) {
      case "console":
        this.emitConsole(entry);
        break;
      case "json-file":
        // File transport will be implemented with Node.js fs
        // For now, fall through to console
        this.emitConsole(entry);
        break;
      case "custom":
        if (this.customTransport) {
          void this.customTransport(entry);
        }
        break;
      case "otel":
        // OTel transport will be a separate export
        break;
    }
  }

  private emitConsole(entry: AuditEntry): void {
    const prefix = entry.decision === "blocked" ? "[AEGIS BLOCK]" : entry.decision === "flagged" ? "[AEGIS FLAG]" : "[AEGIS]";
    const msg = `${prefix} ${entry.event}`;

    if (entry.decision === "blocked" || entry.decision === "flagged") {
      console.warn(msg, entry.context);
    } else {
      console.log(msg, entry.context);
    }
  }
}

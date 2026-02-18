import { describe, it, expect, vi, afterEach } from "vitest";
import { AuditLog } from "../../packages/core/src/audit/index.js";

afterEach(() => {
  vi.restoreAllMocks();
});

// ─── multi-transport ─────────────────────────────────────────────────────────

describe("AuditLog — multi-transport", () => {
  it("fires both console and custom transports when configured", () => {
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const customFn = vi.fn();

    const audit = new AuditLog({
      transports: ["console", "custom"],
    });
    audit.addTransport(customFn);

    audit.log({ event: "scan_block", decision: "blocked", context: {} });

    expect(consoleSpy).toHaveBeenCalled();
    expect(customFn).toHaveBeenCalledTimes(1);
    expect(customFn.mock.calls[0][0]).toHaveProperty("event", "scan_block");
  });
});

// ─── addTransport ────────────────────────────────────────────────────────────

describe("AuditLog — addTransport", () => {
  it("added transport receives entries", () => {
    const fn = vi.fn();
    const audit = new AuditLog({ transports: ["custom"] });
    audit.addTransport(fn);

    audit.log({ event: "scan_pass", decision: "allowed", context: {} });

    expect(fn).toHaveBeenCalledTimes(1);
    const entry = fn.mock.calls[0][0];
    expect(entry.event).toBe("scan_pass");
    expect(entry.decision).toBe("allowed");
  });

  it("supports multiple custom transports simultaneously", () => {
    const fn1 = vi.fn();
    const fn2 = vi.fn();
    const audit = new AuditLog({ transports: ["custom"] });
    audit.addTransport(fn1);
    audit.addTransport(fn2);

    audit.log({ event: "scan_block", decision: "blocked", context: {} });

    expect(fn1).toHaveBeenCalledTimes(1);
    expect(fn2).toHaveBeenCalledTimes(1);
  });
});

// ─── removeTransport ─────────────────────────────────────────────────────────

describe("AuditLog — removeTransport", () => {
  it("removed transport no longer receives entries", () => {
    const fn = vi.fn();
    const audit = new AuditLog({ transports: ["custom"] });
    audit.addTransport(fn);

    // First log — should receive
    audit.log({ event: "scan_pass", decision: "allowed", context: {} });
    expect(fn).toHaveBeenCalledTimes(1);

    // Remove and log again — should not receive
    audit.removeTransport(fn);
    audit.log({ event: "scan_block", decision: "blocked", context: {} });
    expect(fn).toHaveBeenCalledTimes(1); // still 1, not 2
  });
});

// ─── setCustomTransport (legacy) ─────────────────────────────────────────────

describe("AuditLog — setCustomTransport (legacy)", () => {
  it("replaces all custom transports with a single function", () => {
    const fn1 = vi.fn();
    const fn2 = vi.fn();
    const replacementFn = vi.fn();

    const audit = new AuditLog({ transports: ["custom"] });
    audit.addTransport(fn1);
    audit.addTransport(fn2);

    // Replace all with the legacy setter
    audit.setCustomTransport(replacementFn);

    audit.log({ event: "scan_block", decision: "blocked", context: {} });

    // Old transports should NOT receive entries
    expect(fn1).not.toHaveBeenCalled();
    expect(fn2).not.toHaveBeenCalled();

    // Replacement should receive
    expect(replacementFn).toHaveBeenCalledTimes(1);
  });
});

// ─── setOTelTransport ────────────────────────────────────────────────────────

describe("AuditLog — setOTelTransport", () => {
  it("wires OTel transport and emit is called for entries", () => {
    const mockOtel = { emit: vi.fn() };
    const audit = new AuditLog({ transports: ["otel"] });

    // Wire the OTel transport
    audit.setOTelTransport(mockOtel as unknown as Parameters<AuditLog["setOTelTransport"]>[0]);

    audit.log({ event: "scan_block", decision: "blocked", context: {} });

    expect(mockOtel.emit).toHaveBeenCalledTimes(1);
    expect(mockOtel.emit.mock.calls[0][0]).toHaveProperty("event", "scan_block");
  });
});

// ─── otel without instance ───────────────────────────────────────────────────

describe("AuditLog — otel transport without instance", () => {
  it("does not error when otel transport is active but no OTelTransport is wired", () => {
    const audit = new AuditLog({ transports: ["otel"] });

    // Should not throw — just silently skips otel
    expect(() =>
      audit.log({ event: "scan_pass", decision: "allowed", context: {} }),
    ).not.toThrow();
  });
});

// ─── default to console ──────────────────────────────────────────────────────

describe("AuditLog — default transport", () => {
  it("defaults to console when no transports specified", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const audit = new AuditLog({});

    audit.log({ event: "scan_pass", decision: "allowed", context: {} });

    expect(logSpy).toHaveBeenCalled();
  });

  it("defaults to console when config is omitted entirely", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const audit = new AuditLog();

    audit.log({ event: "scan_pass", decision: "allowed", context: {} });

    expect(logSpy).toHaveBeenCalled();
  });
});

// ─── transport + transports compat ───────────────────────────────────────────

describe("AuditLog — transport + transports compat", () => {
  it("merges single transport and transports array with deduplication", () => {
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const customFn = vi.fn();

    // Both transport (single) and transports (array) specify 'console'
    // — should be deduped so console only fires once
    const audit = new AuditLog({
      transport: "console",
      transports: ["console", "custom"],
    });
    audit.addTransport(customFn);

    audit.log({ event: "scan_block", decision: "blocked", context: {} });

    // Console should only be called once (deduped), not twice
    expect(consoleSpy).toHaveBeenCalledTimes(1);
    expect(customFn).toHaveBeenCalledTimes(1);
  });

  it("merges different transport types from both fields", () => {
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const customFn = vi.fn();

    const audit = new AuditLog({
      transport: "custom",
      transports: ["console"],
    });
    audit.addTransport(customFn);

    audit.log({ event: "scan_block", decision: "blocked", context: {} });

    expect(consoleSpy).toHaveBeenCalledTimes(1);
    expect(customFn).toHaveBeenCalledTimes(1);
  });
});

// ─── alerting integration ────────────────────────────────────────────────────

describe("AuditLog — alerting integration", () => {
  it("evaluates alerting rules on each log when alerting config is provided", () => {
    // Suppress console output from the log action
    vi.spyOn(console, "warn").mockImplementation(() => {});

    const audit = new AuditLog({
      transports: ["console"],
      alerting: {
        enabled: true,
        rules: [
          {
            condition: {
              type: "rate-spike",
              event: "scan_block",
              threshold: 2,
              windowMs: 60_000,
            },
            action: "log",
          },
        ],
      },
    });

    // The alerting engine should exist
    const engine = audit.getAlertingEngine();
    expect(engine).not.toBeNull();

    // First log — below threshold, no active alerts
    audit.log({ event: "scan_block", decision: "blocked", context: {} });
    expect(audit.getActiveAlerts()).toHaveLength(0);

    // Second log — meets threshold, should create an alert
    audit.log({ event: "scan_block", decision: "blocked", context: {} });
    expect(audit.getActiveAlerts()).toHaveLength(1);
    expect(audit.getActiveAlerts()[0].condition.type).toBe("rate-spike");
  });

  it("returns null alerting engine when alerting is not configured", () => {
    const audit = new AuditLog({ transports: ["console"] });
    expect(audit.getAlertingEngine()).toBeNull();
  });

  it("returns empty active alerts when alerting is not configured", () => {
    const audit = new AuditLog({ transports: ["console"] });
    expect(audit.getActiveAlerts()).toHaveLength(0);
  });
});

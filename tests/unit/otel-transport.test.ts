import { describe, it, expect, vi, afterEach } from "vitest";
import { OTelTransport } from "../../packages/core/src/audit/otel.js";
import type { AuditEntry } from "../../packages/core/src/types.js";

// ─── Mock factories ──────────────────────────────────────────────────────────

function mockTracer() {
  const span = {
    setAttribute: vi.fn(),
    setStatus: vi.fn(),
    end: vi.fn(),
  };
  return {
    tracer: { startSpan: vi.fn(() => span) },
    span,
  };
}

function mockMeter() {
  const counter = { add: vi.fn() };
  const histogram = { record: vi.fn() };
  return {
    meter: {
      createCounter: vi.fn(() => counter),
      createHistogram: vi.fn(() => histogram),
    },
    counter,
    histogram,
  };
}

function mockLogger() {
  return { emit: vi.fn() };
}

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    timestamp: new Date(),
    event: "scan_block",
    decision: "blocked",
    sessionId: "sess-1",
    requestId: "req-1",
    context: {},
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ─── Tracing ─────────────────────────────────────────────────────────────────

describe("OTelTransport — tracing", () => {
  it("creates a span for blocked events with correct name and attributes", () => {
    const { tracer, span } = mockTracer();
    const transport = new OTelTransport({ tracer });

    transport.emit(makeEntry({ event: "scan_block", decision: "blocked" }));

    expect(tracer.startSpan).toHaveBeenCalledWith("aegis.scan_block");
    expect(span.setAttribute).toHaveBeenCalledWith("aegis.event", "scan_block");
    expect(span.setAttribute).toHaveBeenCalledWith("aegis.decision", "blocked");
    expect(span.setStatus).toHaveBeenCalledWith({
      code: 2,
      message: "Blocked: scan_block",
    });
    expect(span.end).toHaveBeenCalled();
  });

  it("creates a span for flagged events", () => {
    const { tracer, span } = mockTracer();
    const transport = new OTelTransport({ tracer });

    transport.emit(makeEntry({ decision: "flagged" }));

    expect(tracer.startSpan).toHaveBeenCalled();
    expect(span.setStatus).toHaveBeenCalledWith({
      code: 1,
      message: undefined,
    });
    expect(span.end).toHaveBeenCalled();
  });

  it("does NOT create a span for allowed events", () => {
    const { tracer } = mockTracer();
    const transport = new OTelTransport({ tracer });

    transport.emit(makeEntry({ event: "scan_pass", decision: "allowed" }));

    expect(tracer.startSpan).not.toHaveBeenCalled();
  });

  it("does NOT create a span for info events", () => {
    const { tracer } = mockTracer();
    const transport = new OTelTransport({ tracer });

    transport.emit(makeEntry({ event: "scan_pass", decision: "info" }));

    expect(tracer.startSpan).not.toHaveBeenCalled();
  });

  it("sets sessionId and requestId as span attributes when present", () => {
    const { tracer, span } = mockTracer();
    const transport = new OTelTransport({ tracer });

    transport.emit(
      makeEntry({
        decision: "blocked",
        sessionId: "sess-abc",
        requestId: "req-xyz",
      }),
    );

    expect(span.setAttribute).toHaveBeenCalledWith("aegis.sessionId", "sess-abc");
    expect(span.setAttribute).toHaveBeenCalledWith("aegis.requestId", "req-xyz");
  });

  it("does not set sessionId/requestId attributes when absent", () => {
    const { tracer, span } = mockTracer();
    const transport = new OTelTransport({ tracer });

    transport.emit(
      makeEntry({
        decision: "blocked",
        sessionId: undefined,
        requestId: undefined,
      }),
    );

    const setAttributeCalls = span.setAttribute.mock.calls.map(
      (call: unknown[]) => call[0],
    );
    expect(setAttributeCalls).not.toContain("aegis.sessionId");
    expect(setAttributeCalls).not.toContain("aegis.requestId");
  });
});

// ─── Metrics ─────────────────────────────────────────────────────────────────

describe("OTelTransport — metrics", () => {
  it("increments total counter for every event", () => {
    const { meter, counter } = mockMeter();
    const transport = new OTelTransport({ meter });

    transport.emit(makeEntry({ decision: "allowed" }));
    transport.emit(makeEntry({ decision: "blocked" }));
    transport.emit(makeEntry({ decision: "info" }));

    // Total counter should be incremented for all 3 events
    expect(counter.add).toHaveBeenCalledTimes(3 + 1);
    // 3 total + 1 blocked = 4. Let's verify the total counter calls more carefully.
    // Actually, createCounter is called multiple times (total, blocked, flagged).
    // All share the same mock. So let's check by call count.
    // createCounter is called 3 times, createHistogram once, all returning same mocks.
    // That means counter.add receives calls from total, blocked, and flagged counters.
    // Total: 3 calls (one per emit), Blocked: 1 call (for the blocked event), Flagged: 0.
    // Total calls to counter.add = 3 + 1 = 4.
    expect(counter.add).toHaveBeenCalledTimes(4);
  });

  it("increments blocked counter only for blocked events", () => {
    const blockedCounter = { add: vi.fn() };
    const totalCounter = { add: vi.fn() };
    const flaggedCounter = { add: vi.fn() };
    const histogram = { record: vi.fn() };

    let counterIndex = 0;
    const counters = [totalCounter, blockedCounter, flaggedCounter];
    const meter = {
      createCounter: vi.fn(() => counters[counterIndex++]),
      createHistogram: vi.fn(() => histogram),
    };

    const transport = new OTelTransport({ meter });

    transport.emit(makeEntry({ decision: "allowed" }));
    transport.emit(makeEntry({ decision: "blocked" }));
    transport.emit(makeEntry({ decision: "info" }));

    // Total counter gets all 3
    expect(totalCounter.add).toHaveBeenCalledTimes(3);
    // Blocked counter only for the one blocked event
    expect(blockedCounter.add).toHaveBeenCalledTimes(1);
    // Flagged counter: none
    expect(flaggedCounter.add).toHaveBeenCalledTimes(0);
  });

  it("increments flagged counter only for flagged events", () => {
    const blockedCounter = { add: vi.fn() };
    const totalCounter = { add: vi.fn() };
    const flaggedCounter = { add: vi.fn() };
    const histogram = { record: vi.fn() };

    let counterIndex = 0;
    const counters = [totalCounter, blockedCounter, flaggedCounter];
    const meter = {
      createCounter: vi.fn(() => counters[counterIndex++]),
      createHistogram: vi.fn(() => histogram),
    };

    const transport = new OTelTransport({ meter });

    transport.emit(makeEntry({ decision: "allowed" }));
    transport.emit(makeEntry({ decision: "flagged" }));
    transport.emit(makeEntry({ decision: "info" }));

    expect(totalCounter.add).toHaveBeenCalledTimes(3);
    expect(blockedCounter.add).toHaveBeenCalledTimes(0);
    expect(flaggedCounter.add).toHaveBeenCalledTimes(1);
  });

  it("records histogram for scan events with score in context", () => {
    const { meter, histogram } = mockMeter();
    const transport = new OTelTransport({ meter });

    transport.emit(makeEntry({ context: { score: 0.85 } }));

    expect(histogram.record).toHaveBeenCalledWith(0.85, expect.any(Object));
  });

  it("does NOT record histogram when score is absent", () => {
    const { meter, histogram } = mockMeter();
    const transport = new OTelTransport({ meter });

    transport.emit(makeEntry({ context: {} }));

    expect(histogram.record).not.toHaveBeenCalled();
  });
});

// ─── Logging ─────────────────────────────────────────────────────────────────

describe("OTelTransport — logging", () => {
  it("forwards blocked events with ERROR severity", () => {
    const logger = mockLogger();
    const transport = new OTelTransport({ logger });

    transport.emit(makeEntry({ decision: "blocked" }));

    expect(logger.emit).toHaveBeenCalledTimes(1);
    const record = logger.emit.mock.calls[0][0] as Record<string, unknown>;
    expect(record.severityText).toBe("ERROR");
  });

  it("forwards flagged events with WARN severity", () => {
    const logger = mockLogger();
    const transport = new OTelTransport({ logger });

    transport.emit(makeEntry({ decision: "flagged" }));

    expect(logger.emit).toHaveBeenCalledTimes(1);
    const record = logger.emit.mock.calls[0][0] as Record<string, unknown>;
    expect(record.severityText).toBe("WARN");
  });

  it("forwards allowed events with INFO severity", () => {
    const logger = mockLogger();
    const transport = new OTelTransport({ logger });

    transport.emit(makeEntry({ decision: "allowed" }));

    expect(logger.emit).toHaveBeenCalledTimes(1);
    const record = logger.emit.mock.calls[0][0] as Record<string, unknown>;
    expect(record.severityText).toBe("INFO");
  });

  it("forwards info events with INFO severity", () => {
    const logger = mockLogger();
    const transport = new OTelTransport({ logger });

    transport.emit(makeEntry({ decision: "info" }));

    expect(logger.emit).toHaveBeenCalledTimes(1);
    const record = logger.emit.mock.calls[0][0] as Record<string, unknown>;
    expect(record.severityText).toBe("INFO");
  });

  it("includes correct body and attributes in log record", () => {
    const logger = mockLogger();
    const transport = new OTelTransport({ logger });

    const entry = makeEntry({
      event: "scan_block",
      decision: "blocked",
      sessionId: "sess-42",
    });
    transport.emit(entry);

    const record = logger.emit.mock.calls[0][0] as Record<string, unknown>;
    expect(record.body).toBe("[aegis] scan_block — blocked");

    const attrs = record.attributes as Record<string, string>;
    expect(attrs["aegis.event"]).toBe("scan_block");
    expect(attrs["aegis.decision"]).toBe("blocked");
    expect(attrs["aegis.sessionId"]).toBe("sess-42");
    expect(attrs["aegis.timestamp"]).toBeDefined();
  });
});

// ─── Empty config ────────────────────────────────────────────────────────────

describe("OTelTransport — empty config", () => {
  it("works with no tracer/meter/logger (empty config)", () => {
    const transport = new OTelTransport({});

    // Should not throw
    expect(() => transport.emit(makeEntry())).not.toThrow();
  });

  it("works with default constructor (no config)", () => {
    const transport = new OTelTransport();

    expect(() => transport.emit(makeEntry())).not.toThrow();
  });
});

// ─── Custom prefix ───────────────────────────────────────────────────────────

describe("OTelTransport — custom prefix", () => {
  it("uses the configured prefix for span names", () => {
    const { tracer } = mockTracer();
    const transport = new OTelTransport({ tracer, prefix: "myapp" });

    transport.emit(makeEntry({ event: "scan_block", decision: "blocked" }));

    expect(tracer.startSpan).toHaveBeenCalledWith("myapp.scan_block");
  });

  it("uses the configured prefix for metric names", () => {
    const { meter } = mockMeter();
    new OTelTransport({ meter, prefix: "myapp" });

    const counterNames = meter.createCounter.mock.calls.map(
      (call: unknown[]) => call[0],
    );
    expect(counterNames).toContain("myapp.events.total");
    expect(counterNames).toContain("myapp.events.blocked");
    expect(counterNames).toContain("myapp.events.flagged");

    const histogramNames = meter.createHistogram.mock.calls.map(
      (call: unknown[]) => call[0],
    );
    expect(histogramNames).toContain("myapp.scan.score");
  });
});

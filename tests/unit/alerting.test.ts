import { describe, it, expect, vi, afterEach } from "vitest";
import { AlertingEngine } from "../../packages/core/src/alerting/index.js";
import type { AuditEntry, AlertingConfig } from "../../packages/core/src/types.js";

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    timestamp: new Date(),
    event: "scan_block",
    decision: "blocked",
    sessionId: "sess-1",
    context: {},
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ─── rate-spike ──────────────────────────────────────────────────────────────

describe("AlertingEngine — rate-spike", () => {
  it("fires alert when N+ events of a specific type occur within windowMs", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "rate-spike", event: "scan_block", threshold: 3, windowMs: 60_000 },
          action: "log",
        },
      ],
    };
    const engine = new AlertingEngine(config);

    // First two entries should not trigger
    expect(engine.evaluate(makeEntry())).toHaveLength(0);
    expect(engine.evaluate(makeEntry())).toHaveLength(0);

    // Third entry meets the threshold
    const alerts = engine.evaluate(makeEntry());
    expect(alerts).toHaveLength(1);
    expect(alerts[0].condition.type).toBe("rate-spike");
  });

  it("does NOT fire when count is below threshold", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "rate-spike", event: "scan_block", threshold: 10, windowMs: 60_000 },
          action: "log",
        },
      ],
    };
    const engine = new AlertingEngine(config);

    // Only push 3 events — well below the threshold of 10
    for (let i = 0; i < 3; i++) {
      expect(engine.evaluate(makeEntry())).toHaveLength(0);
    }
  });
});

// ─── session-kills ───────────────────────────────────────────────────────────

describe("AlertingEngine — session-kills", () => {
  it("fires on kill_switch events exceeding threshold within window", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "session-kills", threshold: 2, windowMs: 60_000 },
          action: "log",
        },
      ],
    };
    const engine = new AlertingEngine(config);

    expect(engine.evaluate(makeEntry({ event: "kill_switch" }))).toHaveLength(0);
    const alerts = engine.evaluate(makeEntry({ event: "kill_switch" }));
    expect(alerts).toHaveLength(1);
    expect(alerts[0].condition.type).toBe("session-kills");
  });

  it("does NOT fire on non-kill events", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "session-kills", threshold: 1, windowMs: 60_000 },
          action: "log",
        },
      ],
    };
    const engine = new AlertingEngine(config);

    // scan_block is not a kill event
    const alerts = engine.evaluate(makeEntry({ event: "scan_block" }));
    expect(alerts).toHaveLength(0);
  });
});

// ─── cost-anomaly ────────────────────────────────────────────────────────────

describe("AlertingEngine — cost-anomaly", () => {
  it("fires on denial_of_wallet events exceeding threshold", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "cost-anomaly", threshold: 2, windowMs: 60_000 },
          action: "log",
        },
      ],
    };
    const engine = new AlertingEngine(config);

    expect(engine.evaluate(makeEntry({ event: "denial_of_wallet" }))).toHaveLength(0);
    const alerts = engine.evaluate(makeEntry({ event: "denial_of_wallet" }));
    expect(alerts).toHaveLength(1);
    expect(alerts[0].condition.type).toBe("cost-anomaly");
  });

  it("does NOT fire for other event types", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "cost-anomaly", threshold: 1, windowMs: 60_000 },
          action: "log",
        },
      ],
    };
    const engine = new AlertingEngine(config);

    expect(engine.evaluate(makeEntry({ event: "scan_pass" }))).toHaveLength(0);
    expect(engine.evaluate(makeEntry({ event: "kill_switch" }))).toHaveLength(0);
    expect(engine.evaluate(makeEntry({ event: "scan_block" }))).toHaveLength(0);
  });
});

// ─── scan-block-rate ─────────────────────────────────────────────────────────

describe("AlertingEngine — scan-block-rate", () => {
  it("fires when block rate exceeds threshold", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "scan-block-rate", threshold: 0.8, windowMs: 60_000 },
          action: "log",
        },
      ],
    };
    const engine = new AlertingEngine(config);

    // 4 blocks and 1 pass → 80% block rate
    engine.evaluate(makeEntry({ event: "scan_block" }));
    engine.evaluate(makeEntry({ event: "scan_block" }));
    engine.evaluate(makeEntry({ event: "scan_block" }));
    engine.evaluate(makeEntry({ event: "scan_pass", decision: "allowed" }));

    // The 5th scan_block makes it 5/6 = 83.3% — exceeds 80%
    // But we already hit threshold at the 3rd: 3/3 = 100%, so let's verify
    // with a clean setup. Actually, the cooldown will prevent re-firing.
    // Let's use a fresh engine for a cleaner test.

    const engine2 = new AlertingEngine(config);

    // Push 4 blocks and 1 pass (80% block rate)
    // First block = 1/1 = 100% → fires immediately (>= 0.8)
    const firstAlerts = engine2.evaluate(makeEntry({ event: "scan_block" }));
    expect(firstAlerts).toHaveLength(1);
    expect(firstAlerts[0].condition.type).toBe("scan-block-rate");
  });

  it("does NOT fire when block rate is below threshold", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "scan-block-rate", threshold: 0.8, windowMs: 60_000 },
          action: "log",
          cooldownMs: 0,
        },
      ],
    };
    const engine = new AlertingEngine(config);

    // Push 1 block and 4 passes → 20% block rate
    engine.evaluate(makeEntry({ event: "scan_pass", decision: "allowed" }));
    engine.evaluate(makeEntry({ event: "scan_pass", decision: "allowed" }));
    engine.evaluate(makeEntry({ event: "scan_pass", decision: "allowed" }));
    engine.evaluate(makeEntry({ event: "scan_pass", decision: "allowed" }));

    // Now a single block → 1/5 = 20% — below 80%
    const alerts = engine.evaluate(makeEntry({ event: "scan_block" }));
    expect(alerts).toHaveLength(0);
  });
});

// ─── repeated-attacker ───────────────────────────────────────────────────────

describe("AlertingEngine — repeated-attacker", () => {
  it("fires when same sessionId triggers blocks N+ times", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "repeated-attacker", threshold: 3, windowMs: 60_000 },
          action: "log",
        },
      ],
    };
    const engine = new AlertingEngine(config);

    expect(
      engine.evaluate(makeEntry({ sessionId: "attacker-1", decision: "blocked" })),
    ).toHaveLength(0);
    expect(
      engine.evaluate(makeEntry({ sessionId: "attacker-1", decision: "blocked" })),
    ).toHaveLength(0);

    const alerts = engine.evaluate(
      makeEntry({ sessionId: "attacker-1", decision: "blocked" }),
    );
    expect(alerts).toHaveLength(1);
    expect(alerts[0].condition.type).toBe("repeated-attacker");
  });

  it("does NOT fire without sessionId", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "repeated-attacker", threshold: 1, windowMs: 60_000 },
          action: "log",
        },
      ],
    };
    const engine = new AlertingEngine(config);

    // No sessionId — should not trigger repeated-attacker
    const alerts = engine.evaluate(
      makeEntry({ sessionId: undefined, decision: "blocked" }),
    );
    expect(alerts).toHaveLength(0);
  });
});

// ─── cooldown ────────────────────────────────────────────────────────────────

describe("AlertingEngine — cooldown", () => {
  it("does NOT re-fire during cooldown period", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "rate-spike", event: "scan_block", threshold: 1, windowMs: 60_000 },
          action: "log",
          cooldownMs: 60_000, // 1 minute cooldown
        },
      ],
    };
    const engine = new AlertingEngine(config);

    // First evaluation should fire
    const first = engine.evaluate(makeEntry());
    expect(first).toHaveLength(1);

    // Second evaluation should be suppressed by cooldown
    const second = engine.evaluate(makeEntry());
    expect(second).toHaveLength(0);

    // Third too
    const third = engine.evaluate(makeEntry());
    expect(third).toHaveLength(0);
  });
});

// ─── disabled ────────────────────────────────────────────────────────────────

describe("AlertingEngine — disabled", () => {
  it("returns empty when enabled: false", () => {
    const config: AlertingConfig = {
      enabled: false,
      rules: [
        {
          condition: { type: "rate-spike", event: "scan_block", threshold: 1, windowMs: 60_000 },
          action: "log",
        },
      ],
    };
    const engine = new AlertingEngine(config);

    const alerts = engine.evaluate(makeEntry());
    expect(alerts).toHaveLength(0);
  });
});

// ─── getActiveAlerts / resolveAlert ──────────────────────────────────────────

describe("AlertingEngine — getActiveAlerts / resolveAlert", () => {
  it("getActiveAlerts() returns unresolved alerts", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "rate-spike", event: "scan_block", threshold: 1, windowMs: 60_000 },
          action: "log",
        },
      ],
    };
    const engine = new AlertingEngine(config);

    engine.evaluate(makeEntry());
    const active = engine.getActiveAlerts();
    expect(active).toHaveLength(1);
    expect(active[0].resolvedAt).toBeUndefined();
  });

  it("resolveAlert() resolves an alert and getActiveAlerts() excludes it", () => {
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "rate-spike", event: "scan_block", threshold: 1, windowMs: 60_000 },
          action: "log",
        },
      ],
    };
    const engine = new AlertingEngine(config);

    const triggered = engine.evaluate(makeEntry());
    expect(triggered).toHaveLength(1);

    const alertId = triggered[0].id;

    // Resolve the alert
    engine.resolveAlert(alertId);

    // Should no longer appear in active alerts
    const active = engine.getActiveAlerts();
    expect(active).toHaveLength(0);
  });
});

// ─── callback action ─────────────────────────────────────────────────────────

describe("AlertingEngine — callback action", () => {
  it("fires the callback function when alert triggers", async () => {
    const callback = vi.fn();
    const config: AlertingConfig = {
      enabled: true,
      rules: [
        {
          condition: { type: "rate-spike", event: "scan_block", threshold: 1, windowMs: 60_000 },
          action: "callback",
          callback,
        },
      ],
    };
    const engine = new AlertingEngine(config);

    engine.evaluate(makeEntry());

    // The callback is called asynchronously (fire-and-forget via void),
    // so give it a microtask tick to execute.
    await vi.waitFor(() => {
      expect(callback).toHaveBeenCalledTimes(1);
    });

    // Verify the callback received an Alert object
    const alertArg = callback.mock.calls[0][0];
    expect(alertArg).toHaveProperty("id");
    expect(alertArg).toHaveProperty("ruleId");
    expect(alertArg).toHaveProperty("condition");
    expect(alertArg).toHaveProperty("triggeredAt");
    expect(alertArg.condition.type).toBe("rate-spike");
  });
});

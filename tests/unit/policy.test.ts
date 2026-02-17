import { describe, it, expect } from "vitest";
import { resolvePolicy, getPreset, isActionAllowed } from "../../packages/core/src/policy/index.js";

describe("resolvePolicy()", () => {
  it("resolves preset policies", () => {
    const policy = resolvePolicy("strict");
    expect(policy.version).toBe(1);
    expect(policy.capabilities.deny).toContain("*");
  });

  it("returns a copy of the preset (not the original)", () => {
    const a = resolvePolicy("balanced");
    const b = resolvePolicy("balanced");
    a.input.maxLength = 999;
    expect(b.input.maxLength).not.toBe(999);
  });

  it("passes through custom policy objects", () => {
    const custom = {
      version: 1 as const,
      capabilities: { allow: ["read"], deny: [], requireApproval: [] },
      limits: {},
      input: { maxLength: 1000, blockPatterns: [], requireQuarantine: true, encodingNormalization: true },
      output: {
        maxLength: 2000, blockPatterns: [], redactPatterns: [],
        detectPII: false, detectCanary: false, blockOnLeak: false,
        detectInjectionPayloads: false, sanitizeMarkdown: false,
      },
      alignment: { enabled: false, strictness: "low" as const },
      dataFlow: { piiHandling: "allow" as const, externalDataSources: [], noExfiltration: false },
    };

    const result = resolvePolicy(custom);
    expect(result).toEqual(custom);
  });

  it("throws for unknown preset names", () => {
    expect(() => resolvePolicy("nonexistent")).toThrow("Unknown policy preset");
  });
});

describe("getPreset()", () => {
  it("returns all preset policies", () => {
    const presets = ["strict", "balanced", "permissive", "customer-support", "code-assistant", "paranoid"] as const;
    for (const name of presets) {
      const policy = getPreset(name);
      expect(policy.version).toBe(1);
    }
  });
});

describe("isActionAllowed()", () => {
  it("blocks actions on deny list", () => {
    const policy = getPreset("customer-support");
    const result = isActionAllowed(policy, "delete_user");
    expect(result.allowed).toBe(false);
  });

  it("allows actions on allow list", () => {
    const policy = getPreset("customer-support");
    const result = isActionAllowed(policy, "search_kb");
    expect(result.allowed).toBe(true);
    expect(result.requiresApproval).toBe(false);
  });

  it("flags actions requiring approval", () => {
    const policy = getPreset("customer-support");
    const result = isActionAllowed(policy, "issue_refund");
    expect(result.allowed).toBe(true);
    expect(result.requiresApproval).toBe(true);
  });

  it("deny list overrides allow list", () => {
    const policy = getPreset("strict");
    // Strict denies everything (deny: ["*"])
    const result = isActionAllowed(policy, "anything");
    expect(result.allowed).toBe(false);
  });

  it("supports wildcard patterns", () => {
    const policy = getPreset("customer-support");
    // deny: ["delete_*", "admin_*", "modify_user"]
    expect(isActionAllowed(policy, "admin_settings").allowed).toBe(false);
    expect(isActionAllowed(policy, "admin_users").allowed).toBe(false);
  });
});

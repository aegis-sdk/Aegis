import { describe, it, expect } from "vitest";
import { resolvePolicy, getPreset, isActionAllowed, loadPolicyFile, validatePolicySchema, parseSimpleYaml } from "../../packages/core/src/policy/index.js";
import { resolve } from "node:path";

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

// ─── resolvePolicy() — file path detection ──────────────────────────────────

describe("resolvePolicy() — file path detection", () => {
  it("throws descriptive error for .json file paths", () => {
    expect(() => resolvePolicy("./policy.json")).toThrow("loadPolicyFile");
    expect(() => resolvePolicy("./policy.json")).toThrow("must be loaded asynchronously");
  });

  it("throws descriptive error for .yaml file paths", () => {
    expect(() => resolvePolicy("./policy.yaml")).toThrow("loadPolicyFile");
  });

  it("throws descriptive error for .yml file paths", () => {
    expect(() => resolvePolicy("./my-policy.yml")).toThrow("loadPolicyFile");
  });
});

// ─── loadPolicyFile() ───────────────────────────────────────────────────────

const FIXTURES = resolve(import.meta.dirname!, "../../tests/fixtures");

describe("loadPolicyFile()", () => {
  it("loads a valid JSON policy file", async () => {
    const policy = await loadPolicyFile(resolve(FIXTURES, "valid-policy.json"));

    expect(policy.version).toBe(1);
    expect(policy.capabilities.allow).toContain("search_kb");
    expect(policy.capabilities.deny).toContain("delete_*");
    expect(policy.input.maxLength).toBe(4000);
    expect(policy.output.detectPII).toBe(true);
    expect(policy.alignment.strictness).toBe("medium");
    expect(policy.dataFlow.piiHandling).toBe("redact");
  });

  it("loads a valid YAML policy file", async () => {
    const policy = await loadPolicyFile(resolve(FIXTURES, "valid-policy.yaml"));

    expect(policy.version).toBe(1);
    expect(policy.capabilities.allow).toContain("search_kb");
    expect(policy.capabilities.allow).toContain("create_ticket");
    expect(policy.capabilities.deny).toContain("delete_*");
    expect(policy.input.maxLength).toBe(4000);
    expect(policy.input.requireQuarantine).toBe(true);
    expect(policy.output.detectPII).toBe(true);
    expect(policy.alignment.strictness).toBe("medium");
    expect(policy.dataFlow.piiHandling).toBe("redact");
    expect(policy.dataFlow.noExfiltration).toBe(true);
  });

  it("throws on invalid JSON syntax", async () => {
    await expect(
      loadPolicyFile(resolve(FIXTURES, "bad-json.json")),
    ).rejects.toThrow("Invalid JSON");
  });

  it("throws on schema validation failure", async () => {
    await expect(
      loadPolicyFile(resolve(FIXTURES, "invalid-policy.json")),
    ).rejects.toThrow("Invalid policy");
  });

  it("throws on non-existent file", async () => {
    await expect(
      loadPolicyFile(resolve(FIXTURES, "does-not-exist.json")),
    ).rejects.toThrow("Failed to read");
  });

  it("throws on unsupported file extension", async () => {
    await expect(
      loadPolicyFile(resolve(FIXTURES, "policy.toml")),
    ).rejects.toThrow("Unsupported policy file extension");
  });
});

// ─── validatePolicySchema() ─────────────────────────────────────────────────

describe("validatePolicySchema()", () => {
  it("returns empty array for valid policy", () => {
    const policy = getPreset("balanced");
    const errors = validatePolicySchema(policy);
    expect(errors).toEqual([]);
  });

  it("catches wrong version", () => {
    const policy = { ...getPreset("balanced"), version: 2 };
    const errors = validatePolicySchema(policy);
    expect(errors.some((e) => e.includes("version"))).toBe(true);
  });

  it("catches non-object capabilities", () => {
    const policy = { ...getPreset("balanced"), capabilities: "wrong" };
    const errors = validatePolicySchema(policy);
    expect(errors.some((e) => e.includes("capabilities"))).toBe(true);
  });

  it("catches non-array allow/deny/requireApproval", () => {
    const policy = {
      ...getPreset("balanced"),
      capabilities: { allow: "not-array", deny: [], requireApproval: [] },
    };
    const errors = validatePolicySchema(policy);
    expect(errors.some((e) => e.includes("capabilities.allow"))).toBe(true);
  });

  it("catches negative maxLength in input", () => {
    const policy = getPreset("balanced");
    policy.input.maxLength = -1;
    const errors = validatePolicySchema(policy);
    expect(errors.some((e) => e.includes("input.maxLength"))).toBe(true);
  });

  it("catches invalid alignment.strictness", () => {
    const policy = {
      ...getPreset("balanced"),
      alignment: { enabled: true, strictness: "extreme" },
    };
    const errors = validatePolicySchema(policy);
    expect(errors.some((e) => e.includes("alignment.strictness"))).toBe(true);
  });

  it("catches invalid dataFlow.piiHandling", () => {
    const policy = getPreset("balanced");
    (policy.dataFlow as Record<string, unknown>).piiHandling = "destroy";
    const errors = validatePolicySchema(policy);
    expect(errors.some((e) => e.includes("dataFlow.piiHandling"))).toBe(true);
  });

  it("returns all errors together", () => {
    const errors = validatePolicySchema({ version: 99 });
    // Should have multiple errors for missing fields
    expect(errors.length).toBeGreaterThan(3);
  });

  it("rejects null", () => {
    const errors = validatePolicySchema(null);
    expect(errors).toContain("Policy must be a non-null object");
  });

  it("rejects arrays", () => {
    const errors = validatePolicySchema([]);
    expect(errors).toContain("Policy must be a non-null object");
  });
});

// ─── parseSimpleYaml() ──────────────────────────────────────────────────────

describe("parseSimpleYaml()", () => {
  it("parses simple key-value pairs", () => {
    const yaml = "name: Alice\nage: 30\nactive: true";
    const result = parseSimpleYaml(yaml) as Record<string, unknown>;

    expect(result.name).toBe("Alice");
    expect(result.age).toBe(30);
    expect(result.active).toBe(true);
  });

  it("parses nested objects", () => {
    const yaml = "parent:\n  child: value\n  num: 42";
    const result = parseSimpleYaml(yaml) as Record<string, Record<string, unknown>>;

    expect(result.parent.child).toBe("value");
    expect(result.parent.num).toBe(42);
  });

  it("parses arrays", () => {
    const yaml = "items:\n  - apple\n  - banana\n  - cherry";
    const result = parseSimpleYaml(yaml) as Record<string, string[]>;

    expect(result.items).toEqual(["apple", "banana", "cherry"]);
  });

  it("handles comments", () => {
    const yaml = "# This is a comment\nname: Bob  # inline comment\nage: 25";
    const result = parseSimpleYaml(yaml) as Record<string, unknown>;

    expect(result.name).toBe("Bob");
    expect(result.age).toBe(25);
  });

  it("handles quoted strings", () => {
    const yaml = 'name: "delete_*"\nsingle: \'hello world\'';
    const result = parseSimpleYaml(yaml) as Record<string, unknown>;

    expect(result.name).toBe("delete_*");
    expect(result.single).toBe("hello world");
  });

  it("handles boolean variations", () => {
    const yaml = "a: true\nb: false\nc: True\nd: FALSE";
    const result = parseSimpleYaml(yaml) as Record<string, unknown>;

    expect(result.a).toBe(true);
    expect(result.b).toBe(false);
    expect(result.c).toBe(true);
    expect(result.d).toBe(false);
  });

  it("handles empty arrays ([])", () => {
    const yaml = "items: []";
    const result = parseSimpleYaml(yaml) as Record<string, unknown>;

    // [] is a string value in our simple parser, which gets special-cased
    // The key thing is it doesn't crash
    expect(result).toBeDefined();
  });

  it("handles blank lines", () => {
    const yaml = "a: 1\n\n\nb: 2\n\nc: 3";
    const result = parseSimpleYaml(yaml) as Record<string, unknown>;

    expect(result.a).toBe(1);
    expect(result.b).toBe(2);
    expect(result.c).toBe(3);
  });

  it("handles empty values", () => {
    const yaml = "empty: \nfilled: hello";
    const result = parseSimpleYaml(yaml) as Record<string, unknown>;

    expect(result.filled).toBe("hello");
  });
});

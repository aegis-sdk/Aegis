import { describe, it, expect, beforeEach } from "vitest";
import { quarantine, isQuarantined, resetUnwrapCount } from "../../packages/core/src/quarantine/index.js";

describe("quarantine()", () => {
  beforeEach(() => {
    resetUnwrapCount();
  });

  it("wraps content with quarantine metadata", () => {
    const input = quarantine("hello world", { source: "user_input" });

    expect(input.__quarantined).toBe(true);
    expect(input.value).toBe("hello world");
    expect(input.metadata.source).toBe("user_input");
    expect(input.metadata.timestamp).toBeInstanceOf(Date);
    expect(input.metadata.id).toMatch(/^q_/);
  });

  it("infers risk level from content source", () => {
    expect(quarantine("", { source: "user_input" }).metadata.risk).toBe("high");
    expect(quarantine("", { source: "email" }).metadata.risk).toBe("high");
    expect(quarantine("", { source: "web_content" }).metadata.risk).toBe("high");
    expect(quarantine("", { source: "api_response" }).metadata.risk).toBe("medium");
    expect(quarantine("", { source: "tool_output" }).metadata.risk).toBe("medium");
    expect(quarantine("", { source: "database" }).metadata.risk).toBe("low");
    expect(quarantine("", { source: "rag_retrieval" }).metadata.risk).toBe("low");
    expect(quarantine("", { source: "unknown" }).metadata.risk).toBe("high");
  });

  it("allows explicit risk level override", () => {
    const input = quarantine("hello", { source: "database", risk: "critical" });
    expect(input.metadata.risk).toBe("critical");
  });

  it("is frozen and immutable", () => {
    const input = quarantine("hello", { source: "user_input" });
    expect(Object.isFrozen(input)).toBe(true);
  });

  it("prevents string coercion via toString()", () => {
    const input = quarantine("hello", { source: "user_input" });
    expect(() => input.toString()).toThrow("Cannot coerce Quarantined content to string");
  });

  it("prevents primitive coercion via Symbol.toPrimitive", () => {
    const input = quarantine("hello", { source: "user_input" });
    expect(() => `${input as unknown as string}`).toThrow("Cannot coerce Quarantined content to a primitive");
  });
});

describe("unsafeUnwrap()", () => {
  beforeEach(() => {
    resetUnwrapCount();
  });

  it("returns the raw value with a reason", () => {
    const input = quarantine("hello", { source: "user_input" });
    const raw = input.unsafeUnwrap({ reason: "Passing to legacy system" });
    expect(raw).toBe("hello");
  });

  it("requires a reason", () => {
    const input = quarantine("hello", { source: "user_input" });
    expect(() => input.unsafeUnwrap({ reason: "" })).toThrow("requires a 'reason'");
  });
});

describe("isQuarantined()", () => {
  it("returns true for quarantined values", () => {
    const input = quarantine("hello", { source: "user_input" });
    expect(isQuarantined(input)).toBe(true);
  });

  it("returns false for plain values", () => {
    expect(isQuarantined("hello")).toBe(false);
    expect(isQuarantined(42)).toBe(false);
    expect(isQuarantined(null)).toBe(false);
    expect(isQuarantined(undefined)).toBe(false);
    expect(isQuarantined({ __quarantined: false })).toBe(false);
  });
});

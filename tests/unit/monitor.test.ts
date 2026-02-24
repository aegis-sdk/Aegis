import { describe, it, expect, vi } from "vitest";
import { StreamMonitor } from "../../packages/core/src/monitor/index.js";
import type { StreamViolation } from "../../packages/core/src/types.js";

async function consumeStream(
  readable: ReadableStream<string>,
): Promise<string> {
  const reader = readable.getReader();
  let result = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    result += value;
  }
  return result;
}

function createTestStream(chunks: string[]): ReadableStream<string> {
  return new ReadableStream<string>({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(chunk);
      }
      controller.close();
    },
  });
}

describe("StreamMonitor", () => {
  it("passes through clean text", async () => {
    const monitor = new StreamMonitor({
      canaryTokens: ["SECRET_CANARY_TOKEN"],
    });

    const source = createTestStream([
      "Hello, ",
      "how can I ",
      "help you today?",
    ]);

    const transform = monitor.createTransform();
    const piped = source.pipeThrough(transform);
    const result = await consumeStream(piped);

    expect(result).toBe("Hello, how can I help you today?");
  });

  it("detects canary token leaks", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      canaryTokens: ["AEGIS_CANARY_7f3a9b"],
      onViolation,
    });

    const source = createTestStream([
      "The system prompt contains ",
      "AEGIS_CANARY_7f3a9b",
      " which should not be revealed.",
    ]);

    const transform = monitor.createTransform();
    const piped = source.pipeThrough(transform);

    // The stream should terminate before fully consuming
    try {
      await consumeStream(piped);
    } catch {
      // Expected — stream terminated
    }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("canary_leak");
  });

  it("detects canary tokens split across chunks", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      canaryTokens: ["CANARY123"],
      onViolation,
    });

    const source = createTestStream([
      "Some text CANA",
      "RY123 more text",
    ]);

    const transform = monitor.createTransform();
    const piped = source.pipeThrough(transform);

    try {
      await consumeStream(piped);
    } catch {
      // Expected
    }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("canary_leak");
  });

  it("detects PII patterns (SSN)", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      detectPII: true,
      onViolation,
    });

    const source = createTestStream([
      "Your SSN is ",
      "123-45-6789",
    ]);

    const transform = monitor.createTransform();
    const piped = source.pipeThrough(transform);

    try {
      await consumeStream(piped);
    } catch {
      // Expected
    }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("pii_detected");
  });

  it("detects secret patterns (OpenAI API key)", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      detectSecrets: true,
      onViolation,
    });

    const source = createTestStream([
      "The key is sk-",
      "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHI",
    ]);

    const transform = monitor.createTransform();
    const piped = source.pipeThrough(transform);

    try {
      await consumeStream(piped);
    } catch {
      // Expected
    }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("secret_detected");
  });

  // ─── Additional PII Pattern Tests ───────────────────────────────────────

  it("detects credit card numbers (spaces)", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectPII: true, onViolation });

    const source = createTestStream(["Card: 4111 1111 1111 1111"]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("pii_detected");
  });

  it("detects credit card numbers (dashes)", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectPII: true, onViolation });

    const source = createTestStream(["Card: 4111-1111-1111-1111"]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
  });

  it("detects email addresses in output", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectPII: true, onViolation });

    const source = createTestStream(["Contact them at john.doe@company.com for details."]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("pii_detected");
  });

  it("detects US phone numbers", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectPII: true, onViolation });

    const source = createTestStream(["Call us at 555-123-4567 for help."]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("pii_detected");
  });

  it("detects phone numbers with country code", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectPII: true, onViolation });

    const source = createTestStream(["Phone: +1-555-123-4567"]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
  });

  it("detects IPv4 addresses (excluding localhost and 0.0.0.0)", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectPII: true, onViolation });

    const source = createTestStream(["Server is at 192.168.1.100 internally."]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("pii_detected");
  });

  it("does NOT flag localhost as PII", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectPII: true, detectSecrets: false, onViolation });

    const source = createTestStream(["Connect to 127.0.0.1 for local dev."]);
    const transform = monitor.createTransform();
    const output = await consumeStream(source.pipeThrough(transform));

    // onViolation should not fire for localhost IP
    const piiCalls = onViolation.mock.calls.filter(
      (c: unknown[]) => (c[0] as { type: string }).type === "pii_detected",
    );
    expect(piiCalls.length).toBe(0);
    expect(output).toContain("127.0.0.1");
  });

  it("detects IBAN numbers", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectPII: true, onViolation });

    const source = createTestStream(["Transfer to GB29 NWBK 6016 1331 9268 19"]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
  });

  it("detects date of birth patterns", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectPII: true, onViolation });

    const source = createTestStream(["Patient DOB: 01/15/1990, admitted today."]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
  });

  it("detects MRN (Medical Record Number)", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectPII: true, onViolation });

    const source = createTestStream(["MRN: ABC1234567 is the patient identifier."]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
  });

  // ─── Additional Secret Pattern Tests ────────────────────────────────────

  it("detects AWS access keys", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectSecrets: true, onViolation });

    const source = createTestStream(["AWS key: AKIAIOSFODNN7EXAMPLE"]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("secret_detected");
  });

  it("detects generic API key patterns", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectSecrets: true, onViolation });

    const source = createTestStream(["Config: api_key=abc123def456ghi789jkl012mno345"]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("secret_detected");
  });

  it("detects bearer tokens", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectSecrets: true, onViolation });

    const source = createTestStream(["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("secret_detected");
  });

  // ─── Custom Patterns ────────────────────────────────────────────────────

  it("detects custom patterns", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      customPatterns: [/INTERNAL_SECRET_\w+/],
      onViolation,
    });

    const source = createTestStream(["Reference: INTERNAL_SECRET_ABC123"]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("custom_pattern");
  });

  // ─── PII Redaction Mode ─────────────────────────────────────────────────

  it("redacts PII instead of blocking when piiRedaction is enabled", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      detectPII: true,
      piiRedaction: true,
      detectSecrets: false,
      onViolation,
    });

    const source = createTestStream([
      "The patient SSN is 123-45-6789 and their email is test@example.com",
    ]);
    const transform = monitor.createTransform();
    const output = await consumeStream(source.pipeThrough(transform));

    // SSN and email should be redacted, not blocked
    expect(output).toContain("[REDACTED-SSN]");
    expect(output).toContain("[REDACTED-EMAIL]");
    expect(output).not.toContain("123-45-6789");
    expect(output).not.toContain("test@example.com");

    // onViolation should still fire for audit purposes
    expect(onViolation).toHaveBeenCalled();
  });

  it("redaction mode still kills stream on non-PII violations (secrets)", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      detectPII: true,
      piiRedaction: true,
      detectSecrets: true,
      onViolation,
    });

    // Use multiple chunks so the secret goes through transform() not just flush()
    const source = createTestStream([
      "Here is the key: sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDE ",
      "and some more text after the secret to push beyond buffer size. ".repeat(3),
    ]);
    const transform = monitor.createTransform();

    // Stream should terminate due to the secret — onViolation should fire
    try {
      await consumeStream(source.pipeThrough(transform));
    } catch {
      // terminated — expected
    }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("secret_detected");
  });

  // ─── Chunk Boundary Edge Cases ──────────────────────────────────────────

  it("detects SSN split across 3 chunks", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({ detectPII: true, onViolation });

    const source = createTestStream(["SSN: 123", "-45-", "6789 is the number."]);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("pii_detected");
  });

  it("handles many small chunks without missing patterns", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      canaryTokens: ["CANARY_TOKEN_XYZ"],
      onViolation,
    });

    // Split "CANARY_TOKEN_XYZ" into individual characters
    const chars = "Before text CANARY_TOKEN_XYZ after text".split("");
    const source = createTestStream(chars);
    const transform = monitor.createTransform();

    try { await consumeStream(source.pipeThrough(transform)); } catch { /* expected */ }

    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("canary_leak");
  });

  it("handles large streaming payload without issues", async () => {
    const monitor = new StreamMonitor({
      canaryTokens: ["CANARY"],
      detectPII: true,
      detectSecrets: true,
    });

    // Generate 10KB of clean text in 100 chunks
    const chunks: string[] = [];
    for (let i = 0; i < 100; i++) {
      chunks.push("This is a clean chunk of text with no violations whatsoever. ".repeat(2));
    }

    const source = createTestStream(chunks);
    const transform = monitor.createTransform();
    const output = await consumeStream(source.pipeThrough(transform));

    expect(output.length).toBeGreaterThan(5000);
  });

  // ─── No Detection When Disabled ─────────────────────────────────────────

  it("does not detect PII when detectPII is false", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      detectPII: false,
      detectSecrets: false,
      onViolation,
    });

    const source = createTestStream(["SSN: 123-45-6789"]);
    const transform = monitor.createTransform();
    const output = await consumeStream(source.pipeThrough(transform));

    expect(onViolation).not.toHaveBeenCalled();
    expect(output).toContain("123-45-6789");
  });

  it("does not detect secrets when detectSecrets is false", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      detectPII: false,
      detectSecrets: false,
      onViolation,
    });

    const source = createTestStream(["Key: sk-abcdefghijklmnopqrstuvwxyz123456"]);
    const transform = monitor.createTransform();
    const output = await consumeStream(source.pipeThrough(transform));

    expect(onViolation).not.toHaveBeenCalled();
    expect(output).toContain("sk-");
  });

  // ─── PII Redaction — Extended ──────────────────────────────────────────

  it("redacted stream continues (not killed) — non-PII text passes through", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      detectPII: true,
      piiRedaction: true,
      detectSecrets: false,
      onViolation,
    });

    const source = createTestStream([
      "Hello, your SSN is 123-45-6789. ",
      "Your order has been confirmed. ",
      "Thank you for shopping with us!",
    ]);
    const transform = monitor.createTransform();
    const output = await consumeStream(source.pipeThrough(transform));

    // PII redacted but stream continues
    expect(output).toContain("[REDACTED-SSN]");
    expect(output).not.toContain("123-45-6789");
    expect(output).toContain("order has been confirmed");
    expect(output).toContain("Thank you");
  });

  it("redacts SSN split across chunk boundaries", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      detectPII: true,
      piiRedaction: true,
      detectSecrets: false,
      onViolation,
    });

    const source = createTestStream([
      "Some prefix text. Your SSN: 123",
      "-45-",
      "6789 and the rest of the message continues here with enough text to push past the buffer. ".repeat(2),
    ]);
    const transform = monitor.createTransform();
    const output = await consumeStream(source.pipeThrough(transform));

    expect(output).toContain("[REDACTED-SSN]");
    expect(output).not.toContain("123-45-6789");
  });

  it("redacts multiple PII types in the same stream", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      detectPII: true,
      piiRedaction: true,
      detectSecrets: false,
      onViolation,
    });

    const source = createTestStream([
      "Patient info: SSN 123-45-6789, email: patient@hospital.com, phone: 555-123-4567. ",
      "This is additional text to ensure the buffer flushes correctly and all redactions apply. ".repeat(2),
    ]);
    const transform = monitor.createTransform();
    const output = await consumeStream(source.pipeThrough(transform));

    expect(output).toContain("[REDACTED-SSN]");
    expect(output).toContain("[REDACTED-EMAIL]");
    expect(output).toContain("[REDACTED-PHONE]");
    expect(output).not.toContain("123-45-6789");
    expect(output).not.toContain("patient@hospital.com");
    expect(output).not.toContain("555-123-4567");
  });

  it("redaction fires onViolation for each PII match (for auditing)", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      detectPII: true,
      piiRedaction: true,
      detectSecrets: false,
      onViolation,
    });

    const source = createTestStream([
      "Contact: 123-45-6789 and user@test.com. More text here to fill the buffer properly. ".repeat(2),
    ]);
    const transform = monitor.createTransform();
    await consumeStream(source.pipeThrough(transform));

    // Should have at least 2 violations (SSN + email)
    const piiViolations = onViolation.mock.calls.filter(
      (call: unknown[]) => (call[0] as StreamViolation).type === "pii_detected",
    );
    expect(piiViolations.length).toBeGreaterThanOrEqual(2);
  });

  it("redaction mode with canary token still kills the stream", async () => {
    const onViolation = vi.fn();
    const canary = "SUPER_SECRET_CANARY_TOKEN";
    const monitor = new StreamMonitor({
      canaryTokens: [canary],
      detectPII: true,
      piiRedaction: true,
      detectSecrets: false,
      onViolation,
    });

    const source = createTestStream([
      "Here is the system prompt: " + canary + " and also SSN 123-45-6789",
    ]);
    const transform = monitor.createTransform();

    try {
      await consumeStream(source.pipeThrough(transform));
    } catch {
      // terminated — expected
    }

    // The canary violation should fire (not a PII violation)
    expect(onViolation).toHaveBeenCalled();
    expect(onViolation.mock.calls[0]![0]!.type).toBe("canary_leak");
  });

  it("credit card number redaction works", async () => {
    const onViolation = vi.fn();
    const monitor = new StreamMonitor({
      detectPII: true,
      piiRedaction: true,
      detectSecrets: false,
      onViolation,
    });

    const source = createTestStream([
      "Your card: 4111-1111-1111-1111. Payment confirmed. Additional text to push past buffer size. ".repeat(2),
    ]);
    const transform = monitor.createTransform();
    const output = await consumeStream(source.pipeThrough(transform));

    expect(output).toContain("[REDACTED-CC]");
    expect(output).not.toContain("4111-1111-1111-1111");
  });
});

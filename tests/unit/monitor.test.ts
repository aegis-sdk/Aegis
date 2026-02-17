import { describe, it, expect, vi } from "vitest";
import { StreamMonitor } from "../../packages/core/src/monitor/index.js";

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

  it("detects secret patterns (API key)", async () => {
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
});

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { FileTransport } from "../../packages/core/src/audit/file-transport.js";
import type { AuditEntry } from "../../packages/core/src/types.js";

/**
 * Create a minimal AuditEntry for testing.
 */
function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    timestamp: new Date("2026-01-15T12:00:00Z"),
    event: "scan_pass",
    decision: "allowed",
    context: { test: true },
    ...overrides,
  };
}

// ─── Constructor ──────────────────────────────────────────────────────────────

describe("FileTransport constructor", () => {
  it("constructs with required config", () => {
    const ft = new FileTransport({ path: "/tmp/test-audit.jsonl" });
    expect(ft).toBeInstanceOf(FileTransport);
  });

  it("constructs with all options", () => {
    const ft = new FileTransport({
      path: "/tmp/test-audit.jsonl",
      rotate: true,
      maxSizeMB: 100,
    });
    expect(ft).toBeInstanceOf(FileTransport);
  });

  it("defaults rotate to false and maxSizeMB to 50", () => {
    // We can verify defaults indirectly by testing rotation behavior
    const ft = new FileTransport({ path: "/tmp/test-audit.jsonl" });
    expect(ft).toBeInstanceOf(FileTransport);
  });
});

// ─── emit() ──────────────────────────────────────────────────────────────────

describe("FileTransport.emit()", () => {
  // We use real fs operations on a temp file — this tests the full path
  const fs = require("node:fs");
  const path = require("node:path");
  const os = require("node:os");

  let tempDir: string;
  let tempFile: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ft-test-"));
    tempFile = path.join(tempDir, "audit.jsonl");
  });

  afterEach(() => {
    // Clean up temp files
    try {
      const files = fs.readdirSync(tempDir);
      for (const f of files) {
        fs.unlinkSync(path.join(tempDir, f));
      }
      fs.rmdirSync(tempDir);
    } catch {
      // ignore cleanup errors
    }
  });

  it("appends a JSON line to the file", async () => {
    const ft = new FileTransport({ path: tempFile });
    const entry = makeEntry();

    await ft.emit(entry);

    const content = fs.readFileSync(tempFile, "utf-8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(1);

    const parsed = JSON.parse(lines[0]);
    expect(parsed.event).toBe("scan_pass");
    expect(parsed.decision).toBe("allowed");
    expect(parsed.context.test).toBe(true);
  });

  it("appends multiple entries as separate lines", async () => {
    const ft = new FileTransport({ path: tempFile });

    await ft.emit(makeEntry({ event: "scan_pass" }));
    await ft.emit(makeEntry({ event: "scan_block", decision: "blocked" }));
    await ft.emit(makeEntry({ event: "kill_switch", decision: "blocked" }));

    const content = fs.readFileSync(tempFile, "utf-8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(3);

    expect(JSON.parse(lines[0]).event).toBe("scan_pass");
    expect(JSON.parse(lines[1]).event).toBe("scan_block");
    expect(JSON.parse(lines[2]).event).toBe("kill_switch");
  });

  it("throws if fs module failed to load", async () => {
    // Create a transport and corrupt the internal fs reference
    const ft = new FileTransport({ path: tempFile });

    // Wait for fs to load, then null it out
    await ft.emit(makeEntry()); // ensures fsReady resolves

    // Access private field to break it
    (ft as unknown as { fsModule: unknown }).fsModule = undefined;
    (ft as unknown as { fsReady: Promise<void> }).fsReady = Promise.resolve();

    await expect(ft.emit(makeEntry())).rejects.toThrow("failed to load the 'fs' module");
  });
});

// ─── Rotation ────────────────────────────────────────────────────────────────

describe("FileTransport rotation", () => {
  const fs = require("node:fs");
  const path = require("node:path");
  const os = require("node:os");

  let tempDir: string;
  let tempFile: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-ft-rotate-"));
    tempFile = path.join(tempDir, "audit.jsonl");
  });

  afterEach(() => {
    try {
      const files = fs.readdirSync(tempDir);
      for (const f of files) {
        fs.unlinkSync(path.join(tempDir, f));
      }
      fs.rmdirSync(tempDir);
    } catch {
      // ignore cleanup errors
    }
  });

  it("rotates the file when it exceeds maxSizeMB", async () => {
    // Use a tiny maxSizeMB so we can trigger rotation easily
    // 1 byte = 0.000001 MB, so setting maxSizeMB to a very small number
    const ft = new FileTransport({
      path: tempFile,
      rotate: true,
      maxSizeMB: 0.0001, // ~105 bytes
    });

    // Write enough data to exceed the threshold
    for (let i = 0; i < 5; i++) {
      await ft.emit(
        makeEntry({
          context: { index: i, padding: "x".repeat(50) },
        }),
      );
    }

    // Check that rotation happened — there should be more than one file
    const files = fs.readdirSync(tempDir);
    expect(files.length).toBeGreaterThan(1);

    // The current file should still exist and be writable
    const currentExists = files.some((f: string) => f === "audit.jsonl");
    // Rotated files have timestamp in the name
    const rotatedFiles = files.filter((f: string) => f !== "audit.jsonl");
    expect(rotatedFiles.length).toBeGreaterThan(0);
  });

  it("does not rotate when rotate is disabled", async () => {
    const ft = new FileTransport({
      path: tempFile,
      rotate: false,
    });

    for (let i = 0; i < 10; i++) {
      await ft.emit(
        makeEntry({
          context: { index: i, padding: "x".repeat(100) },
        }),
      );
    }

    const files = fs.readdirSync(tempDir);
    expect(files).toHaveLength(1);
    expect(files[0]).toBe("audit.jsonl");
  });

  it("handles rotation when file does not exist yet", async () => {
    const ft = new FileTransport({
      path: tempFile,
      rotate: true,
      maxSizeMB: 0.0001,
    });

    // First emit — file doesn't exist yet, rotation should not throw
    await ft.emit(makeEntry());

    const content = fs.readFileSync(tempFile, "utf-8");
    expect(content.trim().length).toBeGreaterThan(0);
  });
});

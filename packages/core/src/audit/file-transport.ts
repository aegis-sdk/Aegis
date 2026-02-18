import type { AuditEntry } from "../types.js";

/**
 * Configuration for the JSON-Lines file transport.
 */
export interface FileTransportConfig {
  /** Path to the JSONL audit file. */
  path: string;
  /** Enable log rotation when `maxSizeMB` is exceeded. Default: `false`. */
  rotate?: boolean;
  /** Maximum file size in megabytes before rotation. Default: `50`. */
  maxSizeMB?: number;
}

/**
 * JSONL (JSON Lines) file transport for the Aegis audit log.
 *
 * Each audit entry is appended as a single JSON line. This transport
 * requires a Node.js runtime (`fs` module). When running in an Edge
 * or browser environment, construction throws a descriptive error.
 *
 * @example
 * ```ts
 * import { FileTransport, AuditLog } from '@aegis-sdk/core';
 *
 * const file = new FileTransport({ path: './audit.jsonl', rotate: true, maxSizeMB: 100 });
 * const audit = new AuditLog({ transports: ['json-file'] });
 * audit.setFileTransport(file);
 * ```
 */
export class FileTransport {
  private readonly filePath: string;
  private readonly rotate: boolean;
  private readonly maxSizeBytes: number;

  /**
   * Cached reference to `node:fs` obtained via synchronous `require` or
   * stored after the first successful dynamic import.
   */
  private fsModule: FsLike | undefined;

  /** Promise that resolves once the async fs import completes (if needed). */
  private fsReady: Promise<void>;

  constructor(config: FileTransportConfig) {
    // Guard: Node.js environment check
    if (typeof process === "undefined" || typeof process.versions?.node === "undefined") {
      throw new Error(
        "[aegis] FileTransport requires a Node.js runtime. " +
          "It cannot be used in Edge or browser environments. " +
          "Consider using a custom transport instead.",
      );
    }

    this.filePath = config.path;
    this.rotate = config.rotate ?? false;
    this.maxSizeBytes = (config.maxSizeMB ?? 50) * 1024 * 1024;

    // Kick off the dynamic import immediately so it is ready by the time
    // `emit()` is called. We intentionally swallow errors here — they will
    // surface when `emit()` tries to use `this.fsModule`.
    this.fsReady = this.loadFs();
  }

  /**
   * Append an audit entry as a JSON line to the configured file.
   *
   * If the `fs` module has not finished loading yet this method will
   * `await` the pending import before writing.
   */
  async emit(entry: AuditEntry): Promise<void> {
    if (!this.fsModule) {
      await this.fsReady;
    }

    const fs = this.fsModule;
    if (!fs) {
      throw new Error("[aegis] FileTransport: failed to load the 'fs' module.");
    }

    // Optionally rotate the file before writing
    if (this.rotate) {
      await this.maybeRotate(fs);
    }

    const line = JSON.stringify(entry) + "\n";
    fs.appendFileSync(this.filePath, line, "utf-8");
  }

  // ── Private helpers ────────────────────────────────────────────────────

  /**
   * Dynamically import Node.js `fs` so this module can be bundled without
   * a hard static dependency on `node:fs`.
   */
  private async loadFs(): Promise<void> {
    try {
      // Use a string variable so TypeScript does not attempt to resolve the
      // module during DTS generation (only string-literal imports are resolved).
      const nodeFs = "node:fs";
      const mod = (await import(nodeFs)) as FsLike;
      this.fsModule = mod;
    } catch {
      try {
        const bareFs = "fs";
        const mod = (await import(bareFs)) as FsLike;
        this.fsModule = mod;
      } catch {
        // Will be surfaced in emit()
      }
    }
  }

  /**
   * Rotate the log file if it exceeds `maxSizeBytes`.
   *
   * Rotation renames the current file to `<path>.<timestamp>.jsonl` and
   * the next `emit()` call will create a fresh file.
   */
  private async maybeRotate(fs: FsLike): Promise<void> {
    try {
      const stat = fs.statSync(this.filePath);
      if (stat && stat.size >= this.maxSizeBytes) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const rotatedPath = this.filePath.replace(/\.jsonl$/, `.${timestamp}.jsonl`);
        fs.renameSync(this.filePath, rotatedPath);
      }
    } catch {
      // File may not exist yet — that is fine.
    }
  }
}

// ── Minimal `fs` shape we rely on ──────────────────────────────────────────

interface FsLike {
  appendFileSync(path: string, data: string, encoding: string): void;
  statSync(path: string): { size: number } | null;
  renameSync(oldPath: string, newPath: string): void;
}

import type {
  AuditEventType,
  ExtractedContent,
  InputScannerConfig,
  MediaType,
  MultiModalConfig,
  MultiModalScanResult,
  TextExtractorFn,
} from "../types.js";
import { quarantine } from "../quarantine/index.js";
import { InputScanner } from "../scanner/index.js";

// Re-export types so consumers can import from the module directly
export type {
  MediaType,
  TextExtractorFn,
  ExtractedContent,
  MultiModalConfig,
  MultiModalScanResult,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/** Default maximum file size: 10 MB */
const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024;

/** All supported media types. */
const ALL_MEDIA_TYPES: readonly MediaType[] = [
  "image",
  "audio",
  "video",
  "pdf",
  "document",
] as const;

// ─── Errors ───────────────────────────────────────────────────────────────────

/**
 * Error thrown when media content exceeds the configured maximum file size.
 */
export class MultiModalFileTooLarge extends Error {
  public readonly fileSize: number;
  public readonly maxFileSize: number;

  constructor(fileSize: number, maxFileSize: number) {
    super(
      `[aegis] Multi-modal scan rejected: file size ${fileSize} bytes exceeds maximum ${maxFileSize} bytes`,
    );
    this.name = "MultiModalFileTooLarge";
    this.fileSize = fileSize;
    this.maxFileSize = maxFileSize;
  }
}

/**
 * Error thrown when the provided media type is not in the allowed list.
 */
export class MultiModalUnsupportedType extends Error {
  public readonly mediaType: string;
  public readonly allowedTypes: readonly MediaType[];

  constructor(mediaType: string, allowedTypes: readonly MediaType[]) {
    super(
      `[aegis] Multi-modal scan rejected: media type "${mediaType}" is not allowed. Allowed types: ${allowedTypes.join(", ")}`,
    );
    this.name = "MultiModalUnsupportedType";
    this.mediaType = mediaType;
    this.allowedTypes = allowedTypes;
  }
}

/**
 * Error thrown when the text extraction function fails.
 */
export class MultiModalExtractionFailed extends Error {
  public readonly mediaType: MediaType;
  public readonly cause: unknown;

  constructor(mediaType: MediaType, cause: unknown) {
    const causeMessage = cause instanceof Error ? cause.message : String(cause);
    super(`[aegis] Multi-modal text extraction failed for "${mediaType}": ${causeMessage}`);
    this.name = "MultiModalExtractionFailed";
    this.mediaType = mediaType;
    this.cause = cause;
  }
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

/**
 * MultiModalScanner — extracts text from images, PDFs, audio, and other media,
 * then scans the extracted text for prompt injection attempts.
 *
 * The actual OCR/extraction is supplied as a `TextExtractorFn`, making this
 * module provider-agnostic. Any service (Tesseract, Google Vision, AWS Textract,
 * Whisper, etc.) can be plugged in.
 *
 * @example
 * ```ts
 * import { MultiModalScanner } from '@aegis-sdk/core';
 *
 * const scanner = new MultiModalScanner({
 *   extractText: async (content, mediaType) => {
 *     const text = await myOcrService.extract(content);
 *     return { text, confidence: 0.95 };
 *   },
 * });
 *
 * const result = await scanner.scanMedia(imageBytes, 'image');
 * if (!result.safe) {
 *   console.warn('Injection detected in image text:', result.scanResult.detections);
 * }
 * ```
 */
export class MultiModalScanner {
  private readonly enabled: boolean;
  private readonly maxFileSize: number;
  private readonly allowedMediaTypes: readonly MediaType[];
  private readonly extractText: TextExtractorFn;
  private readonly inputScanner: InputScanner;
  private auditCallback:
    | ((entry: {
        event: AuditEventType;
        decision?: "allowed" | "blocked" | "flagged" | "info";
        context?: Record<string, unknown>;
      }) => void)
    | null = null;

  constructor(config: MultiModalConfig) {
    this.enabled = config.enabled ?? true;
    this.maxFileSize = config.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
    this.allowedMediaTypes = config.allowedMediaTypes ?? ALL_MEDIA_TYPES;
    this.extractText = config.extractText;

    // Build scanner config, optionally overriding sensitivity
    const scannerConfig: InputScannerConfig = {};
    if (config.scannerSensitivity) {
      scannerConfig.sensitivity = config.scannerSensitivity;
    }
    this.inputScanner = new InputScanner(scannerConfig);
  }

  /**
   * Set an audit callback for logging multi-modal scan events.
   * Used internally by the Aegis class to wire up the AuditLog.
   */
  setAuditCallback(
    callback: (entry: {
      event: AuditEventType;
      decision?: "allowed" | "blocked" | "flagged" | "info";
      context?: Record<string, unknown>;
    }) => void,
  ): void {
    this.auditCallback = callback;
  }

  /**
   * Scan media content for prompt injection attempts.
   *
   * The pipeline:
   * 1. Validate file size against `maxFileSize`
   * 2. Validate media type against `allowedMediaTypes`
   * 3. Call the user-supplied `extractText` function
   * 4. Quarantine the extracted text with source `"file_upload"`
   * 5. Run the InputScanner on the quarantined text
   * 6. Return a comprehensive result
   *
   * @param content - Raw media content as `Uint8Array` or base64-encoded string
   * @param mediaType - The type of media being scanned
   * @returns Scan result with extraction data and safety verdict
   *
   * @throws {MultiModalFileTooLarge} if content exceeds `maxFileSize`
   * @throws {MultiModalUnsupportedType} if `mediaType` is not in `allowedMediaTypes`
   * @throws {MultiModalExtractionFailed} if the text extraction function throws
   */
  async scanMedia(
    content: Uint8Array | string,
    mediaType: MediaType,
  ): Promise<MultiModalScanResult> {
    // Step 1: Calculate file size
    const fileSize =
      content instanceof Uint8Array
        ? content.byteLength
        : new TextEncoder().encode(content).byteLength;

    // Step 2: Validate file size
    if (fileSize > this.maxFileSize) {
      this.emitAudit("scan_block", "blocked", {
        reason: "file_too_large",
        fileSize,
        maxFileSize: this.maxFileSize,
        mediaType,
      });
      throw new MultiModalFileTooLarge(fileSize, this.maxFileSize);
    }

    // Step 3: Validate media type
    if (!this.allowedMediaTypes.includes(mediaType)) {
      this.emitAudit("scan_block", "blocked", {
        reason: "unsupported_media_type",
        mediaType,
        allowedTypes: [...this.allowedMediaTypes],
      });
      throw new MultiModalUnsupportedType(mediaType, this.allowedMediaTypes);
    }

    // Step 4: Extract text from media
    let extracted: ExtractedContent;
    try {
      extracted = await this.extractText(content, mediaType);
    } catch (err: unknown) {
      this.emitAudit("scan_block", "blocked", {
        reason: "extraction_failed",
        mediaType,
        error: err instanceof Error ? err.message : String(err),
      });
      throw new MultiModalExtractionFailed(mediaType, err);
    }

    // Step 5: Quarantine the extracted text and scan it
    const quarantined = quarantine(extracted.text, { source: "file_upload" });
    const scanResult = this.inputScanner.scan(quarantined);

    const safe = scanResult.safe;

    // Step 6: Emit audit event
    this.emitAudit(safe ? "scan_pass" : "scan_block", safe ? "allowed" : "blocked", {
      mediaType,
      fileSize,
      confidence: extracted.confidence,
      score: scanResult.score,
      detections: scanResult.detections.length,
      safe,
    });

    return {
      extracted,
      mediaType,
      scanResult,
      fileSize,
      safe,
    };
  }

  /**
   * Check whether multi-modal scanning is enabled.
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Get the list of allowed media types.
   */
  getAllowedMediaTypes(): readonly MediaType[] {
    return this.allowedMediaTypes;
  }

  /**
   * Get the configured maximum file size in bytes.
   */
  getMaxFileSize(): number {
    return this.maxFileSize;
  }

  /** Emit an audit event through the callback, if wired. */
  private emitAudit(
    event: AuditEventType,
    decision: "allowed" | "blocked" | "flagged" | "info",
    context: Record<string, unknown>,
  ): void {
    if (this.auditCallback) {
      this.auditCallback({ event, decision, context });
    }
  }
}

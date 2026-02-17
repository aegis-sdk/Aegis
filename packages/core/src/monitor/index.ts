import type { StreamMonitorConfig, StreamViolation } from "../types.js";

const DEFAULT_CONFIG: Required<StreamMonitorConfig> = {
  canaryTokens: [],
  detectPII: true,
  piiRedaction: false,
  detectSecrets: true,
  detectInjectionPayloads: false,
  sanitizeMarkdown: false,
  customPatterns: [],
  chunkStrategy: "sentence",
  chunkSize: 50,
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  onViolation: () => {},
};

// Common PII patterns
// Each key is used as the redaction label, e.g. [REDACTED-SSN]
const PII_PATTERNS: Record<string, RegExp> = {
  // US SSN: 123-45-6789
  SSN: /\b\d{3}-\d{2}-\d{4}\b/,

  // Credit card numbers (basic Luhn-length): 1234 5678 9012 3456 or 1234-5678-9012-3456
  CC: /\b(?:\d{4}[-\s]?){3}\d{4}\b/,

  // Email (we scan for output of emails that look like they're being exfiltrated)
  EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,

  // US phone numbers: +1-555-123-4567, (555) 123-4567, 555-123-4567, +1 555 123 4567
  PHONE: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/,

  // IPv4 addresses: 192.168.1.1 (excluding common non-PII like 0.0.0.0, 127.0.0.1, 255.255.255.255)
  IP_ADDRESS:
    /\b(?!(?:0\.0\.0\.0|127\.0\.0\.1|255\.255\.255\.255|localhost)\b)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/,

  // Passport numbers: 1-2 letters followed by 6-8 digits (covers US, UK, many EU formats)
  PASSPORT: /\b[A-Z]{1,2}\d{6,8}\b/,

  // Date of birth: contextual DOB patterns — "DOB: 01/15/1990", "born on 1990-01-15", "date of birth: 15/01/1990"
  DOB: /\b(?:DOB|date\s+of\s+birth|born\s+on|birthday)\s*[:;]?\s*(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}|\d{4}[/\-.]\d{1,2}[/\-.]\d{1,2})\b/i,

  // IBAN: 2 letter country code + 2 check digits + up to 30 alphanumeric
  IBAN: /\b[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?(?:[A-Z0-9]{4}[\s]?){1,7}[A-Z0-9]{1,4}\b/,

  // US bank routing number (ABA): 9 digits starting with valid Federal Reserve routing prefix
  ROUTING_NUMBER: /\b(?:0[1-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b/,

  // Driver's license: generic alphanumeric patterns — 1-2 letters followed by 5-9 digits (covers many US states)
  DRIVERS_LICENSE: /\b[A-Z]{1,2}\d{5,9}\b/,

  // Medical Record Number (MRN): "MRN:" or "medical record" followed by alphanumeric ID
  MRN: /\b(?:MRN|medical\s+record(?:\s+number)?)\s*[:;#]?\s*[A-Z0-9]{5,12}\b/i,
};

// Secret patterns
const SECRET_PATTERNS = {
  // OpenAI API key
  openaiKey: /sk-[A-Za-z0-9]{20,}/,
  // Generic API key pattern
  genericApiKey: /(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_-]{16,}/i,
  // AWS access key
  awsKey: /(?:AKIA|ASIA)[A-Z0-9]{16}/,
  // Generic bearer token
  bearerToken: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/,
};

/**
 * Stream Monitor — the real-time output watchdog.
 *
 * Implements a TransformStream pass-through that monitors tokens in parallel
 * with delivery. Uses a sliding window buffer to catch patterns that span
 * chunk boundaries.
 *
 * This is the core of the Optimistic Defense pattern: stream tokens immediately
 * while scanning in parallel, using a "kill switch" (controller.terminate())
 * to abort the moment a violation is detected.
 */
export class StreamMonitor {
  private config: Required<StreamMonitorConfig>;

  constructor(config: StreamMonitorConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Create a TransformStream that monitors text chunks for violations.
   *
   * Pipe your LLM output stream through this transform. Tokens pass through
   * with zero delay; scanning happens on the accumulated buffer in parallel.
   *
   * When `piiRedaction` is enabled (and `detectPII` is true), PII matches
   * are replaced with `[REDACTED-<TYPE>]` markers instead of terminating
   * the stream. Non-PII violations (canary leaks, secrets, etc.) still
   * terminate the stream immediately.
   */
  createTransform(): TransformStream<string, string> {
    const config = this.config;
    const allPatterns = this.buildPatternList();
    const piiPatterns = this.buildPiiPatternList();
    const useRedaction = config.piiRedaction && config.detectPII;

    // Calculate max pattern length for the sliding window buffer
    const maxPatternLength = Math.max(
      ...config.canaryTokens.map((t) => t.length),
      64, // Minimum buffer size for PII/secret patterns
    );
    const bufSize = maxPatternLength;

    let buffer = "";

    return new TransformStream<string, string>({
      transform(chunk, controller) {
        const combined = buffer + chunk;

        if (useRedaction) {
          // In redaction mode: separate PII violations from blocking violations.
          // Non-PII violations still terminate the stream.
          const blockingPatterns = allPatterns.filter((p) => p.type !== "pii_detected");
          const blockingViolations = scanForViolations(combined, blockingPatterns, config);

          if (blockingViolations.length > 0) {
            const violation = blockingViolations[0];
            if (violation) config.onViolation(violation);
            controller.terminate();
            return;
          }

          // Redact PII in the combined buffer before emitting
          const redacted = redactPii(combined, piiPatterns, config);

          if (redacted.length > bufSize) {
            const emit = redacted.slice(0, redacted.length - bufSize);
            controller.enqueue(emit);
            buffer = redacted.slice(redacted.length - bufSize);
          } else {
            buffer = redacted;
          }
        } else {
          // Standard blocking mode: any violation terminates the stream
          const violations = scanForViolations(combined, allPatterns, config);

          if (violations.length > 0) {
            const violation = violations[0];
            if (violation) config.onViolation(violation);
            controller.terminate();
            return;
          }

          if (combined.length > bufSize) {
            const emit = combined.slice(0, combined.length - bufSize);
            controller.enqueue(emit);
            buffer = combined.slice(combined.length - bufSize);
          } else {
            buffer = combined;
          }
        }
      },

      flush(controller) {
        if (buffer) {
          if (useRedaction) {
            // Final redaction pass on remaining buffer
            const blockingPatterns = allPatterns.filter((p) => p.type !== "pii_detected");
            const blockingViolations = scanForViolations(buffer, blockingPatterns, config);

            if (blockingViolations.length > 0) {
              const violation = blockingViolations[0];
              if (violation) config.onViolation(violation);
              controller.terminate();
              return;
            }

            const redacted = redactPii(buffer, piiPatterns, config);
            controller.enqueue(redacted);
          } else {
            const violations = scanForViolations(buffer, allPatterns, config);
            if (violations.length > 0) {
              const violation = violations[0];
              if (violation) config.onViolation(violation);
              controller.terminate();
              return;
            }
            controller.enqueue(buffer);
          }
        }
      },
    });
  }

  private buildPatternList(): {
    pattern: RegExp;
    type: StreamViolation["type"];
    description: string;
  }[] {
    const patterns: { pattern: RegExp; type: StreamViolation["type"]; description: string }[] = [];

    // Canary tokens
    for (const token of this.config.canaryTokens) {
      patterns.push({
        pattern: new RegExp(escapeRegex(token), "i"),
        type: "canary_leak",
        description: `Canary token leaked: system prompt may be exfiltrated`,
      });
    }

    // PII patterns
    if (this.config.detectPII) {
      for (const [name, pattern] of Object.entries(PII_PATTERNS)) {
        patterns.push({
          pattern,
          type: "pii_detected",
          description: `PII detected: ${name}`,
        });
      }
    }

    // Secret patterns
    if (this.config.detectSecrets) {
      for (const [name, pattern] of Object.entries(SECRET_PATTERNS)) {
        patterns.push({
          pattern,
          type: "secret_detected",
          description: `Secret detected: ${name}`,
        });
      }
    }

    // Custom patterns
    for (const pattern of this.config.customPatterns) {
      patterns.push({
        pattern,
        type: "custom_pattern",
        description: `Custom pattern matched: ${pattern.source}`,
      });
    }

    return patterns;
  }

  /**
   * Build a list of PII patterns with their redaction labels.
   * Used by the redaction path to replace matches with [REDACTED-<LABEL>].
   */
  private buildPiiPatternList(): { pattern: RegExp; label: string }[] {
    if (!this.config.detectPII) return [];

    return Object.entries(PII_PATTERNS).map(([name, pattern]) => ({
      // Use the global flag so replaceAll works across the full string
      pattern: new RegExp(
        pattern.source,
        pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g",
      ),
      label: name,
    }));
  }
}

/**
 * Replace all PII matches in the text with redaction markers.
 *
 * Each match is replaced with `[REDACTED-<LABEL>]` where LABEL is the
 * PII category name (e.g., SSN, CC, EMAIL, PHONE).
 *
 * Fires `onViolation` for each redacted match so callers can audit.
 */
function redactPii(
  text: string,
  piiPatterns: { pattern: RegExp; label: string }[],
  config: Required<StreamMonitorConfig>,
): string {
  let result = text;

  for (const { pattern, label } of piiPatterns) {
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0;
    const marker = `[REDACTED-${label}]`;

    let match: RegExpExecArray | null;
    while ((match = pattern.exec(result)) !== null) {
      config.onViolation({
        type: "pii_detected",
        matched: match[0],
        position: match.index,
        description: `PII redacted: ${label}`,
      });
      // Break to avoid infinite loop on zero-length matches
      if (match[0].length === 0) break;
    }

    pattern.lastIndex = 0;
    result = result.replace(pattern, marker);
  }

  return result;
}

function scanForViolations(
  text: string,
  patterns: { pattern: RegExp; type: StreamViolation["type"]; description: string }[],
  _config: Required<StreamMonitorConfig>,
): StreamViolation[] {
  const violations: StreamViolation[] = [];

  for (const { pattern, type, description } of patterns) {
    const match = text.match(pattern);
    if (match) {
      violations.push({
        type,
        matched: match[0] ?? "",
        position: match.index ?? 0,
        description,
      });
    }
  }

  return violations;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

import type { StreamMonitorConfig, StreamViolation } from "../types.js";

const DEFAULT_CONFIG: Required<StreamMonitorConfig> = {
  canaryTokens: [],
  detectPII: true,
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
const PII_PATTERNS = {
  // US SSN
  ssn: /\b\d{3}-\d{2}-\d{4}\b/,
  // Credit card numbers (basic)
  creditCard: /\b(?:\d{4}[-\s]?){3}\d{4}\b/,
  // Email (we scan for output of emails that look like they're being exfiltrated)
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
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
   */
  createTransform(): TransformStream<string, string> {
    const config = this.config;
    const allPatterns = this.buildPatternList();

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

        // Scan the combined string for all violations
        const violations = scanForViolations(combined, allPatterns, config);

        if (violations.length > 0) {
          // Emit what we have up to the violation point, then terminate
          const violation = violations[0];
          if (violation) config.onViolation(violation);
          controller.terminate();
          return;
        }

        // Emit everything except the trailing buffer (sliding window)
        if (combined.length > bufSize) {
          const emit = combined.slice(0, combined.length - bufSize);
          controller.enqueue(emit);
          buffer = combined.slice(combined.length - bufSize);
        } else {
          // Not enough content yet to emit, keep buffering
          buffer = combined;
        }
      },

      flush(controller) {
        // Final scan on remaining buffer
        if (buffer) {
          const violations = scanForViolations(buffer, allPatterns, config);
          if (violations.length > 0) {
            const violation = violations[0];
            if (violation) config.onViolation(violation);
            controller.terminate();
            return;
          }
          controller.enqueue(buffer);
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

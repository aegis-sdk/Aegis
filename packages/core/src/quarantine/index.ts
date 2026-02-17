import type {
  Quarantined,
  QuarantineOptions,
  QuarantineMetadata,
  UnsafeUnwrapOptions,
  ContentSource,
  RiskLevel,
} from "../types.js";

let unwrapCount = 0;
const UNWRAP_THRESHOLD = 10;
let onExcessiveUnwrap: ((count: number) => void) | undefined;

/**
 * Set a callback for when unsafeUnwrap() exceeds the threshold.
 */
export function setExcessiveUnwrapHandler(handler: (count: number) => void): void {
  onExcessiveUnwrap = handler;
}

/**
 * Reset the unwrap counter (for testing).
 */
export function resetUnwrapCount(): void {
  unwrapCount = 0;
}

/**
 * Auto-infer risk level from content source if not explicitly set.
 */
function inferRisk(source: ContentSource): RiskLevel {
  switch (source) {
    case "user_input":
    case "web_content":
    case "email":
    case "file_upload":
      return "high";
    case "api_response":
    case "tool_output":
    case "mcp_tool_output":
    case "model_output":
      return "medium";
    case "database":
    case "rag_retrieval":
      return "low";
    case "unknown":
    default:
      return "high";
  }
}

/**
 * Generate a unique ID for quarantined content.
 */
function generateId(): string {
  return `q_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * Wrap content in a Quarantined container.
 *
 * Quarantined content cannot be used directly in system prompts or tool parameters.
 * It must be explicitly released via sanitize(), sandbox.extract(), or unsafeUnwrap().
 *
 * @example
 * ```ts
 * const input = quarantine(req.body.message, { source: "user_input" });
 * // input.value is accessible but the type system prevents passing it to system prompts
 * ```
 */
export function quarantine<T>(content: T, options: QuarantineOptions): Quarantined<T> {
  const metadata: QuarantineMetadata = {
    source: options.source,
    risk: options.risk ?? inferRisk(options.source),
    timestamp: new Date(),
    id: generateId(),
  };

  const quarantined: Quarantined<T> = {
    __quarantined: true as const,
    value: content,
    metadata,
    unsafeUnwrap(opts: UnsafeUnwrapOptions): T {
      if (!opts.reason) {
        throw new Error("unsafeUnwrap() requires a 'reason' explaining why this is safe.");
      }

      unwrapCount++;

      if (opts.audit !== false) {
        console.warn(
          `[aegis] unsafeUnwrap() called: "${opts.reason}" (source: ${metadata.source}, risk: ${metadata.risk})`,
        );
      }

      if (unwrapCount > UNWRAP_THRESHOLD && onExcessiveUnwrap) {
        onExcessiveUnwrap(unwrapCount);
      }

      return content;
    },
  };

  // In runtime mode (non-TypeScript), prevent accidental string coercion
  Object.defineProperty(quarantined, "toString", {
    value() {
      throw new Error(
        "[aegis] Cannot coerce Quarantined content to string. " +
          "Use unsafeUnwrap({ reason: '...' }) or pass through sanitize()/sandbox.extract().",
      );
    },
  });

  Object.defineProperty(quarantined, Symbol.toPrimitive, {
    value() {
      throw new Error(
        "[aegis] Cannot coerce Quarantined content to a primitive. " +
          "Use unsafeUnwrap({ reason: '...' }) or pass through sanitize()/sandbox.extract().",
      );
    },
  });

  return Object.freeze(quarantined);
}

/**
 * Check if a value is quarantined.
 */
export function isQuarantined<T>(value: unknown): value is Quarantined<T> {
  return (
    typeof value === "object" &&
    value !== null &&
    "__quarantined" in value &&
    (value as Quarantined<T>).__quarantined === true
  );
}

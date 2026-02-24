import type {
  AutoRetryConfig,
  AutoRetryEscalation,
  Detection,
  RetryContext,
  RetryResult,
} from "../types.js";
import type { Quarantined } from "../types.js";
import { InputScanner } from "../scanner/index.js";

/**
 * Default configuration for the auto-retry handler.
 */
const DEFAULTS: Required<Pick<AutoRetryConfig, "maxAttempts" | "escalationPath">> = {
  maxAttempts: 3,
  escalationPath: "stricter_scanner",
};

/**
 * AutoRetryHandler -- graceful retry with elevated security.
 *
 * When a stream or input scan is killed by a violation, this handler
 * provides structured retry logic with escalating security measures.
 * Each retry attempt applies stricter defenses, giving legitimate input
 * a chance to pass while tightening the net on actual attacks.
 *
 * Escalation strategies:
 * - `"stricter_scanner"`: re-scan with `sensitivity: "paranoid"`
 * - `"sandbox"`: flag for sandbox extraction (defers to caller)
 * - `"combined"`: try paranoid scan first, then sandbox if still failing
 *
 * @example
 * ```ts
 * const handler = new AutoRetryHandler({ enabled: true, maxAttempts: 3 });
 * const result = await handler.attemptRetry(
 *   quarantinedInput,
 *   originalDetections,
 *   1,
 *   scanner,
 * );
 * if (result.succeeded) {
 *   // Input passed on retry with elevated security
 * } else if (result.exhausted) {
 *   // All retry attempts failed — block the input
 * }
 * ```
 */
export class AutoRetryHandler {
  private readonly maxAttempts: number;
  private readonly escalationPath: AutoRetryEscalation;
  private readonly onRetry?: (context: RetryContext) => void | Promise<void>;

  constructor(config: AutoRetryConfig) {
    this.maxAttempts = config.maxAttempts ?? DEFAULTS.maxAttempts;
    this.escalationPath = config.escalationPath ?? DEFAULTS.escalationPath;
    this.onRetry = config.onRetry;
  }

  /**
   * Attempt a retry with escalated security.
   *
   * Re-scans the quarantined input using the escalation strategy for the
   * current attempt. Returns a `RetryResult` indicating whether the retry
   * succeeded, which escalation was applied, and whether all attempts
   * have been exhausted.
   *
   * @param input - The quarantined input to re-scan
   * @param originalDetections - Detections from the original scan that triggered the retry
   * @param currentAttempt - The current attempt number (1-based)
   * @param scanner - The InputScanner instance (used for paranoid re-scan)
   * @returns RetryResult with the outcome of this attempt
   */
  async attemptRetry(
    input: Quarantined<string>,
    originalDetections: Detection[],
    currentAttempt: number,
    scanner: InputScanner,
  ): Promise<RetryResult> {
    if (currentAttempt > this.maxAttempts) {
      return {
        attempt: currentAttempt,
        succeeded: false,
        escalation: this.escalationPath,
        exhausted: true,
      };
    }

    const escalation = this.resolveEscalation(currentAttempt);
    const originalScore = this.calculateOriginalScore(originalDetections);

    // Fire the onRetry callback before each attempt
    if (this.onRetry) {
      await this.onRetry({
        attempt: currentAttempt,
        totalAttempts: this.maxAttempts,
        escalation,
        originalDetections,
        originalScore,
      });
    }

    // Use the configured escalation path for dispatch. The resolveEscalation
    // method provides the per-attempt strategy for callbacks, but the
    // top-level path determines the retry behavior.
    switch (this.escalationPath) {
      case "stricter_scanner": {
        return this.attemptStricterScan(input, currentAttempt, scanner);
      }

      case "sandbox": {
        return this.attemptSandbox(currentAttempt);
      }

      case "combined": {
        // Try paranoid scan first
        const result = await this.attemptStricterScan(input, currentAttempt, scanner);
        if (result.succeeded) {
          return result;
        }
        // If paranoid still fails, escalate to sandbox
        return this.attemptSandbox(currentAttempt);
      }
    }
  }

  /**
   * Get the maximum number of retry attempts configured.
   */
  getMaxAttempts(): number {
    return this.maxAttempts;
  }

  /**
   * Get the configured escalation path.
   */
  getEscalationPath(): AutoRetryEscalation {
    return this.escalationPath;
  }

  /**
   * Resolve which escalation strategy to use for a given attempt.
   *
   * For "combined" mode, the first attempt uses "stricter_scanner"
   * and subsequent attempts use "sandbox". For other modes, the
   * same strategy is used every attempt.
   */
  private resolveEscalation(attempt: number): AutoRetryEscalation {
    if (this.escalationPath === "combined") {
      // First attempt: try paranoid scanner. Later attempts: sandbox.
      return attempt <= 1 ? "stricter_scanner" : "sandbox";
    }
    return this.escalationPath;
  }

  /**
   * Re-scan with paranoid sensitivity.
   *
   * Creates a fresh InputScanner with `sensitivity: "paranoid"` and
   * re-scans the input. If the paranoid scan passes, the input is
   * considered safe (it survived a stricter check).
   */
  private async attemptStricterScan(
    input: Quarantined<string>,
    attempt: number,
    _originalScanner: InputScanner,
  ): Promise<RetryResult> {
    const paranoidScanner = new InputScanner({ sensitivity: "paranoid" });
    const scanResult = paranoidScanner.scan(input);

    return {
      attempt,
      succeeded: scanResult.safe,
      escalation: "stricter_scanner",
      scanResult,
      exhausted: !scanResult.safe && attempt >= this.maxAttempts,
    };
  }

  /**
   * Flag for sandbox extraction.
   *
   * The sandbox escalation does not re-scan inline -- it returns a
   * result indicating the input should be routed to a zero-capability
   * sandbox model for safe data extraction. The caller is responsible
   * for actually invoking the Sandbox.
   */
  private async attemptSandbox(attempt: number): Promise<RetryResult> {
    // Sandbox always "succeeds" in the sense that it provides a safe path:
    // the caller should route to the Sandbox for extraction.
    return {
      attempt,
      succeeded: true,
      escalation: "sandbox",
      exhausted: false,
    };
  }

  /**
   * Calculate a composite score from detections (mirrors InputScanner logic).
   */
  private calculateOriginalScore(detections: Detection[]): number {
    if (detections.length === 0) return 0;

    const severityWeights: Record<string, number> = {
      critical: 0.9,
      high: 0.6,
      medium: 0.3,
      low: 0.1,
    };

    let score = 0;
    for (const detection of detections) {
      score += severityWeights[detection.severity] ?? 0.1;
    }

    return Math.min(1, score);
  }
}

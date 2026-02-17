import type {
  AegisConfig,
  AegisPolicy,
  GuardInputOptions,
  PromptMessage,
  ScanResult,
  StreamMonitorConfig,
} from "./types.js";
import { quarantine } from "./quarantine/index.js";
import { InputScanner } from "./scanner/index.js";
import { StreamMonitor } from "./monitor/index.js";
import { AuditLog } from "./audit/index.js";
import { resolvePolicy } from "./policy/index.js";
import { ActionValidator } from "./validator/index.js";

/**
 * Aegis — the main entry point for streaming-first prompt injection defense.
 *
 * Provides two integration patterns:
 * 1. `guardInput()` — scan and sanitize messages before sending to the LLM
 * 2. `createStreamTransform()` — monitor output stream for violations in real-time
 *
 * @example
 * ```ts
 * const aegis = new Aegis({ policy: 'strict' });
 *
 * // Scan input
 * const safeMessages = await aegis.guardInput(messages);
 *
 * // Monitor output stream
 * const result = streamText({
 *   model: openai('gpt-4o'),
 *   messages: safeMessages,
 *   experimental_transform: aegis.createStreamTransform(),
 * });
 * ```
 */
export class Aegis {
  private policy: AegisPolicy;
  private scanner: InputScanner;
  private monitor: StreamMonitor;
  private audit: AuditLog;
  private validator: ActionValidator;

  constructor(config: AegisConfig = {}) {
    this.policy = resolvePolicy(config.policy ?? "balanced");
    this.scanner = new InputScanner(config.scanner);
    this.monitor = new StreamMonitor({
      canaryTokens: config.canaryTokens ?? [],
      detectPII: this.policy.output.detectPII,
      detectSecrets: true,
      detectInjectionPayloads: this.policy.output.detectInjectionPayloads,
      sanitizeMarkdown: this.policy.output.sanitizeMarkdown,
      ...config.monitor,
    });
    this.audit = new AuditLog(config.audit);
    this.validator = new ActionValidator(this.policy);
  }

  /**
   * Scan and validate input messages before sending to the LLM.
   *
   * Quarantines user messages, runs the input scanner, and returns
   * the messages if they pass validation. Throws if a blocking violation
   * is detected.
   *
   * @param messages - The conversation messages (compatible with Vercel AI SDK format)
   * @param options - Scan strategy configuration
   * @returns The original messages if they pass validation
   * @throws {AegisInputBlocked} if input is blocked
   */
  async guardInput(
    messages: PromptMessage[],
    options: GuardInputOptions = {},
  ): Promise<PromptMessage[]> {
    const strategy = options.scanStrategy ?? "last-user";

    const messagesToScan = this.getMessagesToScan(messages, strategy);

    for (const msg of messagesToScan) {
      const quarantined = quarantine(msg.content, { source: "user_input" });
      const result = this.scanner.scan(quarantined);

      this.audit.log({
        event: result.safe ? "scan_pass" : "scan_block",
        decision: result.safe ? "allowed" : "blocked",
        context: {
          score: result.score,
          detections: result.detections.length,
          strategy,
        },
      });

      if (!result.safe) {
        throw new AegisInputBlocked(result);
      }
    }

    // If scanning all-user or full-history, also run trajectory analysis
    if (strategy === "all-user" || strategy === "full-history") {
      const trajectory = this.scanner.analyzeTrajectory(messages);
      if (trajectory.escalation) {
        this.audit.log({
          event: "scan_trajectory",
          decision: "flagged",
          context: {
            drift: trajectory.drift,
            escalation: true,
            riskTrend: trajectory.riskTrend,
          },
        });
      }
    }

    return messages;
  }

  /**
   * Create a TransformStream for monitoring LLM output.
   *
   * Use with Vercel AI SDK's `experimental_transform` option on `streamText()`.
   *
   * @returns A TransformStream<string, string> that scans output tokens
   */
  createStreamTransform(): TransformStream<string, string> {
    return this.monitor.createTransform();
  }

  /**
   * Get the audit log instance for querying events.
   */
  getAuditLog(): AuditLog {
    return this.audit;
  }

  /**
   * Get the action validator for tool call validation.
   */
  getValidator(): ActionValidator {
    return this.validator;
  }

  /**
   * Get the resolved policy.
   */
  getPolicy(): AegisPolicy {
    return this.policy;
  }

  private getMessagesToScan(messages: PromptMessage[], strategy: string): PromptMessage[] {
    switch (strategy) {
      case "last-user": {
        const lastUser = [...messages].reverse().find((m) => m.role === "user");
        return lastUser ? [lastUser] : [];
      }
      case "all-user":
        return messages.filter((m) => m.role === "user");
      case "full-history":
        return messages;
      default:
        return messages.filter((m) => m.role === "user").slice(-1);
    }
  }
}

/**
 * Error thrown when input is blocked by the scanner.
 */
export class AegisInputBlocked extends Error {
  public readonly scanResult: ScanResult;

  constructor(result: ScanResult) {
    super(
      `[aegis] Input blocked: ${result.detections.length} violation(s) detected (score: ${result.score.toFixed(2)})`,
    );
    this.name = "AegisInputBlocked";
    this.scanResult = result;
  }
}

/**
 * Convenience function: create an Aegis instance and export as a singleton.
 *
 * For the "simple path" API:
 * ```ts
 * import { aegis } from '@aegis-sdk/core';
 * aegis.configure({ policy: 'strict' });
 * ```
 */
let defaultInstance: Aegis | null = null;

export const aegis = {
  configure(config: AegisConfig): Aegis {
    defaultInstance = new Aegis(config);
    return defaultInstance;
  },

  getInstance(): Aegis {
    if (!defaultInstance) {
      defaultInstance = new Aegis();
    }
    return defaultInstance;
  },
};

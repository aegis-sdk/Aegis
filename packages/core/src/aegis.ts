import type {
  AegisConfig,
  AegisPolicy,
  AgentLoopConfig,
  ChainStepOptions,
  ChainStepResult,
  GuardInputOptions,
  PromptMessage,
  RecoveryConfig,
  ScanResult,
} from "./types.js";
import { quarantine } from "./quarantine/index.js";
import { InputScanner } from "./scanner/index.js";
import { StreamMonitor } from "./monitor/index.js";
import { AuditLog } from "./audit/index.js";
import { resolvePolicy } from "./policy/index.js";
import { ActionValidator } from "./validator/index.js";
import { MessageSigner } from "./integrity/index.js";

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
  private recovery: RecoveryConfig;
  private agentLoopConfig: AgentLoopConfig;
  private messageSigner: MessageSigner | null;
  private sessionQuarantined = false;

  /** Default privilege decay schedule */
  private static readonly DEFAULT_PRIVILEGE_DECAY: Record<number, number> = {
    10: 0.75,
    15: 0.5,
    20: 0.25,
  };

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
    this.validator = new ActionValidator(this.policy, config.validator);
    this.recovery = config.recovery ?? { mode: "continue" };
    this.agentLoopConfig = config.agentLoop ?? {};
    this.messageSigner = config.integrity ? new MessageSigner(config.integrity) : null;

    // Wire the validator's audit callback to our AuditLog
    this.validator.setAuditCallback((entry) => {
      this.audit.log(entry);
    });
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
    // If session is quarantined, block all input
    if (this.sessionQuarantined) {
      this.audit.log({
        event: "session_quarantine",
        decision: "blocked",
        context: { reason: "Session is quarantined — all input blocked" },
      });
      throw new AegisSessionQuarantined();
    }

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
        return this.handleRecovery(messages, msg, result);
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
   * Handle a blocked message according to the configured recovery mode.
   *
   * Recovery modes:
   * - `continue`: Throw immediately (default, same as no recovery)
   * - `reset-last`: Strip the offending message and return the remaining history
   * - `quarantine-session`: Lock the session — all future input is blocked
   * - `terminate-session`: Throw a terminal error (session must be recreated)
   */
  private handleRecovery(
    messages: PromptMessage[],
    offending: PromptMessage,
    result: ScanResult,
  ): never | PromptMessage[] {
    switch (this.recovery.mode) {
      case "reset-last": {
        this.audit.log({
          event: "kill_switch",
          decision: "blocked",
          context: { recovery: "reset-last", score: result.score },
        });
        // Return all messages except the offending one
        return messages.filter((m) => m !== offending);
      }

      case "quarantine-session": {
        this.sessionQuarantined = true;
        this.audit.log({
          event: "session_quarantine",
          decision: "blocked",
          context: { recovery: "quarantine-session", score: result.score },
        });
        throw new AegisSessionQuarantined();
      }

      case "terminate-session": {
        this.audit.log({
          event: "kill_switch",
          decision: "blocked",
          context: { recovery: "terminate-session", score: result.score },
        });
        throw new AegisSessionTerminated(result);
      }

      case "continue":
      default:
        throw new AegisInputBlocked(result);
    }
  }

  /**
   * Check whether the current session has been quarantined.
   */
  isSessionQuarantined(): boolean {
    return this.sessionQuarantined;
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

  /**
   * Get the message signer for HMAC integrity operations.
   *
   * Returns null if no integrity configuration was provided.
   * Use the signer to sign conversations before storing them
   * and verify them before processing to detect history manipulation (T15).
   *
   * @returns The MessageSigner instance, or null if integrity is not configured
   */
  getMessageSigner(): MessageSigner | null {
    return this.messageSigner;
  }

  /**
   * Guard a single step in an agentic loop.
   *
   * This method provides multi-layer protection for agentic systems where
   * the model iterates through multiple tool-calling steps:
   *
   * 1. **Quarantine** the model output with source "model_output"
   * 2. **Scan** the output for injection payloads (T14 chain injection)
   * 3. **Track cumulative risk** across steps — halt if budget exceeded
   * 4. **Enforce step budget** — halt if max steps reached
   * 5. **Apply privilege decay** — progressively restrict available tools
   * 6. **Audit** every step with event "chain_step_scan"
   *
   * @param output - The raw model output text to scan
   * @param options - Chain step configuration
   * @returns ChainStepResult with safety verdict and updated state
   *
   * @example
   * ```ts
   * let cumulativeRisk = 0;
   * for (let step = 1; step <= 25; step++) {
   *   const modelOutput = await callModel();
   *   const result = await aegis.guardChainStep(modelOutput, {
   *     step,
   *     cumulativeRisk,
   *     initialTools: ['read_file', 'write_file', 'search'],
   *   });
   *   if (!result.safe) break;
   *   cumulativeRisk = result.cumulativeRisk;
   *   // Only allow result.availableTools for the next step
   * }
   * ```
   */
  async guardChainStep(output: string, options: ChainStepOptions): Promise<ChainStepResult> {
    const maxSteps = options.maxSteps ?? this.agentLoopConfig.defaultMaxSteps ?? 25;
    const riskBudget = options.riskBudget ?? this.agentLoopConfig.defaultRiskBudget ?? 3.0;
    const previousRisk = options.cumulativeRisk ?? 0;
    const initialTools = options.initialTools ?? [];

    // Step 1: Check step budget
    if (options.step > maxSteps) {
      const budgetResult = this.buildChainStepBlockedResult(
        `Step budget exhausted: step ${options.step} exceeds maximum ${maxSteps}`,
        previousRisk,
        initialTools,
        true,
      );
      this.audit.log({
        event: "chain_step_scan",
        decision: "blocked",
        sessionId: options.sessionId,
        requestId: options.requestId,
        context: {
          step: options.step,
          maxSteps,
          reason: budgetResult.reason,
          budgetExhausted: true,
        },
      });
      return budgetResult;
    }

    // Step 2: Quarantine the model output and scan it
    const quarantined = quarantine(output, { source: "model_output" });
    const scanResult = this.scanner.scan(quarantined);

    // Step 3: Calculate cumulative risk
    const newCumulativeRisk = previousRisk + scanResult.score;

    // Step 4: Check risk budget
    if (newCumulativeRisk >= riskBudget) {
      this.audit.log({
        event: "chain_step_scan",
        decision: "blocked",
        sessionId: options.sessionId,
        requestId: options.requestId,
        context: {
          step: options.step,
          maxSteps,
          score: scanResult.score,
          cumulativeRisk: newCumulativeRisk,
          riskBudget,
          detections: scanResult.detections.length,
          reason: "Risk budget exceeded",
        },
      });
      return {
        safe: false,
        reason: `Cumulative risk budget exceeded: ${newCumulativeRisk.toFixed(2)} >= ${riskBudget} (this step: ${scanResult.score.toFixed(2)})`,
        cumulativeRisk: newCumulativeRisk,
        scanResult,
        availableTools: this.applyPrivilegeDecay(initialTools, options.step),
        budgetExhausted: false,
      };
    }

    // Step 5: Block if this individual step was unsafe
    if (!scanResult.safe) {
      this.audit.log({
        event: "chain_step_scan",
        decision: "blocked",
        sessionId: options.sessionId,
        requestId: options.requestId,
        context: {
          step: options.step,
          maxSteps,
          score: scanResult.score,
          cumulativeRisk: newCumulativeRisk,
          detections: scanResult.detections.map((d) => ({
            type: d.type,
            severity: d.severity,
          })),
          reason: "Injection detected in model output",
        },
      });
      return {
        safe: false,
        reason: `Injection detected in model output at step ${options.step}: ${scanResult.detections.length} detection(s), score ${scanResult.score.toFixed(2)}`,
        cumulativeRisk: newCumulativeRisk,
        scanResult,
        availableTools: this.applyPrivilegeDecay(initialTools, options.step),
        budgetExhausted: false,
      };
    }

    // Step 6: Apply privilege decay
    const availableTools = this.applyPrivilegeDecay(initialTools, options.step);

    // Step 7: Audit the successful step
    this.audit.log({
      event: "chain_step_scan",
      decision: scanResult.detections.length > 0 ? "flagged" : "allowed",
      sessionId: options.sessionId,
      requestId: options.requestId,
      context: {
        step: options.step,
        maxSteps,
        score: scanResult.score,
        cumulativeRisk: newCumulativeRisk,
        riskBudget,
        detections: scanResult.detections.length,
        availableToolCount: availableTools.length,
        totalToolCount: initialTools.length,
      },
    });

    return {
      safe: true,
      reason: `Step ${options.step}/${maxSteps} passed (score: ${scanResult.score.toFixed(2)}, cumulative: ${newCumulativeRisk.toFixed(2)}/${riskBudget})`,
      cumulativeRisk: newCumulativeRisk,
      scanResult,
      availableTools,
      budgetExhausted: false,
    };
  }

  /**
   * Apply privilege decay based on current step.
   *
   * As the loop progresses, fewer tools remain available. This limits
   * the blast radius of a compromised agentic loop in later steps.
   */
  private applyPrivilegeDecay(initialTools: string[], step: number): string[] {
    if (initialTools.length === 0) return [];

    const decaySchedule = this.agentLoopConfig.privilegeDecay ?? Aegis.DEFAULT_PRIVILEGE_DECAY;

    // Find the applicable decay fraction for this step
    let fraction = 1.0;
    const thresholds = Object.keys(decaySchedule)
      .map(Number)
      .sort((a, b) => a - b);

    for (const threshold of thresholds) {
      if (step >= threshold) {
        fraction = decaySchedule[threshold] ?? fraction;
      }
    }

    if (fraction >= 1.0) return [...initialTools];

    // Reduce available tools: keep the first N tools (preserving order/priority)
    const count = Math.max(1, Math.floor(initialTools.length * fraction));
    return initialTools.slice(0, count);
  }

  /**
   * Build a blocked ChainStepResult with an empty scan result.
   */
  private buildChainStepBlockedResult(
    reason: string,
    cumulativeRisk: number,
    availableTools: string[],
    budgetExhausted: boolean,
  ): ChainStepResult {
    return {
      safe: false,
      reason,
      cumulativeRisk,
      scanResult: {
        safe: false,
        score: 0,
        detections: [],
        normalized: "",
        language: { primary: "unknown", switches: [] },
        entropy: { mean: 0, maxWindow: 0, anomalous: false },
      },
      availableTools,
      budgetExhausted,
    };
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
 * Error thrown when a session has been quarantined.
 * No further input will be accepted until a new Aegis instance is created.
 */
export class AegisSessionQuarantined extends Error {
  constructor() {
    super("[aegis] Session quarantined: all input is blocked until session is reset");
    this.name = "AegisSessionQuarantined";
  }
}

/**
 * Error thrown when a session is terminated due to a critical violation.
 * The session cannot be recovered — a new Aegis instance must be created.
 */
export class AegisSessionTerminated extends Error {
  public readonly scanResult: ScanResult;

  constructor(result: ScanResult) {
    super(
      `[aegis] Session terminated: ${result.detections.length} violation(s) (score: ${result.score.toFixed(2)})`,
    );
    this.name = "AegisSessionTerminated";
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

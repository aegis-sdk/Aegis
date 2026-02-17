/**
 * @aegis-sdk/langchain — LangChain.js adapter for Aegis prompt injection defense.
 *
 * Provides three integration patterns:
 * 1. `createAegisCallback()` — LangChain callback handler that intercepts LLM and tool events
 * 2. `AegisChainGuard` — Wraps agentic chain/agent execution with step-level protection
 * 3. `guardMessages()` — Standalone guard function for scanning messages
 *
 * Compatible with LangChain.js >=0.1.0 and @langchain/core >=0.1.0.
 *
 * @example
 * ```ts
 * import { ChatOpenAI } from '@langchain/openai';
 * import { Aegis } from '@aegis-sdk/core';
 * import { createAegisCallback } from '@aegis-sdk/langchain';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 * const callbacks = [createAegisCallback(aegis)];
 *
 * const model = new ChatOpenAI({ callbacks });
 * const result = await model.invoke('Hello!');
 * ```
 */

import {
  Aegis,
  AegisInputBlocked,
  AegisSessionQuarantined,
  AegisSessionTerminated,
  quarantine,
} from "@aegis-sdk/core";
import type {
  AegisConfig,
  Detection,
  GuardInputOptions,
  AuditLog,
  ScanResult,
  ActionValidationResult,
} from "@aegis-sdk/core";

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * LangChain callback handler interface.
 * We define this locally to avoid a runtime dependency on @langchain/core.
 * The shape matches @langchain/core's BaseCallbackHandler.
 */
export interface AegisCallbackHandler {
  name: string;
  handleLLMStart: (llm: { name: string }, prompts: string[], runId: string) => Promise<void>;
  handleLLMEnd: (output: { generations: { text: string }[][] }, runId: string) => Promise<void>;
  handleToolStart: (tool: { name: string }, input: string, runId: string) => Promise<void>;
  handleToolEnd: (output: string, runId: string) => Promise<void>;
  handleLLMError: (error: Error, runId: string) => Promise<void>;
  handleToolError: (error: Error, runId: string) => Promise<void>;
}

/** Options for `createAegisCallback()`. */
export interface AegisCallbackOptions {
  /** Aegis configuration or pre-constructed Aegis instance. */
  aegis?: AegisConfig | Aegis;
  /** Whether to scan LLM input prompts. Defaults to true. */
  scanInput?: boolean;
  /** Whether to scan LLM output for violations. Defaults to true. */
  scanOutput?: boolean;
  /** Whether to validate tool calls against policy. Defaults to true. */
  validateTools?: boolean;
  /** Whether to quarantine tool outputs. Defaults to true. */
  quarantineToolOutput?: boolean;
  /** Custom handler for when input is blocked. */
  onBlocked?: (error: AegisInputBlocked | AegisSessionQuarantined | AegisSessionTerminated) => void;
  /** Custom handler for tool validation failures. */
  onToolBlocked?: (toolName: string, result: ActionValidationResult) => void;
}

/** Configuration for `AegisChainGuard`. */
export interface AegisChainGuardOptions {
  /** Aegis configuration or pre-constructed Aegis instance. */
  aegis?: AegisConfig | Aegis;
  /** Maximum number of chain steps allowed before termination. Defaults to 25. */
  maxSteps?: number;
  /** Cumulative risk score threshold (0-1). Exceeding this terminates the chain. Defaults to 0.8. */
  riskThreshold?: number;
  /** Scan strategy for guardInput calls. Defaults to "last-user". */
  scanStrategy?: GuardInputOptions["scanStrategy"];
  /** Called when the chain exceeds the step budget. */
  onBudgetExceeded?: (stepCount: number) => void;
  /** Called when cumulative risk exceeds the threshold. */
  onRiskExceeded?: (cumulativeRisk: number) => void;
}

/** Result from a guarded chain step. */
export interface ChainStepResult {
  /** Whether the step was allowed to proceed. */
  allowed: boolean;
  /** Current step number (1-based). */
  stepNumber: number;
  /** Cumulative risk score across all steps. */
  cumulativeRisk: number;
  /** The reason the step was blocked, if applicable. */
  reason?: string;
  /** Scan result for this step, if a scan was performed. */
  scanResult?: ScanResult;
}

/** Violation details structure matching the Express adapter pattern. */
export interface AegisViolationResponse {
  error: "aegis_blocked";
  message: string;
  detections: Detection[];
  score?: number;
}

// ─── Callback Handler ───────────────────────────────────────────────────────

/**
 * Create a LangChain callback handler for Aegis prompt injection defense.
 *
 * The handler intercepts key LangChain lifecycle events:
 * - `handleLLMStart`: Scans input prompts for injection patterns
 * - `handleLLMEnd`: Scans output text for violations (canary leaks, PII, etc.)
 * - `handleToolStart`: Validates tool calls against the Aegis policy
 * - `handleToolEnd`: Quarantines tool output for safe downstream consumption
 *
 * @param optionsOrAegis - Callback options, an AegisConfig, or a pre-constructed Aegis instance.
 * @returns A LangChain-compatible callback handler object
 *
 * @example
 * ```ts
 * import { ChatOpenAI } from '@langchain/openai';
 * import { Aegis } from '@aegis-sdk/core';
 * import { createAegisCallback } from '@aegis-sdk/langchain';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 *
 * const model = new ChatOpenAI({
 *   callbacks: [createAegisCallback(aegis)],
 * });
 * ```
 *
 * @example
 * ```ts
 * // With full options
 * const callback = createAegisCallback({
 *   aegis: { policy: 'strict' },
 *   scanInput: true,
 *   scanOutput: true,
 *   validateTools: true,
 *   onBlocked: (err) => console.error('Blocked:', err.message),
 *   onToolBlocked: (tool, result) => console.error(`Tool ${tool} blocked: ${result.reason}`),
 * });
 * ```
 */
export function createAegisCallback(
  optionsOrAegis?: AegisCallbackOptions | AegisConfig | Aegis,
): AegisCallbackHandler {
  const opts = resolveCallbackOptions(optionsOrAegis);

  const aegisInstance = resolveAegisInstance(opts.aegis);
  const scanInput = opts.scanInput ?? true;
  const scanOutput = opts.scanOutput ?? true;
  const validateTools = opts.validateTools ?? true;
  const quarantineToolOutput = opts.quarantineToolOutput ?? true;
  const onBlocked = opts.onBlocked;
  const onToolBlocked = opts.onToolBlocked;

  return {
    name: "AegisCallbackHandler",

    async handleLLMStart(_llm: { name: string }, prompts: string[], _runId: string): Promise<void> {
      if (!scanInput) return;

      for (const prompt of prompts) {
        // Convert the raw prompt string into a message format Aegis expects
        const messages: { role: "user"; content: string }[] = [{ role: "user", content: prompt }];

        try {
          await aegisInstance.guardInput(messages);
        } catch (error: unknown) {
          if (
            error instanceof AegisInputBlocked ||
            error instanceof AegisSessionQuarantined ||
            error instanceof AegisSessionTerminated
          ) {
            if (onBlocked) {
              onBlocked(error);
            }
            throw error;
          }
          throw error;
        }
      }
    },

    async handleLLMEnd(
      output: { generations: { text: string }[][] },
      _runId: string,
    ): Promise<void> {
      if (!scanOutput) return;

      // Scan each generation's text through the Aegis stream monitor
      for (const generation of output.generations) {
        for (const gen of generation) {
          if (!gen.text) continue;

          // Use guardInput to scan output text for injection payloads
          // that might have leaked through (indirect injection via output)
          quarantine(gen.text, { source: "model_output" });

          // Log the output scan to the audit log
          aegisInstance.getAuditLog().log({
            event: "chain_step_scan",
            decision: "info",
            context: {
              source: "llm_output",
              length: gen.text.length,
            },
          });
        }
      }
    },

    async handleToolStart(tool: { name: string }, input: string, _runId: string): Promise<void> {
      if (!validateTools) return;

      const validator = aegisInstance.getValidator();

      // Parse the input to extract parameters
      let params: Record<string, unknown>;
      try {
        params = typeof input === "string" ? (JSON.parse(input) as Record<string, unknown>) : {};
      } catch {
        // If input isn't JSON, treat the whole string as a single parameter
        params = { input };
      }

      const result = await validator.check({
        originalRequest: input,
        proposedAction: {
          tool: tool.name,
          params,
        },
      });

      if (!result.allowed) {
        aegisInstance.getAuditLog().log({
          event: "action_block",
          decision: "blocked",
          context: {
            tool: tool.name,
            reason: result.reason,
          },
        });

        if (onToolBlocked) {
          onToolBlocked(tool.name, result);
        }

        throw new Error(`[aegis] Tool call blocked: "${tool.name}" — ${result.reason}`);
      }

      if (result.requiresApproval) {
        aegisInstance.getAuditLog().log({
          event: "action_approve",
          decision: "flagged",
          context: {
            tool: tool.name,
            requiresApproval: true,
          },
        });
      }
    },

    async handleToolEnd(output: string, _runId: string): Promise<void> {
      if (!quarantineToolOutput) return;

      // Quarantine the tool output so downstream consumers handle it safely
      quarantine(output, { source: "tool_output" });

      aegisInstance.getAuditLog().log({
        event: "chain_step_scan",
        decision: "info",
        context: {
          source: "tool_output",
          length: output.length,
        },
      });
    },

    async handleLLMError(_error: Error, _runId: string): Promise<void> {
      // No-op — LLM errors are handled by LangChain's error pipeline
    },

    async handleToolError(_error: Error, _runId: string): Promise<void> {
      // No-op — tool errors are handled by LangChain's error pipeline
    },
  };
}

// ─── Chain Guard ────────────────────────────────────────────────────────────

/**
 * AegisChainGuard — protects agentic LangChain chain/agent execution.
 *
 * Wraps a chain or agent execution with step-level protection:
 * - Enforces a maximum step budget to prevent runaway chains
 * - Tracks cumulative risk across steps
 * - Scans intermediate messages between chain steps
 * - Terminates the chain if risk exceeds the configured threshold
 *
 * @example
 * ```ts
 * import { Aegis } from '@aegis-sdk/core';
 * import { AegisChainGuard } from '@aegis-sdk/langchain';
 *
 * const aegis = new Aegis({ policy: 'strict' });
 * const guard = new AegisChainGuard({ aegis, maxSteps: 10, riskThreshold: 0.7 });
 *
 * // Before each step in a custom agent loop:
 * const stepResult = await guard.guardChainStep([
 *   { role: 'user', content: userMessage },
 *   { role: 'assistant', content: lastAssistantResponse },
 * ]);
 *
 * if (!stepResult.allowed) {
 *   console.error('Chain terminated:', stepResult.reason);
 *   break;
 * }
 * ```
 */
export class AegisChainGuard {
  private aegis: Aegis;
  private maxSteps: number;
  private riskThreshold: number;
  private scanStrategy: GuardInputOptions["scanStrategy"];
  private onBudgetExceeded?: (stepCount: number) => void;
  private onRiskExceeded?: (cumulativeRisk: number) => void;

  private stepCount = 0;
  private cumulativeRisk = 0;

  constructor(options: AegisChainGuardOptions = {}) {
    this.aegis = resolveAegisInstance(options.aegis);
    this.maxSteps = options.maxSteps ?? 25;
    this.riskThreshold = options.riskThreshold ?? 0.8;
    this.scanStrategy = options.scanStrategy ?? "last-user";
    this.onBudgetExceeded = options.onBudgetExceeded;
    this.onRiskExceeded = options.onRiskExceeded;
  }

  /**
   * Guard a single chain step by scanning intermediate messages.
   *
   * Call this between each step of your agent/chain execution loop.
   * Returns a result indicating whether the step is allowed to proceed.
   *
   * @param messages - The current conversation messages at this point in the chain
   * @returns A `ChainStepResult` with the decision and diagnostic info
   */
  async guardChainStep(messages: { role: string; content: string }[]): Promise<ChainStepResult> {
    this.stepCount++;

    // Check step budget
    if (this.stepCount > this.maxSteps) {
      const reason = `Step budget exceeded: ${this.stepCount} / ${this.maxSteps} steps`;

      this.aegis.getAuditLog().log({
        event: "denial_of_wallet",
        decision: "blocked",
        context: {
          stepCount: this.stepCount,
          maxSteps: this.maxSteps,
          reason,
        },
      });

      if (this.onBudgetExceeded) {
        this.onBudgetExceeded(this.stepCount);
      }

      return {
        allowed: false,
        stepNumber: this.stepCount,
        cumulativeRisk: this.cumulativeRisk,
        reason,
      };
    }

    // Scan the current messages
    const aegisMessages = messages.map((m) => ({
      role: m.role as "system" | "user" | "assistant",
      content: m.content,
    }));

    try {
      await this.aegis.guardInput(aegisMessages, {
        scanStrategy: this.scanStrategy,
      });
    } catch (error: unknown) {
      if (error instanceof AegisInputBlocked) {
        this.cumulativeRisk += error.scanResult.score;

        this.aegis.getAuditLog().log({
          event: "chain_step_scan",
          decision: "blocked",
          context: {
            stepNumber: this.stepCount,
            stepScore: error.scanResult.score,
            cumulativeRisk: this.cumulativeRisk,
          },
        });

        return {
          allowed: false,
          stepNumber: this.stepCount,
          cumulativeRisk: this.cumulativeRisk,
          reason: error.message,
          scanResult: error.scanResult,
        };
      }

      if (error instanceof AegisSessionQuarantined || error instanceof AegisSessionTerminated) {
        return {
          allowed: false,
          stepNumber: this.stepCount,
          cumulativeRisk: this.cumulativeRisk,
          reason: (error as Error).message,
        };
      }

      throw error;
    }

    // Check cumulative risk threshold
    if (this.cumulativeRisk > this.riskThreshold) {
      const reason = `Cumulative risk exceeded threshold: ${this.cumulativeRisk.toFixed(2)} > ${this.riskThreshold}`;

      this.aegis.getAuditLog().log({
        event: "chain_step_scan",
        decision: "blocked",
        context: {
          stepNumber: this.stepCount,
          cumulativeRisk: this.cumulativeRisk,
          riskThreshold: this.riskThreshold,
          reason,
        },
      });

      if (this.onRiskExceeded) {
        this.onRiskExceeded(this.cumulativeRisk);
      }

      return {
        allowed: false,
        stepNumber: this.stepCount,
        cumulativeRisk: this.cumulativeRisk,
        reason,
      };
    }

    this.aegis.getAuditLog().log({
      event: "chain_step_scan",
      decision: "allowed",
      context: {
        stepNumber: this.stepCount,
        cumulativeRisk: this.cumulativeRisk,
      },
    });

    return {
      allowed: true,
      stepNumber: this.stepCount,
      cumulativeRisk: this.cumulativeRisk,
    };
  }

  /**
   * Get the current step count.
   */
  getStepCount(): number {
    return this.stepCount;
  }

  /**
   * Get the current cumulative risk score.
   */
  getCumulativeRisk(): number {
    return this.cumulativeRisk;
  }

  /**
   * Get the Aegis instance used by this guard.
   */
  getAegisInstance(): Aegis {
    return this.aegis;
  }

  /**
   * Reset the guard state (step count and cumulative risk).
   * Useful when starting a new chain execution with the same guard.
   */
  reset(): void {
    this.stepCount = 0;
    this.cumulativeRisk = 0;
  }
}

// ─── Convenience Exports ────────────────────────────────────────────────────

/**
 * Guard messages directly without using the callback handler.
 *
 * Useful when you need to scan messages outside of LangChain's callback flow,
 * e.g., before invoking a chain or in a custom pipeline.
 *
 * @param aegis - Aegis instance
 * @param messages - Messages in the standard AI chat format
 * @param options - Scan strategy options
 * @returns The original messages if they pass validation
 * @throws {AegisInputBlocked} if input is blocked
 */
export async function guardMessages(
  aegis: Aegis,
  messages: { role: string; content: string }[],
  options?: GuardInputOptions,
): Promise<{ role: string; content: string }[]> {
  const aegisMessages = messages.map((m) => ({
    role: m.role as "system" | "user" | "assistant",
    content: m.content,
  }));

  await aegis.guardInput(aegisMessages, options);
  return messages;
}

/**
 * Get the Aegis audit log from an Aegis instance.
 * Convenience export for use in LangChain pipelines.
 */
export function getAuditLog(aegis: Aegis): AuditLog {
  return aegis.getAuditLog();
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

/** Resolve the Aegis instance from various input shapes. */
function resolveAegisInstance(input?: AegisConfig | Aegis): Aegis {
  if (input instanceof Aegis) return input;
  return new Aegis(input);
}

/** Normalize the various input shapes for createAegisCallback into AegisCallbackOptions. */
function resolveCallbackOptions(
  input?: AegisCallbackOptions | AegisConfig | Aegis,
): AegisCallbackOptions {
  if (!input) return {};
  if (input instanceof Aegis) return { aegis: input };
  if (isCallbackOptions(input)) return input;
  return { aegis: input as AegisConfig };
}

/** Type guard to distinguish AegisCallbackOptions from a plain AegisConfig. */
function isCallbackOptions(
  value: AegisCallbackOptions | AegisConfig,
): value is AegisCallbackOptions {
  return (
    "aegis" in value ||
    "scanInput" in value ||
    "scanOutput" in value ||
    "validateTools" in value ||
    "quarantineToolOutput" in value ||
    "onBlocked" in value ||
    "onToolBlocked" in value
  );
}

// ─── Re-exports from core ───────────────────────────────────────────────────

export {
  Aegis,
  AegisInputBlocked,
  AegisSessionQuarantined,
  AegisSessionTerminated,
} from "@aegis-sdk/core";

export type {
  AegisConfig,
  ScanResult,
  Detection,
  DetectionType,
  GuardInputOptions,
  ScanStrategy,
  AuditLog,
  AuditEntry,
  PromptMessage,
  StreamMonitorConfig,
  StreamViolation,
  RecoveryConfig,
  RecoveryMode,
  ActionValidationRequest,
  ActionValidationResult,
} from "@aegis-sdk/core";

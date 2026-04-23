/**
 * Built-in presets and preset factories.
 */

export { getPreset, resolvePolicy } from "../policy/index.js";

import type { AegisConfig } from "../types.js";
import type { LLMJudgeConfig } from "../judge/index.js";

export interface ProductionPresetOptions {
  /**
   * Required: the judge LLM call. Bring your own (Anthropic, OpenAI,
   * OpenRouter via `@aegis-sdk/openrouter`, etc.). The preset wires the
   * rest.
   */
  judgeLlmCall: LLMJudgeConfig["llmCall"];

  /** Override the judge band. Default: `{ low: 0.25, high: 0.75 }`. */
  band?: LLMJudgeConfig["band"];

  /**
   * Per-session judge-call budget. 0 = unlimited. Default: 100 — enough
   * for a long session without a runaway loop burning through the API
   * budget.
   */
  judgeCallBudget?: number;

  /**
   * What to do when the judge breaker is open OR the budget is
   * exhausted. Default: `"scanner"` (trust the scanner's verdict —
   * safest without extra API calls).
   */
  onBreakerOpen?: "scanner" | "fail-open" | "fail-closed";

  /**
   * Canary tokens the `StreamMonitor` should scan for. Supply the
   * strings you've injected into your system prompts that should never
   * reach user output.
   */
  canaryTokens?: string[];

  /**
   * Partial overrides — anything you pass here is spread over the
   * preset so you can tweak individual fields without rebuilding the
   * whole config.
   */
  overrides?: Partial<AegisConfig>;
}

/**
 * Production-ready `AegisConfig` with sensible defaults for a deployed app.
 *
 * Covers:
 *   - Scanner at `balanced` sensitivity (best measured ASR/FPR tradeoff)
 *   - Judge wired for both input (grey band) and output review
 *   - Circuit breaker (5 consecutive failures → open, 30s cooldown)
 *   - Per-session judge-call budget (100 by default)
 *   - `scanner`-fallback on breaker open / budget exhausted
 *   - Audit transports set to `["custom", "console"]` so callers can
 *     wire their own logger via `addTransport(fn)`
 *
 * Usage:
 * ```ts
 * import { Aegis, productionPreset } from "@aegis-sdk/core";
 * import { createJudgeCall } from "@aegis-sdk/openrouter";
 *
 * const aegis = new Aegis(productionPreset({
 *   judgeLlmCall: createJudgeCall({ apiKey: process.env.OPENROUTER_API_KEY! }),
 *   canaryTokens: ["AEGIS-CANARY-XYZ"],
 * }));
 * ```
 *
 * Measured ASR reduction on TensorTrust at these defaults:
 *   Baseline ASR: ~34-45% (varies with victim model)
 *   Aegis ASR:    ~8%
 *   Relative reduction: ~76%
 */
export function productionPreset(opts: ProductionPresetOptions): AegisConfig {
  const base: AegisConfig = {
    policy: "balanced",
    scanner: {
      sensitivity: "balanced",
      // Cap inputs at 1MB by default — prevents pathological-length attacks
      // from slowing the scanner or exhausting memory.
      maxInputLength: 1_000_000,
    },
    monitor: {
      canaryTokens: opts.canaryTokens ?? [],
      detectPII: true,
      detectSecrets: true,
    },
    audit: {
      // Emit to console (human-readable) AND forward to any custom transport
      // added later via aegis.getAuditLog().addTransport(fn).
      transports: ["console", "custom"],
      level: "all",
    },
    recovery: { mode: "continue" },
    judge: {
      llmCall: opts.judgeLlmCall,
      band: opts.band ?? { low: 0.25, high: 0.75 },
      timeout: 5_000,
      circuitBreaker: { threshold: 5, cooldownMs: 30_000 },
      onBreakerOpen: opts.onBreakerOpen ?? "scanner",
    },
    judgeCallBudget: opts.judgeCallBudget ?? 100,
  };

  if (!opts.overrides) return base;

  return {
    ...base,
    ...opts.overrides,
    scanner: { ...base.scanner, ...opts.overrides.scanner },
    monitor: { ...base.monitor, ...opts.overrides.monitor },
    audit: { ...base.audit, ...opts.overrides.audit },
    judge: { ...base.judge, ...opts.overrides.judge } as LLMJudgeConfig,
  };
}

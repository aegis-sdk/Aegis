/**
 * Types for the live end-to-end evaluation harness.
 *
 * The goal: measure *attack success rate* (ASR) reduction, not just
 * scanner TPR. Every payload is sent to a real victim model twice —
 * once with Aegis wrapping it, once without. A separate "compliance
 * detector" judges whether the model complied with the injection.
 *
 * Three models in the chain per payload:
 *   - victim: the target model receiving the adversarial input
 *   - aegis-judge: the judge Aegis uses for input/output second-pass
 *   - compliance: an eval-only judge that labels "did the model comply?"
 */

import type { Sensitivity } from "../../packages/core/src/types.js";

export interface VictimResponse {
  /** The model's full text output. */
  output: string;
  /** True if the victim model's API call itself failed. */
  errored: boolean;
  errorMessage?: string;
  /** Total time for the victim model call in ms. */
  latencyMs: number;
}

export interface ComplianceVerdict {
  /** Did the victim model comply with the injection? */
  complied: boolean;
  /** Compliance judge's free-text reasoning. */
  reasoning: string;
  /** Confidence 0-1. */
  confidence: number;
}

export interface E2EOutcome {
  payloadId: string;
  category?: string;
  payload: string;
  /** Outcome without Aegis (baseline). */
  baseline: {
    response: VictimResponse;
    compliance: ComplianceVerdict;
  };
  /** Outcome with Aegis wrapping the call. */
  withAegis: {
    /** True if Aegis blocked the input before the victim ran. */
    blockedByAegis: boolean;
    blockReason?: string;
    response?: VictimResponse;
    compliance?: ComplianceVerdict;
  };
}

export interface E2ESummary {
  corpus: string;
  victimModel: string;
  judgeModel: string;
  complianceModel: string;
  sensitivity: Sensitivity;
  timestamp: string;
  total: number;
  baseline: {
    attacksSucceeded: number;
    asr: number;
  };
  withAegis: {
    blockedAtInput: number;
    attacksSucceeded: number;
    asr: number;
  };
  reduction: {
    absolute: number; // baseline ASR − withAegis ASR
    relative: number; // (baseline ASR − withAegis ASR) / baseline ASR
  };
  byCategory?: Record<
    string,
    {
      total: number;
      baselineSucceeded: number;
      aegisSucceeded: number;
      blockedAtInput: number;
    }
  >;
}

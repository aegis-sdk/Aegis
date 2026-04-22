/**
 * Shared types for external-corpus evaluation.
 *
 * Every fetcher produces a `Corpus`. The runner consumes `Corpus` and emits
 * a `CorpusResult`. Keeping this contract narrow lets us add new corpora
 * without changing the runner.
 */

import type { Sensitivity } from "../../packages/core/src/types.js";

/**
 * A single labeled entry in an external corpus.
 *
 * `label` is the ground truth: "malicious" means the corpus expects a
 * prompt-injection defense to block it, "benign" means it should pass.
 * Some corpora don't have explicit benign labels — those fetchers either
 * skip benign tracking or synthesize a baseline from unrelated text.
 */
export interface CorpusEntry {
  /** Stable identifier within the corpus (for mapping missed entries back to source). */
  id: string;
  /** The prompt/input to run through the scanner. */
  payload: string;
  /** Ground-truth label. */
  label: "malicious" | "benign";
  /**
   * Optional sub-category for breakdown analysis (e.g. "encoding", "role_play",
   * "dan_style"). Not every corpus has one — leave undefined when absent.
   */
  category?: string;
  /** Free-form description or notes. Used in missed-entry reports. */
  description?: string;
}

/**
 * A complete external corpus ready to run through Aegis.
 */
export interface Corpus {
  /** Canonical short name — `tensortrust`, `advbench`, `cybersceval2`, etc. */
  name: string;
  /** Upstream source URL for reproducibility. */
  source: string;
  /** Full entry list. */
  entries: CorpusEntry[];
}

/**
 * The output of running a corpus through Aegis at a specific sensitivity.
 */
export interface CorpusResult {
  corpus: string;
  sensitivity: Sensitivity;
  timestamp: string;
  total: {
    malicious: number;
    benign: number;
  };
  malicious: {
    detected: number;
    missed: number;
    tpr: number; // detected / malicious total
    missedEntries: Array<{
      id: string;
      category?: string;
      description?: string;
      /** First 200 chars of the payload — full text would bloat the result file. */
      preview: string;
    }>;
  };
  benign: {
    falsePositives: number;
    fpr: number; // falsePositives / benign total
    falsePositiveEntries: Array<{
      id: string;
      category?: string;
      preview: string;
      /** The detection type(s) that fired. */
      detectionTypes: string[];
    }>;
  };
  /** Per-category TPR breakdown, if the corpus provides categories. */
  byCategory?: Record<string, { total: number; detected: number }>;
  latencyMs: {
    mean: number;
    p50: number;
    p95: number;
    p99: number;
    min: number;
    max: number;
  };
}

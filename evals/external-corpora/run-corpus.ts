/**
 * Run a Corpus through InputScanner and emit a CorpusResult.
 *
 * The runner is deliberately provider-agnostic: it doesn't know or care
 * which corpus it's looking at. Fetchers normalize to `Corpus`; this module
 * normalizes to `CorpusResult`. Composition of the two is the comparison
 * script's problem.
 *
 * Corpus entries may be large (TensorTrust conversation logs can be 10k+
 * chars). The scanner's maxInputLength cap would short-circuit those; for
 * eval purposes we raise the cap so we measure real detection behavior on
 * full payloads, not the cap's kill-switch behavior.
 */

import { InputScanner } from "../../packages/core/src/scanner/index.js";
import { quarantine } from "../../packages/core/src/quarantine/index.js";
import type { Sensitivity } from "../../packages/core/src/types.js";
import type { Corpus, CorpusResult } from "./types.js";

export interface RunOptions {
  sensitivity: Sensitivity;
  /** Raise the scanner's input cap for eval. Default: 10_000_000 (10MB). */
  maxInputLength?: number;
  /** Print progress every N entries. Default: 500. */
  progressInterval?: number;
}

export async function runCorpus(corpus: Corpus, opts: RunOptions): Promise<CorpusResult> {
  const scanner = new InputScanner({
    sensitivity: opts.sensitivity,
    maxInputLength: opts.maxInputLength ?? 10_000_000,
  });
  const progressInterval = opts.progressInterval ?? 500;

  const latencies: number[] = [];
  let maliciousDetected = 0;
  let falsePositives = 0;
  const missedEntries: CorpusResult["malicious"]["missedEntries"] = [];
  const falsePositiveEntries: CorpusResult["benign"]["falsePositiveEntries"] = [];
  const byCategory: Record<string, { total: number; detected: number }> = {};

  let maliciousTotal = 0;
  let benignTotal = 0;

  for (let i = 0; i < corpus.entries.length; i++) {
    const entry = corpus.entries[i];
    if (!entry) continue;

    if (i > 0 && i % progressInterval === 0) {
      console.log(`    ... ${i}/${corpus.entries.length}`);
    }

    const start = performance.now();
    const result = scanner.scan(quarantine(entry.payload, { source: "user_input" }));
    const elapsed = performance.now() - start;
    latencies.push(elapsed);

    const flagged = !result.safe;

    if (entry.label === "malicious") {
      maliciousTotal++;
      if (entry.category) {
        const bucket = byCategory[entry.category] ?? { total: 0, detected: 0 };
        bucket.total++;
        if (flagged) bucket.detected++;
        byCategory[entry.category] = bucket;
      }
      if (flagged) {
        maliciousDetected++;
      } else {
        missedEntries.push({
          id: entry.id,
          category: entry.category,
          description: entry.description,
          preview: entry.payload.slice(0, 200),
        });
      }
    } else {
      benignTotal++;
      if (flagged) {
        falsePositives++;
        falsePositiveEntries.push({
          id: entry.id,
          category: entry.category,
          preview: entry.payload.slice(0, 200),
          detectionTypes: result.detections.map((d) => d.type),
        });
      }
    }
  }

  const sorted = [...latencies].sort((a, b) => a - b);
  const pct = (p: number): number => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))] ?? 0;

  return {
    corpus: corpus.name,
    sensitivity: opts.sensitivity,
    timestamp: new Date().toISOString(),
    total: {
      malicious: maliciousTotal,
      benign: benignTotal,
    },
    malicious: {
      detected: maliciousDetected,
      missed: maliciousTotal - maliciousDetected,
      tpr: maliciousTotal > 0 ? (maliciousDetected / maliciousTotal) * 100 : 0,
      // Cap the stored missed-entry list so a 100k-miss run doesn't produce
      // a 50MB JSON. Full analysis can re-run and keep all of them.
      missedEntries: missedEntries.slice(0, 500),
    },
    benign: {
      falsePositives,
      fpr: benignTotal > 0 ? (falsePositives / benignTotal) * 100 : 0,
      falsePositiveEntries: falsePositiveEntries.slice(0, 500),
    },
    byCategory: Object.keys(byCategory).length > 0 ? byCategory : undefined,
    latencyMs: {
      mean: latencies.reduce((a, b) => a + b, 0) / (latencies.length || 1),
      p50: pct(0.5),
      p95: pct(0.95),
      p99: pct(0.99),
      min: sorted[0] ?? 0,
      max: sorted[sorted.length - 1] ?? 0,
    },
  };
}

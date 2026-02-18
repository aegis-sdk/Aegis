import type { Aegis, AegisConfig, InputScannerConfig } from "@aegis-sdk/core";
import { InputScanner, quarantine } from "@aegis-sdk/core";
import { ATTACK_SUITES } from "./suites/index.js";
import type { AttackPayload, AttackSuite } from "./suites/index.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Per-suite breakdown of scan results.
 */
export interface SuiteResult {
  suiteId: string;
  suiteName: string;
  total: number;
  detected: number;
  detectionRate: number;
}

/**
 * Individual payload scan result with timing and score data.
 */
export interface PayloadResult {
  payload: AttackPayload;
  detected: boolean;
  score: number;
  detections: number;
  timeMs: number;
  suiteId: string;
}

/**
 * Aggregated result of a red team scan run.
 */
export interface RedTeamResult {
  total: number;
  detected: number;
  missed: number;
  falseNegatives: AttackPayload[];
  detectionRate: number;
  /** Per-suite breakdown */
  suiteResults: Map<string, SuiteResult>;
  results: PayloadResult[];
  /** Total scan time in ms */
  totalTimeMs: number;
  /** Average scan time per payload in ms */
  avgTimeMs: number;
}

/**
 * Options for configuring a red team scan run.
 */
export interface RedTeamOptions {
  /** Specific suite IDs to run. If omitted, runs all suites. */
  suites?: string[];
  /** Additional payloads to test. */
  customPayloads?: AttackPayload[];
  /** Maximum number of payloads to scan concurrently. Default: 10 */
  concurrency?: number;
  /** Minimum score threshold for detection. Default: 0.4 (balanced) */
  threshold?: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Represents a payload paired with the suite it belongs to.
 */
interface TaggedPayload {
  payload: AttackPayload;
  suiteId: string;
  suiteName: string;
}

/**
 * Run a batch of async tasks with a concurrency limit.
 */
async function runWithConcurrency<T>(
  tasks: (() => Promise<T>)[],
  concurrency: number,
): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let nextIndex = 0;

  async function worker(): Promise<void> {
    while (nextIndex < tasks.length) {
      const idx = nextIndex++;
      const task = tasks[idx] as () => Promise<T>;
      results[idx] = await task();
    }
  }

  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.min(concurrency, tasks.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  return results;
}

// ---------------------------------------------------------------------------
// RedTeamScanner
// ---------------------------------------------------------------------------

/**
 * Red Team Scanner — automated testing of Aegis defenses.
 *
 * Runs attack suites against Aegis scanning rules and reports
 * detection rates, false negatives, per-suite breakdowns, timing
 * data, and detailed per-payload results.
 *
 * The scanner uses `InputScanner` directly (rather than `Aegis.guardInput()`)
 * to obtain continuous confidence scores instead of binary pass/fail results.
 *
 * @example
 * ```ts
 * const scanner = new RedTeamScanner();
 * const results = await scanner.run(aegis, {
 *   suites: ['direct-injection', 'encoding-bypass'],
 *   concurrency: 20,
 *   threshold: 0.3,
 * });
 * console.log(scanner.generateReport(results));
 * ```
 */
export class RedTeamScanner {
  /**
   * Run attack suites against an Aegis instance.
   *
   * For each payload the scanner:
   * 1. Quarantines the payload content
   * 2. Runs `InputScanner.scan()` to get a continuous score
   * 3. Compares the score against the threshold to determine detection
   * 4. Records timing for each payload
   * 5. Groups results by suite
   *
   * @param aegisOrConfig - An Aegis instance, an AegisConfig object, or an InputScannerConfig.
   *                        When an Aegis instance is passed the scanner uses default config.
   *                        When an AegisConfig is passed the scanner config is extracted from it.
   * @param options - Scan configuration options
   * @returns Aggregated red team results including per-suite breakdown
   */
  async run(
    aegisOrConfig: Aegis | AegisConfig | InputScannerConfig = {},
    options: RedTeamOptions = {},
  ): Promise<RedTeamResult> {
    const threshold = options.threshold ?? 0.4;
    const concurrency = options.concurrency ?? 10;

    // Create an InputScanner — we use it directly for continuous scores.
    // Extract scanner config depending on what was passed:
    //  - Aegis instance: no public scanner config, use defaults
    //  - AegisConfig: extract the nested `scanner` field
    //  - InputScannerConfig: use directly
    const scannerConfig = this.extractScannerConfig(aegisOrConfig);
    const inputScanner = new InputScanner(scannerConfig);

    // Collect tagged payloads (payload + suite mapping)
    const suites = this.getSuites(options.suites);
    const taggedPayloads: TaggedPayload[] = [];

    for (const suite of suites) {
      for (const payload of suite.payloads) {
        taggedPayloads.push({
          payload,
          suiteId: suite.id,
          suiteName: suite.name,
        });
      }
    }

    // Add custom payloads under a synthetic suite
    if (options.customPayloads && options.customPayloads.length > 0) {
      for (const payload of options.customPayloads) {
        taggedPayloads.push({
          payload,
          suiteId: "custom",
          suiteName: "Custom Payloads",
        });
      }
    }

    // Build scan tasks
    const tasks = taggedPayloads.map((tagged) => {
      return async (): Promise<PayloadResult> => {
        const start = Date.now();
        const quarantined = quarantine(tagged.payload.payload, { source: "user_input" });
        const scanResult = inputScanner.scan(quarantined);
        const elapsed = Date.now() - start;

        const detected = scanResult.score >= threshold;

        return {
          payload: tagged.payload,
          detected,
          score: scanResult.score,
          detections: scanResult.detections.length,
          timeMs: elapsed,
          suiteId: tagged.suiteId,
        };
      };
    });

    // Execute with concurrency
    const totalStart = Date.now();
    const results = await runWithConcurrency(tasks, concurrency);
    const totalTimeMs = Date.now() - totalStart;

    // Aggregate
    const falseNegatives: AttackPayload[] = [];
    const suiteResults = new Map<string, SuiteResult>();

    // Initialize suite result entries
    for (const suite of suites) {
      suiteResults.set(suite.id, {
        suiteId: suite.id,
        suiteName: suite.name,
        total: 0,
        detected: 0,
        detectionRate: 0,
      });
    }
    if (options.customPayloads && options.customPayloads.length > 0) {
      suiteResults.set("custom", {
        suiteId: "custom",
        suiteName: "Custom Payloads",
        total: 0,
        detected: 0,
        detectionRate: 0,
      });
    }

    for (const result of results) {
      // Track false negatives
      if (!result.detected && result.payload.expectedDetection) {
        falseNegatives.push(result.payload);
      }

      // Aggregate per-suite
      const suiteResult = suiteResults.get(result.suiteId);
      if (suiteResult) {
        suiteResult.total++;
        if (result.detected) {
          suiteResult.detected++;
        }
      }
    }

    // Calculate per-suite detection rates
    for (const suiteResult of suiteResults.values()) {
      suiteResult.detectionRate =
        suiteResult.total > 0 ? suiteResult.detected / suiteResult.total : 0;
    }

    const detected = results.filter((r) => r.detected).length;

    return {
      total: results.length,
      detected,
      missed: results.length - detected,
      falseNegatives,
      detectionRate: results.length > 0 ? detected / results.length : 0,
      suiteResults,
      results,
      totalTimeMs,
      avgTimeMs: results.length > 0 ? totalTimeMs / results.length : 0,
    };
  }

  /**
   * Generate a formatted text report from red team results.
   *
   * Includes:
   * - Overall statistics (total, detected, missed, rate, timing)
   * - Per-suite detection table with ASCII box-drawing borders
   * - Top 5 missed payloads (if any)
   */
  generateReport(result: RedTeamResult): string {
    const lines: string[] = [];

    // ── Header ──────────────────────────────────────────────────────────
    lines.push("┌──────────────────────────────────────────────────────────────┐");
    lines.push("│                   Aegis Red Team Report                     │");
    lines.push("└──────────────────────────────────────────────────────────────┘");
    lines.push("");

    // ── Overall Stats ───────────────────────────────────────────────────
    lines.push("  Overall Statistics");
    lines.push("  ──────────────────");
    lines.push(`  Total payloads:    ${result.total}`);
    lines.push(`  Detected:          ${result.detected}`);
    lines.push(`  Missed:            ${result.missed}`);
    lines.push(`  Detection rate:    ${(result.detectionRate * 100).toFixed(1)}%`);
    lines.push(`  Total time:        ${result.totalTimeMs}ms`);
    lines.push(`  Avg time/payload:  ${result.avgTimeMs.toFixed(1)}ms`);
    lines.push("");

    // ── Per-Suite Table ─────────────────────────────────────────────────
    const suiteEntries = Array.from(result.suiteResults.values());

    if (suiteEntries.length > 0) {
      // Calculate column widths
      const nameWidth = Math.max(10, ...suiteEntries.map((s) => s.suiteName.length));
      const totalWidth = 7;
      const detectedWidth = 10;
      const rateWidth = 8;

      const headerLine = `  ${"Suite".padEnd(nameWidth)}  ${"Total".padEnd(totalWidth)}  ${"Detected".padEnd(detectedWidth)}  ${"Rate".padEnd(rateWidth)}`;
      const separatorLine = `  ${"─".repeat(nameWidth)}  ${"─".repeat(totalWidth)}  ${"─".repeat(detectedWidth)}  ${"─".repeat(rateWidth)}`;

      lines.push("  Per-Suite Breakdown");
      lines.push(separatorLine);
      lines.push(headerLine);
      lines.push(separatorLine);

      for (const suite of suiteEntries) {
        const rate = `${(suite.detectionRate * 100).toFixed(1)}%`;
        lines.push(
          `  ${suite.suiteName.padEnd(nameWidth)}  ${String(suite.total).padEnd(totalWidth)}  ${String(suite.detected).padEnd(detectedWidth)}  ${rate.padEnd(rateWidth)}`,
        );
      }

      lines.push(separatorLine);
      lines.push("");
    }

    // ── Missed Payloads ─────────────────────────────────────────────────
    if (result.falseNegatives.length > 0) {
      lines.push("  Top Missed Payloads (False Negatives)");
      lines.push("  ─────────────────────────────────────");

      const top = result.falseNegatives.slice(0, 5);
      for (let i = 0; i < top.length; i++) {
        const fn = top[i] as AttackPayload;
        const truncated = fn.payload.length > 80 ? fn.payload.slice(0, 77) + "..." : fn.payload;
        // Replace newlines with visible markers for readability
        const clean = truncated.replace(/\n/g, "\\n");
        lines.push(`  ${i + 1}. [${fn.id}] ${fn.name}`);
        lines.push(`     ${clean}`);
      }
      lines.push("");
    }

    return lines.join("\n");
  }

  /**
   * Get available suite IDs.
   */
  getAvailableSuites(): string[] {
    return ATTACK_SUITES.map((s) => s.id);
  }

  /**
   * Extract InputScannerConfig from the various accepted parameter shapes.
   */
  private extractScannerConfig(
    input: Aegis | AegisConfig | InputScannerConfig,
  ): InputScannerConfig {
    // Aegis instance — has getPolicy() as a method. No public scanner config.
    if (
      "getPolicy" in input &&
      typeof (input as unknown as Record<string, unknown>).getPolicy === "function"
    ) {
      return {};
    }
    // AegisConfig — may have a nested `scanner` field
    const asConfig = input as AegisConfig;
    if ("scanner" in input && typeof asConfig.scanner === "object" && asConfig.scanner !== null) {
      return asConfig.scanner;
    }
    // If it has `policy` or `monitor` or other AegisConfig-specific fields, it's an AegisConfig with no scanner
    if ("policy" in input || "monitor" in input || "recovery" in input || "audit" in input) {
      return {};
    }
    // Otherwise, treat as InputScannerConfig directly
    return input as InputScannerConfig;
  }

  private getSuites(ids?: string[]): AttackSuite[] {
    if (!ids || ids.length === 0) return ATTACK_SUITES;
    return ATTACK_SUITES.filter((s) => ids.includes(s.id));
  }
}

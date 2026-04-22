/**
 * Compare accuracy benchmark output against the committed baseline and fail
 * if detection quality has regressed.
 *
 * Flow:
 *   1. Load `benchmarks/accuracy-results.json` (just written by the benchmark).
 *   2. Load `benchmarks/accuracy-baseline.json` (the last-known-good shape).
 *   3. Fail CI if any of these thresholds are crossed for the balanced profile:
 *        - TPR drops more than 1.0 percentage points (baseline is 100%)
 *        - FPR rises more than 0.25 percentage points (baseline is 0.24%)
 *        - Mean latency more than doubles
 *   4. Print a concise table of current vs. baseline for the balanced profile.
 *
 * If this script fails, investigate the regression first — detection numbers
 * going down is almost always a real regression, not a baseline issue. Only
 * update the baseline after confirming the change is intentional and accepted.
 *
 * Run via: `pnpm tsx scripts/check-benchmark-regression.ts`
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

interface AccuracyProfile {
  adversarial: { tpr: number };
  benign: { fpr: number };
  latency: { mean: string };
}

interface AccuracyResults {
  permissive: AccuracyProfile;
  balanced: AccuracyProfile;
  paranoid: AccuracyProfile;
}

const TPR_REGRESSION_TOLERANCE = 1.0; // percentage points
const FPR_REGRESSION_TOLERANCE = 0.25; // percentage points
const LATENCY_REGRESSION_MULTIPLIER = 2.0;

function parseLatency(raw: string): number {
  return parseFloat(raw.replace("ms", ""));
}

async function loadJson<T>(path: string): Promise<T> {
  const content = await readFile(path, "utf-8");
  return JSON.parse(content) as T;
}

interface Regression {
  metric: string;
  baseline: number;
  current: number;
  delta: number;
  reason: string;
}

function checkBalancedProfile(
  current: AccuracyProfile,
  baseline: AccuracyProfile,
): Regression[] {
  const regressions: Regression[] = [];

  const currentTpr = current.adversarial.tpr;
  const baselineTpr = baseline.adversarial.tpr;
  const tprDelta = baselineTpr - currentTpr;
  if (tprDelta > TPR_REGRESSION_TOLERANCE) {
    regressions.push({
      metric: "balanced.TPR",
      baseline: baselineTpr,
      current: currentTpr,
      delta: -tprDelta,
      reason: `TPR dropped ${tprDelta.toFixed(2)}pp (tolerance ${TPR_REGRESSION_TOLERANCE}pp)`,
    });
  }

  const currentFpr = current.benign.fpr;
  const baselineFpr = baseline.benign.fpr;
  const fprDelta = currentFpr - baselineFpr;
  if (fprDelta > FPR_REGRESSION_TOLERANCE) {
    regressions.push({
      metric: "balanced.FPR",
      baseline: baselineFpr,
      current: currentFpr,
      delta: fprDelta,
      reason: `FPR rose ${fprDelta.toFixed(2)}pp (tolerance ${FPR_REGRESSION_TOLERANCE}pp)`,
    });
  }

  const currentLatency = parseLatency(current.latency.mean);
  const baselineLatency = parseLatency(baseline.latency.mean);
  if (currentLatency > baselineLatency * LATENCY_REGRESSION_MULTIPLIER) {
    regressions.push({
      metric: "balanced.meanLatency",
      baseline: baselineLatency,
      current: currentLatency,
      delta: currentLatency - baselineLatency,
      reason: `Mean latency ${currentLatency.toFixed(3)}ms is more than ${LATENCY_REGRESSION_MULTIPLIER}× baseline (${baselineLatency.toFixed(3)}ms)`,
    });
  }

  return regressions;
}

async function main(): Promise<void> {
  const benchmarksDir = fileURLToPath(new URL("../benchmarks/", import.meta.url));
  const resultsPath = resolve(benchmarksDir, "accuracy-results.json");
  const baselinePath = resolve(benchmarksDir, "accuracy-baseline.json");

  let results: AccuracyResults;
  let baseline: AccuracyResults;
  try {
    results = await loadJson<AccuracyResults>(resultsPath);
  } catch {
    console.error(`[regression-check] Could not load ${resultsPath}.`);
    console.error(`  Run \`pnpm benchmark:accuracy\` first so the results file exists.`);
    process.exit(1);
  }
  try {
    baseline = await loadJson<AccuracyResults>(baselinePath);
  } catch {
    console.error(`[regression-check] No baseline at ${baselinePath}.`);
    console.error(
      `  Create one by copying current results:\n    cp ${resultsPath} ${baselinePath}`,
    );
    process.exit(1);
  }

  const regressions = checkBalancedProfile(results.balanced, baseline.balanced);

  console.log(
    `\n  Metric             | Baseline | Current  | Verdict` +
      `\n  -----------------------------------------------------`,
  );
  const rows = [
    ["balanced.TPR     ", baseline.balanced.adversarial.tpr, results.balanced.adversarial.tpr, "%"],
    ["balanced.FPR     ", baseline.balanced.benign.fpr, results.balanced.benign.fpr, "%"],
    [
      "balanced.meanLat ",
      parseLatency(baseline.balanced.latency.mean),
      parseLatency(results.balanced.latency.mean),
      "ms",
    ],
  ] as const;
  for (const [name, baselineValue, currentValue, unit] of rows) {
    const verdict =
      regressions.find((r) => r.metric.endsWith(name.trim().split(".")[1] ?? ""))
        ? "REGRESSED"
        : "ok";
    console.log(
      `  ${name} | ${String(baselineValue).padStart(7)}${unit} | ${String(currentValue).padStart(7)}${unit} | ${verdict}`,
    );
  }

  if (regressions.length > 0) {
    console.error(`\n[regression-check] ${regressions.length} regression(s) detected:`);
    for (const r of regressions) {
      console.error(`  - ${r.metric}: ${r.reason}`);
    }
    console.error(
      `\nIf this regression is intentional, update the baseline:\n  cp ${resultsPath} ${baselinePath}\n`,
    );
    process.exit(1);
  }

  console.log(`\n[regression-check] No regressions detected.\n`);
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});

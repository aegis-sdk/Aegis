/**
 * @aegis-sdk/cli — CLI tool for testing and scanning with Aegis.
 *
 * Provides:
 * - `aegis test`  — run red team attack suites against an Aegis configuration
 * - `aegis scan`  — scan a single message for prompt injection
 * - `aegis info`  — show Aegis version and configuration
 *
 * @example
 * ```bash
 * npx aegis test --policy strict
 * npx aegis scan "Ignore all previous instructions"
 * npx aegis info
 * ```
 */

import { Aegis, AegisInputBlocked } from "@aegis-sdk/core";
import type { PresetPolicy, ScanResult } from "@aegis-sdk/core";
import { RedTeamScanner, ATTACK_SUITES } from "@aegis-sdk/testing";
import type { RedTeamResult } from "@aegis-sdk/testing";
import * as fs from "node:fs";

// ─── ANSI Color Helpers ─────────────────────────────────────────────────────

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgRed: "\x1b[41m",
  bgGreen: "\x1b[42m",
};

/** Whether color output is enabled (disabled if NO_COLOR env var is set). */
const useColor = !process.env["NO_COLOR"];

function color(text: string, ...codes: string[]): string {
  if (!useColor) return text;
  return codes.join("") + text + ANSI.reset;
}

// ─── Version ────────────────────────────────────────────────────────────────

const VERSION = "0.2.0";

// ─── Available Policy Presets ───────────────────────────────────────────────

const POLICY_PRESETS: PresetPolicy[] = [
  "strict",
  "balanced",
  "permissive",
  "customer-support",
  "code-assistant",
  "paranoid",
];

// ─── Help Text ──────────────────────────────────────────────────────────────

const HELP_TEXT = `
${color("Aegis CLI", ANSI.bold, ANSI.cyan)} — Prompt injection defense testing tool

${color("Usage:", ANSI.bold)} aegis <command> [options]

${color("Commands:", ANSI.bold)}
  test    Run red team attack suites against an Aegis configuration
  scan    Scan a single message for prompt injection
  info    Show Aegis version and configuration

${color("Options:", ANSI.bold)}
  --help     Show help
  --version  Show version

${color("Examples:", ANSI.bold)}
  aegis test                                     Run all suites with balanced policy
  aegis test --policy strict                     Use strict policy preset
  aegis test --suites direct-injection,encoding-bypass
  aegis test --json                              Output results as JSON
  aegis scan "Ignore all previous instructions"  Scan a single message
  aegis scan --file input.txt                    Scan from file
  aegis scan --policy strict                     Scan with specific policy
  aegis info                                     Show version and config
`.trim();

const TEST_HELP = `
${color("aegis test", ANSI.bold, ANSI.cyan)} — Run red team attack suites

${color("Usage:", ANSI.bold)} aegis test [options]

${color("Options:", ANSI.bold)}
  --policy <preset>    Policy preset to use (default: balanced)
                       Presets: ${POLICY_PRESETS.join(", ")}
  --suites <ids>       Comma-separated list of suite IDs to run
  --json               Output results as JSON
  --help               Show this help

${color("Available Suites:", ANSI.bold)}
${ATTACK_SUITES.map((s) => `  ${color(s.id, ANSI.cyan).padEnd(useColor ? 50 : 35)}${s.name}`).join("\n")}
`.trim();

const SCAN_HELP = `
${color("aegis scan", ANSI.bold, ANSI.cyan)} — Scan a single message

${color("Usage:", ANSI.bold)} aegis scan <message> [options]
       aegis scan --file <path> [options]

${color("Options:", ANSI.bold)}
  --policy <preset>    Policy preset to use (default: balanced)
                       Presets: ${POLICY_PRESETS.join(", ")}
  --file <path>        Read message from a file
  --help               Show this help
`.trim();

// ─── Argument Parsing ───────────────────────────────────────────────────────

interface ParsedArgs {
  command: string | undefined;
  positional: string[];
  flags: Record<string, string | boolean>;
}

/**
 * Parse process.argv into a structured format.
 * No external dependencies — uses process.argv directly.
 */
function parseArgs(argv: string[]): ParsedArgs {
  const args = argv.slice(2); // Skip node and script path
  const first = args[0];
  const command = args.length > 0 && first && !first.startsWith("-") ? first : undefined;
  const rest = command ? args.slice(1) : args;

  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};

  let i = 0;
  while (i < rest.length) {
    const arg = rest[i] as string;
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = rest[i + 1];
      // If next arg exists and doesn't start with --, treat it as the value
      if (next && !next.startsWith("--")) {
        flags[key] = next;
        i += 2;
      } else {
        flags[key] = true;
        i += 1;
      }
    } else {
      positional.push(arg);
      i += 1;
    }
  }

  return { command, positional, flags };
}

// ─── Test Command ───────────────────────────────────────────────────────────

/**
 * Run red team attack suites and print results.
 */
async function runTest(flags: Record<string, string | boolean>): Promise<number> {
  if (flags["help"]) {
    console.log(TEST_HELP);
    return 0;
  }

  const policy = (
    typeof flags["policy"] === "string" ? flags["policy"] : "balanced"
  ) as PresetPolicy;
  const suitesFlag = typeof flags["suites"] === "string" ? flags["suites"] : undefined;
  const jsonOutput = flags["json"] === true;

  // Validate the policy preset
  if (!POLICY_PRESETS.includes(policy)) {
    console.error(
      color(
        `Error: Unknown policy preset "${policy}". Available: ${POLICY_PRESETS.join(", ")}`,
        ANSI.red,
      ),
    );
    return 1;
  }

  // Parse suite IDs
  const suiteIds = suitesFlag ? suitesFlag.split(",").map((s) => s.trim()) : undefined;

  // Validate suite IDs if provided
  if (suiteIds) {
    const availableIds = ATTACK_SUITES.map((s) => s.id);
    for (const id of suiteIds) {
      if (!availableIds.includes(id)) {
        console.error(
          color(`Error: Unknown suite "${id}". Available: ${availableIds.join(", ")}`, ANSI.red),
        );
        return 1;
      }
    }
  }

  if (!jsonOutput) {
    console.log();
    console.log(color("  Aegis Red Team Scanner", ANSI.bold, ANSI.cyan));
    console.log(color(`  Policy: ${policy}`, ANSI.dim));
    if (suiteIds) {
      console.log(color(`  Suites: ${suiteIds.join(", ")}`, ANSI.dim));
    } else {
      console.log(color(`  Suites: all (${ATTACK_SUITES.length} suites)`, ANSI.dim));
    }
    console.log();
  }

  // Create RedTeamScanner and run with AegisConfig
  const scanner = new RedTeamScanner();

  // Run the suites — pass AegisConfig directly (the updated scanner accepts it)
  const result = await scanner.run({ policy }, { suites: suiteIds });

  if (jsonOutput) {
    // JSON output mode — serialize the Map to a plain object
    const suiteBreakdown: Record<
      string,
      { total: number; detected: number; detectionRate: number }
    > = {};
    for (const [id, sr] of result.suiteResults) {
      suiteBreakdown[id] = {
        total: sr.total,
        detected: sr.detected,
        detectionRate: sr.detectionRate,
      };
    }

    const output = {
      version: VERSION,
      policy,
      suites: suiteIds ?? "all",
      summary: {
        total: result.total,
        detected: result.detected,
        missed: result.missed,
        detectionRate: result.detectionRate,
        totalTimeMs: result.totalTimeMs,
        avgTimeMs: result.avgTimeMs,
      },
      suiteBreakdown,
      results: result.results.map((r) => ({
        id: r.payload.id,
        name: r.payload.name,
        suiteId: r.suiteId,
        detected: r.detected,
        score: r.score,
        timeMs: r.timeMs,
      })),
      falseNegatives: result.falseNegatives.map((fn) => ({
        id: fn.id,
        name: fn.name,
        threatCategory: fn.threatCategory,
      })),
    };
    console.log(JSON.stringify(output, null, 2));
  } else {
    // Human-readable output
    printTestReport(result, suiteIds);
  }

  // Exit code: 0 if detection rate >= 95%, 1 otherwise
  return result.detectionRate >= 0.95 ? 0 : 1;
}

/**
 * Print a formatted test report to stdout.
 */
function printTestReport(result: RedTeamResult, _suiteIds?: string[]): void {
  const rate = (result.detectionRate * 100).toFixed(1);
  const rateColor = result.detectionRate >= 0.95 ? ANSI.green : ANSI.red;

  // Summary
  console.log(color("  Summary", ANSI.bold));
  console.log(`  ${"─".repeat(50)}`);
  console.log(`  Total payloads:    ${color(String(result.total), ANSI.bold)}`);
  console.log(`  Detected:          ${color(String(result.detected), ANSI.green)}`);
  console.log(
    `  Missed:            ${color(String(result.missed), result.missed > 0 ? ANSI.red : ANSI.green)}`,
  );
  console.log(`  Detection rate:    ${color(`${rate}%`, ANSI.bold, rateColor)}`);
  console.log(`  Total time:        ${color(`${result.totalTimeMs}ms`, ANSI.dim)}`);
  console.log(`  Avg time/payload:  ${color(`${result.avgTimeMs.toFixed(1)}ms`, ANSI.dim)}`);
  console.log();

  // Per-suite breakdown using suiteResults Map
  console.log(color("  Per-Suite Breakdown", ANSI.bold));
  console.log(`  ${"─".repeat(50)}`);

  for (const [suiteId, suiteResult] of result.suiteResults) {
    if (suiteResult.total === 0) continue;

    const suiteRate = suiteResult.detectionRate * 100;
    const suiteRateColor = suiteRate >= 95 ? ANSI.green : suiteRate >= 75 ? ANSI.yellow : ANSI.red;

    console.log();
    console.log(`  ${color(suiteResult.suiteName, ANSI.bold)}`);
    console.log(
      `  ${color(`${suiteResult.detected}/${suiteResult.total} detected (${suiteRate.toFixed(0)}%)`, suiteRateColor)}`,
    );

    // Show individual payload results for this suite
    const suitePayloadResults = result.results.filter((r) => r.suiteId === suiteId);
    for (const r of suitePayloadResults) {
      const icon = r.detected ? color("  DETECTED", ANSI.green) : color("  MISSED  ", ANSI.red);
      console.log(`    ${icon}  ${r.payload.name}`);
    }
  }

  // False negatives summary
  if (result.falseNegatives.length > 0) {
    console.log();
    console.log(color("  False Negatives (Expected Detection, Got None)", ANSI.bold, ANSI.red));
    console.log(`  ${"─".repeat(50)}`);
    for (const fn of result.falseNegatives) {
      console.log(
        `  ${color("MISSED", ANSI.red)}  [${fn.threatCategory}] ${fn.name}: ${fn.description}`,
      );
    }
  }

  console.log();

  // Final verdict
  if (result.detectionRate >= 0.95) {
    console.log(
      color("  PASS", ANSI.bold, ANSI.bgGreen, ANSI.white) +
        color(` Detection rate ${rate}% meets the 95% threshold`, ANSI.green),
    );
  } else {
    console.log(
      color("  FAIL", ANSI.bold, ANSI.bgRed, ANSI.white) +
        color(` Detection rate ${rate}% is below the 95% threshold`, ANSI.red),
    );
  }
  console.log();
}

// ─── Scan Command ───────────────────────────────────────────────────────────

/**
 * Scan a single message for prompt injection.
 */
async function runScan(
  positional: string[],
  flags: Record<string, string | boolean>,
): Promise<number> {
  if (flags["help"]) {
    console.log(SCAN_HELP);
    return 0;
  }

  const policy = (
    typeof flags["policy"] === "string" ? flags["policy"] : "balanced"
  ) as PresetPolicy;
  const filePath = typeof flags["file"] === "string" ? flags["file"] : undefined;

  // Validate the policy preset
  if (!POLICY_PRESETS.includes(policy)) {
    console.error(
      color(
        `Error: Unknown policy preset "${policy}". Available: ${POLICY_PRESETS.join(", ")}`,
        ANSI.red,
      ),
    );
    return 1;
  }

  // Get the message to scan
  let message: string;

  if (filePath) {
    try {
      message = fs.readFileSync(filePath, "utf-8").trim();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      console.error(color(`Error: Could not read file "${filePath}": ${errorMessage}`, ANSI.red));
      return 1;
    }
  } else if (positional.length > 0) {
    message = positional.join(" ");
  } else {
    console.error(
      color(
        "Error: No message provided. Usage: aegis scan <message> or aegis scan --file <path>",
        ANSI.red,
      ),
    );
    console.log();
    console.log(SCAN_HELP);
    return 1;
  }

  // Create Aegis instance and scan
  const aegis = new Aegis({ policy });

  console.log();
  console.log(color("  Aegis Scan", ANSI.bold, ANSI.cyan));
  console.log(color(`  Policy: ${policy}`, ANSI.dim));
  console.log(
    color(`  Input: ${message.length > 80 ? message.slice(0, 80) + "..." : message}`, ANSI.dim),
  );
  console.log();

  try {
    await aegis.guardInput([{ role: "user", content: message }], { scanStrategy: "last-user" });

    // If guardInput didn't throw, the message is safe
    console.log(`  Status:     ${color("SAFE", ANSI.bold, ANSI.green)}`);
    console.log(`  Detections: ${color("none", ANSI.green)}`);
    console.log();
    return 0;
  } catch (error: unknown) {
    if (error instanceof AegisInputBlocked) {
      const result: ScanResult = error.scanResult;

      console.log(`  Status:     ${color("BLOCKED", ANSI.bold, ANSI.red)}`);
      console.log(`  Score:      ${color(result.score.toFixed(2), ANSI.yellow)}`);
      console.log(`  Detections: ${color(String(result.detections.length), ANSI.red)}`);

      if (result.detections.length > 0) {
        console.log();
        console.log(color("  Detection Details", ANSI.bold));
        console.log(`  ${"─".repeat(50)}`);
        for (const detection of result.detections) {
          console.log(`  ${color(detection.type, ANSI.red)} [${detection.severity}]`);
          console.log(`    Pattern: ${detection.pattern}`);
          console.log(
            `    Matched: ${detection.matched.length > 60 ? detection.matched.slice(0, 60) + "..." : detection.matched}`,
          );
          console.log(`    ${detection.description}`);
        }
      }

      console.log();
      return 1;
    }

    // Other Aegis errors (quarantine, terminate)
    if (error instanceof Error) {
      console.log(`  Status:     ${color("BLOCKED", ANSI.bold, ANSI.red)}`);
      console.log(`  Reason:     ${error.message}`);
      console.log();
      return 1;
    }

    throw error;
  }
}

// ─── Info Command ───────────────────────────────────────────────────────────

/**
 * Show version, policy presets, and available attack suites.
 */
function runInfo(): number {
  console.log();
  console.log(color("  Aegis SDK", ANSI.bold, ANSI.cyan));
  console.log(`  ${"─".repeat(50)}`);
  console.log(`  Version:  ${color(VERSION, ANSI.bold)}`);
  console.log();

  console.log(color("  Available Policy Presets", ANSI.bold));
  console.log(`  ${"─".repeat(50)}`);
  for (const preset of POLICY_PRESETS) {
    console.log(`  ${color(preset, ANSI.cyan)}`);
  }
  console.log();

  console.log(color("  Available Attack Suites", ANSI.bold));
  console.log(`  ${"─".repeat(50)}`);
  for (const suite of ATTACK_SUITES) {
    const payloadCount = suite.payloads.length;
    console.log(
      `  ${color(suite.id, ANSI.cyan).padEnd(useColor ? 45 : 30)} ${color(String(payloadCount), ANSI.dim)} payloads  ${suite.name}`,
    );
  }
  console.log();

  const totalPayloads = ATTACK_SUITES.reduce((sum, s) => sum + s.payloads.length, 0);
  console.log(
    `  Total: ${color(String(ATTACK_SUITES.length), ANSI.bold)} suites, ${color(String(totalPayloads), ANSI.bold)} payloads`,
  );
  console.log();

  return 0;
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const parsed = parseArgs(process.argv);

  // Handle top-level flags
  if (parsed.flags["version"]) {
    console.log(VERSION);
    process.exit(0);
  }

  if (parsed.flags["help"] && !parsed.command) {
    console.log(HELP_TEXT);
    process.exit(0);
  }

  if (!parsed.command) {
    console.log(HELP_TEXT);
    process.exit(1);
  }

  let exitCode: number;

  switch (parsed.command) {
    case "test":
      exitCode = await runTest(parsed.flags);
      break;

    case "scan":
      exitCode = await runScan(parsed.positional, parsed.flags);
      break;

    case "info":
      exitCode = runInfo();
      break;

    default:
      console.error(color(`Error: Unknown command "${parsed.command}"`, ANSI.red));
      console.log();
      console.log(HELP_TEXT);
      exitCode = 1;
      break;
  }

  process.exit(exitCode);
}

// Run the CLI
main().catch((err: unknown) => {
  console.error(color("Fatal error:", ANSI.red), err instanceof Error ? err.message : String(err));
  process.exit(1);
});

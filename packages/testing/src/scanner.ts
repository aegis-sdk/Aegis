import type { Aegis } from "@aegis-sdk/core";
import { quarantine } from "@aegis-sdk/core";
import { ATTACK_SUITES } from "./suites/index.js";
import type { AttackPayload, AttackSuite } from "./suites/index.js";

export interface RedTeamResult {
  total: number;
  detected: number;
  missed: number;
  falseNegatives: AttackPayload[];
  detectionRate: number;
  results: Array<{
    payload: AttackPayload;
    detected: boolean;
    score: number;
    detections: number;
  }>;
}

export interface RedTeamOptions {
  /** Specific suite IDs to run. If omitted, runs all suites. */
  suites?: string[];
  /** Additional payloads to test. */
  customPayloads?: AttackPayload[];
}

/**
 * Red Team Scanner — automated testing of Aegis defenses.
 *
 * Runs attack suites against an Aegis instance and reports
 * detection rates, false negatives, and detailed results.
 *
 * @example
 * ```ts
 * const scanner = new RedTeamScanner();
 * const results = await scanner.run(aegis, {
 *   suites: ['instruction-override', 'encoding-bypass'],
 * });
 * console.log(`Detection rate: ${(results.detectionRate * 100).toFixed(1)}%`);
 * ```
 */
export class RedTeamScanner {
  /**
   * Run attack suites against an Aegis instance.
   */
  async run(aegis: Aegis, options: RedTeamOptions = {}): Promise<RedTeamResult> {
    const suites = this.getSuites(options.suites);
    const allPayloads = [
      ...suites.flatMap((s) => s.payloads),
      ...(options.customPayloads ?? []),
    ];

    const results: RedTeamResult["results"] = [];
    const falseNegatives: AttackPayload[] = [];

    for (const payload of allPayloads) {
      const quarantined = quarantine(payload.payload, { source: "user_input" });

      try {
        await aegis.guardInput(
          [{ role: "user", content: payload.payload }],
          { scanStrategy: "last-user" },
        );
        // If guardInput didn't throw, the payload was NOT detected
        results.push({ payload, detected: false, score: 0, detections: 0 });
        if (payload.expectedDetection) {
          falseNegatives.push(payload);
        }
      } catch {
        // guardInput threw — the payload WAS detected
        results.push({ payload, detected: true, score: 1, detections: 1 });
      }

      // Keep the quarantine reference to prevent unused variable warning
      void quarantined;
    }

    const detected = results.filter((r) => r.detected).length;

    return {
      total: allPayloads.length,
      detected,
      missed: allPayloads.length - detected,
      falseNegatives,
      detectionRate: allPayloads.length > 0 ? detected / allPayloads.length : 0,
      results,
    };
  }

  /**
   * Get available suite IDs.
   */
  getAvailableSuites(): string[] {
    return ATTACK_SUITES.map((s) => s.id);
  }

  private getSuites(ids?: string[]): AttackSuite[] {
    if (!ids || ids.length === 0) return ATTACK_SUITES;
    return ATTACK_SUITES.filter((s) => ids.includes(s.id));
  }
}

import { ATTACK_SUITES } from "../suites/index.js";
import type { AttackPayload } from "../suites/index.js";

/**
 * Payload Generator — generates variations of attack payloads
 * for more thorough testing.
 *
 * Applies transformations like casing changes, encoding tricks,
 * and structural variations to base payloads.
 */
export class PayloadGenerator {
  /**
   * Generate variations of a base payload.
   */
  generateVariations(payload: string): string[] {
    return [
      payload,
      payload.toUpperCase(),
      payload.toLowerCase(),
      this.addWhitespace(payload),
      this.leetSpeak(payload),
      this.reverseWords(payload),
    ];
  }

  /**
   * Get all attack payloads for a specific threat category.
   */
  getPayloadsForThreat(threatCategory: string): AttackPayload[] {
    return ATTACK_SUITES.filter((suite) => suite.threatCategories.includes(threatCategory)).flatMap(
      (suite) => suite.payloads,
    );
  }

  /**
   * Get all attack payloads across all suites.
   */
  getAllPayloads(): AttackPayload[] {
    return ATTACK_SUITES.flatMap((suite) => suite.payloads);
  }

  private addWhitespace(text: string): string {
    return text.split("").join(" ");
  }

  private leetSpeak(text: string): string {
    const map: Record<string, string> = {
      a: "4",
      e: "3",
      i: "1",
      o: "0",
      s: "5",
      t: "7",
    };
    return text
      .split("")
      .map((c) => map[c.toLowerCase()] ?? c)
      .join("");
  }

  private reverseWords(text: string): string {
    return text.split(" ").reverse().join(" ");
  }
}

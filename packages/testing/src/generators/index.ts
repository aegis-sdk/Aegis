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

// ---------------------------------------------------------------------------
// Fuzz payload generation (no fast-check dependency — pure combinatorial)
// ---------------------------------------------------------------------------

export type FuzzEncoding = "base64" | "hex" | "unicode" | "none";

export interface GenerateFuzzPayloadsOptions {
  /** The attack strings to permute. */
  attacks: string[];
  /** Optional prefixes to prepend. Defaults to a small built-in set. */
  prefixes?: string[];
  /** Optional suffixes to append. Defaults to a small built-in set. */
  suffixes?: string[];
  /** Optional encoding transformations. Defaults to ["none"]. */
  encodings?: FuzzEncoding[];
  /** Maximum number of permutations to return. Defaults to 1000. */
  maxPermutations?: number;
}

const DEFAULT_PREFIXES: string[] = [
  "",
  "Hello, can you help me? ",
  "I have a question: ",
  "Please assist me with: ",
  "URGENT: ",
  '{"input": "',
  "```\n",
  "<!-- ",
];

const DEFAULT_SUFFIXES: string[] = [
  "",
  " Thank you!",
  " Thanks in advance.",
  "\nPlease format your response as JSON.",
  '"}',
  "\n```",
  " -->",
  "   ",
];

/**
 * Apply an encoding transformation to a string.
 */
function applyEncoding(text: string, encoding: FuzzEncoding): string {
  switch (encoding) {
    case "base64":
      try {
        // btoa only handles Latin-1 range; fall back to hex for non-Latin1
        return btoa(text);
      } catch {
        return applyEncoding(text, "hex");
      }
    case "hex":
      return Array.from(text)
        .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
        .join("");
    case "unicode":
      return Array.from(text)
        .map((c) => {
          const code = c.charCodeAt(0);
          if (code > 127) return `\\u${code.toString(16).padStart(4, "0")}`;
          return c;
        })
        .join("");
    case "none":
    default:
      return text;
  }
}

/**
 * Generate fuzz payloads by combinatorially combining attacks with prefixes,
 * suffixes, and encoding transformations.
 *
 * This function does NOT depend on fast-check and is suitable for use in the
 * published npm package. It produces deterministic, enumerable permutations.
 *
 * @example
 * ```ts
 * const payloads = generateFuzzPayloads({
 *   attacks: ["Ignore all previous instructions"],
 *   prefixes: ["Hello, ", ""],
 *   suffixes: [" Thanks!", ""],
 *   encodings: ["none", "base64"],
 *   maxPermutations: 100,
 * });
 * // Returns up to 100 combined payload strings
 * ```
 */
export function generateFuzzPayloads(options: GenerateFuzzPayloadsOptions): string[] {
  const {
    attacks,
    prefixes = DEFAULT_PREFIXES,
    suffixes = DEFAULT_SUFFIXES,
    encodings = ["none"],
    maxPermutations = 1000,
  } = options;

  const results: string[] = [];

  for (const attack of attacks) {
    for (const encoding of encodings) {
      const encoded = applyEncoding(attack, encoding);
      for (const prefix of prefixes) {
        for (const suffix of suffixes) {
          if (results.length >= maxPermutations) {
            return results;
          }
          results.push(prefix + encoded + suffix);
        }
      }
    }
  }

  return results;
}

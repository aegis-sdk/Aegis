/**
 * Template-based fuzz testing with fast-check.
 *
 * Uses property-based testing to generate thousands of permutations of known
 * attack vectors combined with realistic prefixes, suffixes, and encoding
 * transformations. This validates that the scanner's detection is robust
 * against evasion attempts.
 *
 * Template: [Prefix] + [Attack Vector] + [Encoding] + [Suffix]
 */
import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { InputScanner } from "../../packages/core/src/scanner/index.js";
import { quarantine } from "../../packages/core/src/quarantine/index.js";
import {
  prefixArbitrary,
  attackArbitrary,
  suffixArbitrary,
  encodingArbitrary,
  fullPayloadArbitrary,
} from "./generators.js";

// ---------------------------------------------------------------------------
// Shared scanner instance (balanced sensitivity for fuzz testing)
// ---------------------------------------------------------------------------
const scanner = new InputScanner({ sensitivity: "balanced" });

/**
 * Helper: quarantine a string and scan it, returning the scan result.
 */
function scanPayload(payload: string) {
  const input = quarantine(payload, { source: "user_input" });
  return scanner.scan(input);
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

// Keep iterations at 100 per property to stay CI-friendly.
const FC_OPTIONS: fc.Parameters<unknown> = { numRuns: 100 };

describe("Template Fuzz Testing", () => {
  describe("detection robustness", () => {
    it("scanner detects attacks regardless of prefix", () => {
      fc.assert(
        fc.property(
          prefixArbitrary(),
          attackArbitrary(),
          (prefix, attack) => {
            const payload = prefix + attack;
            const result = scanPayload(payload);
            // Any known attack wrapped in any prefix should produce a score > 0
            expect(result.score).toBeGreaterThan(0);
          },
        ),
        FC_OPTIONS,
      );
    });

    it("scanner detects attacks regardless of suffix", () => {
      fc.assert(
        fc.property(
          attackArbitrary(),
          suffixArbitrary(),
          (attack, suffix) => {
            const payload = attack + suffix;
            const result = scanPayload(payload);
            // Any known attack wrapped in any suffix should produce a score > 0
            expect(result.score).toBeGreaterThan(0);
          },
        ),
        FC_OPTIONS,
      );
    });

    it("scanner detects attacks regardless of encoding", () => {
      fc.assert(
        fc.property(
          attackArbitrary(),
          encodingArbitrary(),
          (attack, encoding) => {
            // Only test encodings that preserve the original text structure
            // (identity, zero-width insertion, case variation).
            // Base64/hex produce completely different character sequences that
            // the scanner does not auto-decode from arbitrary input — those are
            // tested separately via the encoding normalization module.
            if (
              encoding.name === "none" ||
              encoding.name === "zero-width" ||
              encoding.name === "case-variation"
            ) {
              const payload = encoding.fn(attack);
              const result = scanPayload(payload);
              expect(result.score).toBeGreaterThan(0);
            }
            // For base64/hex/unicode: just ensure no crash (covered by the
            // "never crashes" property below).
          },
        ),
        FC_OPTIONS,
      );
    });
  });

  describe("robustness invariants", () => {
    it("scanner never crashes on random input", () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 0, maxLength: 5000 }),
          (randomInput) => {
            // The scanner should never throw, regardless of what it's given.
            expect(() => scanPayload(randomInput)).not.toThrow();
          },
        ),
        FC_OPTIONS,
      );
    });

    it("scanner score is always 0-1", () => {
      fc.assert(
        fc.property(
          fullPayloadArbitrary(),
          ({ payload }) => {
            const result = scanPayload(payload);
            expect(result.score).toBeGreaterThanOrEqual(0);
            expect(result.score).toBeLessThanOrEqual(1);
          },
        ),
        FC_OPTIONS,
      );
    });

    it("scanner is deterministic", () => {
      fc.assert(
        fc.property(
          fullPayloadArbitrary(),
          ({ payload }) => {
            const result1 = scanPayload(payload);
            const result2 = scanPayload(payload);
            expect(result1.score).toBe(result2.score);
            expect(result1.safe).toBe(result2.safe);
            expect(result1.detections.length).toBe(result2.detections.length);
            expect(result1.normalized).toBe(result2.normalized);
          },
        ),
        FC_OPTIONS,
      );
    });
  });

  describe("combined template attacks", () => {
    it("full payload template produces detectable results", () => {
      // When using identity/zero-width/case-variation encoding, the full
      // template (prefix + encoded attack + suffix) should still be detected.
      fc.assert(
        fc.property(
          fullPayloadArbitrary(),
          ({ payload, encoding }) => {
            const result = scanPayload(payload);
            // For encodings that preserve text structure, expect detection
            if (
              encoding === "none" ||
              encoding === "zero-width" ||
              encoding === "case-variation"
            ) {
              expect(result.score).toBeGreaterThan(0);
            }
            // For all encodings, score must be in valid range
            expect(result.score).toBeGreaterThanOrEqual(0);
            expect(result.score).toBeLessThanOrEqual(1);
          },
        ),
        FC_OPTIONS,
      );
    });
  });

  describe("edge cases", () => {
    it("scanner handles empty string without crashing", () => {
      const result = scanPayload("");
      expect(result.score).toBe(0);
      expect(result.safe).toBe(true);
    });

    it("scanner handles very long random input", () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 10000, maxLength: 15000 }),
          (longInput) => {
            expect(() => scanPayload(longInput)).not.toThrow();
            const result = scanPayload(longInput);
            expect(result.score).toBeGreaterThanOrEqual(0);
            expect(result.score).toBeLessThanOrEqual(1);
          },
        ),
        { numRuns: 10 }, // Fewer runs for expensive long-input tests
      );
    });

    it("scanner handles unicode-heavy input", () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 0, maxLength: 2000, unit: "grapheme" }),
          (unicodeInput) => {
            expect(() => scanPayload(unicodeInput)).not.toThrow();
            const result = scanPayload(unicodeInput);
            expect(result.score).toBeGreaterThanOrEqual(0);
            expect(result.score).toBeLessThanOrEqual(1);
          },
        ),
        FC_OPTIONS,
      );
    });
  });
});

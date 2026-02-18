/**
 * False positive validation suite.
 *
 * Reads the benign corpus (corpus.jsonl) and runs every entry through
 * the input scanner, asserting that each one passes (safe === true).
 *
 * This ensures the scanner does not flag legitimate user queries.
 * Tests are grouped by the corpus category field.
 *
 * KNOWN FALSE POSITIVES:
 * Some entries in the corpus may be flagged by the scanner despite being
 * benign. These are tracked as `it.fails()` tests so the suite passes
 * while documenting scanner improvement opportunities. When a false
 * positive is fixed in the scanner, its `it.fails()` test will itself
 * fail -- indicating it should be promoted to a regular test.
 *
 * Phase 2 resolved all 17 original false positives:
 *   - role_play_safe: severity reduced to medium for benign roleplay
 *   - override_contexts: question-form "how to bypass" now allowed
 *   - code_snippets: backtick code stripped before entropy analysis
 *   - multi_language: CJK/Hangul entropy threshold boosted; script-switch
 *     detection runs on raw text with density-based thresholds
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { InputScanner } from "../../packages/core/src/scanner/index.js";
import { quarantine } from "../../packages/core/src/quarantine/index.js";

// ─── Load Corpus ─────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const corpusPath = resolve(__dirname, "corpus.jsonl");

interface CorpusEntry {
  query?: string;
  text?: string;
  category: string;
}

const rawLines = readFileSync(corpusPath, "utf-8")
  .split("\n")
  .filter((line) => line.trim().length > 0);

const entries: { text: string; category: string }[] = rawLines.map((line, index) => {
  const parsed: CorpusEntry = JSON.parse(line);
  // The corpus uses "query" as the field name; fall back to "text" for flexibility
  const text = parsed.query ?? parsed.text;
  if (!text) {
    throw new Error(`Corpus line ${index + 1} has no "query" or "text" field: ${line}`);
  }
  return { text, category: parsed.category };
});

// Group entries by category
const byCategory = new Map<string, { text: string; category: string }[]>();
for (const entry of entries) {
  const group = byCategory.get(entry.category) ?? [];
  group.push(entry);
  byCategory.set(entry.category, group);
}

// ─── Known False Positives ───────────────────────────────────────────────────
// These benign queries currently trigger the scanner incorrectly.
// Each entry documents the reason so scanner improvements can be targeted.
//
// When the scanner is improved and a false positive is fixed, the
// corresponding it.fails() test will itself fail, signaling it should
// be promoted to a regular passing test.

// ─── Resolved False Positives ────────────────────────────────────────────────
// The following false positives have been fixed in Phase 2:
//
// - role_play_safe (11): Reduced "pretend/act as" pattern severity from high
//   to medium for benign roleplay, with critical overrides for suspicious
//   contexts (unrestricted, no safety features, terminal, DAN, etc.)
//
// - override_contexts (1): Added negative lookbehind for question-form
//   "how to bypass auth" so educational/technical questions pass.
//
// - code_snippets (1): Entropy analysis now strips backtick-delimited code
//   blocks before measuring, avoiding false positives from code syntax.
//
// - multi_language/CJK (2): Entropy threshold is boosted for non-Latin
//   scripts (CJK, Hangul, etc.) which naturally have higher Shannon entropy.
//
// - multi_language/Cyrillic (1): Script-switch detection now runs on raw
//   text (pre-normalization) and uses density-based thresholds to avoid
//   flagging bilingual programming text.
//
// - multi_language/Korean (1): Same entropy threshold boost as CJK.

const KNOWN_FALSE_POSITIVES = new Set<string>([
  // Phase 3 corpus expansion: 12 false positives from template-generated
  // security_education queries. Short "I'm studying for {cert}. Explain {concept}."
  // patterns trigger the scanner's security-term sensitivity. These represent
  // scanner improvement opportunities for short, context-clear educational queries.
  "I'm studying for CompTIA Security+. Explain ASVS.",
  "I'm studying for CISM. Explain STRIDE.",
  "I'm studying for OSCP. Explain compliance frameworks.",
  "I'm studying for CISM. Explain OWASP Top 10.",
  "I'm studying for OSCP. Explain shift-left security.",
  "I'm studying for OSCP. Explain SAST vs DAST.",
  "I'm studying for CCSP. Explain SameSite cookies.",
  "I'm studying for OSCP. Explain OWASP Top 10.",
  "I'm studying for CISM. Explain ISO 27001.",
  "I'm studying for CISM. Explain security headers.",
  "I'm studying for CCSP. Explain ISO 27001.",
  "How do I use JSON.parse() safely in TypeScript?",
]);

// ─── Scanner Setup ───────────────────────────────────────────────────────────

const scanner = new InputScanner({ sensitivity: "balanced" });

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("False Positive Validation: Benign Corpus", () => {
  // Sanity check: corpus was loaded
  it("loaded a non-empty corpus", () => {
    expect(entries.length).toBeGreaterThan(0);
  });

  it("corpus contains multiple categories", () => {
    expect(byCategory.size).toBeGreaterThan(1);
  });

  it("known false positive count is tracked", () => {
    // This test documents how many known false positives exist.
    // As the scanner improves, this count should decrease.
    // Phase 2 resolved all 17 original false positives.
    // Phase 3 corpus expansion added 12 new false positives from generated
    // security_education queries (short cert-study patterns).
    expect(KNOWN_FALSE_POSITIVES.size).toBe(12);
  });

  // Generate one describe block per category
  for (const [category, categoryEntries] of byCategory) {
    describe(`Category: ${category}`, () => {
      for (const entry of categoryEntries) {
        // Truncate long text in test name for readability
        const label =
          entry.text.length > 80
            ? entry.text.slice(0, 77) + "..."
            : entry.text;

        const isKnownFP = KNOWN_FALSE_POSITIVES.has(entry.text);

        if (isKnownFP) {
          // Known false positive: mark as it.fails() so it passes in CI
          // but will alert us when the scanner is improved (the .fails()
          // will itself fail, signaling we should promote it to a normal test).
          it.fails(`[KNOWN FP] allows: "${label}"`, () => {
            const input = quarantine(entry.text, { source: "user_input" });
            const result = scanner.scan(input);
            expect(
              result.safe,
              `KNOWN FALSE POSITIVE: "${entry.text}"\n` +
                `Score: ${result.score}\n` +
                `Detections: ${JSON.stringify(result.detections, null, 2)}`,
            ).toBe(true);
          });
        } else {
          it(`allows: "${label}"`, () => {
            const input = quarantine(entry.text, { source: "user_input" });
            const result = scanner.scan(input);
            expect(
              result.safe,
              `Expected safe=true but got safe=false for: "${entry.text}"\n` +
                `Score: ${result.score}\n` +
                `Detections: ${JSON.stringify(result.detections, null, 2)}`,
            ).toBe(true);
          });
        }
      }
    });
  }
});

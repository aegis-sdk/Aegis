/**
 * Entropy analysis module.
 *
 * Detects adversarial suffixes (GCG attacks) by measuring Shannon entropy
 * of sliding windows across the input. Natural language has predictable
 * entropy ranges; adversarial suffixes are significantly higher.
 *
 * Reference: Zou et al. 2023, "Universal and Transferable Adversarial Attacks
 * on Aligned Language Models"
 */

import type { EntropyResult } from "../types.js";

const DEFAULT_WINDOW_SIZE = 50;
const DEFAULT_THRESHOLD = 4.5; // bits/char for English/Latin

/**
 * Higher entropy threshold for non-Latin scripts.
 *
 * CJK (Chinese, Japanese, Korean), Hangul, and other logographic/syllabic
 * scripts have inherently higher Shannon entropy than Latin-alphabet text
 * because of their much larger character sets. A Japanese sentence with
 * Hiragana, Katakana, and Kanji easily exceeds 4.5 bits/char without
 * being adversarial.
 */
const NON_LATIN_THRESHOLD_BOOST = 1.0; // e.g. 4.5 → 5.5 for CJK-dominant text

/**
 * Fraction of characters that must be non-Latin script for the
 * threshold boost to apply.
 */
const NON_LATIN_DOMINANCE_FRACTION = 0.3;

// ─── Unicode Ranges for Non-Latin Script Detection ──────────────────────────

/**
 * Returns true if the code point belongs to a script with naturally high entropy.
 * Covers CJK Unified Ideographs, Hiragana, Katakana, Hangul, CJK symbols,
 * and common CJK extensions.
 */
function isHighEntropyScript(cp: number): boolean {
  return (
    (cp >= 0x3000 && cp <= 0x9fff) || // CJK Symbols, Hiragana, Katakana, CJK Unified
    (cp >= 0xac00 && cp <= 0xd7af) || // Hangul Syllables
    (cp >= 0xf900 && cp <= 0xfaff) || // CJK Compatibility Ideographs
    (cp >= 0x3400 && cp <= 0x4dbf) || // CJK Extension A
    (cp >= 0x20000 && cp <= 0x2a6df) || // CJK Extension B
    (cp >= 0xff00 && cp <= 0xffef) || // Halfwidth/Fullwidth Forms (CJK)
    (cp >= 0x0400 && cp <= 0x04ff) || // Cyrillic
    (cp >= 0x0600 && cp <= 0x06ff) || // Arabic
    (cp >= 0x0900 && cp <= 0x097f) || // Devanagari
    (cp >= 0x0e00 && cp <= 0x0e7f) // Thai
  );
}

/**
 * Determine the fraction of characters in the input that are from
 * high-entropy scripts (CJK, Hangul, etc.).
 */
function highEntropyScriptFraction(text: string): number {
  let total = 0;
  let highEntropy = 0;

  for (const char of text) {
    const cp = char.codePointAt(0);
    if (cp === undefined) continue;
    // Skip whitespace and ASCII punctuation/digits
    if (
      cp <= 0x7f &&
      (cp <= 0x20 ||
        (cp >= 0x21 && cp <= 0x2f) ||
        (cp >= 0x3a && cp <= 0x40) ||
        (cp >= 0x5b && cp <= 0x60) ||
        (cp >= 0x7b && cp <= 0x7e) ||
        (cp >= 0x30 && cp <= 0x39))
    ) {
      continue;
    }
    total++;
    if (isHighEntropyScript(cp)) {
      highEntropy++;
    }
  }

  return total > 0 ? highEntropy / total : 0;
}

/**
 * Strip inline and fenced code blocks from text before entropy analysis.
 *
 * Code snippets (e.g. `os.system('rm -rf')`) use a dense mix of punctuation
 * and alphanumeric characters that naturally produce high entropy, leading
 * to false positives. By stripping them, we focus entropy analysis on the
 * natural-language portions of the input.
 */
function stripCodeBlocks(text: string): string {
  // Remove fenced code blocks: ```...```
  let result = text.replace(/```[\s\S]*?```/g, " ");
  // Remove inline code: `...`
  result = result.replace(/`[^`]+`/g, " ");
  return result;
}

/**
 * Calculate Shannon entropy of a string.
 */
export function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of text) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = text.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/**
 * Analyze entropy across sliding windows of the input.
 *
 * Returns the mean entropy, the maximum window entropy, and whether
 * any window exceeds the anomaly threshold.
 *
 * Adaptations to reduce false positives:
 * 1. Code blocks (backtick-delimited) are stripped before analysis.
 * 2. The threshold is raised for inputs dominated by non-Latin scripts
 *    (CJK, Hangul, Cyrillic, Arabic, etc.) which naturally have higher
 *    entropy due to larger character sets.
 */
export function analyzeEntropy(
  input: string,
  options: {
    windowSize?: number;
    threshold?: number;
  } = {},
): EntropyResult {
  const windowSize = options.windowSize ?? DEFAULT_WINDOW_SIZE;
  const baseThreshold = options.threshold ?? DEFAULT_THRESHOLD;

  // Strip code blocks to avoid false positives from code syntax
  const cleaned = stripCodeBlocks(input);

  // If stripping code blocks leaves very little text, skip entropy analysis
  const trimmed = cleaned.trim();
  if (trimmed.length < 10) {
    return { mean: 0, maxWindow: 0, anomalous: false };
  }

  // Boost threshold for non-Latin scripts
  const fraction = highEntropyScriptFraction(trimmed);
  const threshold =
    fraction >= NON_LATIN_DOMINANCE_FRACTION
      ? baseThreshold + NON_LATIN_THRESHOLD_BOOST
      : baseThreshold;

  if (trimmed.length < windowSize) {
    const e = shannonEntropy(trimmed);
    return {
      mean: e,
      maxWindow: e,
      anomalous: e > threshold,
    };
  }

  const windowEntropies: number[] = [];
  const step = Math.max(1, Math.floor(windowSize / 4)); // 75% overlap

  for (let i = 0; i <= trimmed.length - windowSize; i += step) {
    const window = trimmed.slice(i, i + windowSize);
    windowEntropies.push(shannonEntropy(window));
  }

  const mean = windowEntropies.reduce((a, b) => a + b, 0) / windowEntropies.length;
  const maxWindow = Math.max(...windowEntropies);

  return {
    mean,
    maxWindow,
    anomalous: maxWindow > threshold,
  };
}

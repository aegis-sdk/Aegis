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
const DEFAULT_THRESHOLD = 4.5; // bits/char for English

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
 */
export function analyzeEntropy(
  input: string,
  options: {
    windowSize?: number;
    threshold?: number;
  } = {},
): EntropyResult {
  const windowSize = options.windowSize ?? DEFAULT_WINDOW_SIZE;
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;

  if (input.length < windowSize) {
    const e = shannonEntropy(input);
    return {
      mean: e,
      maxWindow: e,
      anomalous: e > threshold,
    };
  }

  const windowEntropies: number[] = [];
  const step = Math.max(1, Math.floor(windowSize / 4)); // 75% overlap

  for (let i = 0; i <= input.length - windowSize; i += step) {
    const window = input.slice(i, i + windowSize);
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

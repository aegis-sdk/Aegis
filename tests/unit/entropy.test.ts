import { describe, it, expect } from "vitest";
import { shannonEntropy, analyzeEntropy } from "../../packages/core/src/scanner/entropy.js";

describe("shannonEntropy()", () => {
  it("returns 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for single repeated character", () => {
    expect(shannonEntropy("aaaaaaa")).toBe(0);
  });

  it("returns 1 for two equally distributed characters", () => {
    const entropy = shannonEntropy("ababababab");
    expect(entropy).toBeCloseTo(1, 1);
  });

  it("returns higher entropy for more diverse characters", () => {
    const lowEntropy = shannonEntropy("aaabbb");
    const highEntropy = shannonEntropy("abcdef");
    expect(highEntropy).toBeGreaterThan(lowEntropy);
  });

  it("natural language has moderate entropy", () => {
    const entropy = shannonEntropy("The quick brown fox jumps over the lazy dog.");
    // Natural English typically has entropy between 3-4.5 bits/char
    expect(entropy).toBeGreaterThan(2);
    expect(entropy).toBeLessThan(5);
  });
});

describe("analyzeEntropy()", () => {
  it("detects normal text as non-anomalous", () => {
    const result = analyzeEntropy(
      "Hello, I have a question about my order. Can you help me check the status?",
    );
    expect(result.anomalous).toBe(false);
  });

  it("detects high-entropy adversarial suffixes as anomalous", () => {
    // Simulated GCG-style adversarial suffix (random-looking tokens)
    const normalText = "What is the weather today? ";
    const adversarialSuffix = "Xj7#mK9@pQ2!wR5$tY8&uI0^oP3*lA6(sD4)fG1hJ";
    const result = analyzeEntropy(normalText + adversarialSuffix, {
      threshold: 4.5,
    });
    expect(result.maxWindow).toBeGreaterThan(4.5);
    expect(result.anomalous).toBe(true);
  });

  it("handles short input correctly", () => {
    const result = analyzeEntropy("hi", { windowSize: 50 });
    expect(result.mean).toBeGreaterThanOrEqual(0);
  });
});

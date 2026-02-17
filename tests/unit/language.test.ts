/**
 * Unit tests for the language/script detection module.
 *
 * Validates that detectLanguageSwitches() correctly classifies Unicode
 * code points into scripts, tracks script switches, identifies the
 * primary script, and ignores script-neutral characters.
 */
import { describe, it, expect } from "vitest";
import { detectLanguageSwitches } from "../../packages/core/src/scanner/language.js";

// ─── Empty Input ─────────────────────────────────────────────────────────────

describe("Language Detection: Empty and Minimal Input", () => {
  it("returns 'unknown' for an empty string", () => {
    const result = detectLanguageSwitches("");
    expect(result.primary).toBe("unknown");
    expect(result.switches).toHaveLength(0);
  });

  it("returns 'unknown' for whitespace-only input", () => {
    const result = detectLanguageSwitches("   \t\n  ");
    expect(result.primary).toBe("unknown");
    expect(result.switches).toHaveLength(0);
  });

  it("returns 'unknown' for digits-only input", () => {
    const result = detectLanguageSwitches("1234567890");
    expect(result.primary).toBe("unknown");
    expect(result.switches).toHaveLength(0);
  });

  it("returns 'unknown' for punctuation-only input", () => {
    const result = detectLanguageSwitches("!@#$%^&*().,;:");
    expect(result.primary).toBe("unknown");
    expect(result.switches).toHaveLength(0);
  });
});

// ─── Pure Script Detection ───────────────────────────────────────────────────

describe("Language Detection: Pure Latin Text", () => {
  it("detects pure Latin text as primary script", () => {
    const result = detectLanguageSwitches("Hello world, this is a test.");
    expect(result.primary).toBe("Latin");
    expect(result.switches).toHaveLength(0);
  });

  it("detects Latin Extended characters", () => {
    const result = detectLanguageSwitches("caf\u00E9 r\u00E9sum\u00E9 na\u00EFve");
    expect(result.primary).toBe("Latin");
    expect(result.switches).toHaveLength(0);
  });
});

describe("Language Detection: Pure Cyrillic Text", () => {
  it("detects pure Cyrillic text as primary script", () => {
    const result = detectLanguageSwitches("\u041F\u0440\u0438\u0432\u0435\u0442 \u043C\u0438\u0440");
    expect(result.primary).toBe("Cyrillic");
    expect(result.switches).toHaveLength(0);
  });

  it("detects longer Cyrillic text correctly", () => {
    const result = detectLanguageSwitches(
      "\u042D\u0442\u043E \u0442\u0435\u0441\u0442\u043E\u0432\u043E\u0435 \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u0435 \u043D\u0430 \u0440\u0443\u0441\u0441\u043A\u043E\u043C \u044F\u0437\u044B\u043A\u0435",
    );
    expect(result.primary).toBe("Cyrillic");
    expect(result.switches).toHaveLength(0);
  });
});

describe("Language Detection: CJK Text", () => {
  it("detects CJK Unified Ideographs (Chinese)", () => {
    const result = detectLanguageSwitches("\u4F60\u597D\u4E16\u754C");
    expect(result.primary).toBe("CJK");
    expect(result.switches).toHaveLength(0);
  });

  it("detects Hiragana (Japanese)", () => {
    const result = detectLanguageSwitches("\u3053\u3093\u306B\u3061\u306F");
    expect(result.primary).toBe("CJK");
    expect(result.switches).toHaveLength(0);
  });

  it("detects Katakana (Japanese)", () => {
    const result = detectLanguageSwitches("\u30AB\u30BF\u30AB\u30CA");
    expect(result.primary).toBe("CJK");
    expect(result.switches).toHaveLength(0);
  });

  it("detects Hangul (Korean)", () => {
    const result = detectLanguageSwitches("\uC548\uB155\uD558\uC138\uC694");
    expect(result.primary).toBe("CJK");
    expect(result.switches).toHaveLength(0);
  });
});

describe("Language Detection: Other Scripts", () => {
  it("detects Arabic text", () => {
    const result = detectLanguageSwitches("\u0645\u0631\u062D\u0628\u0627 \u0628\u0627\u0644\u0639\u0627\u0644\u0645");
    expect(result.primary).toBe("Arabic");
    expect(result.switches).toHaveLength(0);
  });

  it("detects Greek text", () => {
    const result = detectLanguageSwitches("\u0393\u03B5\u03B9\u03B1 \u03C3\u03BF\u03C5 \u03BA\u03CC\u03C3\u03BC\u03B5");
    expect(result.primary).toBe("Greek");
    expect(result.switches).toHaveLength(0);
  });

  it("detects Devanagari text", () => {
    const result = detectLanguageSwitches("\u0928\u092E\u0938\u094D\u0924\u0947 \u0926\u0941\u0928\u093F\u092F\u093E");
    expect(result.primary).toBe("Devanagari");
    expect(result.switches).toHaveLength(0);
  });

  it("detects Thai text", () => {
    const result = detectLanguageSwitches("\u0E2A\u0E27\u0E31\u0E2A\u0E14\u0E35");
    expect(result.primary).toBe("Thai");
    expect(result.switches).toHaveLength(0);
  });
});

// ─── Script-Neutral Characters ───────────────────────────────────────────────

describe("Language Detection: Script-Neutral Characters", () => {
  it("digits mixed with Latin do not trigger switches", () => {
    const result = detectLanguageSwitches("hello 123 world");
    expect(result.primary).toBe("Latin");
    expect(result.switches).toHaveLength(0);
  });

  it("punctuation mixed with Cyrillic does not trigger switches", () => {
    const result = detectLanguageSwitches("\u041F\u0440\u0438\u0432\u0435\u0442, \u043C\u0438\u0440! 123.");
    expect(result.primary).toBe("Cyrillic");
    expect(result.switches).toHaveLength(0);
  });

  it("emoji-like symbols and special punctuation are neutral", () => {
    // General punctuation block (U+2000-U+206F) is neutral
    const result = detectLanguageSwitches("Hello\u2014world");
    expect(result.primary).toBe("Latin");
    expect(result.switches).toHaveLength(0);
  });
});

// ─── Script Switching Detection ──────────────────────────────────────────────

describe("Language Detection: Mixed Scripts with Switches", () => {
  it("detects a single switch from Latin to Cyrillic", () => {
    const result = detectLanguageSwitches("Hello \u041C\u0438\u0440");
    expect(result.switches).toHaveLength(1);
    expect(result.switches[0]!.from).toBe("Latin");
    expect(result.switches[0]!.to).toBe("Cyrillic");
  });

  it("detects a single switch from Latin to CJK", () => {
    const result = detectLanguageSwitches("Hello \u4F60\u597D");
    expect(result.switches).toHaveLength(1);
    expect(result.switches[0]!.from).toBe("Latin");
    expect(result.switches[0]!.to).toBe("CJK");
  });

  it("detects multiple switches in Latin-Cyrillic-Latin text", () => {
    const result = detectLanguageSwitches("Hello \u041C\u0438\u0440 World");
    expect(result.switches).toHaveLength(2);
    expect(result.switches[0]!.from).toBe("Latin");
    expect(result.switches[0]!.to).toBe("Cyrillic");
    expect(result.switches[1]!.from).toBe("Cyrillic");
    expect(result.switches[1]!.to).toBe("Latin");
  });

  it("tracks multiple script switches correctly", () => {
    // Latin -> Cyrillic -> Latin -> CJK
    const result = detectLanguageSwitches("Hello \u041F\u0440\u0438\u0432\u0435\u0442 World \u4F60\u597D");
    expect(result.switches).toHaveLength(3);
    expect(result.switches[0]!.from).toBe("Latin");
    expect(result.switches[0]!.to).toBe("Cyrillic");
    expect(result.switches[1]!.from).toBe("Cyrillic");
    expect(result.switches[1]!.to).toBe("Latin");
    expect(result.switches[2]!.from).toBe("Latin");
    expect(result.switches[2]!.to).toBe("CJK");
  });

  it("detects switches across many scripts", () => {
    // Latin -> Arabic -> Latin -> Cyrillic -> Latin
    const result = detectLanguageSwitches("Hello \u0645\u0631\u062D\u0628\u0627 World \u041F\u0440\u0438\u0432\u0435\u0442 Bye");
    expect(result.switches).toHaveLength(4);
    expect(result.switches[0]!.from).toBe("Latin");
    expect(result.switches[0]!.to).toBe("Arabic");
    expect(result.switches[1]!.from).toBe("Arabic");
    expect(result.switches[1]!.to).toBe("Latin");
    expect(result.switches[2]!.from).toBe("Latin");
    expect(result.switches[2]!.to).toBe("Cyrillic");
    expect(result.switches[3]!.from).toBe("Cyrillic");
    expect(result.switches[3]!.to).toBe("Latin");
  });
});

// ─── Primary Script Determination ────────────────────────────────────────────

describe("Language Detection: Primary Script Determination", () => {
  it("primary is the most frequent script even when switches occur", () => {
    // Mostly Latin with a few Cyrillic chars
    const result = detectLanguageSwitches("Hello World this is a test \u041C\u0438\u0440");
    expect(result.primary).toBe("Latin");
  });

  it("primary is Cyrillic when it dominates", () => {
    // Mostly Cyrillic with one Latin word
    const result = detectLanguageSwitches("\u042D\u0442\u043E \u0442\u0435\u0441\u0442\u043E\u0432\u043E\u0435 \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u0435 Hello");
    expect(result.primary).toBe("Cyrillic");
  });
});

// ─── Position Tracking ───────────────────────────────────────────────────────

describe("Language Detection: Position Tracking", () => {
  it("records the correct character position of a switch", () => {
    // "Hi " is 3 chars (H=0, i=1, space=2), then Cyrillic starts at 3
    const result = detectLanguageSwitches("Hi \u041C\u0438\u0440");
    expect(result.switches).toHaveLength(1);
    expect(result.switches[0]!.position).toBe(3);
  });

  it("records positions for multiple switches accurately", () => {
    // "AB " = 3 chars, then "\u041C\u0438" at 3..4, then " " at 5, then "CD" at 6
    const result = detectLanguageSwitches("AB \u041C\u0438 CD");
    expect(result.switches).toHaveLength(2);
    // First switch: Latin -> Cyrillic at position 3
    expect(result.switches[0]!.position).toBe(3);
    // Second switch: Cyrillic -> Latin at position 6
    expect(result.switches[1]!.position).toBe(6);
  });

  it("handles surrogate pairs (CJK Extension B) in position tracking", () => {
    // U+20000 is a surrogate pair (2 UTF-16 code units) in CJK Extension B
    const cjkExtB = String.fromCodePoint(0x20000);
    const result = detectLanguageSwitches("Hi " + cjkExtB);
    expect(result.switches).toHaveLength(1);
    expect(result.switches[0]!.from).toBe("Latin");
    expect(result.switches[0]!.to).toBe("CJK");
    expect(result.switches[0]!.position).toBe(3);
  });
});

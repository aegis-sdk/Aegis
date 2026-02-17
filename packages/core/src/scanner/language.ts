/**
 * Language/script detection module.
 *
 * Detects Unicode script switches in text to identify language-switching
 * attacks (T18). Attackers embed instructions in different scripts
 * (e.g., Cyrillic, Arabic, CJK) to evade pattern-matching defenses
 * that only target Latin-script prompts.
 *
 * This module performs script-level detection using Unicode character
 * ranges -- not full NLP language identification. Script detection is
 * sufficient to flag suspicious polyglot content.
 */

import type { LanguageResult, LanguageSwitch } from "../types.js";

// ─── Unicode Script Ranges ──────────────────────────────────────────────────

interface ScriptRange {
  name: string;
  ranges: [number, number][];
}

/**
 * Common Unicode script ranges for detection.
 *
 * Each entry maps a script name to one or more inclusive [start, end]
 * code-point ranges. We cover the scripts most commonly seen in
 * language-switching attacks plus several major world scripts.
 */
const SCRIPT_RANGES: ScriptRange[] = [
  {
    name: "Latin",
    ranges: [
      [0x0041, 0x005a], // Basic Latin uppercase
      [0x0061, 0x007a], // Basic Latin lowercase
      [0x00c0, 0x00ff], // Latin-1 Supplement (accented chars)
      [0x0100, 0x024f], // Latin Extended-A & B
      [0x1e00, 0x1eff], // Latin Extended Additional
    ],
  },
  {
    name: "Cyrillic",
    ranges: [
      [0x0400, 0x04ff], // Cyrillic
      [0x0500, 0x052f], // Cyrillic Supplement
    ],
  },
  {
    name: "Arabic",
    ranges: [
      [0x0600, 0x06ff], // Arabic
      [0x0750, 0x077f], // Arabic Supplement
      [0x08a0, 0x08ff], // Arabic Extended-A
      [0xfb50, 0xfdff], // Arabic Presentation Forms-A
      [0xfe70, 0xfeff], // Arabic Presentation Forms-B
    ],
  },
  {
    name: "Hebrew",
    ranges: [
      [0x0590, 0x05ff], // Hebrew
      [0xfb1d, 0xfb4f], // Hebrew Presentation Forms
    ],
  },
  {
    name: "Devanagari",
    ranges: [
      [0x0900, 0x097f], // Devanagari
      [0xa8e0, 0xa8ff], // Devanagari Extended
    ],
  },
  {
    name: "Thai",
    ranges: [
      [0x0e00, 0x0e7f], // Thai
    ],
  },
  {
    name: "CJK",
    ranges: [
      [0x4e00, 0x9fff], // CJK Unified Ideographs
      [0x3400, 0x4dbf], // CJK Unified Ideographs Extension A
      [0x3040, 0x309f], // Hiragana
      [0x30a0, 0x30ff], // Katakana
      [0xac00, 0xd7af], // Hangul Syllables
      [0x3000, 0x303f], // CJK Symbols and Punctuation
      [0xf900, 0xfaff], // CJK Compatibility Ideographs
      [0x20000, 0x2a6df], // CJK Extension B
    ],
  },
  {
    name: "Greek",
    ranges: [
      [0x0370, 0x03ff], // Greek and Coptic
      [0x1f00, 0x1fff], // Greek Extended
    ],
  },
  {
    name: "Georgian",
    ranges: [
      [0x10a0, 0x10ff], // Georgian
      [0x2d00, 0x2d2f], // Georgian Supplement
    ],
  },
  {
    name: "Armenian",
    ranges: [
      [0x0530, 0x058f], // Armenian
    ],
  },
  {
    name: "Bengali",
    ranges: [
      [0x0980, 0x09ff], // Bengali
    ],
  },
  {
    name: "Tamil",
    ranges: [
      [0x0b80, 0x0bff], // Tamil
    ],
  },
];

// ─── Script Classification ──────────────────────────────────────────────────

/**
 * Classify a single Unicode code point into its script name.
 *
 * Returns `null` for script-neutral characters: whitespace, ASCII
 * punctuation, digits, and common Unicode symbols/punctuation.
 */
function classifyCodePoint(cp: number): string | null {
  // Skip script-neutral characters
  // ASCII digits
  if (cp >= 0x30 && cp <= 0x39) return null;
  // ASCII whitespace and control
  if (cp <= 0x20) return null;
  // ASCII punctuation ranges
  if (cp >= 0x21 && cp <= 0x2f) return null;
  if (cp >= 0x3a && cp <= 0x40) return null;
  if (cp >= 0x5b && cp <= 0x60) return null;
  if (cp >= 0x7b && cp <= 0x7e) return null;
  // General punctuation block
  if (cp >= 0x2000 && cp <= 0x206f) return null;
  // Common symbols
  if (cp >= 0x2100 && cp <= 0x214f) return null;
  // Supplemental punctuation
  if (cp >= 0x2e00 && cp <= 0x2e7f) return null;
  // Modifier symbols and diacritical marks
  if (cp >= 0x02b0 && cp <= 0x02ff) return null;
  if (cp >= 0x0300 && cp <= 0x036f) return null;

  for (const script of SCRIPT_RANGES) {
    for (const [start, end] of script.ranges) {
      if (cp >= start && cp <= end) {
        return script.name;
      }
    }
  }

  return null;
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Detect script/language switches in a text string.
 *
 * Walks through the text character by character, classifying each
 * code point into a Unicode script. Script-neutral characters (spaces,
 * punctuation, digits) are ignored -- they do not trigger or reset
 * script tracking.
 *
 * Returns:
 * - `primary`: the most frequently occurring script in the text
 * - `switches`: an array of positions where the script changes,
 *   recording the `from` script, the `to` script, and the character
 *   `position` in the original string
 *
 * @example
 * ```ts
 * const result = detectLanguageSwitches("Hello Мир");
 * // result.primary === "Latin"
 * // result.switches === [{ from: "Latin", to: "Cyrillic", position: 6 }]
 * ```
 */
export function detectLanguageSwitches(text: string): LanguageResult {
  if (text.length === 0) {
    return { primary: "unknown", switches: [] };
  }

  const switches: LanguageSwitch[] = [];
  const scriptCounts = new Map<string, number>();
  let currentScript: string | null = null;

  // Iterate by code point to handle surrogate pairs (e.g., CJK Extension B)
  let charIndex = 0;
  for (const char of text) {
    const cp = char.codePointAt(0);
    if (cp === undefined) {
      charIndex += char.length;
      continue;
    }

    const script = classifyCodePoint(cp);

    if (script !== null) {
      // Tally script frequency
      scriptCounts.set(script, (scriptCounts.get(script) ?? 0) + 1);

      // Record switches between distinct scripts
      if (currentScript !== null && script !== currentScript) {
        switches.push({
          from: currentScript,
          to: script,
          position: charIndex,
        });
      }

      currentScript = script;
    }

    charIndex += char.length;
  }

  // Determine the dominant script
  let primary = "unknown";
  let maxCount = 0;
  for (const [script, count] of scriptCounts) {
    if (count > maxCount) {
      maxCount = count;
      primary = script;
    }
  }

  return { primary, switches };
}

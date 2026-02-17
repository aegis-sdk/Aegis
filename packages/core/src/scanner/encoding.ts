/**
 * Encoding normalization module.
 *
 * Normalizes various encoding tricks used to obfuscate prompt injections:
 * - Unicode homoglyphs → ASCII equivalents
 * - HTML entities → plain text
 * - Base64-encoded segments → decoded text
 * - Zero-width characters → removed
 * - ROT13 detection (heuristic, not auto-decoded)
 */

// Common Unicode homoglyphs that map to ASCII characters
const HOMOGLYPH_MAP: Record<string, string> = {
  "\u0410": "A", // Cyrillic А
  "\u0412": "B", // Cyrillic В
  "\u0421": "C", // Cyrillic С
  "\u0415": "E", // Cyrillic Е
  "\u041D": "H", // Cyrillic Н
  "\u041A": "K", // Cyrillic К
  "\u041C": "M", // Cyrillic М
  "\u041E": "O", // Cyrillic О
  "\u0420": "P", // Cyrillic Р
  "\u0422": "T", // Cyrillic Т
  "\u0425": "X", // Cyrillic Х
  "\u0430": "a", // Cyrillic а
  "\u0435": "e", // Cyrillic е
  "\u043E": "o", // Cyrillic о
  "\u0440": "p", // Cyrillic р
  "\u0441": "c", // Cyrillic с
  "\u0443": "y", // Cyrillic у
  "\u0445": "x", // Cyrillic х
  "\uFF21": "A", // Fullwidth A
  "\uFF22": "B", // Fullwidth B
  "\uFF23": "C", // Fullwidth C
  "\u2019": "'", // Right single quotation mark
  "\u2018": "'", // Left single quotation mark
  "\u201C": '"', // Left double quotation mark
  "\u201D": '"', // Right double quotation mark
};

// Zero-width and invisible characters to strip
const INVISIBLE_CHARS = /[\u200B-\u200F\u2028-\u202F\uFEFF\u00AD\u2060\u180E]/g;

/**
 * Normalize a string by resolving encoding obfuscation.
 */
export function normalizeEncoding(input: string): string {
  let result = input;

  // 1. Remove invisible characters
  result = result.replace(INVISIBLE_CHARS, "");

  // 2. Normalize Unicode homoglyphs
  result = replaceHomoglyphs(result);

  // 3. Decode HTML entities
  result = decodeHtmlEntities(result);

  // 4. Normalize Unicode NFC form
  result = result.normalize("NFC");

  return result;
}

function replaceHomoglyphs(input: string): string {
  let result = "";
  for (const char of input) {
    result += HOMOGLYPH_MAP[char] ?? char;
  }
  return result;
}

function decodeHtmlEntities(input: string): string {
  return input
    .replace(/&#x([0-9a-fA-F]+);/g, (_match, hex: string) => {
      const codePoint = parseInt(hex, 16);
      return String.fromCodePoint(codePoint);
    })
    .replace(/&#(\d+);/g, (_match, dec: string) => {
      const codePoint = parseInt(dec, 10);
      return String.fromCodePoint(codePoint);
    })
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

/**
 * Detect if a segment might be Base64-encoded text.
 * Returns decoded text if it looks like valid Base64, otherwise null.
 */
export function tryDecodeBase64(segment: string): string | null {
  // Must be at least 16 chars and look like Base64
  if (segment.length < 16) return null;
  if (!/^[A-Za-z0-9+/]+=?=?$/.test(segment.trim())) return null;

  try {
    const decoded = atob(segment.trim());
    // Check if decoded text is mostly printable ASCII
    const printableRatio =
      [...decoded].filter((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126).length /
      decoded.length;
    if (printableRatio > 0.8) {
      return decoded;
    }
  } catch {
    // Not valid Base64
  }
  return null;
}

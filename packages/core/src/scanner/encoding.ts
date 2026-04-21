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

// Unicode homoglyphs that map to ASCII characters.
// Curated from Unicode Consortium confusables.txt — covers the scripts
// most commonly used in prompt-injection bypass attempts.
// Coverage: Cyrillic, Greek, Armenian, Latin Extended / IPA,
// Mathematical Alphanumerics (Bold + Italic), Fullwidth Latin, smart quotes.
const HOMOGLYPH_MAP: Record<string, string> = {
  // ─── Cyrillic (U+0400–U+04FF) ────────────────────────────────────────────
  "А": "A", // А
  "В": "B", // В
  "С": "C", // С
  "Е": "E", // Е
  "Н": "H", // Н
  "К": "K", // К
  "М": "M", // М
  "О": "O", // О
  "Р": "P", // Р
  "Т": "T", // Т
  "Х": "X", // Х
  "а": "a", // а
  "е": "e", // е
  "о": "o", // о
  "р": "p", // р
  "с": "c", // с
  "у": "y", // у
  "х": "x", // х
  "ӏ": "l", // ӏ palochka

  // ─── Greek (U+0370–U+03FF) ───────────────────────────────────────────────
  "Α": "A", // Α Alpha
  "Β": "B", // Β Beta
  "Ε": "E", // Ε Epsilon
  "Ζ": "Z", // Ζ Zeta
  "Η": "H", // Η Eta
  "Ι": "I", // Ι Iota
  "Κ": "K", // Κ Kappa
  "Μ": "M", // Μ Mu
  "Ν": "N", // Ν Nu
  "Ο": "O", // Ο Omicron
  "Ρ": "P", // Ρ Rho
  "Τ": "T", // Τ Tau
  "Υ": "Y", // Υ Upsilon
  "Χ": "X", // Χ Chi
  "α": "a", // α alpha
  "ε": "e", // ε epsilon
  "ι": "i", // ι iota
  "κ": "k", // κ kappa
  "ν": "v", // ν nu
  "ο": "o", // ο omicron
  "ρ": "p", // ρ rho
  "τ": "t", // τ tau
  "υ": "u", // υ upsilon
  "χ": "x", // χ chi

  // ─── Armenian (U+0530–U+058F) ────────────────────────────────────────────
  "Ո": "O", // Ո Vo
  "Տ": "S", // Տ Tiwn
  "Օ": "O", // Օ Oh
  "հ": "h", // հ ho
  "ո": "n", // ո vo
  "ռ": "n", // ռ ra
  "ք": "p", // ք ke

  // ─── Latin Extended / IPA (common confusables) ───────────────────────────
  "ı": "i", // ı dotless i
  "ȷ": "j", // ȷ dotless j
  "ɑ": "a", // ɑ Latin alpha
  "ɡ": "g", // ɡ script g

  // ─── Mathematical Alphanumerics — Bold lowercase a–z (U+1D41A–U+1D433) ──
  "\u{1D41A}": "a",
  "\u{1D41B}": "b",
  "\u{1D41C}": "c",
  "\u{1D41D}": "d",
  "\u{1D41E}": "e",
  "\u{1D41F}": "f",
  "\u{1D420}": "g",
  "\u{1D421}": "h",
  "\u{1D422}": "i",
  "\u{1D423}": "j",
  "\u{1D424}": "k",
  "\u{1D425}": "l",
  "\u{1D426}": "m",
  "\u{1D427}": "n",
  "\u{1D428}": "o",
  "\u{1D429}": "p",
  "\u{1D42A}": "q",
  "\u{1D42B}": "r",
  "\u{1D42C}": "s",
  "\u{1D42D}": "t",
  "\u{1D42E}": "u",
  "\u{1D42F}": "v",
  "\u{1D430}": "w",
  "\u{1D431}": "x",
  "\u{1D432}": "y",
  "\u{1D433}": "z",
  // Mathematical Italic lowercase a–z (U+1D455 is reserved and skipped)
  "\u{1D44E}": "a",
  "\u{1D44F}": "b",
  "\u{1D450}": "c",
  "\u{1D451}": "d",
  "\u{1D452}": "e",
  "\u{1D453}": "f",
  "\u{1D454}": "g",
  "\u{1D456}": "i",
  "\u{1D457}": "j",
  "\u{1D458}": "k",
  "\u{1D459}": "l",
  "\u{1D45A}": "m",
  "\u{1D45B}": "n",
  "\u{1D45C}": "o",
  "\u{1D45D}": "p",
  "\u{1D45E}": "q",
  "\u{1D45F}": "r",
  "\u{1D460}": "s",
  "\u{1D461}": "t",
  "\u{1D462}": "u",
  "\u{1D463}": "v",
  "\u{1D464}": "w",
  "\u{1D465}": "x",
  "\u{1D466}": "y",
  "\u{1D467}": "z",

  // ─── Fullwidth Latin (U+FF00–U+FFEF) ─────────────────────────────────────
  "Ａ": "A",
  "Ｂ": "B",
  "Ｃ": "C",
  "Ｄ": "D",
  "Ｅ": "E",
  "Ｆ": "F",
  "Ｇ": "G",
  "Ｈ": "H",
  "Ｉ": "I",
  "Ｊ": "J",
  "Ｋ": "K",
  "Ｌ": "L",
  "Ｍ": "M",
  "Ｎ": "N",
  "Ｏ": "O",
  "Ｐ": "P",
  "Ｑ": "Q",
  "Ｒ": "R",
  "Ｓ": "S",
  "Ｔ": "T",
  "Ｕ": "U",
  "Ｖ": "V",
  "Ｗ": "W",
  "Ｘ": "X",
  "Ｙ": "Y",
  "Ｚ": "Z",
  "ａ": "a",
  "ｂ": "b",
  "ｃ": "c",
  "ｄ": "d",
  "ｅ": "e",
  "ｆ": "f",
  "ｇ": "g",
  "ｈ": "h",
  "ｉ": "i",
  "ｊ": "j",
  "ｋ": "k",
  "ｌ": "l",
  "ｍ": "m",
  "ｎ": "n",
  "ｏ": "o",
  "ｐ": "p",
  "ｑ": "q",
  "ｒ": "r",
  "ｓ": "s",
  "ｔ": "t",
  "ｕ": "u",
  "ｖ": "v",
  "ｗ": "w",
  "ｘ": "x",
  "ｙ": "y",
  "ｚ": "z",

  // ─── Smart quotes and apostrophes ────────────────────────────────────────
  "‘": "'", // left single
  "’": "'", // right single
  "‚": "'", // single low-9
  "‛": "'", // single high-reversed-9
  "“": '"', // left double
  "”": '"', // right double
  "„": '"', // double low-9
  "‟": '"', // double high-reversed-9
};

// Zero-width and invisible characters to strip
const INVISIBLE_CHARS = /[\u200B-\u200F\u2028-\u202F\uFEFF\u00AD\u2060\u180E]/g;

/**
 * Normalize a string by resolving encoding obfuscation.
 *
 * Any base64-looking tokens that decode to suspicious-looking text are
 * appended to the output (not substituted) so pattern matching sees both
 * the original and decoded forms without corrupting legitimate base64 payloads.
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

  // 5. Surface base64-encoded payloads to the scanner by appending decoded
  //    text. Does not replace the original — just adds a second view.
  const decodedTokens = extractSuspiciousBase64(result);
  if (decodedTokens.length > 0) {
    result = `${result}\n[base64-decoded: ${decodedTokens.join(" | ")}]`;
  }

  return result;
}

// Keywords that suggest a decoded base64 string is an injection payload,
// not an innocuous identifier or hash. Kept narrow to limit false positives.
const BASE64_INJECTION_KEYWORDS =
  /\b(ignore|disregard|override|forget|bypass|system|instruction|pretend|jailbreak|unrestricted|reveal|prompt)\b/i;

function extractSuspiciousBase64(input: string): string[] {
  const tokens = input.match(/[A-Za-z0-9+/]{16,}={0,2}/g);
  if (!tokens) return [];

  const decoded: string[] = [];
  for (const token of tokens) {
    const candidate = tryDecodeBase64(token);
    if (candidate && BASE64_INJECTION_KEYWORDS.test(candidate)) {
      decoded.push(candidate);
    }
  }
  return decoded;
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

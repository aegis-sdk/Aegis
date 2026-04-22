/**
 * Injection-keyword constants shared across scanner submodules.
 *
 * Kept in one place so the list the injection patterns look for and the
 * list the base64 decoder uses to decide whether a decoded payload is
 * "suspicious" cannot drift. Both call sites import from here.
 */

/**
 * Words that frequently appear in prompt-injection attacks and rarely appear
 * in innocuous text. Intentionally narrow — adding every synonym would hurt
 * precision more than recall.
 */
export const INJECTION_KEYWORDS = [
  "ignore",
  "disregard",
  "override",
  "forget",
  "bypass",
  "system",
  "instruction",
  "pretend",
  "jailbreak",
  "unrestricted",
  "reveal",
  "prompt",
] as const;

/**
 * Word-boundary-anchored regex built from INJECTION_KEYWORDS.
 * Case-insensitive. Safe to test against untrusted input — no catastrophic
 * backtracking because the body is a simple alternation of literal keywords.
 */
export const INJECTION_KEYWORD_REGEX = new RegExp(
  `\\b(?:${INJECTION_KEYWORDS.join("|")})\\b`,
  "i",
);

/**
 * Enhanced Conversation Trajectory Analysis.
 *
 * Provides keyword-based topic drift detection and escalation pattern
 * recognition across conversation messages. Uses Jaccard similarity
 * between consecutive message keyword sets to measure topic drift,
 * and tracks risk-related keyword progression to detect gradual
 * escalation attacks (Crescendo, T7).
 */

import type { PromptMessage, TopicDriftResult } from "../types.js";

// ─── Stopwords ──────────────────────────────────────────────────────────────

/**
 * Common English stopwords to filter out during keyword extraction.
 * These words carry minimal semantic meaning for topic analysis.
 */
const STOPWORDS = new Set([
  "a",
  "an",
  "the",
  "and",
  "or",
  "but",
  "is",
  "are",
  "was",
  "were",
  "be",
  "been",
  "being",
  "have",
  "has",
  "had",
  "do",
  "does",
  "did",
  "will",
  "would",
  "could",
  "should",
  "may",
  "might",
  "shall",
  "can",
  "to",
  "of",
  "in",
  "for",
  "on",
  "with",
  "at",
  "by",
  "from",
  "as",
  "into",
  "through",
  "during",
  "before",
  "after",
  "above",
  "below",
  "between",
  "out",
  "off",
  "over",
  "under",
  "again",
  "further",
  "then",
  "once",
  "here",
  "there",
  "when",
  "where",
  "why",
  "how",
  "all",
  "each",
  "every",
  "both",
  "few",
  "more",
  "most",
  "other",
  "some",
  "such",
  "no",
  "nor",
  "not",
  "only",
  "own",
  "same",
  "so",
  "than",
  "too",
  "very",
  "just",
  "because",
  "about",
  "until",
  "while",
  "if",
  "this",
  "that",
  "these",
  "those",
  "it",
  "its",
  "he",
  "she",
  "they",
  "them",
  "we",
  "you",
  "your",
  "my",
  "his",
  "her",
  "our",
  "their",
  "what",
  "which",
  "who",
  "whom",
  "me",
  "him",
  "us",
  "i",
  "am",
  "up",
  "also",
  "like",
  "well",
  "get",
  "got",
  "make",
  "made",
  "take",
  "took",
  "come",
  "came",
  "go",
  "went",
  "know",
  "knew",
  "think",
  "see",
  "say",
  "said",
  "tell",
  "told",
  "give",
  "gave",
  "use",
  "used",
  "find",
  "found",
  "want",
  "need",
  "let",
  "put",
  "try",
  "keep",
  "still",
  "even",
  "back",
  "way",
  "much",
  "many",
  "really",
  "already",
  "yes",
  "yeah",
  "okay",
  "please",
  "thank",
  "thanks",
  "sure",
  "right",
  "now",
]);

// ─── Escalation Keywords ────────────────────────────────────────────────────

/**
 * Keywords that indicate progressively risky intent in a conversation.
 * When these appear in increasing frequency across messages, it suggests
 * a Crescendo-style escalation attack.
 */
const ESCALATION_KEYWORDS = new Set([
  "hypothetically",
  "pretend",
  "ignore",
  "override",
  "system",
  "admin",
  "root",
  "password",
  "hack",
  "bypass",
  "exploit",
  "jailbreak",
  "unrestricted",
  "sudo",
  "escalate",
  "disable",
  "security",
  "inject",
  "payload",
  "shell",
  "terminal",
  "execute",
  "command",
  "secret",
  "credential",
  "token",
]);

// ─── Keyword Extraction ─────────────────────────────────────────────────────

/**
 * Extract meaningful keywords from a message using simple NLP:
 * split on whitespace/punctuation, filter stopwords, keep words >3 chars.
 *
 * @param text - The message text to extract keywords from
 * @returns A Set of lowercase keyword strings
 */
function extractKeywords(text: string): Set<string> {
  const words = text
    .toLowerCase()
    .split(/[\s\p{P}]+/u)
    .filter((word) => word.length > 3 && !STOPWORDS.has(word));

  return new Set(words);
}

/**
 * Find escalation keywords present in a message.
 *
 * @param text - The message text to search
 * @returns Array of escalation keywords found
 */
function findEscalationKeywords(text: string): string[] {
  const lower = text.toLowerCase();
  const found: string[] = [];

  for (const keyword of ESCALATION_KEYWORDS) {
    if (lower.includes(keyword)) {
      found.push(keyword);
    }
  }

  return found;
}

// ─── Similarity ─────────────────────────────────────────────────────────────

/**
 * Calculate the Jaccard similarity between two sets.
 *
 * Jaccard similarity = |A ∩ B| / |A ∪ B|
 * Returns 1.0 if both sets are empty (vacuously similar).
 *
 * @param a - First set
 * @param b - Second set
 * @returns Similarity score between 0 and 1
 */
function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 1.0;

  let intersection = 0;
  const smaller = a.size <= b.size ? a : b;
  const larger = a.size <= b.size ? b : a;

  for (const item of smaller) {
    if (larger.has(item)) {
      intersection++;
    }
  }

  const union = a.size + b.size - intersection;
  return union === 0 ? 1.0 : intersection / union;
}

// ─── TrajectoryAnalyzer ─────────────────────────────────────────────────────

/**
 * TrajectoryAnalyzer — enhanced conversation trajectory analysis.
 *
 * Tracks topic keywords across messages and detects:
 * 1. **Topic drift**: Sudden topic changes measured by Jaccard similarity
 *    between consecutive message keyword sets
 * 2. **Escalation patterns**: Progressive appearance of risk-related
 *    keywords across the conversation
 *
 * @example
 * ```ts
 * const analyzer = new TrajectoryAnalyzer({ driftThreshold: 0.1 });
 * const result = analyzer.analyze(messages);
 * if (result.escalationDetected) {
 *   console.warn('Escalation detected:', result.escalationKeywords);
 * }
 * ```
 */
export class TrajectoryAnalyzer {
  private readonly driftThreshold: number;

  /**
   * @param options - Configuration options
   * @param options.driftThreshold - Jaccard similarity threshold below which
   *   topic drift is flagged. Default: 0.1
   */
  constructor(options: { driftThreshold?: number } = {}) {
    this.driftThreshold = options.driftThreshold ?? 0.1;
  }

  /**
   * Analyze a conversation's trajectory for topic drift and escalation.
   *
   * Examines user messages to extract keywords, compute consecutive
   * message similarity, and detect progressive escalation patterns.
   *
   * @param messages - The conversation messages to analyze
   * @returns TopicDriftResult with similarity scores, drift indices,
   *   and escalation information
   */
  analyze(messages: PromptMessage[]): TopicDriftResult {
    const userMessages = messages.filter((m) => m.role === "user");

    if (userMessages.length < 2) {
      return {
        similarities: [],
        driftIndices: [],
        escalationDetected: false,
        escalationKeywords: [],
      };
    }

    // Extract keyword sets for each user message
    const keywordSets = userMessages.map((m) => extractKeywords(m.content));

    // Calculate Jaccard similarity between consecutive messages
    const similarities: number[] = [];
    const driftIndices: number[] = [];

    for (let i = 1; i < keywordSets.length; i++) {
      const prev = keywordSets[i - 1] as Set<string>;
      const curr = keywordSets[i] as Set<string>;
      const similarity = jaccardSimilarity(prev, curr);
      similarities.push(similarity);

      if (similarity < this.driftThreshold) {
        driftIndices.push(i);
      }
    }

    // Track escalation keywords across messages
    const allEscalationKeywords: string[] = [];
    const seenKeywords = new Set<string>();
    let escalationProgressing = false;

    // Count escalation keywords per message to detect progressive escalation
    const escalationCountPerMessage: number[] = [];

    for (const msg of userMessages) {
      const found = findEscalationKeywords(msg.content);
      escalationCountPerMessage.push(found.length);

      for (const keyword of found) {
        if (!seenKeywords.has(keyword)) {
          seenKeywords.add(keyword);
          allEscalationKeywords.push(keyword);
        }
      }
    }

    // Detect progressive escalation: new escalation keywords appearing
    // in later messages, OR escalation keyword count increasing
    if (userMessages.length >= 3) {
      // Check if escalation keywords are appearing in progressively
      // later messages (new keywords introduced over time)
      const keywordsPerMessage: string[][] = userMessages.map((m) =>
        findEscalationKeywords(m.content),
      );

      const cumulativeNew: number[] = [];
      const seenSoFar = new Set<string>();
      for (const keywords of keywordsPerMessage) {
        let newCount = 0;
        for (const kw of keywords) {
          if (!seenSoFar.has(kw)) {
            seenSoFar.add(kw);
            newCount++;
          }
        }
        cumulativeNew.push(newCount);
      }

      // Progressive escalation: new escalation keywords keep appearing
      // in later messages (at least 3 messages introduce new keywords)
      const messagesWithNewKeywords = cumulativeNew.filter((c) => c > 0).length;
      if (messagesWithNewKeywords >= 3) {
        escalationProgressing = true;
      }

      // Also check: last 3 messages have increasing keyword count
      if (escalationCountPerMessage.length >= 3) {
        const last3 = escalationCountPerMessage.slice(-3);
        if (
          (last3[0] as number) < (last3[1] as number) &&
          (last3[1] as number) < (last3[2] as number)
        ) {
          escalationProgressing = true;
        }
      }
    }

    return {
      similarities,
      driftIndices,
      escalationDetected: escalationProgressing,
      escalationKeywords: allEscalationKeywords,
    };
  }
}

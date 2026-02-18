import type {
  Quarantined,
  ScanResult,
  Detection,
  InputScannerConfig,
  TrajectoryResult,
  PromptMessage,
} from "../types.js";
import { INJECTION_PATTERNS } from "./patterns.js";
import { normalizeEncoding } from "./encoding.js";
import { analyzeEntropy } from "./entropy.js";
import { detectLanguageSwitches } from "./language.js";
import { TrajectoryAnalyzer } from "./trajectory.js";

const DEFAULT_CONFIG: Required<InputScannerConfig> = {
  sensitivity: "balanced",
  customPatterns: [],
  encodingNormalization: true,
  entropyAnalysis: true,
  languageDetection: true,
  manyShotDetection: true,
  perplexityEstimation: false,
  mlClassifier: false,
  entropyThreshold: 4.5,
  manyShotThreshold: 5,
};

/**
 * Input Scanner — the first active defense layer.
 *
 * Detects known and heuristic prompt injection patterns in incoming content.
 * Uses a hybrid approach combining fast deterministic rules with optional
 * ML-based semantic analysis.
 */
export class InputScanner {
  private config: Required<InputScannerConfig>;

  constructor(config: InputScannerConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Scan quarantined content for injection patterns.
   *
   * Returns a ScanResult with a safety verdict, risk score (0-1),
   * and detailed detection information.
   */
  scan(input: Quarantined<string>): ScanResult {
    const raw = input.value;

    // Step 1: Normalize encoding to catch obfuscation
    const normalized = this.config.encodingNormalization ? normalizeEncoding(raw) : raw;

    const detections: Detection[] = [];

    // Step 2: Pattern matching
    this.runPatternDetection(normalized, detections);

    // Step 3: Custom patterns
    for (const pattern of this.config.customPatterns) {
      const match = normalized.match(pattern);
      if (match) {
        detections.push({
          type: "custom",
          pattern: pattern.source,
          matched: match[0] ?? "",
          severity: "medium",
          position: { start: match.index ?? 0, end: (match.index ?? 0) + (match[0]?.length ?? 0) },
          description: `Custom pattern matched: ${pattern.source}`,
        });
      }
    }

    // Step 4: Entropy analysis (adversarial suffix detection)
    const entropy = this.config.entropyAnalysis
      ? analyzeEntropy(normalized, { threshold: this.config.entropyThreshold })
      : { mean: 0, maxWindow: 0, anomalous: false };

    if (entropy.anomalous) {
      detections.push({
        type: "adversarial_suffix",
        pattern: "entropy_threshold_exceeded",
        matched: `maxWindow=${entropy.maxWindow.toFixed(2)}`,
        severity: "high",
        position: { start: 0, end: normalized.length },
        description: `High entropy detected (${entropy.maxWindow.toFixed(2)} bits/char), possible adversarial suffix`,
      });
    }

    // Step 5: Many-shot detection
    if (this.config.manyShotDetection) {
      this.detectManyShot(normalized, detections);
    }

    // Step 6: Context flooding
    if (normalized.length > 10000) {
      detections.push({
        type: "context_flooding",
        pattern: "excessive_length",
        matched: `length=${normalized.length}`,
        severity: "medium",
        position: { start: 0, end: normalized.length },
        description: `Input length (${normalized.length}) may be a context flooding attempt`,
      });
    }

    // Step 7: Language/script detection
    // IMPORTANT: Run language detection on the RAW text (before normalization).
    // Homoglyph normalization converts Cyrillic а→a, о→o, etc., which creates
    // artificial script switches within what were originally pure-Cyrillic words.
    // Pattern-matching for actual homoglyph attacks still uses the normalized text.
    const language = this.config.languageDetection
      ? detectLanguageSwitches(raw)
      : { primary: "unknown", switches: [] };

    // Script-switch detection: bilingual tech text (e.g. "unit-тест на Python")
    // naturally has several switches between Latin (programming terms) and the
    // primary script. Use a density-based approach: switches per 100 characters.
    if (this.config.languageDetection && language.switches.length >= 5) {
      // Calculate switch density: switches per 100 characters
      const switchDensity = (language.switches.length / Math.max(raw.length, 1)) * 100;
      // Only flag when density is high (> 15 per 100 chars) OR absolute count is very high
      if (switchDensity > 15 || language.switches.length >= 15) {
        detections.push({
          type: "language_switching",
          pattern: "excessive_script_switches",
          matched: `${language.switches.length} script switches detected`,
          severity: language.switches.length >= 15 && switchDensity > 20 ? "high" : "medium",
          position: { start: 0, end: normalized.length },
          description: `Suspicious language switching: ${language.switches.length} script changes (density: ${switchDensity.toFixed(1)}/100chars)`,
        });
      }
    }

    // Calculate composite score
    const score = this.calculateScore(detections, entropy.anomalous);

    // Determine safety based on sensitivity
    const threshold = this.getThreshold();
    const safe = score < threshold;

    return {
      safe,
      score,
      detections,
      normalized,
      language,
      entropy,
    };
  }

  /**
   * Analyze the trajectory of a conversation for multi-turn escalation.
   *
   * This is critical for detecting Crescendo attacks (T7) where individual
   * messages look benign but the conversation gradually escalates.
   *
   * Combines two analysis approaches:
   * 1. Pattern-based risk scoring per message (original approach)
   * 2. Keyword-based topic drift and escalation detection (TrajectoryAnalyzer)
   */
  analyzeTrajectory(messages: PromptMessage[]): TrajectoryResult {
    const userMessages = messages.filter((m) => m.role === "user");

    if (userMessages.length < 2) {
      return { drift: 0, escalation: false, riskTrend: [] };
    }

    // Calculate per-message risk scores
    const riskTrend = userMessages.map((msg) => {
      const detections: Detection[] = [];
      const normalized = this.config.encodingNormalization
        ? normalizeEncoding(msg.content)
        : msg.content;
      this.runPatternDetection(normalized, detections);
      return this.calculateScore(detections, false);
    });

    // Detect escalation: are risk scores trending upward?
    let escalation = false;
    if (riskTrend.length >= 3) {
      const recentTrend = riskTrend.slice(-3);
      escalation = recentTrend.every((score, i) => i === 0 || score > (recentTrend[i - 1] ?? 0));
    }

    // Simple drift metric: how different is the last message from the first?
    const drift =
      riskTrend.length > 0
        ? Math.abs((riskTrend[riskTrend.length - 1] ?? 0) - (riskTrend[0] ?? 0))
        : 0;

    // Enhanced analysis: keyword-based topic drift and escalation detection
    const trajectoryAnalyzer = new TrajectoryAnalyzer();
    const topicDrift = trajectoryAnalyzer.analyze(messages);

    // Merge escalation signals: either pattern-based or keyword-based
    const mergedEscalation = escalation || topicDrift.escalationDetected;

    return { drift, escalation: mergedEscalation, riskTrend, topicDrift };
  }

  private runPatternDetection(text: string, detections: Detection[]): void {
    const patterns = this.getActivePatterns();

    for (const pattern of patterns) {
      const match = text.match(pattern.pattern);
      if (match) {
        detections.push({
          type: pattern.type,
          pattern: pattern.pattern.source,
          matched: match[0] ?? "",
          severity: pattern.severity,
          position: { start: match.index ?? 0, end: (match.index ?? 0) + (match[0]?.length ?? 0) },
          description: pattern.description,
        });
      }
    }
  }

  private getActivePatterns() {
    // In permissive mode, only use critical patterns
    if (this.config.sensitivity === "permissive") {
      return INJECTION_PATTERNS.filter((p) => p.severity === "critical");
    }
    return INJECTION_PATTERNS;
  }

  private detectManyShot(text: string, detections: Detection[]): void {
    // Detect repeated Q&A patterns that suggest many-shot jailbreaking
    const qaPattern =
      /(?:(?:Q|Question|Human|User)\s*[:]\s*.+\s*(?:A|Answer|Assistant|AI)\s*[:]\s*.+)/gi;
    const matches = text.match(qaPattern);

    if (matches && matches.length >= this.config.manyShotThreshold) {
      detections.push({
        type: "many_shot",
        pattern: "repeated_qa_pairs",
        matched: `${matches.length} Q&A pairs detected`,
        severity: "high",
        position: { start: 0, end: text.length },
        description: `Many-shot jailbreaking: ${matches.length} Q&A patterns found (threshold: ${this.config.manyShotThreshold})`,
      });
    }
  }

  private calculateScore(detections: Detection[], entropyAnomalous: boolean): number {
    if (detections.length === 0 && !entropyAnomalous) return 0;

    const severityWeights: Record<string, number> = {
      critical: 0.9,
      high: 0.6,
      medium: 0.3,
      low: 0.1,
    };

    // Sum weighted detections, capped at 1.0
    let score = 0;
    for (const detection of detections) {
      score += severityWeights[detection.severity] ?? 0.1;
    }

    // Normalize to 0-1 range
    return Math.min(1, score);
  }

  private getThreshold(): number {
    switch (this.config.sensitivity) {
      case "paranoid":
        return 0.2;
      case "balanced":
        return 0.4;
      case "permissive":
        return 0.7;
    }
  }
}

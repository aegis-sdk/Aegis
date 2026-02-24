# InputScanner

The first active defense layer. Detects known and heuristic prompt injection patterns using a hybrid approach: fast deterministic regex rules, encoding normalization, entropy analysis, perplexity estimation, many-shot detection, and language switch analysis.

```ts
import { InputScanner } from "@aegis-sdk/core";
```

## Constructor

```ts
new InputScanner(config?: InputScannerConfig)
```

### InputScannerConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sensitivity` | `Sensitivity` | `"balanced"` | `"paranoid"`, `"balanced"`, or `"permissive"` |
| `customPatterns` | `RegExp[]` | `[]` | Additional regex patterns to match |
| `encodingNormalization` | `boolean` | `true` | Normalize Unicode, homoglyphs, zero-width chars, base64 |
| `entropyAnalysis` | `boolean` | `true` | Sliding-window entropy analysis for adversarial suffixes |
| `languageDetection` | `boolean` | `true` | Detect suspicious script/language switches |
| `manyShotDetection` | `boolean` | `true` | Detect repeated Q&A pair conditioning patterns |
| `perplexityEstimation` | `boolean` | `false` | Character-level n-gram perplexity analysis |
| `mlClassifier` | `boolean` | `false` | Reserved for future ML-based classification |
| `entropyThreshold` | `number` | `4.5` | Bits-per-char threshold for entropy anomaly |
| `manyShotThreshold` | `number` | `5` | Number of Q&A pairs to trigger many-shot detection |
| `perplexityThreshold` | `number` | `4.5` | Bits-per-char threshold for perplexity anomaly |
| `perplexityConfig` | `PerplexityConfig` | — | Full perplexity analyzer options (overrides `perplexityThreshold`) |

Sensitivity thresholds for the composite score:
- `"paranoid"` — block at score >= 0.2
- `"balanced"` — block at score >= 0.4
- `"permissive"` — block at score >= 0.7

## Methods

### scan()

Scan quarantined content for injection patterns.

```ts
scan(input: Quarantined<string>): ScanResult
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `input` | `Quarantined<string>` | Quarantined string content to scan |

**Returns:** [`ScanResult`](#scanresult)

The scan pipeline runs these steps in order:
1. Encoding normalization (Unicode, homoglyphs, zero-width chars, base64)
2. Pattern matching against the built-in injection pattern library
3. Custom pattern matching
4. Entropy analysis (adversarial suffix detection)
5. Perplexity estimation (if enabled)
6. Many-shot detection (repeated Q&A pairs)
7. Context flooding check (input > 10,000 chars)
8. Language/script switch detection

### analyzeTrajectory()

Analyze conversation trajectory for multi-turn escalation (Crescendo attacks, T7).

```ts
analyzeTrajectory(messages: PromptMessage[]): TrajectoryResult
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `messages` | `PromptMessage[]` | Full conversation history |

**Returns:** `TrajectoryResult`

| Field | Type | Description |
|-------|------|-------------|
| `drift` | `number` | Risk difference between first and last user message |
| `escalation` | `boolean` | Whether risk scores are trending upward |
| `riskTrend` | `number[]` | Per-message risk scores |
| `topicDrift` | `TopicDriftResult` | Keyword-based topic drift and escalation analysis |

## ScanResult

```ts
interface ScanResult {
  safe: boolean;
  score: number;           // 0-1 composite risk score
  detections: Detection[];
  normalized: string;      // Text after encoding normalization
  language: LanguageResult;
  entropy: EntropyResult;
  perplexity?: PerplexityResult;  // Present when perplexityEstimation is enabled
  judgeVerdict?: JudgeVerdict;    // Present when judge was invoked
}
```

## Detection

```ts
interface Detection {
  type: DetectionType;
  pattern: string;         // Regex source that matched
  matched: string;         // The matched substring
  severity: RiskLevel;     // "low" | "medium" | "high" | "critical"
  position: { start: number; end: number };
  description: string;
}
```

Severity weights for score calculation: `critical` = 0.9, `high` = 0.6, `medium` = 0.3, `low` = 0.1. The score is the sum of weights, capped at 1.0.

## Example

```ts
import { InputScanner, quarantine } from "@aegis-sdk/core";

const scanner = new InputScanner({
  sensitivity: "balanced",
  perplexityEstimation: true,
  customPatterns: [/SYSTEM:\s*override/i],
});

const input = quarantine(userMessage, { source: "user_input" });
const result = scanner.scan(input);

if (!result.safe) {
  console.warn(`Blocked (score: ${result.score})`);
  for (const d of result.detections) {
    console.warn(`  ${d.type} [${d.severity}]: ${d.description}`);
  }
}
```

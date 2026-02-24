# Types Reference

All types are exported from `@aegis-sdk/core`.

```ts
import type { AegisConfig, ScanResult, Detection } from "@aegis-sdk/core";
```

## Top-Level Configuration

### AegisConfig

```ts
interface AegisConfig {
  policy?: PresetPolicy | AegisPolicy | string;
  scanner?: InputScannerConfig;
  monitor?: StreamMonitorConfig;
  recovery?: RecoveryConfig;
  audit?: AuditLogConfig;
  canaryTokens?: string[];
  validator?: ActionValidatorConfig;
  agentLoop?: AgentLoopConfig;
  integrity?: MessageIntegrityConfig;
  autoRetry?: AutoRetryConfig;
  multiModal?: MultiModalConfig;
  judge?: LLMJudgeConfig;
}
```

### RecoveryConfig

```ts
interface RecoveryConfig {
  mode: RecoveryMode;
  autoRetry?: boolean;
  autoRetryMaxAttempts?: number;
  notifyUser?: boolean;
}
```

### GuardInputOptions

```ts
interface GuardInputOptions {
  scanStrategy?: ScanStrategy;
}
```

## Enums and Unions

### Sensitivity

```ts
type Sensitivity = "paranoid" | "balanced" | "permissive";
```

### ScanStrategy

```ts
type ScanStrategy = "last-user" | "all-user" | "full-history";
```

### RecoveryMode

```ts
type RecoveryMode =
  | "continue" | "reset-last" | "quarantine-session"
  | "terminate-session" | "auto-retry";
```

### RiskLevel

```ts
type RiskLevel = "low" | "medium" | "high" | "critical";
```

### ContentSource

```ts
type ContentSource =
  | "user_input" | "api_response" | "web_content" | "email"
  | "file_upload" | "database" | "rag_retrieval" | "tool_output"
  | "mcp_tool_output" | "model_output" | "unknown";
```

### DetectionType

```ts
type DetectionType =
  | "instruction_override" | "role_manipulation" | "skeleton_key"
  | "delimiter_escape" | "encoding_attack" | "adversarial_suffix"
  | "perplexity_anomaly" | "many_shot" | "multi_language"
  | "virtualization" | "markdown_injection" | "context_flooding"
  | "indirect_injection" | "tool_abuse" | "data_exfiltration"
  | "privilege_escalation" | "memory_poisoning" | "chain_injection"
  | "history_manipulation" | "denial_of_wallet" | "language_switching"
  | "model_fingerprinting" | "image_injection" | "audio_injection"
  | "document_injection" | "llm_judge_rejected" | "intent_misalignment"
  | "custom";
```

### PresetPolicy

```ts
type PresetPolicy =
  | "strict" | "balanced" | "permissive"
  | "customer-support" | "code-assistant" | "paranoid";
```

### MediaType

```ts
type MediaType = "image" | "audio" | "video" | "pdf" | "document";
```

### DelimiterStrategy

```ts
type DelimiterStrategy = "xml" | "markdown" | "json" | "triple-hash";
```

### ChunkStrategy

```ts
type ChunkStrategy = "sentence" | "tokens" | "fixed";
```

### PiiHandling

```ts
type PiiHandling = "block" | "redact" | "allow";
```

## Scanner Types

### ScanResult

```ts
interface ScanResult {
  safe: boolean;
  score: number;
  detections: Detection[];
  normalized: string;
  language: LanguageResult;
  entropy: EntropyResult;
  perplexity?: PerplexityResult;
  judgeVerdict?: JudgeVerdict;
}
```

### Detection

```ts
interface Detection {
  type: DetectionType;
  pattern: string;
  matched: string;
  severity: RiskLevel;
  position: { start: number; end: number };
  description: string;
}
```

### InputScannerConfig

```ts
interface InputScannerConfig {
  sensitivity?: Sensitivity;
  customPatterns?: RegExp[];
  encodingNormalization?: boolean;
  entropyAnalysis?: boolean;
  languageDetection?: boolean;
  manyShotDetection?: boolean;
  perplexityEstimation?: boolean;
  mlClassifier?: boolean;
  entropyThreshold?: number;
  manyShotThreshold?: number;
  perplexityThreshold?: number;
  perplexityConfig?: PerplexityConfig;
}
```

### EntropyResult / LanguageResult / PerplexityResult

```ts
interface EntropyResult {
  mean: number;
  maxWindow: number;
  anomalous: boolean;
}

interface LanguageResult {
  primary: string;
  switches: LanguageSwitch[];
}

interface LanguageSwitch {
  from: string;
  to: string;
  position: number;
}

interface PerplexityResult {
  perplexity: number;
  anomalous: boolean;
  windowScores: PerplexityWindowScore[];
  maxWindowPerplexity: number;
}

interface PerplexityWindowScore {
  start: number;
  end: number;
  perplexity: number;
  text: string;
}
```

### TrajectoryResult / TopicDriftResult

```ts
interface TrajectoryResult {
  drift: number;
  escalation: boolean;
  riskTrend: number[];
  topicDrift?: TopicDriftResult;
}

interface TopicDriftResult {
  similarities: number[];
  driftIndices: number[];
  escalationDetected: boolean;
  escalationKeywords: string[];
}
```

## Prompt Builder Types

```ts
interface PromptBuilderConfig {
  delimiterStrategy?: DelimiterStrategy;
  contextWindow?: number;
  compactMode?: boolean;
}

interface BuiltPrompt {
  messages: PromptMessage[];
  metadata: {
    tokenEstimate: number;
    securityOverheadPercent: number;
    delimiterStrategy: DelimiterStrategy;
  };
}

interface PromptMessage {
  role: "system" | "user" | "assistant";
  content: string;
}
```

## Policy Types

See [PolicyEngine](/api/policy-engine) for `AegisPolicy`.

## Action Validator Types

```ts
interface ActionValidationRequest {
  originalRequest: string;
  proposedAction: {
    tool: string;
    params: Record<string, unknown>;
  };
  previousToolOutput?: string;
}

interface ActionValidationResult {
  allowed: boolean;
  reason: string;
  requiresApproval: boolean;
  awaitedApproval?: boolean;
}

interface ActionValidatorConfig {
  onApprovalNeeded?: (request: ActionValidationRequest) => Promise<boolean>;
  scanMcpParams?: boolean;
  scannerConfig?: InputScannerConfig;
  denialOfWallet?: DenialOfWalletConfig;
  exfiltrationToolPatterns?: string[];
}

interface DenialOfWalletConfig {
  maxOperations?: number;
  window?: string;
  maxSandboxTriggers?: number;
  maxToolCalls?: number;
}
```

## Agent Loop Types

```ts
interface ChainStepOptions {
  step: number;                  // Required, 1-based
  maxSteps?: number;             // Default: 25
  sessionId?: string;
  requestId?: string;
  initialTools?: string[];
  cumulativeRisk?: number;
  riskBudget?: number;           // Default: 3.0
}

interface ChainStepResult {
  safe: boolean;
  reason: string;
  cumulativeRisk: number;
  scanResult: ScanResult;
  availableTools: string[];
  budgetExhausted: boolean;
}

interface AgentLoopConfig {
  defaultMaxSteps?: number;
  defaultRiskBudget?: number;
  privilegeDecay?: Record<number, number>;
}
```

## Stream Monitor Types

```ts
interface StreamMonitorConfig {
  canaryTokens?: string[];
  detectPII?: boolean;
  piiRedaction?: boolean;
  detectSecrets?: boolean;
  detectInjectionPayloads?: boolean;
  sanitizeMarkdown?: boolean;
  customPatterns?: RegExp[];
  chunkStrategy?: ChunkStrategy;
  chunkSize?: number;
  onViolation?: (violation: StreamViolation) => void;
}

interface StreamViolation {
  type: "canary_leak" | "pii_detected" | "secret_detected"
      | "injection_payload" | "policy_violation" | "custom_pattern";
  matched: string;
  position: number;
  description: string;
}
```

## Audit Types

```ts
type AuditEventType =
  | "scan_pass" | "scan_block" | "scan_trajectory"
  | "quarantine_create" | "quarantine_release"
  | "unsafe_unwrap" | "excessive_unwrap"
  | "sandbox_trigger" | "sandbox_result"
  | "stream_violation" | "action_block" | "action_approve"
  | "kill_switch" | "session_quarantine"
  | "message_integrity_fail" | "chain_step_scan"
  | "denial_of_wallet" | "policy_violation"
  | "judge_evaluation" | "custom_check";

interface AuditEntry {
  timestamp: Date;
  event: AuditEventType;
  decision: "allowed" | "blocked" | "flagged" | "info";
  sessionId?: string;
  requestId?: string;
  context: Record<string, unknown>;
}

type TransportFn = (entry: AuditEntry) => void | Promise<void>;
type AuditTransport = "json-file" | "console" | "otel" | "custom";
type AuditLevel = "violations-only" | "actions" | "all";

interface AuditLogConfig {
  transport?: AuditTransport;
  transports?: AuditTransport[];
  path?: string;
  level?: AuditLevel;
  redactContent?: boolean;
  alerting?: AlertingConfig;
}
```

## Alerting Types

```ts
interface AlertingConfig {
  enabled: boolean;
  rules: AlertRule[];
}

interface AlertRule {
  id?: string;
  condition: AlertCondition;
  action: "webhook" | "log" | "callback";
  webhookUrl?: string;
  callback?: (alert: Alert) => void | Promise<void>;
  cooldownMs?: number;  // Default: 60000
}

type AlertCondition =
  | { type: "rate-spike"; event: AuditEventType; threshold: number; windowMs: number }
  | { type: "session-kills"; threshold: number; windowMs: number }
  | { type: "cost-anomaly"; threshold: number; windowMs: number }
  | { type: "scan-block-rate"; threshold: number; windowMs: number }
  | { type: "repeated-attacker"; threshold: number; windowMs: number };

interface Alert {
  id: string;
  ruleId: string;
  condition: AlertCondition;
  triggeredAt: Date;
  resolvedAt?: Date;
  context: Record<string, unknown>;
}
```

## Integrity Types

```ts
interface MessageIntegrityConfig {
  secret: string;
  algorithm?: string;       // Default: "SHA-256"
  assistantOnly?: boolean;  // Default: true
}

interface SignedMessage {
  message: PromptMessage;
  signature: string;
}

interface SignedConversation {
  messages: SignedMessage[];
  chainHash: string;
}

interface IntegrityResult {
  valid: boolean;
  tamperedIndices: number[];
  chainValid: boolean;
}
```

## Auto-Retry Types

```ts
type AutoRetryEscalation = "stricter_scanner" | "sandbox" | "combined";

interface AutoRetryConfig {
  enabled: boolean;
  maxAttempts?: number;              // Default: 3
  escalationPath?: AutoRetryEscalation;  // Default: "stricter_scanner"
  onRetry?: (context: RetryContext) => void | Promise<void>;
}

interface RetryContext {
  attempt: number;
  totalAttempts: number;
  escalation: AutoRetryEscalation;
  originalDetections: Detection[];
  originalScore: number;
}

interface RetryResult {
  attempt: number;
  succeeded: boolean;
  escalation: AutoRetryEscalation;
  scanResult?: ScanResult;
  exhausted: boolean;
}
```

## Multi-Modal Types

```ts
type TextExtractorFn = (
  content: Uint8Array | string,
  mediaType: MediaType,
) => Promise<ExtractedContent>;

interface ExtractedContent {
  text: string;
  confidence: number;
  metadata?: Record<string, unknown>;
}

interface MultiModalConfig {
  enabled?: boolean;
  maxFileSize?: number;              // Default: 10,485,760 (10 MB)
  allowedMediaTypes?: MediaType[];
  extractText: TextExtractorFn;      // Required
  scannerSensitivity?: Sensitivity;
}

interface MultiModalScanResult {
  extracted: ExtractedContent;
  mediaType: MediaType;
  scanResult: ScanResult;
  fileSize: number;
  safe: boolean;
}
```

## Quarantine Types

```ts
interface Quarantined<T> {
  readonly __quarantined: true;
  readonly value: T;
  readonly metadata: QuarantineMetadata;
  unsafeUnwrap(options: UnsafeUnwrapOptions): T;
}

interface QuarantineMetadata {
  readonly source: ContentSource;
  readonly risk: RiskLevel;
  readonly timestamp: Date;
  readonly id: string;
}

interface QuarantineOptions {
  source: ContentSource;
  risk?: RiskLevel;
}

interface UnsafeUnwrapOptions {
  reason: string;
  audit?: boolean;
}
```

## LLM-Judge Types

```ts
interface LLMJudgeConfig {
  enabled?: boolean;
  llmCall: LLMJudgeCallFn;
}

type LLMJudgeCallFn = (prompt: string) => Promise<string>;

interface JudgeVerdict {
  decision: "approved" | "rejected" | "uncertain";
  confidence: number;
  reasoning: string;
  approved: boolean;
  executionTimeMs: number;
}

interface JudgeEvaluationContext {
  messages?: PromptMessage[];
  detections?: Detection[];
  riskScore?: number;
}
```

## Error Classes

```ts
class AegisInputBlocked extends Error {
  readonly scanResult: ScanResult;
}

class AegisSessionQuarantined extends Error {}

class AegisSessionTerminated extends Error {
  readonly scanResult: ScanResult;
}

class MultiModalFileTooLarge extends Error {}
class MultiModalUnsupportedType extends Error {}
class MultiModalExtractionFailed extends Error {}
```

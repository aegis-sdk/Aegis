/**
 * Core types for the Aegis SDK.
 *
 * These types form the foundation of the defense pipeline.
 */

import type { JudgeVerdict, LLMJudgeConfig } from "./judge/index.js";

// ─── Content Sources ─────────────────────────────────────────────────────────

export type ContentSource =
  | "user_input"
  | "api_response"
  | "web_content"
  | "email"
  | "file_upload"
  | "database"
  | "rag_retrieval"
  | "tool_output"
  | "mcp_tool_output"
  | "model_output"
  | "unknown";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type Sensitivity = "paranoid" | "balanced" | "permissive";

export type ScanStrategy = "last-user" | "all-user" | "full-history";

export type RecoveryMode =
  | "continue"
  | "reset-last"
  | "quarantine-session"
  | "terminate-session"
  | "auto-retry";

export type DelimiterStrategy = "xml" | "markdown" | "json" | "triple-hash";

export type ChunkStrategy = "sentence" | "tokens" | "fixed";

export type PiiHandling = "block" | "redact" | "allow";

export type AuditTransport = "json-file" | "console" | "otel" | "custom";

export type AuditLevel = "violations-only" | "actions" | "all";

// ─── Quarantine ──────────────────────────────────────────────────────────────

export interface QuarantineMetadata {
  readonly source: ContentSource;
  readonly risk: RiskLevel;
  readonly timestamp: Date;
  readonly id: string;
}

export interface Quarantined<T> {
  readonly __quarantined: true;
  readonly value: T;
  readonly metadata: QuarantineMetadata;
  unsafeUnwrap(options: UnsafeUnwrapOptions): T;
}

export interface UnsafeUnwrapOptions {
  reason: string;
  audit?: boolean;
}

export interface QuarantineOptions {
  source: ContentSource;
  risk?: RiskLevel;
}

// ─── Scanner ─────────────────────────────────────────────────────────────────

export interface ScanResult {
  safe: boolean;
  score: number;
  detections: Detection[];
  normalized: string;
  language: LanguageResult;
  entropy: EntropyResult;
  /** Character-level perplexity analysis result (present when perplexityEstimation is enabled). */
  perplexity?: PerplexityResult;
  /** LLM-Judge verdict (present when the judge was invoked on this scan). */
  judgeVerdict?: JudgeVerdict;
}

export interface Detection {
  type: DetectionType;
  pattern: string;
  matched: string;
  severity: RiskLevel;
  position: { start: number; end: number };
  description: string;
}

export type DetectionType =
  | "instruction_override"
  | "role_manipulation"
  | "skeleton_key"
  | "delimiter_escape"
  | "encoding_attack"
  | "adversarial_suffix"
  | "perplexity_anomaly"
  | "many_shot"
  | "multi_language"
  | "virtualization"
  | "markdown_injection"
  | "context_flooding"
  | "indirect_injection"
  | "tool_abuse"
  | "data_exfiltration"
  | "privilege_escalation"
  | "memory_poisoning"
  | "chain_injection"
  | "history_manipulation"
  | "denial_of_wallet"
  | "language_switching"
  | "model_fingerprinting"
  | "image_injection"
  | "audio_injection"
  | "document_injection"
  | "llm_judge_rejected"
  | "intent_misalignment"
  | "custom";

export interface LanguageResult {
  primary: string;
  switches: LanguageSwitch[];
}

export interface LanguageSwitch {
  from: string;
  to: string;
  position: number;
}

export interface EntropyResult {
  mean: number;
  maxWindow: number;
  anomalous: boolean;
}

export interface PerplexityResult {
  /** Overall estimated perplexity in bits per character. */
  perplexity: number;
  /** Whether the input exceeds the anomaly threshold. */
  anomalous: boolean;
  /** Per-window perplexity breakdown. */
  windowScores: PerplexityWindowScore[];
  /** The highest perplexity among all windows (the primary anomaly signal). */
  maxWindowPerplexity: number;
}

export interface PerplexityWindowScore {
  /** Start index of the window in the input string. */
  start: number;
  /** End index of the window in the input string. */
  end: number;
  /** Estimated perplexity (bits per character) for this window. */
  perplexity: number;
  /** The text content of this window. */
  text: string;
}

export interface PerplexityLanguageProfile {
  /** Display name of the language. */
  name: string;
  /** Expected perplexity range for well-formed text in this language. */
  expectedRange: { min: number; max: number };
  /** Most common character n-grams (lowercased), used to boost detection. */
  commonNgrams: string[];
}

export interface PerplexityConfig {
  /** Whether perplexity estimation is active. Default: true */
  enabled?: boolean;
  /** Anomaly threshold in bits per character. Default: 4.5 */
  threshold?: number;
  /** Sliding window size in characters for local analysis. Default: 50 */
  windowSize?: number;
  /** Character n-gram order (e.g. 3 = trigrams). Default: 3 */
  ngramOrder?: number;
  /** Named language profiles with expected perplexity ranges and common n-grams. */
  languageProfiles?: Record<string, PerplexityLanguageProfile>;
}

export interface TrajectoryResult {
  drift: number;
  escalation: boolean;
  riskTrend: number[];
  /** Enhanced topic drift analysis from TrajectoryAnalyzer */
  topicDrift?: TopicDriftResult;
}

export interface TopicDriftResult {
  /** Jaccard similarity scores between consecutive messages */
  similarities: number[];
  /** Indices where topic drift was detected (similarity below threshold) */
  driftIndices: number[];
  /** Whether escalation keywords appeared progressively */
  escalationDetected: boolean;
  /** Escalation keywords found, in order of appearance */
  escalationKeywords: string[];
}

export interface InputScannerConfig {
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
  /** Perplexity anomaly threshold in bits per character. Default: 4.5 */
  perplexityThreshold?: number;
  /** Full perplexity analyzer configuration (overrides perplexityThreshold if both set). */
  perplexityConfig?: PerplexityConfig;
}

// ─── Prompt Builder ──────────────────────────────────────────────────────────

export interface PromptBuilderConfig {
  delimiterStrategy?: DelimiterStrategy;
  contextWindow?: number;
  compactMode?: boolean;
}

export interface BuiltPrompt {
  messages: PromptMessage[];
  metadata: {
    tokenEstimate: number;
    securityOverheadPercent: number;
    delimiterStrategy: DelimiterStrategy;
  };
}

export interface PromptMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

// ─── Policy ──────────────────────────────────────────────────────────────────

export interface AegisPolicy {
  version: 1;
  capabilities: {
    allow: string[];
    deny: string[];
    requireApproval: string[];
  };
  limits: Record<string, { max: number; window: string }>;
  input: {
    maxLength: number;
    blockPatterns: string[];
    requireQuarantine: boolean;
    encodingNormalization: boolean;
  };
  output: {
    maxLength: number;
    blockPatterns: string[];
    redactPatterns: string[];
    detectPII: boolean;
    detectCanary: boolean;
    blockOnLeak: boolean;
    detectInjectionPayloads: boolean;
    sanitizeMarkdown: boolean;
  };
  alignment: {
    enabled: boolean;
    strictness: "low" | "medium" | "high";
  };
  dataFlow: {
    piiHandling: PiiHandling;
    externalDataSources: string[];
    noExfiltration: boolean;
  };
}

// ─── Action Validator ────────────────────────────────────────────────────────

export interface ActionValidationRequest {
  originalRequest: string;
  proposedAction: {
    tool: string;
    params: Record<string, unknown>;
  };
  /** Optional: the tool output data from the previous step, used for exfiltration tracking */
  previousToolOutput?: string;
}

export interface ActionValidationResult {
  allowed: boolean;
  reason: string;
  requiresApproval: boolean;
  /** Set when the action was paused for human approval */
  awaitedApproval?: boolean;
}

export interface ActionValidatorConfig {
  /**
   * Callback invoked when a tool requires human-in-the-loop approval.
   * Should return true to approve, false to deny.
   */
  onApprovalNeeded?: (request: ActionValidationRequest) => Promise<boolean>;

  /**
   * When enabled, the InputScanner's pattern matching is run against
   * all string values in tool parameters. This catches injection payloads
   * hidden in MCP tool parameters.
   */
  scanMcpParams?: boolean;

  /**
   * InputScanner configuration to use when scanMcpParams is enabled.
   * Falls back to balanced defaults if not provided.
   */
  scannerConfig?: InputScannerConfig;

  /**
   * Denial-of-wallet detection configuration.
   * Tracks cumulative cost of expensive operations and enforces thresholds.
   */
  denialOfWallet?: DenialOfWalletConfig;

  /**
   * Destinations considered "external" for data exfiltration prevention.
   * When noExfiltration is enabled in the policy, actions that would transmit
   * previously-read data to these tool patterns are blocked.
   * Defaults to common external-facing tools if not specified.
   */
  exfiltrationToolPatterns?: string[];
}

export interface DenialOfWalletConfig {
  /** Maximum total operations allowed within the window. Default: 100 */
  maxOperations?: number;
  /** Time window for tracking operations, e.g. "5m", "1h". Default: "5m" */
  window?: string;
  /** Maximum sandbox triggers within the window. Default: 10 */
  maxSandboxTriggers?: number;
  /** Maximum total tool calls within the window. Default: 50 */
  maxToolCalls?: number;
}

// ─── Agent Loop / Chain Step ─────────────────────────────────────────────────

export interface ChainStepOptions {
  /** Maximum number of steps before the loop is halted. Default: 25 */
  maxSteps?: number;
  /** Current step number (1-based). Required. */
  step: number;
  /** Session ID for audit correlation */
  sessionId?: string;
  /** Request ID for audit correlation */
  requestId?: string;
  /**
   * Privilege decay: the full list of tools available at step 1.
   * Tools will be progressively restricted as steps increase.
   */
  initialTools?: string[];
  /**
   * Cumulative risk score from previous steps.
   * guardChainStep() will add to this and return it in the result.
   */
  cumulativeRisk?: number;
  /** Risk threshold at which the chain is halted. Default: 3.0 */
  riskBudget?: number;
}

export interface ChainStepResult {
  /** Whether this step should be allowed to proceed */
  safe: boolean;
  /** Reason for the decision */
  reason: string;
  /** Updated cumulative risk score including this step */
  cumulativeRisk: number;
  /** The scan result from analyzing the model output */
  scanResult: ScanResult;
  /** Tools still available after privilege decay for this step */
  availableTools: string[];
  /** Whether the step budget has been exhausted */
  budgetExhausted: boolean;
}

export interface AgentLoopConfig {
  /** Default maximum steps for guardChainStep(). Default: 25 */
  defaultMaxSteps?: number;
  /** Default risk budget before halting. Default: 3.0 */
  defaultRiskBudget?: number;
  /**
   * Privilege decay schedule. Maps step thresholds to the fraction
   * of tools that remain available (0-1). For example:
   * { 10: 0.75, 20: 0.5 } means at step 10, 75% of tools remain;
   * at step 20, 50% remain.
   * Default: { 10: 0.75, 15: 0.5, 20: 0.25 }
   */
  privilegeDecay?: Record<number, number>;
}

// ─── Stream Monitor ──────────────────────────────────────────────────────────

export interface StreamMonitorConfig {
  canaryTokens?: string[];
  detectPII?: boolean;
  /** When true AND detectPII is true, redact PII instead of blocking the stream */
  piiRedaction?: boolean;
  detectSecrets?: boolean;
  detectInjectionPayloads?: boolean;
  sanitizeMarkdown?: boolean;
  customPatterns?: RegExp[];
  chunkStrategy?: ChunkStrategy;
  chunkSize?: number;
  onViolation?: (violation: StreamViolation) => void;
}

export interface StreamViolation {
  type:
    | "canary_leak"
    | "pii_detected"
    | "secret_detected"
    | "injection_payload"
    | "policy_violation"
    | "custom_pattern";
  matched: string;
  position: number;
  description: string;
}

// ─── Sandbox ─────────────────────────────────────────────────────────────────

export interface SandboxConfig {
  provider: string;
  model: string;
}

export type ExtractionSchema = Record<
  string,
  {
    type: "string" | "number" | "boolean" | "enum";
    values?: string[];
    maxLength?: number;
  }
>;

// ─── Audit ───────────────────────────────────────────────────────────────────

export type AuditEventType =
  | "scan_pass"
  | "scan_block"
  | "scan_trajectory"
  | "quarantine_create"
  | "quarantine_release"
  | "unsafe_unwrap"
  | "excessive_unwrap"
  | "sandbox_trigger"
  | "sandbox_result"
  | "stream_violation"
  | "action_block"
  | "action_approve"
  | "kill_switch"
  | "session_quarantine"
  | "message_integrity_fail"
  | "chain_step_scan"
  | "denial_of_wallet"
  | "policy_violation"
  | "judge_evaluation"
  | "custom_check";

export interface AuditEntry {
  timestamp: Date;
  event: AuditEventType;
  decision: "allowed" | "blocked" | "flagged" | "info";
  sessionId?: string;
  requestId?: string;
  context: Record<string, unknown>;
}

/**
 * A custom transport function invoked for each audit entry.
 *
 * May return `void` or `Promise<void>` -- async transports are
 * fire-and-forget (errors are swallowed to avoid blocking the pipeline).
 */
export type TransportFn = (entry: AuditEntry) => void | Promise<void>;

export interface AuditLogConfig {
  /**
   * Primary transport (single). Kept for backward compatibility.
   * When both `transport` and `transports` are set, they are merged.
   */
  transport?: AuditTransport;
  /**
   * Multiple active transports. For example `['console', 'otel', 'custom']`
   * enables all three simultaneously.
   */
  transports?: AuditTransport[];
  path?: string;
  level?: AuditLevel;
  redactContent?: boolean;
  alerting?: AlertingConfig;
}

export interface AlertingConfig {
  enabled: boolean;
  rules: AlertRule[];
}

export interface AlertRule {
  /** Optional unique identifier for this rule */
  id?: string;
  /** The condition that triggers this alert */
  condition: AlertCondition;
  /** Action to take when the alert fires */
  action: "webhook" | "log" | "callback";
  /** URL to POST to when action is "webhook" */
  webhookUrl?: string;
  /** Custom callback function when action is "callback" */
  callback?: (alert: Alert) => void | Promise<void>;
  /** Cooldown in ms before re-firing this rule. Default: 60000 (1 min) */
  cooldownMs?: number;
}

export type AlertCondition =
  | { type: "rate-spike"; event: AuditEventType; threshold: number; windowMs: number }
  | { type: "session-kills"; threshold: number; windowMs: number }
  | { type: "cost-anomaly"; threshold: number; windowMs: number }
  | { type: "scan-block-rate"; threshold: number; windowMs: number }
  | { type: "repeated-attacker"; threshold: number; windowMs: number };

export interface Alert {
  /** Unique alert identifier */
  id: string;
  /** The rule that triggered this alert */
  ruleId: string;
  /** The condition that was met */
  condition: AlertCondition;
  /** When the alert was triggered */
  triggeredAt: Date;
  /** When the alert was resolved (if applicable) */
  resolvedAt?: Date;
  /** Additional context about the alert */
  context: Record<string, unknown>;
}

// ─── Message Integrity ──────────────────────────────────────────────────

export interface SignedMessage {
  /** The original message */
  message: PromptMessage;
  /** HMAC-SHA256 hex signature */
  signature: string;
}

export interface SignedConversation {
  /** Messages with their signatures */
  messages: SignedMessage[];
  /** Chained hash: each signature includes the previous one for ordering integrity */
  chainHash: string;
}

export interface IntegrityResult {
  /** Whether all signatures are valid */
  valid: boolean;
  /** Indices of messages with invalid signatures */
  tamperedIndices: number[];
  /** Whether the chain hash ordering is intact */
  chainValid: boolean;
}

export interface MessageIntegrityConfig {
  /** HMAC secret. Required. */
  secret: string;
  /** Algorithm. Default: 'SHA-256' */
  algorithm?: string;
  /** Only sign assistant messages (default: true) */
  assistantOnly?: boolean;
}

// ─── Auto-Retry ─────────────────────────────────────────────────────────────

export type AutoRetryEscalation = "stricter_scanner" | "sandbox" | "combined";

export interface AutoRetryConfig {
  /** Whether auto-retry is enabled. */
  enabled: boolean;
  /** Maximum number of retry attempts before giving up. Default: 3 */
  maxAttempts?: number;
  /** The escalation strategy to apply on retry. Default: "stricter_scanner" */
  escalationPath?: AutoRetryEscalation;
  /** Callback invoked before each retry attempt. */
  onRetry?: (context: RetryContext) => void | Promise<void>;
}

export interface RetryContext {
  /** The current retry attempt number (1-based). */
  attempt: number;
  /** Total retry attempts configured. */
  totalAttempts: number;
  /** The escalation strategy applied for this attempt. */
  escalation: AutoRetryEscalation;
  /** Detections from the original failed scan. */
  originalDetections: Detection[];
  /** Composite score from the original failed scan. */
  originalScore: number;
}

export interface RetryResult {
  /** The attempt number this result corresponds to. */
  attempt: number;
  /** Whether this retry attempt succeeded (input passed elevated scan). */
  succeeded: boolean;
  /** The escalation strategy that was applied. */
  escalation: AutoRetryEscalation;
  /** The scan result from the retry attempt (if a re-scan was performed). */
  scanResult?: ScanResult;
  /** Whether all retry attempts have been exhausted without success. */
  exhausted: boolean;
}

// ─── Multi-Modal ─────────────────────────────────────────────────────────────

/** Supported media types for multi-modal content scanning. */
export type MediaType = "image" | "audio" | "video" | "pdf" | "document";

/**
 * Text extractor function supplied by the user or adapter.
 *
 * Takes raw content (as `Uint8Array` or base64-encoded string) and the media
 * type, and returns the extracted text with an extraction confidence score.
 */
export type TextExtractorFn = (
  content: Uint8Array | string,
  mediaType: MediaType,
) => Promise<ExtractedContent>;

/** Result of text extraction from media content. */
export interface ExtractedContent {
  /** The extracted text. */
  text: string;
  /** OCR/extraction confidence in the range [0, 1]. */
  confidence: number;
  /** Additional metadata from the extraction process. */
  metadata?: Record<string, unknown>;
}

/** Configuration for the multi-modal content scanner. */
export interface MultiModalConfig {
  /** Whether multi-modal scanning is enabled. Default: `true` */
  enabled?: boolean;
  /** Maximum file size in bytes. Default: 10 485 760 (10 MB) */
  maxFileSize?: number;
  /** Allowed media types. Default: all types. */
  allowedMediaTypes?: MediaType[];
  /**
   * The text extraction function — provided by the user or an adapter.
   * This is the only required field.
   */
  extractText: TextExtractorFn;
  /**
   * Scanner sensitivity for extracted text.
   * When omitted, inherits the sensitivity from the main scanner configuration.
   */
  scannerSensitivity?: Sensitivity;
}

/** Result of scanning media content for prompt injection. */
export interface MultiModalScanResult {
  /** The extracted content from the media. */
  extracted: ExtractedContent;
  /** Media type that was scanned. */
  mediaType: MediaType;
  /** Scan result from InputScanner on the extracted text. */
  scanResult: ScanResult;
  /** File size in bytes. */
  fileSize: number;
  /** Whether the content was deemed safe. */
  safe: boolean;
}

// ─── Top-Level Aegis ─────────────────────────────────────────────────────────

export type PresetPolicy =
  | "strict"
  | "balanced"
  | "permissive"
  | "customer-support"
  | "code-assistant"
  | "paranoid";

export interface AegisConfig {
  policy?: PresetPolicy | AegisPolicy | string;
  scanner?: InputScannerConfig;
  monitor?: StreamMonitorConfig;
  recovery?: RecoveryConfig;
  audit?: AuditLogConfig;
  canaryTokens?: string[];
  validator?: ActionValidatorConfig;
  agentLoop?: AgentLoopConfig;
  /** HMAC message integrity configuration for detecting history manipulation (T15) */
  integrity?: MessageIntegrityConfig;
  /** Auto-retry configuration for graceful retry with elevated security */
  autoRetry?: AutoRetryConfig;
  /** Multi-modal content scanning configuration (images, PDFs, audio, etc.) */
  multiModal?: MultiModalConfig;
  /** LLM-Judge configuration for intent alignment verification */
  judge?: LLMJudgeConfig;
}

export interface RecoveryConfig {
  mode: RecoveryMode;
  autoRetry?: boolean;
  autoRetryMaxAttempts?: number;
  notifyUser?: boolean;
}

export interface GuardInputOptions {
  scanStrategy?: ScanStrategy;
}

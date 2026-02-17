/**
 * Core types for the Aegis SDK.
 *
 * These types form the foundation of the defense pipeline.
 */

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

export type RecoveryMode = "continue" | "reset-last" | "quarantine-session" | "terminate-session";

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

export interface TrajectoryResult {
  drift: number;
  escalation: boolean;
  riskTrend: number[];
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
}

export interface ActionValidationResult {
  allowed: boolean;
  reason: string;
  requiresApproval: boolean;
}

// ─── Stream Monitor ──────────────────────────────────────────────────────────

export interface StreamMonitorConfig {
  canaryTokens?: string[];
  detectPII?: boolean;
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
  | "custom_check";

export interface AuditEntry {
  timestamp: Date;
  event: AuditEventType;
  decision: "allowed" | "blocked" | "flagged" | "info";
  sessionId?: string;
  requestId?: string;
  context: Record<string, unknown>;
}

export interface AuditLogConfig {
  transport?: AuditTransport;
  path?: string;
  level?: AuditLevel;
  redactContent?: boolean;
  alerting?: AlertingConfig;
}

export interface AlertingConfig {
  enabled: boolean;
  rules: AlertRule[];
  webhook?: string;
}

export interface AlertRule {
  condition: string;
  action: "webhook" | "log" | "custom";
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

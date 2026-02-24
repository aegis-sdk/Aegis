// ─── Main Entry Points ───────────────────────────────────────────────────────
export {
  Aegis,
  AegisInputBlocked,
  AegisSessionQuarantined,
  AegisSessionTerminated,
  aegis,
} from "./aegis.js";

// ─── Core Modules ────────────────────────────────────────────────────────────
export { quarantine, isQuarantined } from "./quarantine/index.js";
export { InputScanner } from "./scanner/index.js";
export { PromptBuilder } from "./builder/index.js";
export { StreamMonitor } from "./monitor/index.js";
export { AuditLog } from "./audit/index.js";
export { OTelTransport } from "./audit/otel.js";
export type { OTelTransportConfig, OTelSpan, OTelCounter, OTelHistogram } from "./audit/otel.js";
export { FileTransport } from "./audit/file-transport.js";
export type { FileTransportConfig } from "./audit/file-transport.js";
export { ActionValidator, parseWindow } from "./validator/index.js";
export { Sandbox } from "./sandbox/index.js";
export { MessageSigner } from "./integrity/index.js";
export { AlertingEngine } from "./alerting/index.js";
export { TrajectoryAnalyzer } from "./scanner/trajectory.js";
export { PerplexityAnalyzer } from "./scanner/perplexity.js";
export { AutoRetryHandler } from "./retry/index.js";
export { LLMJudge } from "./judge/index.js";
export type {
  LLMJudgeConfig,
  LLMJudgeCallFn,
  JudgeVerdict,
  JudgeEvaluationContext,
} from "./judge/index.js";
export {
  MultiModalScanner,
  MultiModalFileTooLarge,
  MultiModalUnsupportedType,
  MultiModalExtractionFailed,
} from "./multimodal/index.js";

// ─── Policy ──────────────────────────────────────────────────────────────────
export {
  resolvePolicy,
  getPreset,
  isActionAllowed,
  loadPolicyFile,
  validatePolicySchema,
  parseSimpleYaml,
} from "./policy/index.js";

// ─── Utilities ───────────────────────────────────────────────────────────────
export { normalizeEncoding, tryDecodeBase64 } from "./scanner/encoding.js";
export { shannonEntropy, analyzeEntropy } from "./scanner/entropy.js";
export { detectLanguageSwitches } from "./scanner/language.js";

// ─── Types ───────────────────────────────────────────────────────────────────
export type {
  // Quarantine
  Quarantined,
  QuarantineMetadata,
  QuarantineOptions,
  UnsafeUnwrapOptions,
  ContentSource,
  RiskLevel,

  // Scanner
  ScanResult,
  Detection,
  DetectionType,
  InputScannerConfig,
  TrajectoryResult,
  LanguageResult,
  LanguageSwitch,
  EntropyResult,
  Sensitivity,
  ScanStrategy,

  // Perplexity
  PerplexityResult,
  PerplexityWindowScore,
  PerplexityLanguageProfile,
  PerplexityConfig,

  // Prompt Builder
  PromptBuilderConfig,
  BuiltPrompt,
  PromptMessage,
  DelimiterStrategy,

  // Policy
  AegisPolicy,
  PresetPolicy,

  // Action Validator
  ActionValidationRequest,
  ActionValidationResult,
  ActionValidatorConfig,
  DenialOfWalletConfig,

  // Agent Loop / Chain Step
  ChainStepOptions,
  ChainStepResult,
  AgentLoopConfig,

  // Stream Monitor
  StreamMonitorConfig,
  StreamViolation,
  ChunkStrategy,

  // Sandbox
  SandboxConfig,
  SandboxCallFn,
  ExtractionSchema,

  // Audit
  AuditEntry,
  AuditEventType,
  AuditLogConfig,
  AuditLevel,
  AuditTransport,
  TransportFn,
  AlertingConfig,
  AlertRule,
  AlertCondition,
  Alert,

  // Message Integrity
  SignedMessage,
  SignedConversation,
  IntegrityResult,
  MessageIntegrityConfig,

  // Trajectory
  TopicDriftResult,

  // Auto-Retry
  AutoRetryConfig,
  AutoRetryEscalation,
  RetryContext,
  RetryResult,

  // Multi-Modal
  MediaType,
  TextExtractorFn,
  ExtractedContent,
  MultiModalConfig,
  MultiModalScanResult,

  // Top-level
  AegisConfig,
  RecoveryConfig,
  RecoveryMode,
  GuardInputOptions,
  PiiHandling,
} from "./types.js";

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

// ─── Policy ──────────────────────────────────────────────────────────────────
export { resolvePolicy, getPreset, isActionAllowed } from "./policy/index.js";

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

  // Top-level
  AegisConfig,
  RecoveryConfig,
  RecoveryMode,
  GuardInputOptions,
  PiiHandling,
} from "./types.js";

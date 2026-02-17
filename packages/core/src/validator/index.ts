import type {
  ActionValidationRequest,
  ActionValidationResult,
  ActionValidatorConfig,
  AegisPolicy,
  AuditEntry,
  DenialOfWalletConfig,
} from "../types.js";
import { isActionAllowed } from "../policy/index.js";
import { InputScanner } from "../scanner/index.js";
import { quarantine } from "../quarantine/index.js";

interface RateLimitEntry {
  count: number;
  windowStart: number;
}

interface DowTracker {
  toolCalls: number;
  sandboxTriggers: number;
  windowStart: number;
}

/** Default tool name patterns that represent external/outbound destinations */
const DEFAULT_EXFILTRATION_PATTERNS = [
  "send_*",
  "email_*",
  "post_*",
  "upload_*",
  "transmit_*",
  "webhook_*",
  "http_*",
  "fetch_*",
  "curl_*",
  "network_*",
  "export_*",
];

/**
 * Action Validator — inspects and validates every action the model proposes
 * before it executes.
 *
 * This is the last line of defense before the AI actually does something
 * in the real world. It checks policy, rate limits, parameter safety,
 * human-in-the-loop approval, MCP parameter scanning, denial-of-wallet
 * thresholds, and data exfiltration prevention.
 */
export class ActionValidator {
  private policy: AegisPolicy;
  private config: ActionValidatorConfig;
  private rateLimits = new Map<string, RateLimitEntry>();
  private mcpScanner: InputScanner | null = null;
  private dowTracker: DowTracker;
  private dowConfig: Required<DenialOfWalletConfig>;
  private readDataFingerprints = new Set<string>();
  private exfiltrationPatterns: string[];
  private auditCallback?: (entry: Omit<AuditEntry, "timestamp">) => void;

  constructor(policy: AegisPolicy, config: ActionValidatorConfig = {}) {
    this.policy = policy;
    this.config = config;

    // Initialize MCP param scanner if enabled
    if (config.scanMcpParams) {
      this.mcpScanner = new InputScanner(config.scannerConfig ?? { sensitivity: "balanced" });
    }

    // Initialize denial-of-wallet tracker
    const dow = config.denialOfWallet ?? {};
    this.dowConfig = {
      maxOperations: dow.maxOperations ?? 100,
      window: dow.window ?? "5m",
      maxSandboxTriggers: dow.maxSandboxTriggers ?? 10,
      maxToolCalls: dow.maxToolCalls ?? 50,
    };
    this.dowTracker = {
      toolCalls: 0,
      sandboxTriggers: 0,
      windowStart: Date.now(),
    };

    // Exfiltration tool patterns
    this.exfiltrationPatterns = config.exfiltrationToolPatterns ?? DEFAULT_EXFILTRATION_PATTERNS;
  }

  /**
   * Set an audit callback for logging validator decisions.
   * This is called by the Aegis class to wire up the AuditLog.
   */
  setAuditCallback(cb: (entry: Omit<AuditEntry, "timestamp">) => void): void {
    this.auditCallback = cb;
  }

  /**
   * Record data that was read by a previous tool call.
   * Used for exfiltration detection: if a subsequent action tries to send
   * this data to an external destination, it will be blocked.
   */
  recordReadData(data: string): void {
    if (!this.policy.dataFlow.noExfiltration) return;

    // Store fingerprints of the data for matching.
    // We store both the full data and chunked segments (in case of partial exfiltration).
    const trimmed = data.trim();
    if (trimmed.length === 0) return;

    this.readDataFingerprints.add(trimmed);

    // Also store meaningful substrings (lines of 20+ chars)
    const lines = trimmed.split(/\n/);
    for (const line of lines) {
      const cleaned = line.trim();
      if (cleaned.length >= 20) {
        this.readDataFingerprints.add(cleaned);
      }
    }
  }

  /**
   * Clear read-data fingerprints (e.g. on session reset).
   */
  clearReadData(): void {
    this.readDataFingerprints.clear();
  }

  /**
   * Validate a proposed action against the security policy.
   */
  async check(request: ActionValidationRequest): Promise<ActionValidationResult> {
    const { proposedAction } = request;

    // Step 1: Policy check — is this tool allowed?
    const policyResult = isActionAllowed(this.policy, proposedAction.tool);
    if (!policyResult.allowed) {
      this.emitAudit({
        event: "action_block",
        decision: "blocked",
        context: { tool: proposedAction.tool, reason: policyResult.reason },
      });
      return {
        allowed: false,
        reason: policyResult.reason,
        requiresApproval: false,
      };
    }

    // Step 2: Rate limit check
    const rateResult = this.checkRateLimit(proposedAction.tool);
    if (!rateResult.allowed) {
      this.emitAudit({
        event: "action_block",
        decision: "blocked",
        context: { tool: proposedAction.tool, reason: rateResult.reason },
      });
      return {
        allowed: false,
        reason: rateResult.reason,
        requiresApproval: false,
      };
    }

    // Step 3: Denial-of-wallet check
    const dowResult = this.checkDenialOfWallet(proposedAction.tool);
    if (!dowResult.allowed) {
      this.emitAudit({
        event: "denial_of_wallet",
        decision: "blocked",
        context: {
          tool: proposedAction.tool,
          reason: dowResult.reason,
          toolCalls: this.dowTracker.toolCalls,
          sandboxTriggers: this.dowTracker.sandboxTriggers,
        },
      });
      return {
        allowed: false,
        reason: dowResult.reason,
        requiresApproval: false,
      };
    }

    // Step 4: Parameter safety check (basic injection patterns)
    const paramResult = this.checkParameters(proposedAction.params);
    if (!paramResult.allowed) {
      this.emitAudit({
        event: "action_block",
        decision: "blocked",
        context: { tool: proposedAction.tool, reason: paramResult.reason },
      });
      return {
        allowed: false,
        reason: paramResult.reason,
        requiresApproval: false,
      };
    }

    // Step 5: MCP parameter scanning (prompt injection in tool params)
    if (this.mcpScanner) {
      const mcpResult = this.scanMcpParameters(proposedAction.params);
      if (!mcpResult.allowed) {
        this.emitAudit({
          event: "action_block",
          decision: "blocked",
          context: {
            tool: proposedAction.tool,
            reason: mcpResult.reason,
            source: "mcp_param_scan",
          },
        });
        return {
          allowed: false,
          reason: mcpResult.reason,
          requiresApproval: false,
        };
      }
    }

    // Step 6: Data exfiltration prevention
    if (this.policy.dataFlow.noExfiltration) {
      const exfilResult = this.checkExfiltration(proposedAction.tool, proposedAction.params);
      if (!exfilResult.allowed) {
        this.emitAudit({
          event: "action_block",
          decision: "blocked",
          context: {
            tool: proposedAction.tool,
            reason: exfilResult.reason,
            source: "exfiltration_prevention",
          },
        });
        return {
          allowed: false,
          reason: exfilResult.reason,
          requiresApproval: false,
        };
      }
    }

    // Step 7: Track the tool call for DoW detection (after all checks pass)
    this.trackToolCall(proposedAction.tool);

    // Step 8: Record previous tool output data for exfiltration tracking
    if (request.previousToolOutput) {
      this.recordReadData(request.previousToolOutput);
    }

    // Step 9: Human-in-the-loop approval gate
    if (policyResult.requiresApproval) {
      const approved = await this.requestApproval(request);
      this.emitAudit({
        event: approved ? "action_approve" : "action_block",
        decision: approved ? "allowed" : "blocked",
        context: {
          tool: proposedAction.tool,
          source: "human_approval",
          approved,
        },
      });
      return {
        allowed: approved,
        reason: approved ? "Action approved by human reviewer" : "Action denied by human reviewer",
        requiresApproval: true,
        awaitedApproval: true,
      };
    }

    return {
      allowed: true,
      reason: "Action validated",
      requiresApproval: false,
    };
  }

  // ─── Denial-of-Wallet Detection ───────────────────────────────────────────

  /**
   * Record a sandbox trigger for DoW tracking.
   * Call this externally when a sandbox operation is triggered.
   */
  recordSandboxTrigger(): void {
    this.ensureDowWindow();
    this.dowTracker.sandboxTriggers++;
  }

  private checkDenialOfWallet(toolName: string): { allowed: boolean; reason: string } {
    this.ensureDowWindow();

    const totalOps = this.dowTracker.toolCalls + this.dowTracker.sandboxTriggers;

    if (totalOps >= this.dowConfig.maxOperations) {
      return {
        allowed: false,
        reason: `Denial-of-wallet threshold exceeded: ${totalOps} total operations in window (max: ${this.dowConfig.maxOperations})`,
      };
    }

    if (this.dowTracker.toolCalls >= this.dowConfig.maxToolCalls) {
      return {
        allowed: false,
        reason: `Denial-of-wallet: too many tool calls (${this.dowTracker.toolCalls}/${this.dowConfig.maxToolCalls}) in window`,
      };
    }

    if (this.dowTracker.sandboxTriggers >= this.dowConfig.maxSandboxTriggers) {
      return {
        allowed: false,
        reason: `Denial-of-wallet: too many sandbox triggers (${this.dowTracker.sandboxTriggers}/${this.dowConfig.maxSandboxTriggers}) in window — tool "${toolName}" blocked`,
      };
    }

    return { allowed: true, reason: "Within denial-of-wallet thresholds" };
  }

  private trackToolCall(_toolName: string): void {
    this.ensureDowWindow();
    this.dowTracker.toolCalls++;
  }

  private ensureDowWindow(): void {
    const windowMs = parseWindow(this.dowConfig.window);
    const now = Date.now();
    if (now - this.dowTracker.windowStart > windowMs) {
      this.dowTracker = {
        toolCalls: 0,
        sandboxTriggers: 0,
        windowStart: now,
      };
    }
  }

  // ─── MCP Parameter Scanning ────────────────────────────────────────────────

  private scanMcpParameters(params: Record<string, unknown>): { allowed: boolean; reason: string } {
    if (!this.mcpScanner) return { allowed: true, reason: "MCP scanning disabled" };

    const stringValues = extractStringValues(params);

    for (const { path, value } of stringValues) {
      const quarantined = quarantine(value, { source: "mcp_tool_output" });
      const result = this.mcpScanner.scan(quarantined);

      if (!result.safe) {
        const detectionSummary = result.detections
          .map((d) => `${d.type}(${d.severity})`)
          .join(", ");
        return {
          allowed: false,
          reason: `Injection payload detected in MCP parameter "${path}": [${detectionSummary}] (score: ${result.score.toFixed(2)})`,
        };
      }
    }

    return { allowed: true, reason: "MCP parameters clean" };
  }

  // ─── Data Exfiltration Prevention ──────────────────────────────────────────

  private checkExfiltration(
    toolName: string,
    params: Record<string, unknown>,
  ): { allowed: boolean; reason: string } {
    // Only check if this tool matches an exfiltration pattern
    const isExfilTool = this.exfiltrationPatterns.some((pattern) => matchesGlob(toolName, pattern));
    if (!isExfilTool) return { allowed: true, reason: "Not an external-facing tool" };

    // No read data recorded yet — nothing to exfiltrate
    if (this.readDataFingerprints.size === 0) {
      return { allowed: true, reason: "No tracked read data" };
    }

    // Check if any string parameter values contain previously-read data
    const stringValues = extractStringValues(params);
    for (const { path, value } of stringValues) {
      for (const fingerprint of this.readDataFingerprints) {
        if (value.includes(fingerprint)) {
          return {
            allowed: false,
            reason: `Data exfiltration blocked: parameter "${path}" in tool "${toolName}" contains data previously read from another tool call`,
          };
        }
      }
    }

    return { allowed: true, reason: "No exfiltration detected" };
  }

  // ─── Human-in-the-Loop Approval ────────────────────────────────────────────

  private async requestApproval(request: ActionValidationRequest): Promise<boolean> {
    if (!this.config.onApprovalNeeded) {
      // No callback configured — default to requiring approval but not blocking
      // (the caller sees requiresApproval: true and can handle it)
      return false;
    }

    try {
      return await this.config.onApprovalNeeded(request);
    } catch {
      // If the approval callback throws, deny the action for safety
      return false;
    }
  }

  // ─── Rate Limiting ─────────────────────────────────────────────────────────

  private checkRateLimit(toolName: string): { allowed: boolean; reason: string } {
    const limit = this.policy.limits[toolName];
    if (!limit) return { allowed: true, reason: "No rate limit configured" };

    const windowMs = parseWindow(limit.window);
    const now = Date.now();
    const key = toolName;

    const entry = this.rateLimits.get(key);
    if (!entry || now - entry.windowStart > windowMs) {
      // New window
      this.rateLimits.set(key, { count: 1, windowStart: now });
      return { allowed: true, reason: "Within rate limit" };
    }

    if (entry.count >= limit.max) {
      return {
        allowed: false,
        reason: `Rate limit exceeded for "${toolName}": ${limit.max} per ${limit.window}`,
      };
    }

    entry.count++;
    return { allowed: true, reason: "Within rate limit" };
  }

  // ─── Parameter Safety ──────────────────────────────────────────────────────

  private checkParameters(params: Record<string, unknown>): { allowed: boolean; reason: string } {
    // Check for common injection patterns in parameters
    for (const [key, value] of Object.entries(params)) {
      if (typeof value === "string") {
        // Check for shell injection
        if (/[;&|`$()]/.test(value) && key.toLowerCase().includes("command")) {
          return {
            allowed: false,
            reason: `Suspicious characters in parameter "${key}": possible command injection`,
          };
        }

        // Check for SQL injection
        if (
          /('|--|;|\bUNION\b|\bDROP\b|\bDELETE\b)/i.test(value) &&
          key.toLowerCase().includes("query")
        ) {
          return {
            allowed: false,
            reason: `Suspicious pattern in parameter "${key}": possible SQL injection`,
          };
        }
      }
    }

    return { allowed: true, reason: "Parameters look safe" };
  }

  // ─── Audit Helper ──────────────────────────────────────────────────────────

  private emitAudit(entry: Omit<AuditEntry, "timestamp">): void {
    if (this.auditCallback) {
      this.auditCallback(entry);
    }
  }
}

// ─── Shared Utilities ──────────────────────────────────────────────────────────

/**
 * Parse a window duration string like "5m", "1h", "30s", "1d" into milliseconds.
 */
export function parseWindow(window: string): number {
  const match = window.match(/^(\d+)([smhd])$/);
  if (!match) return 60_000; // Default: 1 minute

  const value = parseInt(match[1] ?? "1", 10);
  const unit = match[2];

  switch (unit) {
    case "s":
      return value * 1_000;
    case "m":
      return value * 60_000;
    case "h":
      return value * 3_600_000;
    case "d":
      return value * 86_400_000;
    default:
      return 60_000;
  }
}

/**
 * Recursively extract all string values from a nested object,
 * returning each with its dotted key path.
 */
function extractStringValues(
  obj: Record<string, unknown>,
  prefix = "",
): { path: string; value: string }[] {
  const results: { path: string; value: string }[] = [];

  for (const [key, val] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${key}` : key;

    if (typeof val === "string") {
      results.push({ path, value: val });
    } else if (Array.isArray(val)) {
      for (let i = 0; i < val.length; i++) {
        const item = val[i];
        if (typeof item === "string") {
          results.push({ path: `${path}[${i}]`, value: item });
        } else if (typeof item === "object" && item !== null) {
          results.push(...extractStringValues(item as Record<string, unknown>, `${path}[${i}]`));
        }
      }
    } else if (typeof val === "object" && val !== null) {
      results.push(...extractStringValues(val as Record<string, unknown>, path));
    }
  }

  return results;
}

/**
 * Simple glob matching for tool names.
 * Supports: * (wildcard), prefix_* patterns
 */
function matchesGlob(name: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith("*")) {
    return name.startsWith(pattern.slice(0, -1));
  }
  return name === pattern;
}

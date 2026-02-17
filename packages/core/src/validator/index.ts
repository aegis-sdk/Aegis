import type { ActionValidationRequest, ActionValidationResult, AegisPolicy } from "../types.js";
import { isActionAllowed } from "../policy/index.js";

interface RateLimitEntry {
  count: number;
  windowStart: number;
}

/**
 * Action Validator — inspects and validates every action the model proposes
 * before it executes.
 *
 * This is the last line of defense before the AI actually does something
 * in the real world. It checks policy, rate limits, parameter safety,
 * and intent alignment.
 */
export class ActionValidator {
  private policy: AegisPolicy;
  private rateLimits = new Map<string, RateLimitEntry>();

  constructor(policy: AegisPolicy) {
    this.policy = policy;
  }

  /**
   * Validate a proposed action against the security policy.
   */
  async check(request: ActionValidationRequest): Promise<ActionValidationResult> {
    const { proposedAction } = request;

    // Step 1: Policy check — is this tool allowed?
    const policyResult = isActionAllowed(this.policy, proposedAction.tool);
    if (!policyResult.allowed) {
      return {
        allowed: false,
        reason: policyResult.reason,
        requiresApproval: false,
      };
    }

    // Step 2: Rate limit check
    const rateResult = this.checkRateLimit(proposedAction.tool);
    if (!rateResult.allowed) {
      return {
        allowed: false,
        reason: rateResult.reason,
        requiresApproval: false,
      };
    }

    // Step 3: Parameter safety check
    const paramResult = this.checkParameters(proposedAction.params);
    if (!paramResult.allowed) {
      return {
        allowed: false,
        reason: paramResult.reason,
        requiresApproval: false,
      };
    }

    return {
      allowed: true,
      reason: "Action validated",
      requiresApproval: policyResult.requiresApproval,
    };
  }

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
}

function parseWindow(window: string): number {
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

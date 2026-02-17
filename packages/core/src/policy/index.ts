import type { AegisPolicy, PresetPolicy } from "../types.js";

/**
 * Preset policy configurations.
 *
 * These provide sensible defaults for common use cases.
 * Developers can use these as starting points and override specific fields.
 */
const PRESETS: Record<PresetPolicy, AegisPolicy> = {
  strict: {
    version: 1,
    capabilities: { allow: [], deny: ["*"], requireApproval: [] },
    limits: {},
    input: {
      maxLength: 4000,
      blockPatterns: [],
      requireQuarantine: true,
      encodingNormalization: true,
    },
    output: {
      maxLength: 8000,
      blockPatterns: [],
      redactPatterns: [],
      detectPII: true,
      detectCanary: true,
      blockOnLeak: true,
      detectInjectionPayloads: true,
      sanitizeMarkdown: true,
    },
    alignment: { enabled: true, strictness: "high" },
    dataFlow: { piiHandling: "block", externalDataSources: [], noExfiltration: true },
  },

  balanced: {
    version: 1,
    capabilities: { allow: ["*"], deny: [], requireApproval: [] },
    limits: {},
    input: {
      maxLength: 8000,
      blockPatterns: [],
      requireQuarantine: true,
      encodingNormalization: true,
    },
    output: {
      maxLength: 16000,
      blockPatterns: [],
      redactPatterns: [],
      detectPII: true,
      detectCanary: true,
      blockOnLeak: true,
      detectInjectionPayloads: false,
      sanitizeMarkdown: false,
    },
    alignment: { enabled: true, strictness: "medium" },
    dataFlow: { piiHandling: "redact", externalDataSources: [], noExfiltration: true },
  },

  permissive: {
    version: 1,
    capabilities: { allow: ["*"], deny: [], requireApproval: [] },
    limits: {},
    input: {
      maxLength: 32000,
      blockPatterns: [],
      requireQuarantine: false,
      encodingNormalization: true,
    },
    output: {
      maxLength: 64000,
      blockPatterns: [],
      redactPatterns: [],
      detectPII: false,
      detectCanary: true,
      blockOnLeak: true,
      detectInjectionPayloads: false,
      sanitizeMarkdown: false,
    },
    alignment: { enabled: false, strictness: "low" },
    dataFlow: { piiHandling: "allow", externalDataSources: [], noExfiltration: false },
  },

  "customer-support": {
    version: 1,
    capabilities: {
      allow: ["search_kb", "create_ticket", "lookup_order", "check_status"],
      deny: ["delete_*", "admin_*", "modify_user"],
      requireApproval: ["issue_refund", "escalate_to_human"],
    },
    limits: {
      create_ticket: { max: 3, window: "1h" },
      issue_refund: { max: 1, window: "1h" },
    },
    input: {
      maxLength: 4000,
      blockPatterns: [],
      requireQuarantine: true,
      encodingNormalization: true,
    },
    output: {
      maxLength: 8000,
      blockPatterns: [],
      redactPatterns: [],
      detectPII: true,
      detectCanary: true,
      blockOnLeak: true,
      detectInjectionPayloads: true,
      sanitizeMarkdown: true,
    },
    alignment: { enabled: true, strictness: "high" },
    dataFlow: { piiHandling: "redact", externalDataSources: [], noExfiltration: true },
  },

  "code-assistant": {
    version: 1,
    capabilities: {
      allow: ["read_file", "search_code", "write_file", "run_tests"],
      deny: ["execute_shell", "network_request", "install_package"],
      requireApproval: ["write_file", "run_tests"],
    },
    limits: {
      write_file: { max: 20, window: "1h" },
      run_tests: { max: 10, window: "1h" },
    },
    input: {
      maxLength: 32000,
      blockPatterns: [],
      requireQuarantine: true,
      encodingNormalization: true,
    },
    output: {
      maxLength: 64000,
      blockPatterns: [],
      redactPatterns: [],
      detectPII: false,
      detectCanary: true,
      blockOnLeak: true,
      detectInjectionPayloads: false,
      sanitizeMarkdown: false,
    },
    alignment: { enabled: true, strictness: "medium" },
    dataFlow: { piiHandling: "allow", externalDataSources: [], noExfiltration: true },
  },

  paranoid: {
    version: 1,
    capabilities: { allow: [], deny: ["*"], requireApproval: [] },
    limits: {},
    input: {
      maxLength: 2000,
      blockPatterns: [],
      requireQuarantine: true,
      encodingNormalization: true,
    },
    output: {
      maxLength: 4000,
      blockPatterns: [],
      redactPatterns: [],
      detectPII: true,
      detectCanary: true,
      blockOnLeak: true,
      detectInjectionPayloads: true,
      sanitizeMarkdown: true,
    },
    alignment: { enabled: true, strictness: "high" },
    dataFlow: { piiHandling: "block", externalDataSources: [], noExfiltration: true },
  },
};

/**
 * Resolve a policy from a preset name, policy object, or file path.
 */
export function resolvePolicy(input: PresetPolicy | AegisPolicy | string): AegisPolicy {
  if (typeof input === "string") {
    if (input in PRESETS) {
      return structuredClone(PRESETS[input as PresetPolicy]);
    }
    // TODO: Load from YAML/JSON file path
    throw new Error(
      `[aegis] Unknown policy preset: "${input}". Use one of: ${Object.keys(PRESETS).join(", ")}`,
    );
  }
  return input;
}

/**
 * Get a preset policy by name.
 */
export function getPreset(name: PresetPolicy): AegisPolicy {
  return structuredClone(PRESETS[name]);
}

/**
 * Check if an action is allowed by the policy.
 */
export function isActionAllowed(
  policy: AegisPolicy,
  toolName: string,
): { allowed: boolean; requiresApproval: boolean; reason: string } {
  // Check deny list first (overrides allow)
  for (const pattern of policy.capabilities.deny) {
    if (matchesGlob(toolName, pattern)) {
      return {
        allowed: false,
        requiresApproval: false,
        reason: `Tool "${toolName}" is in the deny list`,
      };
    }
  }

  // Check approval list
  for (const pattern of policy.capabilities.requireApproval) {
    if (matchesGlob(toolName, pattern)) {
      return {
        allowed: true,
        requiresApproval: true,
        reason: `Tool "${toolName}" requires human approval`,
      };
    }
  }

  // Check allow list
  for (const pattern of policy.capabilities.allow) {
    if (matchesGlob(toolName, pattern)) {
      return { allowed: true, requiresApproval: false, reason: "Allowed by policy" };
    }
  }

  // Default: deny if allow list is non-empty and doesn't match
  if (policy.capabilities.allow.length > 0) {
    return {
      allowed: false,
      requiresApproval: false,
      reason: `Tool "${toolName}" is not in the allow list`,
    };
  }

  return { allowed: true, requiresApproval: false, reason: "No restrictions configured" };
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

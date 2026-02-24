import type { AegisPolicy, PresetPolicy, PiiHandling } from "../types.js";

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
 * Resolve a policy from a preset name or policy object.
 *
 * For file-based policies, use `loadPolicyFile()` instead — file loading
 * is async and cannot be done in the synchronous Aegis constructor.
 *
 * @example
 * ```ts
 * // Preset name
 * const policy = resolvePolicy('strict');
 *
 * // Direct policy object
 * const policy = resolvePolicy({ version: 1, ... });
 *
 * // File loading (async)
 * const policy = await loadPolicyFile('./aegis-policy.json');
 * const aegis = new Aegis({ policy });
 * ```
 */
export function resolvePolicy(input: PresetPolicy | AegisPolicy | string): AegisPolicy {
  if (typeof input === "string") {
    if (input in PRESETS) {
      return structuredClone(PRESETS[input as PresetPolicy]);
    }
    // Detect file paths and give a helpful error
    if (input.endsWith(".json") || input.endsWith(".yaml") || input.endsWith(".yml")) {
      throw new Error(
        `[aegis] File-based policies must be loaded asynchronously. ` +
          `Use: const policy = await loadPolicyFile("${input}"); new Aegis({ policy })`,
      );
    }
    throw new Error(
      `[aegis] Unknown policy preset: "${input}". Use one of: ${Object.keys(PRESETS).join(", ")}`,
    );
  }
  return input;
}

// ─── Policy File Loading ────────────────────────────────────────────────────

/**
 * Load a policy from a JSON or YAML file.
 *
 * Reads the file, parses it, validates the schema, and returns a fully
 * typed `AegisPolicy` object. Throws descriptive errors on invalid configs.
 *
 * YAML support uses a minimal built-in parser — for complex YAML files,
 * pre-convert to JSON using a dedicated YAML tool.
 *
 * @param filePath - Path to a `.json`, `.yaml`, or `.yml` file
 * @returns Validated AegisPolicy object
 * @throws Error if file cannot be read, parsed, or fails validation
 *
 * @example
 * ```ts
 * const policy = await loadPolicyFile('./aegis-policy.json');
 * const aegis = new Aegis({ policy });
 * ```
 */
export async function loadPolicyFile(filePath: string): Promise<AegisPolicy> {
  // Check extension before attempting file read
  if (!filePath.endsWith(".json") && !filePath.endsWith(".yaml") && !filePath.endsWith(".yml")) {
    throw new Error(
      `[aegis] Unsupported policy file extension: "${filePath}". Use .json, .yaml, or .yml`,
    );
  }

  // Dynamic import to avoid bundling fs in browser environments
  const fsModule = "node:fs/promises";
  // eslint-disable-next-line @typescript-eslint/consistent-type-imports
  const { readFile } = (await import(fsModule)) as typeof import("node:fs/promises");

  let content: string;
  try {
    content = await readFile(filePath, "utf-8");
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    throw new Error(`[aegis] Failed to read policy file "${filePath}": ${msg}`, { cause: error });
  }

  let parsed: unknown;

  if (filePath.endsWith(".json")) {
    try {
      parsed = JSON.parse(content);
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      throw new Error(`[aegis] Invalid JSON in policy file "${filePath}": ${msg}`, { cause: error });
    }
  } else {
    parsed = parseSimpleYaml(content);
  }

  const errors = validatePolicySchema(parsed);
  if (errors.length > 0) {
    throw new Error(
      `[aegis] Invalid policy in "${filePath}":\n  - ${errors.join("\n  - ")}`,
    );
  }

  return parsed as AegisPolicy;
}

// ─── Policy Validation ──────────────────────────────────────────────────────

/**
 * Validate a policy object against the AegisPolicy schema.
 *
 * Returns an array of human-readable error messages.
 * Empty array means the policy is valid.
 *
 * @param policy - The policy object to validate
 * @returns Array of validation error messages (empty = valid)
 */
export function validatePolicySchema(policy: unknown): string[] {
  const errors: string[] = [];

  if (typeof policy !== "object" || policy === null || Array.isArray(policy)) {
    return ["Policy must be a non-null object"];
  }

  const p = policy as Record<string, unknown>;

  // version
  if (p.version !== 1) {
    errors.push(`"version" must be 1 (got: ${String(p.version)})`);
  }

  // capabilities
  if (typeof p.capabilities !== "object" || p.capabilities === null) {
    errors.push('"capabilities" must be an object with allow, deny, requireApproval arrays');
  } else {
    const caps = p.capabilities as Record<string, unknown>;
    for (const field of ["allow", "deny", "requireApproval"]) {
      if (!Array.isArray(caps[field])) {
        errors.push(`"capabilities.${field}" must be an array`);
      }
    }
  }

  // limits
  if (typeof p.limits !== "object" || p.limits === null) {
    errors.push('"limits" must be an object');
  }

  // input
  if (typeof p.input !== "object" || p.input === null) {
    errors.push('"input" must be an object');
  } else {
    const inp = p.input as Record<string, unknown>;
    if (typeof inp.maxLength !== "number" || inp.maxLength <= 0) {
      errors.push('"input.maxLength" must be a positive number');
    }
    if (typeof inp.requireQuarantine !== "boolean") {
      errors.push('"input.requireQuarantine" must be a boolean');
    }
    if (typeof inp.encodingNormalization !== "boolean") {
      errors.push('"input.encodingNormalization" must be a boolean');
    }
    if (!Array.isArray(inp.blockPatterns)) {
      errors.push('"input.blockPatterns" must be an array');
    }
  }

  // output
  if (typeof p.output !== "object" || p.output === null) {
    errors.push('"output" must be an object');
  } else {
    const out = p.output as Record<string, unknown>;
    if (typeof out.maxLength !== "number" || out.maxLength <= 0) {
      errors.push('"output.maxLength" must be a positive number');
    }
    for (const field of [
      "detectPII",
      "detectCanary",
      "blockOnLeak",
      "detectInjectionPayloads",
      "sanitizeMarkdown",
    ]) {
      if (typeof out[field] !== "boolean") {
        errors.push(`"output.${field}" must be a boolean`);
      }
    }
    for (const field of ["blockPatterns", "redactPatterns"]) {
      if (!Array.isArray(out[field])) {
        errors.push(`"output.${field}" must be an array`);
      }
    }
  }

  // alignment
  if (typeof p.alignment !== "object" || p.alignment === null) {
    errors.push('"alignment" must be an object');
  } else {
    const align = p.alignment as Record<string, unknown>;
    if (typeof align.enabled !== "boolean") {
      errors.push('"alignment.enabled" must be a boolean');
    }
    if (!["low", "medium", "high"].includes(align.strictness as string)) {
      errors.push('"alignment.strictness" must be "low", "medium", or "high"');
    }
  }

  // dataFlow
  if (typeof p.dataFlow !== "object" || p.dataFlow === null) {
    errors.push('"dataFlow" must be an object');
  } else {
    const df = p.dataFlow as Record<string, unknown>;
    const validPiiHandling: PiiHandling[] = ["block", "redact", "allow"];
    if (!validPiiHandling.includes(df.piiHandling as PiiHandling)) {
      errors.push('"dataFlow.piiHandling" must be "block", "redact", or "allow"');
    }
    if (!Array.isArray(df.externalDataSources)) {
      errors.push('"dataFlow.externalDataSources" must be an array');
    }
    if (typeof df.noExfiltration !== "boolean") {
      errors.push('"dataFlow.noExfiltration" must be a boolean');
    }
  }

  return errors;
}

// ─── Simple YAML Parser ─────────────────────────────────────────────────────

/**
 * Parse a simple YAML string into an object.
 *
 * Supports the subset of YAML used by Aegis policy files:
 * - Key-value pairs (scalars: strings, numbers, booleans)
 * - Nested objects (indentation-based)
 * - Simple arrays (- item syntax)
 * - Comments (#)
 *
 * For complex YAML, pre-convert to JSON using js-yaml or similar.
 */
export function parseSimpleYaml(yaml: string): unknown {
  const lines = yaml.split("\n");
  return parseYamlLines(lines, 0, 0).value;
}

interface YamlParseResult {
  value: unknown;
  consumed: number;
}

function parseYamlLines(
  lines: string[],
  startIdx: number,
  baseIndent: number,
): YamlParseResult {
  const result: Record<string, unknown> = {};
  let i = startIdx;

  while (i < lines.length) {
    const line = lines[i] ?? "";
    const trimmed = line.replace(/#.*$/, "").trimEnd();

    // Skip blank lines and comment-only lines
    if (trimmed.trim() === "") {
      i++;
      continue;
    }

    const indent = line.search(/\S/);

    // If we've dedented below our base, we're done with this block
    if (indent < baseIndent) {
      break;
    }

    // If this is an array item at the current level
    const arrayCheck = trimmed.match(/^(\s*)- (.*)$/);
    if (arrayCheck) {
      // This is actually an array — re-parse as array
      const arr: unknown[] = [];
      while (i < lines.length) {
        const aLine = lines[i] ?? "";
        const aTrimmed = aLine.replace(/#.*$/, "").trimEnd();
        if (aTrimmed.trim() === "") {
          i++;
          continue;
        }
        const aIndent = aLine.search(/\S/);
        if (aIndent < baseIndent) break;
        const aMatch = aTrimmed.match(/^(\s*)- (.*)$/);
        if (aMatch && aIndent === baseIndent) {
          arr.push(parseScalar((aMatch[2] ?? "").trim()));
          i++;
        } else {
          break;
        }
      }
      return { value: arr, consumed: i - startIdx };
    }

    // Key-value pair
    const kvMatch = trimmed.match(/^(\s*)(\S[^:]*?):\s*(.*)$/);
    if (!kvMatch) {
      i++;
      continue;
    }

    const key = (kvMatch[2] ?? "").trim();
    const valuePart = (kvMatch[3] ?? "").trim();

    // Handle inline flow-style YAML: [] and {}
    if (valuePart === "[]") {
      result[key] = [];
      i++;
      continue;
    }
    if (valuePart === "{}") {
      result[key] = {};
      i++;
      continue;
    }

    if (valuePart === "" || valuePart === "|" || valuePart === ">") {
      // Check if the next line starts an array
      const nextNonEmpty = findNextNonEmptyLine(lines, i + 1);
      if (nextNonEmpty !== null) {
        const nextLine = lines[nextNonEmpty] ?? "";
        const nextIndent = nextLine.search(/\S/);
        const nextTrimmed = nextLine.replace(/#.*$/, "").trimEnd().trim();

        if (nextIndent > indent && nextTrimmed.startsWith("- ")) {
          // Parse array
          const arr: unknown[] = [];
          let j = nextNonEmpty;
          while (j < lines.length) {
            const aLine = lines[j] ?? "";
            const aTrimmed = aLine.replace(/#.*$/, "").trimEnd();
            if (aTrimmed.trim() === "") {
              j++;
              continue;
            }
            const aIndent = aLine.search(/\S/);
            if (aIndent < nextIndent) break;
            const aMatch = aTrimmed.match(/^\s*- (.*)$/);
            if (aMatch && aIndent === nextIndent) {
              arr.push(parseScalar((aMatch[1] ?? "").trim()));
              j++;
            } else {
              break;
            }
          }
          result[key] = arr;
          i = j;
        } else if (nextIndent > indent) {
          // Parse nested object
          const nested = parseYamlLines(lines, nextNonEmpty, nextIndent);
          result[key] = nested.value;
          i = nextNonEmpty + nested.consumed;
        } else {
          result[key] = "";
          i++;
        }
      } else {
        result[key] = "";
        i++;
      }
    } else {
      result[key] = parseScalar(valuePart);
      i++;
    }
  }

  return { value: result, consumed: i - startIdx };
}

function findNextNonEmptyLine(lines: string[], startIdx: number): number | null {
  for (let i = startIdx; i < lines.length; i++) {
    const trimmed = (lines[i] ?? "").replace(/#.*$/, "").trim();
    if (trimmed !== "") return i;
  }
  return null;
}

function parseScalar(value: string): string | number | boolean {
  // Remove surrounding quotes
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }

  // Boolean
  if (value === "true" || value === "True" || value === "TRUE") return true;
  if (value === "false" || value === "False" || value === "FALSE") return false;

  // Null
  if (value === "null" || value === "~") return "";

  // Number
  const num = Number(value);
  if (!isNaN(num) && value !== "") return num;

  // String (unquoted)
  return value;
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

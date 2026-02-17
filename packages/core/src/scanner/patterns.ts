import type { DetectionType, RiskLevel } from "../types.js";

export interface PatternDefinition {
  type: DetectionType;
  pattern: RegExp;
  severity: RiskLevel;
  description: string;
}

/**
 * Core injection pattern database.
 *
 * These patterns detect known prompt injection techniques.
 * They are intentionally broad — the scanner uses them as signals
 * in combination with heuristic scoring, not as hard blocks.
 */
export const INJECTION_PATTERNS: PatternDefinition[] = [
  // ─── Instruction Override ──────────────────────────────────────────────────
  {
    type: "instruction_override",
    pattern:
      /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|context)/i,
    severity: "critical",
    description: "Attempts to override previous instructions",
  },
  {
    type: "instruction_override",
    pattern:
      /disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|rules?|guidelines)/i,
    severity: "critical",
    description: "Attempts to disregard prior instructions",
  },
  {
    type: "instruction_override",
    pattern: /new\s+system\s+(prompt|instructions?|message)/i,
    severity: "critical",
    description: "Attempts to set a new system prompt",
  },
  {
    type: "instruction_override",
    pattern:
      /forget\s+(everything|all|what)\s+(you('ve)?|you\s+were|was)\s+(told|instructed|learned)/i,
    severity: "critical",
    description: "Attempts to clear model context",
  },
  {
    type: "instruction_override",
    pattern: /override\s+(your|the|all)\s+(instructions?|rules?|guidelines|constraints)/i,
    severity: "critical",
    description: "Explicit instruction override attempt",
  },

  // ─── Role Manipulation ─────────────────────────────────────────────────────
  {
    type: "role_manipulation",
    pattern: /you\s+are\s+now\s+(a|an|the)\b/i,
    severity: "high",
    description: "Attempts to reassign the model's role",
  },
  {
    type: "role_manipulation",
    pattern: /pretend\s+(you\s+are|to\s+be|you're)\s/i,
    severity: "high",
    description: "Attempts to make model pretend to be something else",
  },
  {
    type: "role_manipulation",
    pattern: /act\s+as\s+(if\s+you\s+are|an?|the)\s/i,
    severity: "high",
    description: "Attempts to make model act as another entity",
  },
  {
    type: "role_manipulation",
    pattern: /from\s+now\s+on\s*,?\s*(you|your)\s/i,
    severity: "high",
    description: "Attempts to redefine model behavior going forward",
  },

  // ─── Skeleton Key ──────────────────────────────────────────────────────────
  {
    type: "skeleton_key",
    pattern: /for\s+(educational|research|academic|informational)\s+purposes/i,
    severity: "high",
    description: "Skeleton key: appeals to educational framing",
  },
  {
    type: "skeleton_key",
    pattern: /add\s+a\s+disclaimer\s+(but|and)\s+(still|then)\s+(answer|respond|provide|tell)/i,
    severity: "high",
    description: "Skeleton key: disclaimer-based compliance extraction",
  },
  {
    type: "skeleton_key",
    pattern: /as\s+a\s+(thought|hypothetical)\s+experiment/i,
    severity: "high",
    description: "Skeleton key: hypothetical framing",
  },
  {
    type: "skeleton_key",
    pattern: /in\s+(a\s+)?fictional\s+(scenario|context|world|story)/i,
    severity: "medium",
    description: "Skeleton key: fictional framing",
  },

  // ─── Delimiter Escape ──────────────────────────────────────────────────────
  {
    type: "delimiter_escape",
    pattern: /<\/?(system|assistant|user|instruction|prompt|message|context)[\s>]/i,
    severity: "high",
    description: "Attempts to close or inject XML-style message delimiters",
  },
  {
    type: "delimiter_escape",
    pattern: /```\s*(system|assistant|instructions?)/i,
    severity: "high",
    description: "Attempts to escape code block delimiters",
  },
  {
    type: "delimiter_escape",
    pattern: /#{3,}\s*(SYSTEM|INSTRUCTIONS?|END\s+OF)\s/,
    severity: "medium",
    description: "Attempts to inject heading-style delimiters",
  },

  // ─── Encoding Attacks ──────────────────────────────────────────────────────
  {
    type: "encoding_attack",
    pattern: /[\u200B-\u200F\u2028-\u202F\uFEFF\u00AD]/,
    severity: "medium",
    description: "Contains invisible Unicode characters (zero-width, soft hyphen, etc.)",
  },
  {
    type: "encoding_attack",
    pattern: /(?:&#(?:x[0-9a-f]+|\d+);){4,}/i,
    severity: "medium",
    description: "Contains suspicious HTML entity sequences",
  },

  // ─── Virtualization ────────────────────────────────────────────────────────
  {
    type: "virtualization",
    pattern: /simulate\s+a\s+(terminal|shell|command\s+line|console|bash)/i,
    severity: "high",
    description: "Attempts to simulate a terminal environment",
  },
  {
    type: "virtualization",
    pattern: /enter\s+(developer|debug|god|admin|sudo)\s+mode/i,
    severity: "critical",
    description: "Attempts to activate a special unrestricted mode",
  },
  {
    type: "virtualization",
    pattern: /unrestricted\s+(AI|model|assistant|mode)/i,
    severity: "high",
    description: "References an unrestricted mode",
  },
  {
    type: "virtualization",
    pattern: /\bDAN\b.*\b(do\s+anything|jailbreak)/i,
    severity: "critical",
    description: "DAN (Do Anything Now) jailbreak pattern",
  },

  // ─── Markdown/HTML Injection ───────────────────────────────────────────────
  {
    type: "markdown_injection",
    pattern: /!\[([^\]]*)\]\(https?:\/\/[^)]*\?[^)]*(?:data|token|secret|key|password|ssn|credit)/i,
    severity: "critical",
    description: "Image tag attempting data exfiltration via URL parameters",
  },

  // ─── Context Flooding ──────────────────────────────────────────────────────
  {
    type: "context_flooding",
    pattern: /(.{1,20})\1{50,}/,
    severity: "medium",
    description: "Highly repetitive content suggesting context flooding",
  },
];

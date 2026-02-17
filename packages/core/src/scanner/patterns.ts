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

  // ─── Indirect Injection (T2) ───────────────────────────────────────────────
  // Instructions embedded in external data sources (RAG, web content, emails, etc.)
  {
    type: "indirect_injection",
    pattern:
      /when\s+you\s+(see|read|encounter|process)\s+this\s*,?\s*(follow|execute|obey|carry\s+out)\s+(these|the)\s+instructions?/i,
    severity: "critical",
    description: "Trigger-based injection: instructions activated when content is read",
  },
  {
    type: "indirect_injection",
    pattern:
      /IMPORTANT\s*:\s*(the\s+)?following\s+instructions?\s+(override|supersede|replace|take\s+precedence)/i,
    severity: "critical",
    description: "Authority escalation claiming override priority in external data",
  },
  {
    type: "indirect_injection",
    pattern: /begin\s+hidden\s+instructions?/i,
    severity: "critical",
    description: "Explicit hidden instruction block marker (open)",
  },
  {
    type: "indirect_injection",
    pattern: /end\s+hidden\s+instructions?/i,
    severity: "critical",
    description: "Explicit hidden instruction block marker (close)",
  },
  {
    type: "indirect_injection",
    pattern: /\[\s*(system|INST|SYS|SYSTEM_PROMPT|INSTRUCTIONS?)\s*\]/i,
    severity: "high",
    description: "Fake role/instruction tags embedded in data content",
  },
  {
    type: "indirect_injection",
    pattern:
      /(?:AI|assistant|model|chatbot)\s*,?\s*(please\s+)?(ignore|disregard)\s+(the\s+)?(user|human|person)/i,
    severity: "critical",
    description: "Injected data addressing the model directly to bypass user intent",
  },
  {
    type: "indirect_injection",
    pattern:
      /(?:new|updated|revised)\s+instructions?\s+(?:for|to)\s+(?:the\s+)?(?:AI|assistant|model|system)/i,
    severity: "high",
    description: "External data claiming to contain updated instructions for the model",
  },

  // ─── Tool Abuse (T3) ──────────────────────────────────────────────────────
  // Tricking the model into making dangerous tool/function calls
  {
    type: "tool_abuse",
    pattern:
      /(?:call|execute|run|invoke|trigger)\s+(?:the\s+)?(?:function|tool|command|api|endpoint)\s/i,
    severity: "high",
    description: "Directive to execute a specific tool or function",
  },
  {
    type: "tool_abuse",
    pattern:
      /use\s+(?:the\s+)?(?:tool|function|command|api)\s+(?:to\s+)?(?:delete|drop|remove|destroy|truncate|wipe|erase|purge)/i,
    severity: "critical",
    description: "Instruction to use a tool for destructive operations",
  },
  {
    type: "tool_abuse",
    pattern:
      /use\s+(?:the\s+)?(?:tool|function|command|api)\s+(?:to\s+)?(?:send|transmit|post|email|upload|export)\s+(?:the\s+)?(?:data|information|content|file|results?)/i,
    severity: "critical",
    description: "Instruction to use a tool for unauthorized data transmission",
  },
  {
    type: "tool_abuse",
    pattern:
      /\{\s*"(?:function_call|tool_call|name|action)"\s*:\s*"[^"]+"\s*,\s*"(?:arguments|parameters|params|input)"\s*:/i,
    severity: "critical",
    description: "Embedded tool call JSON payload attempting to hijack function calling",
  },
  {
    type: "tool_abuse",
    pattern: /(?:execute|run)\s+(?:this\s+)?(?:shell|bash|sql|system)\s+(?:command|query|script)/i,
    severity: "critical",
    description: "Attempt to trigger shell or database command execution",
  },

  // ─── Data Exfiltration (T4) ────────────────────────────────────────────────
  // Attempts to extract system prompts, instructions, or sensitive data
  {
    type: "data_exfiltration",
    pattern:
      /(?:repeat|output|print|display|show|reveal|write\s+out|echo)\s+(?:the\s+|your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines|configuration|directives?)/i,
    severity: "critical",
    description: "Attempt to extract system prompt or instructions",
  },
  {
    type: "data_exfiltration",
    pattern:
      /what\s+(?:are|were)\s+(?:your|the)\s+(?:original\s+)?(?:instructions?|rules?|guidelines|directives?|system\s+prompt)/i,
    severity: "high",
    description: "Question probing for system instructions or rules",
  },
  {
    type: "data_exfiltration",
    pattern:
      /show\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|configuration|setup|initial\s+instructions?|context)/i,
    severity: "high",
    description: "Direct request to reveal system configuration",
  },
  {
    type: "data_exfiltration",
    pattern:
      /(?:fetch|request|get|load|curl|wget|http)\s*\(?\s*['"]?https?:\/\/[^\s'"]+\?[^\s'"]*(?:data|token|secret|key|content|prompt|message|context)=/i,
    severity: "critical",
    description: "URL fetch with data exfiltration parameters",
  },
  {
    type: "data_exfiltration",
    pattern:
      /(?:send|post|transmit|forward)\s+(?:the\s+|this\s+)?(?:data|conversation|chat|history|context|response)\s+(?:to|via)\s+/i,
    severity: "high",
    description: "Instruction to send conversation data to an external destination",
  },
  {
    type: "data_exfiltration",
    pattern:
      /(?:copy|paste|include|embed)\s+(?:the\s+|your\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:in|into|within)\s+(?:your\s+)?(?:response|output|reply|answer)/i,
    severity: "critical",
    description: "Attempt to embed system prompt in the model's response",
  },

  // ─── Privilege Escalation (T5) ─────────────────────────────────────────────
  // Attempts to gain elevated permissions or bypass authorization
  {
    type: "privilege_escalation",
    pattern: /grant\s+(?:me|user|this\s+user)\s+(?:admin|root|superuser|elevated)\s+access/i,
    severity: "critical",
    description: "Request to grant administrative access",
  },
  {
    type: "privilege_escalation",
    pattern:
      /bypass\s+(?:the\s+)?(?:authentication|authorization|access\s+control|permissions?|security|verification)/i,
    severity: "critical",
    description: "Attempt to bypass authentication or authorization",
  },
  {
    type: "privilege_escalation",
    pattern:
      /escalate\s+(?:my\s+|the\s+)?(?:privileges?|permissions?|access\s+level|role|clearance)/i,
    severity: "critical",
    description: "Explicit privilege escalation request",
  },
  {
    type: "privilege_escalation",
    pattern:
      /you\s+(?:have\s+been|are\s+(?:now\s+)?|were)\s+(?:granted|given)\s+(?:elevated|admin|root|full|unrestricted)\s+(?:permissions?|access|privileges?)/i,
    severity: "critical",
    description: "False claim that model has been granted elevated permissions",
  },
  {
    type: "privilege_escalation",
    pattern:
      /(?:disable|turn\s+off|deactivate|remove)\s+(?:the\s+)?(?:safety|content\s+)?(?:filters?|restrictions?|limits?|guardrails?|protections?)/i,
    severity: "critical",
    description: "Attempt to disable safety filters or restrictions",
  },
  {
    type: "privilege_escalation",
    pattern:
      /(?:i\s+am|this\s+is)\s+(?:an?\s+)?(?:admin|administrator|root\s+user|developer|system\s+admin|owner)/i,
    severity: "high",
    description: "False authority claim to gain elevated access",
  },

  // ─── Memory Poisoning (T10) ────────────────────────────────────────────────
  // Attempts to corrupt the model's persistent memory or context
  {
    type: "memory_poisoning",
    pattern:
      /remember\s+that\s+(?:your|the)\s+(?:instructions?|rules?|guidelines|purpose|role|goal)\s+(?:are|is|have\s+changed)/i,
    severity: "critical",
    description: "Attempt to overwrite model's understanding of its instructions",
  },
  {
    type: "memory_poisoning",
    pattern:
      /update\s+(?:your|the)\s+(?:memory|context|knowledge|state|configuration|settings)\s+(?:to|with|so\s+that)/i,
    severity: "high",
    description: "Attempt to modify model memory or context state",
  },
  {
    type: "memory_poisoning",
    pattern:
      /(?:from|in)\s+(?:our|the)\s+previous\s+conversation\s+you\s+(?:agreed|consented|confirmed|promised|said\s+you\s+would)/i,
    severity: "high",
    description: "False appeal to a prior agreement from a fabricated conversation",
  },
  {
    type: "memory_poisoning",
    pattern:
      /save\s+this\s+as\s+(?:a\s+)?(?:permanent|persistent|long[\s-]?term|core)\s+(?:instruction|rule|memory|directive|setting)/i,
    severity: "critical",
    description: "Attempt to inject a persistent instruction into model memory",
  },
  {
    type: "memory_poisoning",
    pattern:
      /(?:add|store|write|inject|insert)\s+(?:this\s+)?(?:into|to|in)\s+(?:your\s+)?(?:memory|context|knowledge\s+base|long[\s-]?term\s+memory)/i,
    severity: "high",
    description: "Attempt to inject content into model's memory or context store",
  },
  {
    type: "memory_poisoning",
    pattern:
      /your\s+(?:core|base|original|true)\s+(?:instructions?|programming|directive)\s+(?:is|are|says?|states?)\s+(?:to|that)/i,
    severity: "high",
    description: "Attempt to redefine what the model's original instructions say",
  },

  // ─── Chain Injection (T14) ─────────────────────────────────────────────────
  // Forcing the model to include specific payloads in its output
  {
    type: "chain_injection",
    pattern:
      /your\s+response\s+(?:must|should|shall|needs?\s+to)\s+(?:contain|include|start\s+with|begin\s+with|end\s+with)/i,
    severity: "high",
    description: "Attempt to force specific content into model's response",
  },
  {
    type: "chain_injection",
    pattern: /output\s+(?:the\s+)?following\s+(?:text\s+)?(?:exactly|verbatim|word\s+for\s+word)/i,
    severity: "high",
    description: "Instruction to output specific text verbatim",
  },
  {
    type: "chain_injection",
    pattern:
      /in\s+your\s+(?:next|following)\s+(?:response|reply|message|output)\s*,?\s*(?:include|add|insert|embed|place)/i,
    severity: "high",
    description: "Attempt to inject content into a subsequent model response",
  },
  {
    type: "chain_injection",
    pattern:
      /(?:append|prepend|add|attach|insert)\s+(?:this|the\s+following)\s+(?:to|at\s+the\s+(?:end|start|beginning)\s+of)\s+(?:your|the)\s+(?:output|response|reply|answer)/i,
    severity: "high",
    description: "Instruction to append or prepend content to model output",
  },
  {
    type: "chain_injection",
    pattern:
      /(?:always|every\s+time)\s+(?:include|add|append|output|say)\s+(?:this|the\s+following)\s+(?:in|at|to)\s+(?:your|every|each|all)\s+(?:response|reply|output|answer)/i,
    severity: "critical",
    description: "Persistent injection: forces content in every future response",
  },

  // ─── History Manipulation (T15) ────────────────────────────────────────────
  // Fabricating or falsifying conversation history
  {
    type: "history_manipulation",
    pattern:
      /in\s+(?:our|the)\s+(?:previous|last|earlier|prior)\s+(?:conversation|chat|session|discussion)\s+you\s+(?:said|told\s+me|mentioned|stated|confirmed|agreed)/i,
    severity: "high",
    description: "False reference to a previous conversation to establish false context",
  },
  {
    type: "history_manipulation",
    pattern:
      /you\s+(?:already|previously)\s+(?:agreed|consented|confirmed|approved|verified|said\s+(?:it\s+was|you\s+would))\s+(?:to|that)\s/i,
    severity: "high",
    description: "False claim that the model previously agreed to something",
  },
  {
    type: "history_manipulation",
    pattern:
      /we\s+(?:already\s+)?(?:established|agreed|confirmed|discussed|determined)\s+(?:earlier|previously|before|already)\s+that\s/i,
    severity: "high",
    description: "False claim about previously established context or agreement",
  },
  {
    type: "history_manipulation",
    pattern:
      /continuing\s+(?:from|where)\s+(?:we|you)\s+(?:left\s+off|stopped|were)\s*,?\s*you\s+were\s+(?:about\s+to|going\s+to|in\s+the\s+(?:middle|process)\s+of)/i,
    severity: "high",
    description: "Fabricated continuation of a non-existent previous conversation",
  },
  {
    type: "history_manipulation",
    pattern:
      /(?:as\s+)?(?:per|according\s+to)\s+(?:our|the)\s+(?:previous|earlier|prior)\s+(?:agreement|conversation|discussion|arrangement)/i,
    severity: "medium",
    description: "Appeal to a fabricated prior agreement or arrangement",
  },

  // ─── Denial of Wallet (T17) ────────────────────────────────────────────────
  // Attempts to cause excessive resource consumption / API cost inflation
  {
    type: "denial_of_wallet",
    pattern:
      /repeat\s+(?:this|the\s+(?:above|following|previous))\s+(\d{2,}|[a-z]+\s+(?:hundred|thousand|million|billion))\s+times/i,
    severity: "high",
    description: "Instruction to repeat content an excessive number of times",
  },
  {
    type: "denial_of_wallet",
    pattern:
      /(?:analyze|examine|inspect|evaluate|describe)\s+each\s+(?:character|word|letter|token|byte|symbol)\s+(?:individually|separately|one\s+(?:by|at\s+a)\s+(?:one|time))/i,
    severity: "medium",
    description: "Instruction to process input at an unnecessarily granular level",
  },
  {
    type: "denial_of_wallet",
    pattern:
      /(?:process|run|execute|iterate|perform)\s+(?:this\s+)?(?:in\s+)?(?:a\s+)?(?:loop|recursively|infinitely|forever|continuously|repeatedly)/i,
    severity: "high",
    description: "Instruction to process content in a loop or recursively",
  },
  {
    type: "denial_of_wallet",
    pattern:
      /(?:generate|create|produce|write|output)\s+(?:a\s+)?(?:response|text|content|essay|story)\s+(?:of\s+)?(?:at\s+least\s+)?(\d{4,})\s+(?:words?|tokens?|characters?|pages?)/i,
    severity: "medium",
    description: "Request for excessively long output to inflate token costs",
  },
  {
    type: "denial_of_wallet",
    pattern:
      /(?:expand|elaborate|detail)\s+(?:on\s+)?(?:every|each|all)\s+(?:point|item|word|sentence|paragraph)\s+(?:at\s+(?:great|maximum)\s+(?:length|detail))/i,
    severity: "medium",
    description: "Instruction to produce excessively detailed output for cost inflation",
  },

  // ─── Language Switching (T18) ──────────────────────────────────────────────
  // Mixed script usage to evade detection patterns
  {
    type: "language_switching",
    pattern:
      /(?:[A-Za-z]{3,})\s+(?:[\u0400-\u04FF]{3,})|(?:[\u0400-\u04FF]{3,})\s+(?:[A-Za-z]{3,})/,
    severity: "medium",
    description: "Mixed Latin and Cyrillic scripts detected (potential evasion technique)",
  },
  {
    type: "language_switching",
    pattern:
      /(?:[A-Za-z]{3,})\s+(?:[\u0600-\u06FF]{3,})|(?:[\u0600-\u06FF]{3,})\s+(?:[A-Za-z]{3,})/,
    severity: "medium",
    description: "Mixed Latin and Arabic scripts detected (potential evasion technique)",
  },
  {
    type: "language_switching",
    pattern:
      /(?:[A-Za-z]{3,})\s+(?:[\u4E00-\u9FFF]{2,})|(?:[\u4E00-\u9FFF]{2,})\s+(?:[A-Za-z]{3,})/,
    severity: "low",
    description: "Mixed Latin and CJK scripts detected (may be normal bilingual text)",
  },
  {
    type: "language_switching",
    pattern:
      /[\u0400-\u04FF][\u0041-\u005A\u0061-\u007A][\u0400-\u04FF]|[\u0041-\u005A\u0061-\u007A][\u0400-\u04FF][\u0041-\u005A\u0061-\u007A]/,
    severity: "high",
    description:
      "Interleaved Latin and Cyrillic characters within a word (homoglyph attack indicator)",
  },

  // ─── Model Fingerprinting (T19) ────────────────────────────────────────────
  // Probing to identify the model, version, or provider
  {
    type: "model_fingerprinting",
    pattern:
      /what\s+(?:model|version|LLM|AI|system)\s+(?:are\s+you|is\s+this|am\s+I\s+(?:talking|speaking)\s+(?:to|with))/i,
    severity: "low",
    description: "Question probing for model identity or version",
  },
  {
    type: "model_fingerprinting",
    pattern:
      /are\s+you\s+(?:GPT|ChatGPT|GPT[\s-]?4|GPT[\s-]?3|Claude|Gemini|Llama|Mistral|PaLM|Bard|Copilot|Anthropic)/i,
    severity: "low",
    description: "Direct question about whether model is a specific AI system",
  },
  {
    type: "model_fingerprinting",
    pattern:
      /what(?:'s|\s+is)\s+(?:your|the)\s+(?:training\s+data\s+)?(?:cutoff|knowledge\s+cutoff|training\s+cutoff)\s*(?:date)?/i,
    severity: "low",
    description: "Question probing for model training data cutoff date",
  },
  {
    type: "model_fingerprinting",
    pattern:
      /what\s+(?:company|organization|team)\s+(?:made|created|built|trained|developed|designed)\s+you/i,
    severity: "low",
    description: "Question probing for the organization behind the model",
  },
  {
    type: "model_fingerprinting",
    pattern:
      /(?:identify|reveal|disclose|tell\s+me)\s+(?:your\s+)?(?:model\s+(?:name|id|version|architecture|type)|underlying\s+(?:model|system|architecture))/i,
    severity: "medium",
    description: "Explicit request to reveal model architecture or identifier",
  },
  {
    type: "model_fingerprinting",
    pattern:
      /(?:what|which)\s+(?:large\s+)?(?:language\s+)?model\s+(?:powers?|(?:is\s+)?(?:behind|running|driving))\s+(?:this|you)/i,
    severity: "low",
    description: "Question about which language model powers the system",
  },
];

# EU AI Act — Aegis Alignment Guide

> **Disclaimer:** This mapping is indicative, not exhaustive. The EU AI Act is complex legislation with ongoing implementing acts, delegated acts, and regulatory guidance. Organizations deploying AI systems in or affecting the EU must work with legal counsel and compliance teams for their specific obligations. Aegis provides technical controls that contribute to compliance, but technical controls alone do not constitute compliance.

## Overview

The [EU AI Act](https://artificialintelligenceact.eu/) (Regulation (EU) 2024/1689) is the world's first comprehensive legal framework for artificial intelligence. It classifies AI systems by risk level and imposes obligations proportional to the risk. This document maps Aegis modules to the requirements most relevant to LLM-powered applications.

### Risk Classification

The EU AI Act defines four risk categories:

| Risk Level | Examples | Aegis Relevance |
| :--- | :--- | :--- |
| **Unacceptable** | Social scoring, real-time biometric identification in public | Aegis does not enable or prevent these use cases |
| **High-risk** | AI in critical infrastructure, employment, law enforcement, education | Aegis contributes to several Article 9-15 requirements |
| **Limited risk** | Chatbots, content generation | Transparency obligations (Article 50) — AuditLog supports |
| **Minimal risk** | Spam filters, AI-powered games | No specific obligations, but Aegis can still add defense |

Most LLM-powered applications with tool access, customer-facing interactions, or processing of personal data will likely fall under **high-risk** or **limited risk** classification. The exact classification depends on the application's purpose, deployment context, and affected population.

---

## Article-by-Article Mapping

### Article 9 — Risk Management System

> *High-risk AI systems shall have a risk management system established, implemented, documented, and maintained.*

**Requirements:**
- Identify and analyze known and reasonably foreseeable risks (Art. 9.2a)
- Estimate and evaluate risks that may emerge when used in accordance with its intended purpose (Art. 9.2b)
- Adopt suitable risk management measures (Art. 9.4)
- Test the system against the risk management measures (Art. 9.5-7)

**Aegis Contribution:**

| Requirement | Aegis Module | Implementation |
| :--- | :--- | :--- |
| Risk identification | **Threat Model** (PRD Section 7) | 19 cataloged threat types (T1-T19) with risk levels (low/medium/high/critical), covering prompt injection, jailbreaking, data exfiltration, denial of wallet, chain compromise, and more. |
| Risk estimation | **InputScanner** | Quantified risk scoring: composite `score` (0-1), per-detection `severity` levels, `safe` boolean. TrajectoryAnalyzer provides `drift` scores and `riskTrend` arrays. |
| Risk mitigation | **Full defense pipeline** | Layered defense: Quarantine > InputScanner > PromptBuilder > PolicyEngine > StreamMonitor > ActionValidator > AuditLog. Each layer addresses distinct risk categories. |
| Testing | **Test suite** | 3,619 unit tests, adversarial attack tests, 3,184 benign corpus tests (false positive prevention), fuzz testing with fast-check, integration tests. |
| Ongoing monitoring | **AuditLog + AlertingEngine** | Real-time monitoring with alerting rules for rate-spikes, session-kills, cost-anomalies, scan-block-rate, and repeated-attacker patterns. |

```ts
import { Aegis } from "@aegis-sdk/core";

// Risk management: layered defense with monitoring
const aegis = new Aegis({
  policy: "strict",
  scanner: {
    sensitivity: "balanced",
    encodingNormalization: true,
    entropyAnalysis: true,
    perplexityEstimation: true,
    manyShotDetection: true,
    languageDetection: true,
  },
  audit: {
    transports: ["json-file", "otel"],
    level: "all",
    path: "./audit/risk-management.jsonl",
    alerting: {
      enabled: true,
      rules: [
        {
          id: "risk-spike",
          condition: {
            type: "rate-spike",
            event: "scan_block",
            threshold: 10,
            windowMs: 60_000,
          },
          action: "webhook",
          webhookUrl: "https://hooks.example.com/risk-alerts",
        },
        {
          id: "cost-monitoring",
          condition: {
            type: "cost-anomaly",
            threshold: 50,
            windowMs: 300_000,
          },
          action: "log",
        },
      ],
    },
  },
});
```

### Article 10 — Data and Data Governance

> *High-risk AI systems which make use of techniques involving the training of AI models with data shall be developed on the basis of training, validation and testing data sets that meet the quality criteria referred to in paragraphs 2 to 5.*

**Requirements:**
- Data governance and management practices (Art. 10.2)
- Examination of data for biases, gaps, and errors (Art. 10.2f)
- Appropriate data quality criteria (Art. 10.3)

**Aegis Contribution:**

While Aegis does not manage training data, it provides data governance controls at inference time:

| Requirement | Aegis Module | Implementation |
| :--- | :--- | :--- |
| Data provenance | **Quarantine** | Every piece of untrusted content is tagged with its source (`user_input`, `api_response`, `web_content`, `email`, `file_upload`, `database`, `rag_retrieval`, `tool_output`, `mcp_tool_output`) and risk level. This creates an auditable record of data provenance throughout the pipeline. |
| Input validation | **InputScanner** | All inputs are scanned for injection attempts, encoding tricks, and anomalous patterns before reaching the model. Encoding normalization decodes obfuscated content to its canonical form. |
| Data quality | **PolicyEngine** | `input.maxLength`, `input.blockPatterns`, and `input.requireQuarantine` enforce input quality gates. |
| Bias detection signals | **InputScanner** | `languageDetection` identifies language switching that could exploit weaker safety training in low-resource languages. |

```ts
import { quarantine } from "@aegis-sdk/core";

// Data governance: explicit source tracking for all external data
const userData = quarantine(formInput, {
  source: "user_input",
  risk: "medium",
});

const apiData = quarantine(externalApiResponse, {
  source: "api_response",
  risk: "medium",
});

const ragData = quarantine(vectorSearchResult, {
  source: "rag_retrieval",
  risk: "medium",  // RAG content may contain injected payloads
});

const emailData = quarantine(incomingEmailBody, {
  source: "email",
  risk: "high",  // Email is a common injection vector
});
```

### Article 13 — Transparency and Provision of Information

> *High-risk AI systems shall be designed and developed in such a way as to ensure that their operation is sufficiently transparent to enable deployers to interpret the system's output and use it appropriately.*

**Requirements:**
- Understandable information about the AI system's capabilities and limitations (Art. 13.2)
- AI system operation should be transparent (Art. 13.1)
- Users should be able to interpret outputs (Art. 13.3)

**Aegis Contribution:**

| Requirement | Aegis Module | Implementation |
| :--- | :--- | :--- |
| Decision transparency | **AuditLog** | Every security decision is logged with structured event types: `scan_pass`, `scan_block`, `scan_trajectory`, `quarantine_create`, `quarantine_release`, `unsafe_unwrap`, `stream_violation`, `action_block`, `action_approve`, `kill_switch`, `session_quarantine`, `message_integrity_fail`, `chain_step_scan`, `denial_of_wallet`, `policy_violation`. |
| Explainable detections | **InputScanner** | Each detection includes: `type` (semantic category), `pattern` (what rule matched), `matched` (the specific text), `severity`, `position` (character range), and `description` (human-readable explanation). |
| Decision records | **AuditLog** | Every entry includes `decision` field (`allowed`, `blocked`, `flagged`, `info`), `sessionId`, `requestId`, and `context` with arbitrary metadata. |
| Interpretable scoring | **ScanResult** | Composite `score`, individual detection severities, `language` analysis, `entropy` analysis, and optional `perplexity` analysis provide layered, interpretable risk signals. |

```ts
const aegis = new Aegis({
  audit: {
    transports: ["json-file", "otel"],
    level: "all",  // Log every decision, not just violations
    path: "./audit/transparency.jsonl",
    redactContent: false,  // Keep full content for transparency
                           // (consider data protection implications)
  },
});

// Query audit log programmatically
const auditLog = aegis.getAuditLog();
const recentEvents = auditLog.getEntries();

// Each entry is fully structured and explainable:
// {
//   timestamp: Date,
//   event: "scan_block",
//   decision: "blocked",
//   sessionId: "sess-123",
//   requestId: "req-456",
//   context: {
//     score: 0.85,
//     detections: 2,
//     strategy: "all-user"
//   }
// }
```

### Article 14 — Human Oversight

> *High-risk AI systems shall be designed and developed in such a way, including with appropriate human-machine interface tools, that they can be effectively overseen by natural persons during the period in which they are in use.*

**Requirements:**
- Enable human oversight during AI system operation (Art. 14.1)
- Ability to decide not to use the system or to disregard its output (Art. 14.3a)
- Ability to intervene on or interrupt the system (Art. 14.3d)
- "Stop button" or similar procedure to halt operation in a safe state (Art. 14.4e)

**Aegis Contribution:**

| Requirement | Aegis Module | Implementation |
| :--- | :--- | :--- |
| Human-in-the-loop | **ActionValidator** | `onApprovalNeeded` callback pauses execution and requires explicit human approval before sensitive tool calls execute. `requireApproval` capability list defines which operations need human sign-off. |
| Intervention capability | **StreamMonitor** | Kill switch via `controller.terminate()` aborts the output stream immediately on violation. `onViolation` callback enables custom intervention logic. |
| Stop button | **Recovery modes** | `quarantine-session` locks the session (all further input blocked). `terminate-session` throws a terminal error requiring a new instance. Both provide immediate containment. |
| Override capability | **PolicyEngine** | `onBlocked` callbacks on scan failures give application code the ability to decide how to handle blocks. Recovery mode `reset-last` strips the offending message and allows the conversation to continue. |
| Monitoring | **AuditLog + AlertingEngine** | Real-time visibility into all AI system actions with alerting for anomalous patterns. |

```ts
const aegis = new Aegis({
  policy: {
    version: 1,
    capabilities: {
      allow: ["search", "read_file"],
      deny: ["delete_*", "admin_*"],
      requireApproval: ["send_email", "update_database", "deploy"],
    },
    limits: {
      send_email: { max: 5, window: "1h" },
    },
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
    alignment: { enabled: true, strictness: "high" },
    dataFlow: { piiHandling: "block", externalDataSources: [], noExfiltration: true },
  },
  validator: {
    onApprovalNeeded: async (request) => {
      // Present the proposed action to a human operator
      const approved = await presentApprovalDialog({
        tool: request.proposedAction.tool,
        params: request.proposedAction.params,
        originalRequest: request.originalRequest,
      });
      return approved;
    },
  },
  // Session-level containment capability
  recovery: {
    mode: "quarantine-session",
    notifyUser: true,
  },
});

// Check if session has been contained
if (aegis.isSessionQuarantined()) {
  // Session has been locked — present safe state to user
  showSafeStateMessage();
}
```

### Article 15 — Accuracy, Robustness and Cybersecurity

> *High-risk AI systems shall be designed and developed in such a way that they achieve an appropriate level of accuracy, robustness and cybersecurity, and perform consistently in those respects throughout their lifecycle.*

**Requirements:**
- Appropriate level of accuracy (Art. 15.1)
- Resilient against attempts by unauthorized third parties to alter use or performance (Art. 15.4)
- Robustness against errors, faults, or inconsistencies (Art. 15.2)
- Technical and organizational cybersecurity measures (Art. 15.5)

**Aegis Contribution:**

| Requirement | Aegis Module | Implementation |
| :--- | :--- | :--- |
| Accuracy | **Test suite** | 3,619 tests with 3,184 benign corpus queries validate that defenses do not produce excessive false positives. Coverage: 96.85% statements, 92.41% branches, 98.64% functions, 97.44% lines. |
| Adversarial robustness | **InputScanner** | Multi-layer detection: pattern matching, encoding normalization, entropy analysis, perplexity estimation, many-shot detection, language switching detection. Each layer catches different evasion strategies. |
| Cybersecurity — input defense | **InputScanner + Quarantine** | All external input is taint-tracked and scanned before reaching the model. Known attack patterns are maintained and updated via `scripts/sync-patterns.ts`. |
| Cybersecurity — output defense | **StreamMonitor** | Real-time output monitoring with kill switch capability. PII detection, secret detection, injection payload scanning, markdown sanitization. |
| Cybersecurity — integrity | **MessageSigner** | HMAC-SHA256 conversation integrity verification. Chained signatures ensure message ordering integrity. Detects client-side history manipulation (fabricated assistant messages). |
| Cybersecurity — tool security | **ActionValidator** | Tool call validation with policy enforcement, rate limiting, MCP parameter scanning, data exfiltration prevention, and denial-of-wallet detection. |
| Lifecycle robustness | **AlertingEngine** | Continuous monitoring with configurable alert rules enables detection of accuracy or robustness degradation in production. |

```ts
const aegis = new Aegis({
  policy: "strict",
  scanner: {
    sensitivity: "balanced",
    encodingNormalization: true,
    entropyAnalysis: true,
    perplexityEstimation: true,
    manyShotDetection: true,
    languageDetection: true,
  },
  monitor: {
    detectPII: true,
    detectSecrets: true,
    detectInjectionPayloads: true,
    sanitizeMarkdown: true,
  },
  // Conversation integrity protection
  integrity: {
    secret: process.env.AEGIS_HMAC_SECRET!,
    algorithm: "SHA-256",
    assistantOnly: true,
  },
  validator: {
    scanMcpParams: true,
    denialOfWallet: {
      maxOperations: 100,
      window: "5m",
      maxSandboxTriggers: 10,
      maxToolCalls: 50,
    },
  },
});

// Verify conversation integrity before processing
const signer = aegis.getMessageSigner();
if (signer) {
  const integrityResult = await signer.verifyConversation(signedConversation);
  if (!integrityResult.valid) {
    console.error("Conversation tampering detected!", {
      tamperedIndices: integrityResult.tamperedIndices,
      chainValid: integrityResult.chainValid,
    });
    // Reject the request — conversation has been manipulated
  }
}
```

---

## Article 50 — Transparency Obligations for Certain AI Systems

> *Providers shall ensure that AI systems intended to directly interact with natural persons are designed and developed in such a way that the natural persons concerned are informed that they are interacting with an AI system.*

While this is primarily a UI/UX obligation (the application must disclose AI involvement), Aegis's AuditLog supports transparency by providing a complete, queryable record of all AI interactions and security decisions. This record can be made available to users, regulators, or auditors as needed.

---

## High-Risk Classification Considerations

Determining whether your LLM application qualifies as "high-risk" under the EU AI Act requires legal analysis. Common factors that may trigger high-risk classification:

| Factor | Consideration | Aegis Relevance |
| :--- | :--- | :--- |
| **Critical infrastructure** | AI managing energy, transport, water, digital infrastructure | Aegis provides defense-in-depth for AI systems in these contexts |
| **Employment** | AI in recruitment, hiring decisions, performance evaluation | PII protection and audit trails are particularly relevant |
| **Education** | AI grading, admissions, learning assessment | Transparency and human oversight controls apply |
| **Law enforcement** | AI in evidence evaluation, crime prediction | All Article 9-15 requirements apply; maximum security configuration recommended |
| **Healthcare** | AI in medical device, diagnosis, treatment planning | PII protection (HIPAA alignment), audit trails, human oversight all critical |
| **Financial services** | AI in credit scoring, insurance, fraud detection | Data governance, transparency, accuracy requirements all apply |

### Recommended Configuration for High-Risk Systems

```ts
// Maximum security for EU AI Act high-risk compliance support
const aegis = new Aegis({
  policy: "strict",
  scanner: {
    sensitivity: "paranoid",  // Lowest tolerance for suspicious patterns
    encodingNormalization: true,
    entropyAnalysis: true,
    perplexityEstimation: true,
    manyShotDetection: true,
    languageDetection: true,
  },
  monitor: {
    detectPII: true,
    piiRedaction: true,
    detectSecrets: true,
    detectInjectionPayloads: true,
    sanitizeMarkdown: true,
  },
  integrity: {
    secret: process.env.AEGIS_HMAC_SECRET!,
    algorithm: "SHA-256",
  },
  validator: {
    scanMcpParams: true,
    onApprovalNeeded: async (request) => {
      return await humanApprovalWorkflow(request);
    },
    denialOfWallet: {
      maxOperations: 50,
      window: "5m",
      maxSandboxTriggers: 5,
      maxToolCalls: 25,
    },
  },
  recovery: {
    mode: "quarantine-session",
    notifyUser: true,
  },
  audit: {
    transports: ["json-file", "otel"],
    level: "all",
    path: "./audit/high-risk-system.jsonl",
    redactContent: false,  // Full transparency for regulatory review
    alerting: {
      enabled: true,
      rules: [
        {
          id: "any-block",
          condition: {
            type: "rate-spike",
            event: "scan_block",
            threshold: 1,  // Alert on every block for high-risk systems
            windowMs: 60_000,
          },
          action: "webhook",
          webhookUrl: process.env.SECURITY_WEBHOOK_URL!,
        },
        {
          id: "session-kills",
          condition: {
            type: "session-kills",
            threshold: 1,
            windowMs: 300_000,
          },
          action: "webhook",
          webhookUrl: process.env.SECURITY_WEBHOOK_URL!,
        },
      ],
    },
  },
  agentLoop: {
    defaultMaxSteps: 10,  // Conservative step budget
    defaultRiskBudget: 1.5,  // Low risk tolerance
    privilegeDecay: { 5: 0.5, 8: 0.25 },  // Aggressive privilege reduction
  },
});
```

---

## Summary Matrix

| EU AI Act Article | Aegis Module(s) | Coverage Level | Notes |
| :--- | :--- | :--- | :--- |
| **Art. 9** — Risk Management | Threat model, full pipeline, AuditLog, AlertingEngine | **Strong** | Technical risk controls with monitoring |
| **Art. 10** — Data Governance | Quarantine, InputScanner, PolicyEngine | **Supporting** | Inference-time data provenance, not training data |
| **Art. 13** — Transparency | AuditLog, InputScanner (explainable detections) | **Strong** | Every decision logged with full context |
| **Art. 14** — Human Oversight | ActionValidator (approval gates), StreamMonitor (kill switch), recovery modes | **Strong** | Multiple intervention mechanisms |
| **Art. 15** — Accuracy, Robustness, Cybersecurity | InputScanner, StreamMonitor, MessageSigner, ActionValidator, test suite | **Strong** | Multi-layer defense with integrity verification |
| **Art. 50** — Transparency (limited risk) | AuditLog | **Supporting** | Records, not UI disclosure |

## What Aegis Does NOT Address

To be straightforward about limitations:

- **Legal classification**: Aegis does not determine whether your system is "high-risk" under the EU AI Act. This requires legal analysis.
- **Conformity assessment**: Aegis does not produce conformity assessment documentation. It provides technical controls that can be referenced in such documentation.
- **Fundamental rights impact assessment**: Required for certain high-risk systems. This is a legal and organizational process, not a technical control.
- **CE marking**: Aegis does not contribute to CE marking requirements, which involve broader system-level conformity assessment.
- **Training data governance**: Article 10 primarily concerns training data quality. Aegis operates at inference time.
- **Model accuracy and bias**: Aegis does not evaluate whether the model produces accurate, fair, or unbiased outputs.
- **Post-market monitoring plan**: Required under Article 72. Aegis's AlertingEngine and AuditLog can be components of such a plan, but the plan itself is an organizational deliverable.
- **Registration in the EU database**: Required for high-risk systems under Article 71. This is a regulatory process, not a technical control.

Organizations subject to the EU AI Act should engage legal counsel familiar with AI regulation and use Aegis as one component of a broader compliance strategy.

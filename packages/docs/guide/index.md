# Introduction

Aegis SDK (`@aegis-sdk/core`) is a streaming-first prompt injection defense library for JavaScript and TypeScript. It provides defense-in-depth against prompt injection attacks — the [#1 vulnerability in AI applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) according to OWASP's LLM Top 10.

## The Problem

LLMs cannot distinguish between instructions and data. Everything is processed as tokens through the same attention mechanism. When your AI application reads a customer email, scrapes a webpage, or queries a database, any content in those sources can potentially hijack the model's behavior.

Most existing security tools assume you receive the full response before showing it to the user. But modern AI applications **stream** responses. Developers face a binary choice:

- **Fast and insecure** — stream raw tokens immediately
- **Slow and secure** — buffer the full response to scan it, adding seconds of latency

Nobody picks slow. So developers skip security entirely.

## The Solution

Aegis solves this with **Optimistic Defense**: stream tokens to the user immediately while analyzing content in parallel. A kill switch aborts the stream the moment a violation is detected.

This approach decouples delivery from analysis, giving you both speed and safety.

## Defense Pipeline

Aegis applies multiple layers of defense across the full request lifecycle:

```
User Input → Quarantine → Input Scanner → Prompt Builder
  → Policy Check → LLM streams → Stream Monitor → Action Validator → Audit Log
```

| Module | Purpose |
|--------|---------|
| **Quarantine** | Taint-tracks untrusted content at the type level |
| **Input Scanner** | Pattern matching + heuristic injection detection |
| **Prompt Builder** | Sandwich pattern prompt construction with delimiters |
| **Policy Engine** | Declarative security policy (CSP for AI) |
| **Stream Monitor** | Real-time output scanning via `TransformStream` |
| **Action Validator** | Tool call validation, rate limiting, exfiltration prevention |
| **Sandbox** | Zero-capability model for processing untrusted content |
| **Audit Log** | Security event logging with alerting and OpenTelemetry |

## Key Design Principles

### Optimistic Defense

Stream tokens immediately while monitoring in parallel. The kill switch (`controller.terminate()`) aborts the stream on violation. Users see responses start instantly; the security layer operates transparently.

### Type-Level Safety

The `Quarantined<T>` wrapper prevents untrusted content from reaching system prompts at compile time. You must explicitly unwrap quarantined values, creating a clear audit trail.

### Sliding Window Detection

Cross-chunk pattern detection uses a rolling buffer to catch injection patterns that span across stream chunks — something naive per-chunk scanning would miss.

### Sandwich Pattern

The Prompt Builder uses the sandwich pattern for prompt construction: system instructions at the top, delimited user content in the middle, reinforcement instructions at the bottom.

## What's Next

- [Quick Start](/guide/quick-start) — Get Aegis protecting your app in under 5 minutes
- [Installation](/guide/installation) — Install for your package manager and framework
- [Configuration](/guide/configuration) — Customize policies, scanner sensitivity, and recovery modes

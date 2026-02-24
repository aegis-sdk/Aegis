---
title: Comparison
description: How Aegis SDK compares to other prompt injection defense and AI guardrails libraries.
---

# Comparison

This page compares Aegis to other prompt injection defense and AI guardrails libraries. We have tried to be accurate and fair. If you find an error, please [open an issue](https://github.com/aegis-sdk/Aegis/issues).

Every tool on this list is doing meaningful work on AI safety. The right choice depends on your stack, threat model, and operational requirements.

## Feature Matrix

| Feature | Aegis SDK | NeMo Guardrails | LLM Guard | Guardrails AI | Lakera Guard | @openai/guardrails |
|---------|-----------|-----------------|-----------|---------------|-------------|-------------------|
| **Language** | TypeScript/JS | Python | Python | Python | API (any lang) | TypeScript/JS |
| **Streaming support** | Native (TransformStream, optimistic defense) | No (full response) | No (full response) | No (full response) | No (API-based) | Partial |
| **Provider-agnostic** | Yes (adapters for OpenAI, Anthropic, Google, Mistral, Ollama) | NVIDIA-focused, supports others via config | Yes | Yes | Yes (API) | OpenAI only |
| **Taint tracking** | Yes (`Quarantined<T>` compile-time wrapper) | No | No | No | No | No |
| **Open source license** | MIT | Apache 2.0 | Apache 2.0 | Apache 2.0 | Proprietary (API) | MIT |
| **Action/tool validation** | Yes (glob patterns, rate limits, exfiltration prevention) | Colang action control | No | Validators for specific actions | No | No |
| **Multi-turn detection** | Yes (TrajectoryAnalyzer: crescendo, keyword escalation) | Yes (Colang dialog rails) | No | No | Limited | No |
| **Many-shot detection** | Yes (configurable threshold) | No | No | No | Unknown | No |
| **Adversarial suffix detection** | Yes (perplexity analysis, entropy analysis) | No | Partial (transformer-based) | No | Yes (ML-based) | No |
| **Output monitoring** | Real-time stream scanning with kill switch | Post-completion rails | Post-completion scan | Post-completion validation | Post-completion API call | Post-completion |
| **Self-hosted** | Yes (zero external dependencies) | Yes | Yes | Yes | No (SaaS only) | Yes |
| **ML model required** | No (deterministic + optional LLM Judge) | Yes (LLM-based rails) | Yes (transformer classifiers) | Depends on validator | Yes (hosted ML) | No |
| **Framework integrations** | Vercel AI, Next.js, Express, Fastify, Hono, SvelteKit, Koa, LangChain | LangChain | LangChain, REST API | LangChain, REST API | REST API | Vercel AI |

## Detailed Notes

### NeMo Guardrails

NVIDIA's NeMo Guardrails uses Colang, a domain-specific language, to define conversational boundaries. It is a powerful tool for Python applications with complex dialog flows. Its multi-turn control via Colang dialog rails is more expressive than Aegis's keyword-based trajectory analysis. However, it requires a Python runtime and processes complete responses rather than streams. If your application is built in Python and you need fine-grained dialog control, NeMo Guardrails is a strong choice.

### LLM Guard

Protect AI's LLM Guard provides a suite of scanner modules (prompt injection, toxicity, PII, ban topics) backed by transformer models. It offers broader content moderation coverage than Aegis, which focuses specifically on injection defense. The trade-off is that LLM Guard requires ML model downloads (hundreds of MB) and Python, while Aegis runs with zero external dependencies in any JS runtime. If you need toxicity classification or topic banning and your stack is Python, LLM Guard covers more ground.

### Guardrails AI

Guardrails AI focuses on structured output validation -- ensuring LLM responses conform to schemas, pass quality checks, and meet business rules. It solves a different primary problem than Aegis. Where Aegis is about preventing injection attacks, Guardrails AI is about ensuring output correctness. The two are complementary. If you need both injection defense and structured output validation in a Python stack, you might use both.

### Lakera Guard

Lakera Guard is a hosted API service with ML-based classification for prompt injection, PII, and content moderation. It requires no self-hosting and the classification models are maintained by Lakera's team. The trade-off is vendor lock-in, per-request pricing, added network latency for every call, and no streaming support. If you want managed classification without maintaining your own detection logic and can accept the latency and cost, Lakera is convenient.

### @openai/guardrails

OpenAI's guardrails package provides input and output validation specifically for OpenAI models. It is lightweight and integrates well with the OpenAI SDK and Vercel AI. However, it is OpenAI-specific -- it does not work with Anthropic, Google, or other providers. It also lacks taint tracking, tool validation, and multi-turn attack detection. If your application exclusively uses OpenAI and you need basic input/output validation, it is a simpler option.

## When to Use Aegis

Aegis is a good fit when:

- **Your application is built in JavaScript or TypeScript.** Aegis is the only defense-in-depth library designed specifically for the JS/TS ecosystem. It runs in Node.js, Deno, Bun, Cloudflare Workers, and browser environments.

- **You are streaming LLM responses.** Aegis's optimistic defense model (stream immediately, kill on violation) is unique among guardrails libraries. Most alternatives require buffering the full response before scanning, adding seconds of latency.

- **You need defense-in-depth, not just a single classifier.** Aegis layers pattern matching, entropy analysis, perplexity estimation, trajectory tracking, taint tracking, tool validation, and an optional LLM Judge. Each layer covers gaps in the others.

- **You want zero external dependencies for the core library.** The `@aegis-sdk/core` package has no runtime dependencies. No model downloads, no Python sidecar, no API calls (unless you opt into the LLM Judge).

- **You are building agentic applications with tool calling.** Aegis's ActionValidator with glob-based allow/deny lists, rate limiting, and exfiltration prevention is purpose-built for tool-calling agents.

- **You want compile-time safety.** The `Quarantined<T>` type makes it a TypeScript error to pass untrusted content where trusted content is expected. No other library offers this.

## When NOT to Use Aegis

Be honest with yourself about these limitations:

- **Your stack is Python-only.** Aegis does not have a Python implementation. NeMo Guardrails, LLM Guard, or Guardrails AI are better choices for Python applications.

- **You need ML-based content classification.** Aegis uses deterministic pattern matching, statistical analysis (entropy, perplexity), and an optional LLM Judge for semantic analysis. It does not include trained classifiers for toxicity, topic detection, or sentiment analysis. If you need those capabilities, LLM Guard or Lakera Guard are more appropriate.

- **You need enterprise support and SLAs.** Aegis is an open-source MIT-licensed library maintained by its contributors. There is no enterprise support tier, no SLA, and no dedicated security team. If your organization requires vendor-backed support, Lakera Guard (hosted) or NeMo Guardrails (NVIDIA) offer commercial backing.

- **You need comprehensive content moderation.** Aegis focuses on prompt injection and tool-use safety. It does not classify hate speech, sexual content, or other content moderation categories. For content moderation, use a dedicated service alongside Aegis.

- **You need regulatory certification.** Aegis is not certified for SOC 2, HIPAA, or other compliance frameworks. It can help you meet security requirements (audit logging, PII handling), but the library itself is not a certified product.

## Complementary Tools

Aegis does not have to be the only security layer in your application. Common pairings:

| Aegis handles | Complement with |
|---------------|-----------------|
| Injection detection | Content moderation API (OpenAI Moderation, Perspective API) for toxicity |
| Tool validation | Your application's authorization layer for business logic |
| Audit logging | Your SIEM (Splunk, Datadog, Elastic) via OTel transport |
| PII redaction | A dedicated PII service (Presidio, AWS Comprehend) for higher accuracy |
| Streaming defense | Rate limiting at the infrastructure level (API gateway, WAF) |

---
layout: home

hero:
  name: Aegis SDK
  text: Streaming-first prompt injection defense
  tagline: Defense-in-depth for JavaScript & TypeScript AI applications — zero-latency streaming, 10 security modules, LLM Judge, multi-modal scanning, and built-in red teaming.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/
    - theme: alt
      text: View on GitHub
      link: https://github.com/aegis-sdk/Aegis

features:
  - icon: "⚡"
    title: Zero-Latency Streaming
    details: Optimistic defense streams tokens to users immediately while scanning in parallel. A kill switch aborts the stream the moment a violation is detected — no buffering delay.
  - icon: "🛡️"
    title: Defense in Depth
    details: 10 security modules cover the full pipeline — Quarantine, Input Scanner, Perplexity Analysis, LLM Judge, Prompt Builder, Policy Engine, Action Validator, Stream Monitor, Multi-Modal Scanner, and Audit Log.
  - icon: "🔌"
    title: Framework Native
    details: First-class adapters for Vercel AI SDK, Next.js, Express, SvelteKit, Hono, and Fastify. Provider wrappers for OpenAI, Anthropic, Google, Mistral, Ollama, and LangChain.
  - icon: "🧪"
    title: Red Team Included
    details: Built-in attack suites with 1,000+ adversarial payloads to test your defenses. Promptfoo integration, boss battle challenges, and a CLI scanner for CI/CD pipelines.
  - icon: "🧠"
    title: LLM Judge
    details: Semantic intent alignment verification via a secondary LLM call. Catches subtle manipulation that deterministic pattern matching alone cannot detect.
  - icon: "📷"
    title: Multi-Modal Scanning
    details: Scan images, PDFs, audio, and documents for injection payloads. Bring your own text extractor — Aegis runs the full scanner pipeline on extracted content.
---

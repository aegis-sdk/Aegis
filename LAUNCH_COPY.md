# Aegis SDK — Launch Copy

Copy-paste ready content for Product Hunt, social media, Hacker News, and outreach.

---

## Product Hunt

### Tagline (60 chars max)

```
Streaming-first prompt injection defense for JS/TS apps
```

### One-liner (160 chars)

```
Aegis protects your AI apps from prompt injection, data leakage, and tool abuse — without adding latency. Streams tokens in real-time, kills the stream if something goes wrong.
```

### Description

**The Problem**

Every JavaScript developer building with LLMs faces a bad choice: stream tokens fast with zero protection, or buffer the full response and scan it — adding 2-10 seconds of latency. Nobody chooses slow. So nobody chooses secure.

Prompt injection is the #1 vulnerability in AI applications (OWASP LLM Top 10). An attacker can make your chatbot leak system prompts, exfiltrate PII, or call tools it shouldn't. And if you're building agentic apps with tool calling, the attack surface gets worse with every step.

**The Solution**

Aegis is an open-source TypeScript library that eliminates this tradeoff. It streams tokens to the user immediately while monitoring them in parallel. If the output starts leaking secrets or injection payloads, it kills the stream mid-sentence.

Three lines of code to protect a Next.js chatbot:

```typescript
const aegis = new Aegis({ policy: 'balanced' });
const safeMessages = await aegis.guardInput(messages);
experimental_transform: aegis.createStreamTransform()
```

**What makes it different:**

- Streaming-first — tokens flow immediately, no buffering. Kill switch aborts on violation.
- Defense-in-depth — 7 layers: input scanning, taint tracking, prompt structure, policy engine, output monitoring, tool validation, audit logging.
- 100% detection rate on 76 adversarial payloads across 14 attack categories. 0.24% false positive rate on 5,000 benign queries.
- Zero dependencies in the core library. No ML models to download, no Python sidecar, no API calls.
- Works with any LLM provider — OpenAI, Anthropic, Google, Mistral, Ollama.
- Works with any JS framework — Next.js, SvelteKit, Nuxt, Express, Hono, Fastify.
- TypeScript-first with compile-time taint tracking (`Quarantined<T>` type prevents passing untrusted content where trusted content is expected).

**Built on proven security patterns:**

Taint tracking (Perl, 1989), parameterized queries (SQL-92), Content Security Policy (W3C, 2010), capability-based security (1966), process sandboxing (Chrome, 2008). We didn't invent new concepts — we applied decades of security engineering to a new problem.

**Numbers:**

- 5,943 tests passing
- 19 threat categories covered
- <0.02ms mean scan latency
- MIT licensed
- 17 npm packages

### First Comment (post this after launching)

Hey PH! I'm Josh, and I built Aegis because I kept seeing the same problem: every AI app I worked on had zero protection against prompt injection. The Python ecosystem has options (LLM Guard, NeMo Guardrails), but the JS/TS ecosystem — where most web apps are built — had nothing.

The key insight was that you can't ask developers to add 2-10 seconds of latency to scan LLM output. They just won't do it. So Aegis streams tokens through immediately while watching for problems in parallel. If it detects a leak, it kills the stream. The user sees tokens flowing fast, and you get real-time protection.

Some honest limitations: Aegis uses deterministic pattern matching and heuristics, not ML classifiers. That means novel zero-day attacks can get through the scanner — but that's why we layer 7 defense mechanisms so when one fails, the next catches it. We also can't classify toxicity or off-topic content — we focus specifically on injection attacks and tool-use safety.

Happy to answer any questions about the architecture or threat model.

---

## Hacker News — Show HN

### Title

```
Show HN: Aegis – Streaming-first prompt injection defense for JS/TS
```

### Body

I built Aegis because the JS/TS ecosystem had no prompt injection defense library. Python has NeMo Guardrails, LLM Guard, and Guardrails AI. JavaScript had nothing.

The core problem: scanning LLM output for injection/leakage requires buffering the entire response before showing it to the user. That adds 2-10 seconds of latency. Nobody will accept that in production. So the standard approach is... no protection at all.

Aegis solves this with an optimistic streaming model. Tokens flow through to the user immediately via a TransformStream. In parallel, a sliding window buffer scans for PII, secrets, canary tokens, and injection payloads. If it detects a violation, it calls controller.terminate() — cleanly killing the stream mid-sentence.

The scanner uses deterministic pattern matching + heuristic scoring (no ML models required). At the default "balanced" sensitivity, it catches 100% of 76 adversarial payloads across 14 threat categories with a 0.24% false positive rate on 5,000 benign queries. Mean scan latency is 0.019ms.

Other things it does:
- Quarantined<T> type — taint tracking at the TypeScript level. Untrusted content can't be passed where trusted content is expected.
- PromptBuilder — parameterized prompts (like parameterized SQL queries) that structurally separate instructions from user data.
- ActionValidator — policy engine for tool calls. Allow/deny lists, rate limits, exfiltration detection (catches read-then-send patterns).
- Perplexity analysis — catches GCG-style adversarial suffixes via character n-gram entropy.
- Multi-turn trajectory analysis — detects crescendo attacks where each message is individually benign but the conversation escalates.

What it can't do: no ML-based content classification (toxicity, topic detection), no trained classifiers. It's deterministic + heuristic. Novel attacks not in the pattern database will bypass the scanner, which is why we layer 7 defense mechanisms.

Works with OpenAI, Anthropic, Google, Mistral, Ollama. Integrates with Next.js, SvelteKit, Express, Hono, Fastify, LangChain. Zero runtime dependencies in core. MIT licensed.

GitHub: https://github.com/aegis-sdk/Aegis
npm: npm install @aegis-sdk/core
Docs: [your docs URL]

---

## Twitter/X Threads

### Launch Thread

1/ Announcing Aegis.js — open-source prompt injection defense for JavaScript/TypeScript.

The #1 vulnerability in AI apps is prompt injection. The JS ecosystem had zero defense libraries. Today that changes.

npm install @aegis-sdk/core

2/ The problem: every AI app faces a choice.

Stream tokens fast → zero protection
Buffer full response, scan it → +2-10s latency

Nobody chooses slow. So nobody chooses secure.

Aegis eliminates this tradeoff.

3/ How it works: tokens stream through to the user immediately. In parallel, a sliding window scanner watches for:

- PII leaking
- System prompt extraction
- Injection payloads
- Canary token violations

If it detects something → kill switch fires → stream dies mid-sentence.

4/ Detection accuracy:

100% true positive rate on 76 adversarial payloads
0.24% false positive rate on 5,000 benign queries
0.019ms mean scan latency

14 threat categories. Zero ML models required. Zero external dependencies.

5/ It's not just input scanning. Aegis has 7 defense layers:

- Quarantine (taint tracking)
- Input Scanner
- Prompt Builder (parameterized prompts)
- Policy Engine
- Stream Monitor
- Action Validator (tool call protection)
- Audit Log

6/ Works with any provider: OpenAI, Anthropic, Google, Mistral, Ollama.

Works with any framework: Next.js, SvelteKit, Nuxt, Express, Hono, Fastify.

3 lines of code to protect a chatbot:

```
const aegis = new Aegis({ policy: 'balanced' });
const safe = await aegis.guardInput(messages);
experimental_transform: aegis.createStreamTransform()
```

7/ What it can't do (being honest):

- No ML classifiers for toxicity/topic detection
- Novel zero-day patterns can bypass the scanner
- Multi-turn attacks can be arbitrarily subtle
- It's mitigation, not a cure

Defense-in-depth means when one layer fails, the next catches it.

8/ MIT licensed. 5,943 tests. 19 packages on npm.

Built on security patterns from the last 40 years: taint tracking (Perl 1989), parameterized queries (SQL-92), CSP (W3C 2010), capability-based security (1966).

GitHub: https://github.com/aegis-sdk/Aegis

### Short Tweet (standalone)

```
Prompt injection is the #1 vulnerability in AI apps, and the JS ecosystem had zero defense libraries.

We built Aegis — streaming-first protection that adds <0.02ms of latency.

100% detection rate. 0.24% false positives. Zero dependencies. MIT licensed.

npm install @aegis-sdk/core
```

---

## Reddit Posts

### r/typescript, r/node

**Title:** I built an open-source prompt injection defense library for TypeScript

I kept seeing the same gap: Python has NeMo Guardrails, LLM Guard, and Guardrails AI for prompt injection defense. The JS/TS ecosystem had nothing.

So I built Aegis — a streaming-first defense library that protects AI apps without adding latency.

**The key insight:** You can't ask developers to buffer entire LLM responses just to scan them. That adds 2-10s of latency. Aegis streams tokens through immediately while scanning in parallel. If it detects a problem, it kills the stream.

**What it does:**
- Input scanning — pattern matching + heuristics for 19 threat categories
- Taint tracking — `Quarantined<T>` TypeScript type that prevents untrusted content from reaching system prompts at compile time
- Prompt builder — parameterized prompts (like parameterized SQL queries)
- Stream monitoring — real-time output scanning with kill switch
- Tool validation — policy engine for agentic apps (allow/deny/rate limit tool calls)
- Audit logging — every decision recorded

**Numbers:**
- 100% TPR on 76 adversarial payloads at default settings
- 0.24% FPR on 5,000 benign queries
- 0.019ms mean scan latency
- 5,943 tests
- Zero runtime dependencies in core

Works with OpenAI, Anthropic, Google, Mistral, Ollama. Integrates with Next.js, SvelteKit, Express, Hono, Fastify, LangChain.

GitHub: https://github.com/aegis-sdk/Aegis

Would love feedback from anyone building AI apps in TypeScript — especially on false positive rates in production scenarios.

### r/MachineLearning

**Title:** Aegis.js: Open-source streaming-first prompt injection defense (TypeScript)

Sharing a library I built for the JS/TS ecosystem. Aegis is a defense-in-depth toolkit for prompt injection in LLM applications. It's not ML-based — it uses deterministic pattern matching, heuristic scoring, entropy analysis (for GCG-style adversarial suffixes), and conversation trajectory analysis (for crescendo attacks).

The novel part is the streaming architecture: tokens flow to the user immediately via TransformStream while a sliding window buffer scans in parallel. On violation, the stream is terminated. This avoids the latency penalty of full-response buffering that makes most guardrails impractical for production.

Results on our internal benchmark (76 adversarial payloads across 14 threat categories, 5,000 benign corpus):
- Balanced: 100% TPR, 0.24% FPR, 0.019ms mean latency
- Paranoid: 100% TPR, 2.80% FPR
- Permissive: 52.6% TPR, 0.00% FPR

Known limitations: no trained classifiers, so novel attack patterns not in the database will bypass input scanning. We compensate with layered defense (taint tracking, prompt structure, tool validation, output monitoring). The Quarantined<T> compile-time type system is the piece I'm most proud of — it makes it a TypeScript error to pass untrusted content where trusted content is expected.

GitHub: https://github.com/aegis-sdk/Aegis

---

## Elevator Pitches

### 10-second pitch

Aegis is helmet.js for AI — it protects your LLM apps from prompt injection without adding latency. Three lines of code. Zero dependencies. Open source.

### 30-second pitch

Every AI app built in JavaScript has zero protection against prompt injection — the #1 vulnerability in LLM applications. Python has guardrails libraries, but the JS ecosystem has nothing. Aegis fixes that. It's a streaming-first defense library that scans input and output in real-time without buffering. It catches 100% of known attack patterns with less than 0.02ms of overhead. Works with any LLM provider, any JS framework, and it's MIT licensed with zero dependencies.

### 60-second pitch

Prompt injection is the #1 security risk in AI applications — it's on OWASP's LLM Top 10. An attacker can make your chatbot leak system prompts, exfiltrate user data, or call dangerous tools. The Python ecosystem has defense libraries, but JavaScript — where most web apps are built — has had nothing.

Aegis is an open-source TypeScript library that solves this with a streaming-first approach. Most security tools require you to buffer the entire LLM response before scanning it, adding 2-10 seconds of latency. Developers won't accept that, so they ship with no protection. Aegis streams tokens immediately while monitoring them in parallel. If it detects a violation, it kills the stream mid-sentence.

Under the hood, it layers 7 defense mechanisms: input scanning, taint tracking, prompt structure, policy engine, real-time output monitoring, tool call validation, and audit logging. At the default sensitivity, it catches 100% of adversarial payloads across 14 threat categories with a 0.24% false positive rate. Mean scan latency is 0.019ms.

It works with OpenAI, Anthropic, Google, and any other provider. It integrates with Next.js, SvelteKit, Express, and every major JS framework. Three lines of code to protect a chatbot. Zero runtime dependencies. MIT licensed.

---

## Dev.to / Hashnode Blog Post Outline

### Title: "Why We Built a Streaming-First Prompt Injection Defense"

**Hook:** Every AI app you've shipped has a vulnerability you probably haven't thought about.

**Section 1: The problem nobody talks about**
- Prompt injection is OWASP #1 for LLMs
- Show a real attack example (ignore previous instructions → leak system prompt)
- The Python ecosystem has solutions. JS/TS has nothing.

**Section 2: The latency trap**
- Traditional approach: buffer full response → scan → show to user
- This adds 2-10 seconds. Nobody will ship that.
- So the industry default is: no protection.

**Section 3: The streaming solution**
- Optimistic defense model: stream immediately, kill on violation
- How TransformStream + sliding window buffer works
- Diagram of the pipeline

**Section 4: Defense in depth**
- Walk through the 7 layers
- Explain why no single layer is enough
- Quarantined<T> — bringing Perl's taint mode to TypeScript

**Section 5: The numbers**
- 100% TPR, 0.24% FPR, 0.019ms latency
- How we built the benchmark (76 adversarial payloads, 5,000 benign corpus)
- What "balanced" vs "paranoid" vs "permissive" means

**Section 6: What we can't do (honesty section)**
- No ML classifiers
- Novel attacks bypass pattern matching
- Multi-turn attacks can be arbitrarily subtle
- It's mitigation, not a cure

**Section 7: Getting started**
- npm install @aegis-sdk/core
- 3-line integration with Next.js
- Link to docs and GitHub

**CTA:** Star the repo, try it in your app, and if you find a bypass — submit it through the Aegis Protocol and get your name in our Hall of Fame.

---

## Email / DM Template (for outreach)

### Short version

Hey [name] — I built an open-source prompt injection defense library for JavaScript/TypeScript. It's the first one in the JS ecosystem (Python has several, JS had zero).

The key difference: it works with streaming. Most guardrails require buffering the full LLM response before scanning, which adds seconds of latency. Aegis streams tokens through immediately and kills the stream if it detects a problem.

100% detection rate on known attacks, 0.24% false positives, <0.02ms overhead.

Would love your feedback: https://github.com/aegis-sdk/Aegis

### Longer version (for YC network / investors)

Hey [name],

I'm building Aegis — an open-source prompt injection defense library for the JavaScript/TypeScript ecosystem.

**The problem:** Prompt injection is the #1 vulnerability in AI applications (OWASP LLM Top 10). The Python ecosystem has NeMo Guardrails (NVIDIA), LLM Guard (Protect AI), and Guardrails AI. The JavaScript ecosystem — where most web applications are built — has had nothing.

**What Aegis does:** It's a streaming-first security layer that scans LLM input and output without adding latency. Traditional approaches buffer the full response before scanning (+2-10s). Aegis streams tokens immediately and kills the stream if it detects a problem. 100% detection rate on 76 adversarial payloads, 0.24% false positive rate on 5,000 benign queries.

**Why now:** Every company building with LLMs needs this. The market is moving from simple chatbots to agentic applications with tool calling — where the attack surface gets dramatically worse. Aegis covers the full attack surface: input injection, output leakage, tool abuse, multi-turn attacks, and more.

**Traction:** 17 packages on npm, 5,943 tests, integrations with every major JS framework and LLM provider. MIT licensed.

Would love to chat if this is relevant to what you're working on.

— Josh

---

## GitHub Description & Topics

### Description (350 chars max)

```
Streaming-first prompt injection defense for JavaScript/TypeScript. Protects AI apps from injection attacks, data leakage, and tool abuse without adding latency. Works with OpenAI, Anthropic, Google, Mistral. Integrates with Next.js, SvelteKit, Express, Hono, Fastify.
```

### Topics

```
prompt-injection, ai-security, llm, typescript, streaming, guardrails, ai-safety, openai, anthropic, langchain, vercel-ai, defense-in-depth, prompt-engineering, owasp
```

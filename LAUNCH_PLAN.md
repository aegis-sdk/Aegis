# Aegis SDK — Launch Prep Plan

**Created:** February 24, 2026
**Last Updated:** February 24, 2026
**Goal:** Close every gap identified in the project audit, then launch on Product Hunt + YC network.
**Status:** Phases 1-4 complete. Phase 5 (Launch Prep) remaining.

---

## Phase 1: Test Coverage (Ship Blockers) — COMPLETE

**Result:** 43 test files, 5,943 tests passing, 5 todo (known detection gaps documented).

### 1.1 ActionValidator Unit Tests — DONE (18 tests)

Created `tests/unit/validator.test.ts` with full coverage:

- [x] `check()` — allows valid tool calls matching policy
- [x] `check()` — blocks tool calls not in policy allowlist
- [x] `check()` — blocks tool calls in policy denylist
- [x] `setRateLimits()` + `checkRateLimits()` — enforces per-tool rate limits
- [x] `checkRateLimits()` — sliding window resets after expiration
- [x] `scanMcpParams()` — detects injection payloads in MCP tool parameters
- [x] `scanMcpParams()` — allows clean parameters through
- [x] `checkExfiltration()` — detects read-then-send tool call chains
- [x] `checkExfiltration()` — fingerprint matching catches data flowing from read to send
- [x] `checkExfiltration()` — allows unrelated sequential tool calls
- [x] `checkDenialOfWallet()` — triggers when tool call rate exceeds threshold
- [x] `checkDenialOfWallet()` — window resets properly
- [x] `setAuditCallback()` — fires callback on blocked actions
- [x] Parameter safety — detects SQL injection in tool args
- [x] Parameter safety — detects shell injection in tool args
- [x] Parameter safety — detects path traversal (`../../etc/passwd`) in tool args
- [x] Privilege decay — validates tool set shrinks over agentic loop steps
- [x] Human-in-the-loop — flags actions requiring approval

### 1.2 Integration Tests — DONE (5 tests)

Created `tests/integration/pipeline.test.ts`:

- [x] **Happy path**: Clean input → scanner passes → prompt built → stream monitored → no violations → audit logged
- [x] **Input blocked**: Injection attempt → scanner catches → session records violation → audit logged → recovery mode activates
- [x] **Stream kill switch**: Clean input passes scanner → LLM output contains violation → StreamMonitor detects mid-stream → kill switch fires → stream aborts → audit logged
- [x] **Agentic loop**: Multi-step tool chain → guardChainStep validates each step → privilege decay applied → step budget enforced → exfiltration attempt caught
- [x] **Auto-retry escalation**: Kill switch fires → AutoRetryHandler escalates to stricter scanner → retried request passes

### 1.3 Missing Adversarial Tests — DONE

Created `tests/adversarial/suites/advanced-threats.test.ts` covering all 7 previously-untested threat categories:

- [x] T6 — Goal Hijacking (3 detected + 2 todo for semantic-only attacks)
- [x] T7 — Crescendo (trajectory analysis + keyword-based detection)
- [x] T8 — Encoding Bypasses (zero-width, Cyrillic, HTML entities, RTL)
- [x] T9 — Multi-modal Injection (text extraction pipeline)
- [x] T11 — Many-Shot Jailbreaking (30+ example pattern)
- [x] T12 — Adversarial Suffixes (GCG-style with perplexity analyzer)
- [x] T13 — Context Window Exhaustion (padding + flooding)

### 1.4 Expanded Monitor Tests — DONE (32 tests, up from 5)

- [x] Credit card, AWS key, bearer token, generic API key detection
- [x] Email, phone, SSN, IBAN PII detection
- [x] Cross-chunk boundary detection (2+ chunks)
- [x] PII redaction mode (`[REDACTED-TYPE]` labels)
- [x] Kill switch abort scenario
- [x] Custom pattern matching
- [x] Large streaming payloads

### 1.5 Adapter Tests — DONE (10 adapters)

Created test files for OpenAI, Anthropic, Vercel, Express, Next, Hono, LangChain, Koa, Fastify, SvelteKit.

### 1.6 Sandbox Tests — DONE (32 tests)

Tests cover: extraction, type coercion, validation, markdown fence handling, retry logic, fail modes, timeout, injection resistance.

---

## Phase 2: Code Completions — COMPLETE

### 2.1 Sandbox Module — DONE

`packages/core/src/sandbox/index.ts` — Full implementation:

- [x] Provider-agnostic via `llmCall: (prompt: string) => Promise<string>` function
- [x] Schema enforcement with type coercion
- [x] Zero-capability prompt construction
- [x] Retry logic (configurable, default 2 retries)
- [x] Timeout support via `Promise.race`
- [x] Default values for missing fields
- [x] Fail-open vs. fail-closed modes
- [x] 32 tests passing

### 2.2 Policy File Loading — DONE

`packages/core/src/policy/index.ts`:

- [x] `loadPolicyFile()` — async JSON/YAML loading
- [x] `validatePolicySchema()` — returns human-readable errors
- [x] `parseSimpleYaml()` — minimal YAML parser (zero dependencies)
- [x] File path detection in `resolvePolicy()` with helpful error
- [x] 38 policy tests passing (up from 10)

### 2.3 PII Redaction Verification — DONE

- [x] Redaction replaces PII with `[REDACTED-{TYPE}]` labels
- [x] Stream continues after redaction (not killed)
- [x] Cross-chunk boundary redaction tested
- [x] 32 monitor tests passing (up from 5)

---

## Phase 3: Documentation & Developer Experience — COMPLETE

### 3.1 Package READMEs — DONE (17 packages)

All packages have npm-facing READMEs: core, openai, anthropic, google, mistral, ollama, vercel, express, fastify, hono, next, sveltekit, koa, langchain, testing, cli, dashboard.

### 3.2 Example READMEs — DONE

- [x] `examples/express-chatbot/` — Full server + README
- [x] `examples/sveltekit-agent/` — Agentic SvelteKit app + README

### 3.3 Comparison Page — DONE

`packages/docs/guide/comparison.md` — Honest comparison vs. NeMo Guardrails, LLM Guard, Guardrails AI, Lakera Guard, @openai/guardrails. Includes "When to Use" and "When NOT to Use" sections.

### 3.4 Production Guide — DONE

`packages/docs/guide/production.md` — Security checklist, OTel setup, alerting, policy-by-use-case table, performance tuning, audit log rotation.

### 3.5 Policy Examples — DONE

`packages/docs/guide/policy-examples.md` — Complete configs for financial services, customer support, code assistant, healthcare/HIPAA.

### 3.6 Migration Guides — DONE

`packages/docs/guide/migration.md` — Guides for Vercel AI SDK, LLM Guard, NeMo Guardrails.

---

## Phase 4: Credibility & Benchmarks — COMPLETE

### 4.1 Published Detection Benchmarks — DONE

`benchmarks/accuracy.ts` + `pnpm benchmark:accuracy`:

| Sensitivity | TPR | FPR | Mean Latency | P95 Latency |
|-------------|-----|-----|-------------|-------------|
| permissive | 52.6% | 0.00% | 0.012ms | 0.019ms |
| **balanced** | **100.0%** | **0.24%** | **0.019ms** | **0.026ms** |
| paranoid | 100.0% | 2.80% | 0.017ms | 0.025ms |

- [x] 76 adversarial payloads across 14 threat categories
- [x] 5,000 benign corpus entries
- [x] Per-scan latency statistics (mean, p50, p95, p99)
- [x] Results published in README
- [x] Reproducible via `pnpm benchmark:accuracy`
- [x] Machine-readable JSON at `benchmarks/accuracy-results.json`

### 4.2 HALL_OF_FAME.md — DONE

Created with Bronze/Silver/Gold recognition tiers and guidelines.

### 4.3 OWASP Project Submission — DEFERRED (post-launch)

### 4.4 Security Policy — DONE

`SECURITY.md` — Responsible disclosure, scope, supported versions, security contact, best practices.

### Additional Credibility Work

- [x] `.github/ISSUE_TEMPLATE/bug_report.md`
- [x] `.github/ISSUE_TEMPLATE/feature_request.md`
- [x] `.github/ISSUE_TEMPLATE/aegis_protocol_bypass.md`
- [x] `.github/pull_request_template.md`

---

## Phase 5: Launch Preparation — IN PROGRESS

### 5.1 Pre-Launch Checklist

- [x] All Phase 1-4 items complete
- [x] Lint clean (0 errors)
- [x] Typecheck clean
- [x] All 5,943 tests passing
- [ ] All packages published to npm (need version bump + changeset)
- [ ] Docs site deployed and accessible
- [ ] GitHub repo public with proper description, topics, and social preview image
- [ ] README badges current (build status, npm version, license, TypeScript)

### 5.2 Product Hunt Launch — TODO

- [ ] Create a compelling tagline
- [ ] Write the PH description
- [ ] Create a demo GIF/video
- [ ] Prepare screenshots
- [ ] Identify launch day
- [ ] Line up first-hour upvoters
- [ ] Prepare responses for common PH questions

### 5.3 GitHub Social Proof — PARTIAL

- [ ] Social preview image (1280x640)
- [ ] GitHub topics: `prompt-injection`, `ai-security`, `llm`, `typescript`, `streaming`, `guardrails`
- [ ] Discussions enabled
- [x] Issue templates (bug report, feature request, aegis protocol bypass)
- [x] PR template

### 5.4 Content for YC Network — TODO

- [ ] Short pitch doc (1-pager)
- [ ] Technical blog post
- [ ] Demo video (2-3 min)

### 5.5 Launch Channels — TODO

- [ ] Product Hunt
- [ ] YC network (personal intros)
- [ ] Hacker News "Show HN"
- [ ] r/typescript, r/node, r/MachineLearning
- [ ] Twitter/X — AI security community
- [ ] Dev.to / Hashnode blog post
- [ ] Discord communities (Vercel, Next.js, AI)

---

## Version Strategy

**Current:** v0.4.0

**Recommendation:** Ship Phase 1-4 work as **v1.0.0-rc.1**, get feedback, then cut **v1.0.0** for Product Hunt launch.

---

## Success Criteria (Before Launch)

- [x] ActionValidator fully tested (18 test cases)
- [x] 5+ integration tests passing (5 scenarios)
- [x] All 19 threat categories have at least one adversarial test
- [x] Monitor has 15+ test cases (32 tests)
- [x] Sandbox module functional with provider-agnostic pattern
- [x] All 17 packages have READMEs
- [x] 2 complete, runnable examples with READMEs
- [x] Comparison page published
- [x] Detection benchmarks published in README
- [x] SECURITY.md exists
- [x] Lint and typecheck clean
- [ ] All packages published to npm
- [ ] Docs site deployed

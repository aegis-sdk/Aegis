# CLAUDE.md — Aegis SDK

## Overview

Aegis.js (`@aegis-sdk/core`) is a streaming-first prompt injection defense library for the JavaScript/TypeScript ecosystem. It provides defense-in-depth against prompt injection attacks while solving the streaming latency problem.

## Repository Structure

```
aegis/
├── packages/
│   ├── core/          # Main library — all defense modules
│   ├── vercel/        # Vercel AI SDK integration
│   ├── testing/       # Red team testing tools, attack suites, Promptfoo compat
│   ├── langchain/     # LangChain.js integration
│   ├── anthropic/     # Anthropic adapter
│   ├── openai/        # OpenAI adapter
│   ├── google/        # Google Gemini adapter
│   ├── mistral/       # Mistral adapter
│   ├── ollama/        # Ollama (local models) adapter
│   ├── express/       # Express middleware
│   ├── fastify/       # Fastify plugin
│   ├── next/          # Next.js integration
│   ├── hono/          # Hono middleware
│   ├── sveltekit/     # SvelteKit integration
│   ├── koa/           # Koa middleware
│   ├── cli/           # CLI tool
│   ├── dashboard/     # Audit log visualization dashboard
│   └── docs/          # VitePress documentation site
├── tests/
│   ├── unit/          # Unit tests (31 files, 5653 tests)
│   ├── adversarial/   # Known attack pattern tests
│   ├── benign/        # False positive prevention tests (5,000 queries)
│   ├── fuzz/          # Template-based fuzzing (fast-check)
│   └── integration/   # End-to-end tests
├── scripts/           # Pattern sync, corpus generation
├── docs/              # Standalone documentation (getting-started, MCP guide, compliance)
├── examples/          # Working example projects
├── benchmarks/        # Performance benchmarks (Vitest bench)
└── PRD.md             # Product Requirements Document (v3.2)
```

## Key Commands

```bash
pnpm install          # Install dependencies
pnpm build            # Build all packages
pnpm test             # Run all tests
pnpm test:watch       # Run tests in watch mode
pnpm test:coverage    # Run tests with coverage
pnpm lint             # Lint all packages
pnpm lint:fix         # Lint and auto-fix
pnpm format           # Format code with Prettier
pnpm typecheck        # TypeScript type checking
```

## Architecture

### Core Modules (packages/core)

| Module | Purpose | File |
|--------|---------|------|
| **Quarantine** | Taint-tracking for untrusted content | `src/quarantine/index.ts` |
| **InputScanner** | Pattern matching + heuristic injection detection | `src/scanner/index.ts` |
| **TrajectoryAnalyzer** | Crescendo/multi-turn attack detection (T7) | `src/scanner/trajectory.ts` |
| **PromptBuilder** | Sandwich pattern prompt construction | `src/builder/index.ts` |
| **PolicyEngine** | Declarative security policy (CSP for AI) | `src/policy/index.ts` |
| **ActionValidator** | Tool call validation + rate limiting + DoW detection | `src/validator/index.ts` |
| **StreamMonitor** | Real-time output scanning (TransformStream) | `src/monitor/index.ts` |
| **Sandbox** | Zero-capability model for untrusted content | `src/sandbox/index.ts` |
| **AuditLog** | Security event logging (console, file, OTel) | `src/audit/index.ts` |
| **FileTransport** | JSONL file transport with rotation | `src/audit/file-transport.ts` |
| **OTelTransport** | OpenTelemetry spans/metrics/logs transport | `src/audit/otel.ts` |
| **AlertingEngine** | Real-time alerting (rate-spike, session-kills, etc.) | `src/alerting/index.ts` |
| **MessageSigner** | HMAC conversation integrity (T15) | `src/integrity/index.ts` |
| **PerplexityAnalyzer** | Character n-gram perplexity for adversarial suffix detection | `src/scanner/perplexity.ts` |
| **LLMJudge** | Provider-agnostic LLM-based intent alignment verification | `src/judge/index.ts` |
| **MultiModalScanner** | Extract + scan text from images/audio/documents | `src/multimodal/index.ts` |
| **AutoRetryHandler** | Retry with escalated security after kill switch | `src/retry/index.ts` |

### Defense Pipeline

```
User Input → Quarantine → Input Scanner → [Adaptive Sandbox] → Prompt Builder
→ Policy Check → LLM streams → Stream Monitor + Action Validator → Audit Log
```

### Key Design Patterns

1. **Optimistic Defense**: Stream tokens immediately while monitoring in parallel. Kill switch (`controller.terminate()`) aborts on violation.
2. **Quarantine Types**: `Quarantined<T>` prevents untrusted content from reaching system prompts at compile time.
3. **Sliding Window**: Cross-chunk pattern detection using a buffer to catch patterns split across stream chunks.
4. **Sandwich Pattern**: system → context → [delimited user content] → reinforcement

## TypeScript Configuration

- `target: ES2022`, `module: ESNext`, `moduleResolution: bundler`
- Strict mode enabled, `verbatimModuleSyntax: true`
- All imports use `.js` extensions (for ESM compatibility)
- Dual CJS/ESM output via tsup

## Testing

- Test framework: **Vitest 4** (globals mode)
- Tests live in `tests/` directory (not co-located with source)
- 31 test files, 5,653 tests passing
- Adversarial tests in `tests/adversarial/` verify detection of known attacks
- Benign corpus in `tests/benign/` prevents false positives (5,000 queries)
- Template-based fuzzing with `fast-check` in `tests/fuzz/`
- Coverage thresholds: 80% statements, 75% branches, 80% functions, 80% lines
- Performance benchmarks in `benchmarks/core.bench.ts` (run with `pnpm benchmark`)
- CI runs tests across Node 18, 20, and 22

## Package Scope

- npm organization: `@aegis-sdk` (owner: msjoshlopez)
- GitHub organization: `aegis-sdk`
- GitHub repo: `https://github.com/aegis-sdk/Aegis`
- All packages published as `@aegis-sdk/<name>`

## Publishing & Releases

We use **Changesets** for versioning and automated npm publishing.

### How to release

1. **Create a changeset** — describes what changed and the semver bump:
   ```bash
   pnpm changeset
   ```
   This walks you through selecting which packages changed and whether it's a patch/minor/major. It creates a markdown file in `.changeset/`.

2. **Commit and push** the changeset file to `main`.

3. **GitHub Action auto-creates a "Version Packages" PR** that:
   - Bumps `version` in each affected package.json
   - Updates CHANGELOG.md files
   - Removes the consumed changeset files

4. **Merge that PR** → the GitHub Action automatically publishes to npm.

### Manual publish (if needed)

```bash
pnpm build && pnpm release
```

### CI/CD setup

- **CI workflow** (`.github/workflows/ci.yml`): Runs lint, typecheck, tests (Node 18/20/22), coverage, build, and adversarial suite on every push/PR to main.
- **Publish workflow** (`.github/workflows/publish.yml`): On push to main, builds, tests, then runs `changesets/action` which either creates a version PR or publishes to npm.
- **NPM_TOKEN**: Stored as a GitHub Actions secret. This is a granular access token scoped to `@aegis-sdk/*` packages. If it expires, generate a new one at https://www.npmjs.com/settings/msjoshlopez/tokens and update the secret at https://github.com/aegis-sdk/Aegis/settings/secrets/actions.

## Important Notes

- The PRD (PRD.md) is the authoritative source for all architecture decisions
- This is a security library — be extra careful about correctness
- All detection patterns should have both positive (catches attack) and negative (allows benign) tests
- Never use `any` types — use `unknown` and narrow
- All public APIs must have JSDoc comments
- Prefer composition over inheritance

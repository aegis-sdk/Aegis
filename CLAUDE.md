# CLAUDE.md — Aegis SDK

## Overview

Aegis.js (`@aegis-sdk/core`) is a streaming-first prompt injection defense library for the JavaScript/TypeScript ecosystem. It provides defense-in-depth against prompt injection attacks while solving the streaming latency problem.

## Repository Structure

```
aegis/
├── packages/
│   ├── core/          # Main library — all defense modules
│   ├── vercel/        # Vercel AI SDK integration (P0)
│   ├── testing/       # Red team testing tools & attack suites
│   ├── langchain/     # LangChain.js integration (future)
│   ├── anthropic/     # Anthropic adapter (future)
│   ├── openai/        # OpenAI adapter (future)
│   ├── express/       # Express middleware (future)
│   ├── next/          # Next.js integration (future)
│   ├── hono/          # Hono middleware (future)
│   ├── sveltekit/     # SvelteKit integration (future)
│   └── cli/           # CLI tool (future)
├── tests/
│   ├── unit/          # Unit tests for all modules
│   ├── adversarial/   # Known attack pattern tests
│   ├── benign/        # False positive prevention tests
│   ├── fuzz/          # Template-based fuzzing
│   └── integration/   # End-to-end tests
├── docs/              # Documentation
├── examples/          # Working example projects
├── benchmarks/        # Performance benchmarks
└── PRD.md             # Product Requirements Document (v3.0)
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
| **PromptBuilder** | Sandwich pattern prompt construction | `src/builder/index.ts` |
| **PolicyEngine** | Declarative security policy (CSP for AI) | `src/policy/index.ts` |
| **ActionValidator** | Tool call validation + rate limiting | `src/validator/index.ts` |
| **StreamMonitor** | Real-time output scanning (TransformStream) | `src/monitor/index.ts` |
| **Sandbox** | Zero-capability model for untrusted content | `src/sandbox/index.ts` |
| **AuditLog** | Security event logging | `src/audit/index.ts` |

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

- Test framework: **Vitest** (globals mode)
- Tests live in `tests/` directory (not co-located with source)
- Adversarial tests in `tests/adversarial/` verify detection of known attacks
- Benign corpus in `tests/benign/` prevents false positives
- Coverage thresholds: 80% statements, 75% branches, 80% functions, 80% lines

## Package Scope

- npm organization: `@aegis-sdk`
- GitHub organization: `aegis-sdk`
- All packages published as `@aegis-sdk/<name>`

## Important Notes

- The PRD (PRD.md) is the authoritative source for all architecture decisions
- This is a security library — be extra careful about correctness
- All detection patterns should have both positive (catches attack) and negative (allows benign) tests
- Never use `any` types — use `unknown` and narrow
- All public APIs must have JSDoc comments
- Prefer composition over inheritance

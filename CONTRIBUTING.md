# Contributing to Aegis

Thank you for your interest in making AI applications safer. Here's how to contribute.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/aegis-sdk/aegis.git
cd aegis

# Install dependencies
pnpm install

# Run tests
pnpm test

# Build all packages
pnpm build
```

## The Aegis Protocol (Red Team Submissions)

Found a bypass? We want to know about it.

### How to submit a bypass

1. **Fork** this repository
2. **Create a test** in `tests/adversarial/bypasses/` that demonstrates the bypass:

```typescript
// tests/adversarial/bypasses/your-bypass.test.ts
import { describe, it, expect } from "vitest";
import { InputScanner } from "../../../packages/core/src/scanner/index.js";
import { quarantine } from "../../../packages/core/src/quarantine/index.js";

describe("[Protocol] Description of your bypass", () => {
  it("should detect this attack but currently does not", () => {
    const scanner = new InputScanner({ sensitivity: "balanced" });
    const input = quarantine("Your attack payload here", { source: "user_input" });
    const result = scanner.scan(input);

    // This test should FAIL — proving the bypass works
    expect(result.safe).toBe(false);
  });
});
```

3. **Submit a PR** with the title `[Protocol] <brief description>`
4. Include in the PR description:
   - What threat category this targets (T1-T19)
   - Why the current detection misses it
   - Suggested fix (optional)

### What happens next

- We'll review and verify the bypass
- If confirmed, we add it to our test suite and fix the detection
- You earn a spot in the [Hall of Fame](./HALL_OF_FAME.md)

## Code Contributions

### Pull Request Process

1. Create a feature branch from `main`
2. Write tests for new functionality
3. Ensure all tests pass: `pnpm test`
4. Ensure linting passes: `pnpm lint`
5. Ensure types check: `pnpm typecheck`
6. Submit a PR with a clear description

### Coding Standards

- TypeScript strict mode
- No `any` types — use `unknown` and narrow
- All public APIs need JSDoc comments
- Imports use `.js` extensions
- Tests for both positive (catches bad) and negative (allows good) cases
- Follow existing patterns in the codebase

### Commit Messages

Use conventional commits:

```
feat: add language detection to input scanner
fix: handle split canary tokens across chunks
test: add adversarial suite for encoding bypass
docs: update API reference for PromptBuilder
```

## Reporting Vulnerabilities

For security vulnerabilities in Aegis itself (not bypass submissions), please email security@aegis-sdk.dev (or open a private security advisory on GitHub) instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

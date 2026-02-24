# Testing Guide

## Philosophy

If you can not break it, you can not trust it.

Prompt injection is an adversarial problem. Your defenses need to be tested against the same attack techniques that real attackers use. The `@aegis-sdk/testing` package provides structured red team tools so you can measure your detection rate, identify blind spots, and prevent regressions before they reach production.

## What @aegis-sdk/testing Provides

- **RedTeamScanner** — automated attack suite runner with per-suite detection rates, timing data, and false negative identification
- **20 attack suites** covering threats T1 through T19: direct injection, role manipulation, delimiter escape, virtualization, indirect injection, tool abuse, data exfiltration, privilege escalation, goal hijacking, crescendo, encoding bypass, memory poisoning, many-shot, adversarial suffix, context flooding, chain injection, history manipulation, skeleton key, denial of wallet, language switching, and model fingerprinting
- **BossBattle** — structured 5-tier challenge system for hands-on red teaming
- **PayloadGenerator** — template-based fuzzing with encoding variants
- **Promptfoo integration** — config generator and custom assertion for CI/CD red teaming

## Quick Start

```ts
import { RedTeamScanner } from "@aegis-sdk/testing";

const scanner = new RedTeamScanner();
const results = await scanner.run(
  { policy: "strict" },
  { suites: ["direct-injection", "encoding-bypass"] }
);

console.log(`Detection rate: ${(results.detectionRate * 100).toFixed(1)}%`);
console.log(`Missed: ${results.missed} of ${results.total}`);

// Detailed report
console.log(scanner.generateReport(results));
```

## CLI Quick Start

```bash
# Run all suites with balanced policy
npx @aegis-sdk/cli test

# Run specific suites with strict policy
npx @aegis-sdk/cli test --policy strict --suites direct-injection,encoding-bypass

# Scan a single message
npx @aegis-sdk/cli scan "Ignore all previous instructions"
```

## CI/CD Integration

The CLI exits with code `0` when the detection rate is >= 95%, and code `1` otherwise. Add it to your CI pipeline:

```yaml
- name: Aegis Red Team
  run: npx @aegis-sdk/cli test --policy strict --json
```

## Sections

- [Red Team Scanner](/testing/red-team) — Full API for the automated scanner
- [Boss Battle](/testing/boss-battle) — Structured 5-tier challenge system
- [CLI Tool](/testing/cli) — Command-line usage and flags
- [Promptfoo Integration](/testing/promptfoo) — CI/CD red teaming with Promptfoo

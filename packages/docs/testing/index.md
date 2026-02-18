# Testing Guide

::: warning Work in Progress
Detailed testing documentation is coming soon. The sections below outline what the `@aegis-sdk/testing` package provides.
:::

## Overview

The `@aegis-sdk/testing` package provides red team tools for validating your Aegis configuration against known prompt injection attack patterns.

```ts
import { RedTeamScanner } from "@aegis-sdk/testing";
```

## What's Included

### Red Team Scanner

A scanner that runs a corpus of adversarial payloads against your Aegis instance and reports which attacks were caught and which slipped through.

### Attack Suites

Built-in attack corpora organized by category:

- **Instruction override** — "Ignore previous instructions" variants
- **Role manipulation** — "You are now DAN" style attacks
- **Skeleton key** — Multi-turn jailbreaks
- **Delimiter escape** — Breaking out of XML/markdown delimiters
- **Encoding attacks** — Base64, Unicode, ROT13 encoded payloads
- **Adversarial suffixes** — High-entropy gibberish suffixes
- **Many-shot jailbreaking** — Repeated example/response conditioning
- **Indirect injection** — Payloads hidden in RAG content
- **Tool abuse** — Manipulating function/tool calls
- **Data exfiltration** — Leaking system prompts or PII

### Benign Corpus

A set of legitimate, non-malicious inputs that should **not** be flagged. This corpus helps you measure false positive rates and tune scanner sensitivity.

### Promptfoo Integration

Integration with [Promptfoo](https://promptfoo.dev) for automated red teaming as part of your CI/CD pipeline.

### CLI Tool

A command-line scanner for running red team tests from your terminal:

```sh
npx @aegis-sdk/cli scan --policy strict --suite all
```

## Next Steps

- [Red Team Scanner](/testing/red-team) — Detailed API for the scanner
- [CLI Tool](/testing/cli) — Command-line usage
- [Promptfoo Integration](/testing/promptfoo) — CI/CD red teaming

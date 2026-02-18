# API Reference

::: warning Work in Progress
The full API reference is being generated from source-level JSDoc comments. In the meantime, refer to the inline documentation in the source code and the [TypeScript type definitions](https://github.com/aegis-sdk/Aegis/blob/main/packages/core/src/types.ts).
:::

## Packages

| Package | Description |
|---------|-------------|
| [`@aegis-sdk/core`](/api/aegis) | Main library — all defense modules |
| [`@aegis-sdk/vercel`](/guide/vercel-ai) | Vercel AI SDK integration |
| [`@aegis-sdk/testing`](/testing/) | Red team testing tools and attack suites |

## Core Exports

```ts
// Main entry point
import { Aegis, aegis } from "@aegis-sdk/core";

// Error classes
import {
  AegisInputBlocked,
  AegisSessionQuarantined,
  AegisSessionTerminated,
} from "@aegis-sdk/core";

// Individual modules
import {
  quarantine,
  isQuarantined,
  InputScanner,
  PromptBuilder,
  StreamMonitor,
  AuditLog,
  ActionValidator,
  Sandbox,
  MessageSigner,
  AlertingEngine,
  TrajectoryAnalyzer,
} from "@aegis-sdk/core";

// Policy utilities
import { resolvePolicy, getPreset, isActionAllowed } from "@aegis-sdk/core";

// Encoding & analysis utilities
import {
  normalizeEncoding,
  tryDecodeBase64,
  shannonEntropy,
  analyzeEntropy,
  detectLanguageSwitches,
} from "@aegis-sdk/core";
```

## Type Exports

All types are exported from `@aegis-sdk/core` and available for TypeScript consumers. See the [Types](/api/types) page for the full list.

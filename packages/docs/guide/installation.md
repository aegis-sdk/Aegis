# Installation

## Core Package

The core package contains all defense modules and works with any JavaScript/TypeScript project.

::: code-group

```sh [pnpm]
pnpm add @aegis-sdk/core
```

```sh [npm]
npm install @aegis-sdk/core
```

```sh [yarn]
yarn add @aegis-sdk/core
```

```sh [bun]
bun add @aegis-sdk/core
```

:::

## Framework Adapters

Install the adapter for your framework alongside the core package.

### Vercel AI SDK

The recommended integration for Next.js and Vercel-based projects.

::: code-group

```sh [pnpm]
pnpm add @aegis-sdk/core @aegis-sdk/vercel
```

```sh [npm]
npm install @aegis-sdk/core @aegis-sdk/vercel
```

```sh [yarn]
yarn add @aegis-sdk/core @aegis-sdk/vercel
```

```sh [bun]
bun add @aegis-sdk/core @aegis-sdk/vercel
```

:::

### Express

::: code-group

```sh [pnpm]
pnpm add @aegis-sdk/core @aegis-sdk/express
```

```sh [npm]
npm install @aegis-sdk/core @aegis-sdk/express
```

:::

### SvelteKit

::: code-group

```sh [pnpm]
pnpm add @aegis-sdk/core @aegis-sdk/sveltekit
```

```sh [npm]
npm install @aegis-sdk/core @aegis-sdk/sveltekit
```

:::

### Hono

::: code-group

```sh [pnpm]
pnpm add @aegis-sdk/core @aegis-sdk/hono
```

```sh [npm]
npm install @aegis-sdk/core @aegis-sdk/hono
```

:::

## Testing Tools

The testing package provides red team attack suites for validating your defenses.

::: code-group

```sh [pnpm]
pnpm add -D @aegis-sdk/testing
```

```sh [npm]
npm install --save-dev @aegis-sdk/testing
```

```sh [yarn]
yarn add -D @aegis-sdk/testing
```

```sh [bun]
bun add -d @aegis-sdk/testing
```

:::

## Requirements

- **Node.js** >= 18.0.0
- **TypeScript** >= 5.0 (recommended, not required)

Aegis uses standard Web APIs (`TransformStream`, `ReadableStream`, `WritableStream`, `crypto.subtle`) that are available in Node.js 18+ and all modern runtimes (Deno, Bun, Cloudflare Workers).

## ESM and CommonJS

Aegis ships dual ESM/CJS builds. Both import styles work:

```ts
// ESM (recommended)
import { Aegis } from "@aegis-sdk/core";

// CommonJS
const { Aegis } = require("@aegis-sdk/core");
```

## Verify Installation

```ts
import { Aegis } from "@aegis-sdk/core";

const aegis = new Aegis({ policy: "balanced" });

const result = await aegis.guardInput([
  { role: "user", content: "Hello, how are you?" },
]);

console.log("Aegis is working. Messages passed:", result.length);
```

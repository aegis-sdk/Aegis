# @aegis-sdk/langchain

LangChain.js callback handler and chain guard for prompt injection defense.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install @aegis-sdk/langchain @aegis-sdk/core
```

## Quick Start

```ts
import { ChatOpenAI } from '@langchain/openai';
import { Aegis } from '@aegis-sdk/core';
import { createAegisCallback } from '@aegis-sdk/langchain';

const aegis = new Aegis({ policy: 'strict' });

const model = new ChatOpenAI({
  callbacks: [createAegisCallback(aegis)],
});

const result = await model.invoke('Hello!');
```

## API

### `createAegisCallback(optionsOrAegis?)`

Creates a LangChain-compatible callback handler that intercepts LLM and tool lifecycle events:

- **`handleLLMStart`** -- Scans input prompts for injection patterns
- **`handleLLMEnd`** -- Quarantines LLM output for safe downstream consumption
- **`handleToolStart`** -- Validates tool calls against the Aegis policy
- **`handleToolEnd`** -- Quarantines tool output

Accepts an `Aegis` instance, `AegisConfig`, or `AegisCallbackOptions`:

| Option | Type | Default | Description |
|---|---|---|---|
| `aegis` | `AegisConfig \| Aegis` | `{}` | Aegis configuration or pre-constructed instance |
| `scanInput` | `boolean` | `true` | Scan LLM input prompts |
| `scanOutput` | `boolean` | `true` | Scan LLM output for violations |
| `validateTools` | `boolean` | `true` | Validate tool calls against policy |
| `quarantineToolOutput` | `boolean` | `true` | Quarantine tool outputs |
| `onBlocked` | `(error) => void` | -- | Called when input is blocked |
| `onToolBlocked` | `(toolName, result) => void` | -- | Called when a tool call is blocked |

### `AegisChainGuard`

Wraps agentic chain/agent execution with step-level protection. Enforces a step budget, tracks cumulative risk across steps, and terminates the chain if risk exceeds the threshold.

```ts
import { AegisChainGuard } from '@aegis-sdk/langchain';

const guard = new AegisChainGuard({
  aegis: new Aegis({ policy: 'strict' }),
  maxSteps: 10,
  riskThreshold: 0.7,
});

// In your agent loop:
const result = await guard.guardChainStep(currentMessages);
if (!result.allowed) {
  console.error('Chain terminated:', result.reason);
  break;
}
```

| Option | Type | Default | Description |
|---|---|---|---|
| `aegis` | `AegisConfig \| Aegis` | `{}` | Aegis configuration or pre-constructed instance |
| `maxSteps` | `number` | `25` | Maximum chain steps before termination |
| `riskThreshold` | `number` | `0.8` | Cumulative risk score threshold (0-1) |
| `scanStrategy` | `ScanStrategy` | `"last-user"` | Which messages to scan per step |
| `onBudgetExceeded` | `(stepCount) => void` | -- | Called when step budget is exceeded |
| `onRiskExceeded` | `(cumulativeRisk) => void` | -- | Called when risk threshold is exceeded |

Methods: `guardChainStep(messages)`, `getStepCount()`, `getCumulativeRisk()`, `getAegisInstance()`, `reset()`.

### `guardMessages(aegis, messages, options?)`

Scans messages directly without using the callback handler. Throws `AegisInputBlocked` if input is blocked.

### Re-exports

`Aegis`, `AegisInputBlocked`, `AegisSessionQuarantined`, `AegisSessionTerminated`, and all core types (including `ActionValidationRequest`, `ActionValidationResult`) are re-exported for convenience.

## Learn More

- [Documentation](https://aegis-sdk.github.io/Aegis/)
- [GitHub](https://github.com/aegis-sdk/Aegis)

## License

MIT

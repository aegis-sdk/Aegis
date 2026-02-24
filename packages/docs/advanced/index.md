# Agentic Defense

AI agents that call tools in multi-step loops — LangChain agents, LangGraph workflows, custom ReAct loops — introduce a category of risk that single-turn LLM calls do not. A compromised intermediate step can cascade: each tool call becomes an opportunity for exfiltration, privilege escalation, or runaway cost accumulation.

Aegis addresses this with `guardChainStep()`, a purpose-built method that wraps every iteration of an agentic loop with multi-layer protection.

## The Challenge

In a typical agent loop, the model produces output, the application parses that output for tool calls, executes them, feeds results back, and repeats. The security problems compound at each step:

1. **Chain injection (T14)** — An attacker embeds instructions in data the model reads at step 3. By step 7, those instructions have steered the model into calling `deleteUser()`.
2. **Infinite loops** — The model gets stuck in a cycle, burning tokens and money.
3. **Privilege creep** — Early steps establish trust. Later steps exploit it. A model that earned permission to `read_file` at step 2 should not still have `write_file` at step 20.
4. **Cumulative risk** — Each step may be individually below threshold, but the accumulated risk across 15 steps crosses into dangerous territory.

```
Step 1: "Read the user's profile"         → score 0.0  (safe)
Step 5: "Search the internal knowledge base" → score 0.1  (safe)
Step 9: "Now update the config file with..." → score 0.4  (hmm)
Step 12: "Execute the following shell..."    → score 0.8  (blocked!)
                                    cumulative: 1.3 → exceeds budget
```

## How `guardChainStep()` Works

At each step in your agent loop, pass the model's raw output through `guardChainStep()`. It runs a six-layer pipeline:

```
Model Output
    │
    ▼
┌─────────────────────┐
│  1. Step Budget      │  Has the loop exceeded maxSteps?
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  2. Quarantine       │  Wrap output with source: "model_output"
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  3. Input Scanner    │  Pattern-match + heuristic detection
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  4. Cumulative Risk  │  previousRisk + thisStep >= riskBudget?
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  5. Privilege Decay  │  Reduce available tools based on step
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  6. Audit Log        │  Record event: "chain_step_scan"
└─────────┘
```

The method returns a `ChainStepResult` containing the safety verdict, updated cumulative risk, scan details, and the list of tools still permitted.

## API Reference

### `aegis.guardChainStep(output, options)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `output` | `string` | Raw model output text to scan |
| `options.step` | `number` | Current step number (1-based). **Required.** |
| `options.maxSteps` | `number` | Maximum steps before halt. Default: `25` |
| `options.cumulativeRisk` | `number` | Accumulated risk from prior steps. Default: `0` |
| `options.riskBudget` | `number` | Risk threshold that halts the chain. Default: `3.0` |
| `options.initialTools` | `string[]` | Full list of tools available at step 1 |
| `options.sessionId` | `string` | Session ID for audit correlation |
| `options.requestId` | `string` | Request ID for audit correlation |

### `ChainStepResult`

| Field | Type | Description |
|-------|------|-------------|
| `safe` | `boolean` | Whether this step is allowed to proceed |
| `reason` | `string` | Human-readable explanation of the decision |
| `cumulativeRisk` | `number` | Updated risk total (pass this to the next step) |
| `scanResult` | `ScanResult` | Full scan result from the InputScanner |
| `availableTools` | `string[]` | Tools still permitted after privilege decay |
| `budgetExhausted` | `boolean` | Whether the step budget was fully consumed |

## Step Budgets

The `maxSteps` parameter caps how many iterations the agent can run. Once the current step exceeds `maxSteps`, `guardChainStep()` immediately returns `{ safe: false, budgetExhausted: true }` without scanning the output.

You can set this globally via `agentLoop.defaultMaxSteps` or per-call:

```ts
const aegis = new Aegis({
  agentLoop: {
    defaultMaxSteps: 15, // Global default
  },
});

// Override per call
const result = await aegis.guardChainStep(output, {
  step: currentStep,
  maxSteps: 30, // This call allows up to 30
});
```

## Risk Budgets

Each scan produces a risk score (0 to 1). These accumulate across steps. When the cumulative total reaches the `riskBudget`, the chain is halted — even if no individual step was flagged as unsafe.

```ts
// Default risk budget is 3.0
// With 25 steps, each step can average 0.12 risk before the budget trips

const result = await aegis.guardChainStep(output, {
  step: 10,
  cumulativeRisk: 2.5, // Already consumed 2.5 of 3.0
  riskBudget: 3.0,
});

// If this step scores 0.6 → cumulative becomes 3.1 → blocked
```

This catches the "death by a thousand cuts" pattern where each step is individually benign but the trajectory is problematic.

## Privilege Decay

As an agent loop progresses, the blast radius of a compromise increases. Privilege decay addresses this by progressively restricting which tools the model can access at later steps.

### Default Schedule

| Step Threshold | Tools Remaining |
|---------------|----------------|
| 1-9 | 100% (all tools) |
| 10-14 | 75% |
| 15-19 | 50% |
| 20+ | 25% |

Tools are kept in their original order — high-priority tools should be listed first in `initialTools` so they survive longer as the decay tightens.

### Custom Decay

```ts
const aegis = new Aegis({
  agentLoop: {
    privilegeDecay: {
      5: 0.8,   // After step 5: keep 80% of tools
      10: 0.5,  // After step 10: keep 50%
      15: 0.2,  // After step 15: keep 20%
    },
  },
});
```

### How It Works in Practice

```ts
const tools = ['read_file', 'write_file', 'delete_file', 'search'];

// Step 1:  all 4 tools available
// Step 10: 3 tools   → ['read_file', 'write_file', 'delete_file']
// Step 15: 2 tools   → ['read_file', 'write_file']
// Step 20: 1 tool    → ['read_file']
```

The returned `result.availableTools` should be used to constrain which tools the model is offered on the next step. Aegis does not enforce this — your application code must pass only `availableTools` to the model.

## Recovery Modes in Agentic Context

When `guardChainStep()` returns `safe: false`, you have several options for how to proceed. These map to the Aegis recovery modes:

```ts
const aegis = new Aegis({
  recovery: { mode: 'reset-last' },
});
```

| Mode | Behavior in Agent Loop |
|------|----------------------|
| `continue` | Throw `AegisInputBlocked`. Your catch block decides what to do. |
| `reset-last` | Strip the offending step's output and retry from the previous step. |
| `quarantine-session` | Lock the entire session. No further steps can execute. |
| `terminate-session` | Throw `AegisSessionTerminated`. The agent loop must be destroyed. |
| `auto-retry` | Re-scan with escalated security. See [Auto-Retry](/advanced/auto-retry). |

## Complete Example: Protecting an Agent Loop

```ts
import { Aegis, AegisInputBlocked } from '@aegis-sdk/core';

const aegis = new Aegis({
  policy: 'strict',
  agentLoop: {
    defaultMaxSteps: 20,
    defaultRiskBudget: 2.5,
    privilegeDecay: {
      8: 0.75,
      14: 0.5,
      18: 0.25,
    },
  },
});

const allTools = [
  'search_docs',
  'read_file',
  'write_file',
  'run_query',
  'send_email',
];

async function runAgent(userQuery: string) {
  // Step 0: Scan the initial user input
  const messages = await aegis.guardInput([
    { role: 'system', content: 'You are a helpful assistant.' },
    { role: 'user', content: userQuery },
  ]);

  let cumulativeRisk = 0;
  let availableTools = allTools;

  for (let step = 1; step <= 20; step++) {
    // Call the model with only the currently available tools
    const modelOutput = await callModel(messages, availableTools);

    // Guard the step
    const result = await aegis.guardChainStep(modelOutput, {
      step,
      cumulativeRisk,
      initialTools: allTools,
      sessionId: 'session-abc',
    });

    if (!result.safe) {
      console.warn(`Agent halted at step ${step}: ${result.reason}`);

      if (result.budgetExhausted) {
        // Graceful completion — agent ran out of steps
        return { status: 'budget_exhausted', step };
      }

      // Security violation — log and exit
      return { status: 'blocked', step, reason: result.reason };
    }

    // Update state for next iteration
    cumulativeRisk = result.cumulativeRisk;
    availableTools = result.availableTools;

    // Parse tool calls from modelOutput and execute them
    const toolResult = await executeToolCalls(modelOutput, availableTools);

    // Check if the agent is done
    if (toolResult.done) {
      return { status: 'complete', step, result: toolResult.output };
    }

    // Feed tool results back into the conversation
    messages.push(
      { role: 'assistant', content: modelOutput },
      { role: 'user', content: toolResult.output },
    );
  }
}
```

## Combining with Other Defenses

`guardChainStep()` handles the model output side. For complete agentic defense, combine it with:

- **[Action Validator](/guide/action-validator)** — Validate the actual tool calls (argument schemas, rate limits, deny-of-wallet detection) before executing them.
- **[Stream Monitor](/guide/stream-monitor)** — If your agent uses streaming, monitor the output stream in real-time alongside `guardChainStep()`.
- **[Trajectory Analysis](/advanced/trajectory)** — Detect gradual escalation across the conversation history, not just the current step.
- **[Message Integrity](/advanced/integrity)** — Sign the conversation to detect history tampering between steps.

## Configuration Reference

```ts
interface AgentLoopConfig {
  /** Default maximum steps. Default: 25 */
  defaultMaxSteps?: number;

  /** Default risk budget before halting. Default: 3.0 */
  defaultRiskBudget?: number;

  /**
   * Privilege decay schedule.
   * Maps step thresholds to the fraction of tools remaining (0-1).
   * Default: { 10: 0.75, 15: 0.5, 20: 0.25 }
   */
  privilegeDecay?: Record<number, number>;
}
```

Pass this under the `agentLoop` key in your Aegis config:

```ts
const aegis = new Aegis({
  agentLoop: {
    defaultMaxSteps: 30,
    defaultRiskBudget: 4.0,
    privilegeDecay: { 10: 0.8, 20: 0.5, 25: 0.2 },
  },
});
```

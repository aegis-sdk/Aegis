# Advanced Topics

::: warning Work in Progress
Detailed documentation for advanced features is coming soon. The sections below provide a brief overview of each topic.
:::

## Agentic Defense

Aegis provides specialized protection for agentic AI systems — LLM applications that call tools in multi-step loops (LangChain agents, LangGraph workflows, custom agent loops).

### Key Features

- **`guardChainStep()`** — Scan model output at each step of an agent loop
- **Cumulative risk tracking** — Halt the loop if total risk across steps exceeds a budget
- **Step budgets** — Enforce maximum iteration counts to prevent infinite loops
- **Privilege decay** — Progressively restrict available tools as steps increase

```ts
let cumulativeRisk = 0;

for (let step = 1; step <= 25; step++) {
  const modelOutput = await callModel();

  const result = await aegis.guardChainStep(modelOutput, {
    step,
    cumulativeRisk,
    initialTools: ["read_file", "write_file", "search"],
  });

  if (!result.safe) break;

  cumulativeRisk = result.cumulativeRisk;
  // Only allow result.availableTools for the next step
}
```

## More Topics

- [MCP Integration](/advanced/mcp) — Securing Model Context Protocol tool calls
- [Alerting](/advanced/alerting) — Rate spike detection, webhook alerts, cost anomaly monitoring
- [Message Integrity](/advanced/integrity) — HMAC-based conversation history tamper detection
- [Trajectory Analysis](/advanced/trajectory) — Topic drift and escalation detection across conversations

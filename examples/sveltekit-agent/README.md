# Aegis + SvelteKit Agentic Example

A SvelteKit API endpoint demonstrating Aegis SDK protection for agentic tool-calling loops.

## What this demonstrates

- **Input scanning** via `guardInput()` — blocks prompt injection before the agentic loop begins
- **Chain step validation** via `guardChainStep()` — scans tool output at every step of the loop
- **Step budget enforcement** — limits the number of agentic steps to prevent infinite loops
- **Privilege decay** — tools are progressively restricted as the loop continues

## Setup

```bash
# From the Aegis repo root
pnpm install
pnpm build

# Set your OpenAI API key
export OPENAI_API_KEY=sk-...

# Run the example
cd examples/sveltekit-agent
pnpm dev
```

## Usage

```bash
curl -X POST http://localhost:5173/api/chat \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": "Search for TypeScript best practices"}]}'
```

## Files

| File | Purpose |
|------|---------|
| `src/routes/api/chat/+server.ts` | API route with agentic loop, Aegis input guard, and chain step validation |
| `package.json` | Dependencies |

## Architecture

```
User Input
  --> aegis.guardInput()          (blocks injection)
  --> LLM call with tools
  --> Tool call?
       --> Execute tool
       --> aegis.guardChainStep()  (scan tool output)
       --> Feed back to LLM
  --> Final response
```

Each step through the loop is validated by Aegis. If injected instructions appear in a tool's output (e.g., a poisoned document from RAG), the chain is halted before those instructions reach the model again.

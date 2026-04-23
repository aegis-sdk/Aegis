# @aegis-sdk/openrouter

OpenRouter adapter for the Aegis SDK. Provides:

- `createJudgeCall(config)` — returns an `LLMJudgeCallFn` for use with `new LLMJudge({ llmCall })`.
- `createChatCall(config)` — generic chat-completion function for victim-model testing in eval harnesses.

Primary use case: cheap / free model access for the Aegis eval suite and for development. OpenRouter's `:free` models rate-limit aggressively (~20 req/min) and vary in quality — fine for testing, not recommended for production judge calls.

## Quick start

```ts
import { Aegis, LLMJudge } from "@aegis-sdk/core";
import { createJudgeCall } from "@aegis-sdk/openrouter";

const judge = new LLMJudge({
  llmCall: createJudgeCall({
    apiKey: process.env.OPENROUTER_API_KEY!,
    model: "meta-llama/llama-3.1-8b-instruct:free",
  }),
});

const aegis = new Aegis({ judge: judge.config });
```

## Free models (April 2026)

- `meta-llama/llama-3.1-8b-instruct:free` (default)
- `google/gemma-2-9b-it:free`
- `mistralai/mistral-7b-instruct:free`
- `deepseek/deepseek-r1:free`
- `qwen/qwen-2.5-7b-instruct:free`

Exported as the `FREE_MODELS` constant. Check `https://openrouter.ai/models` for the current catalog.

## Paid models worth knowing

- `anthropic/claude-haiku-4.5` — recommended for production judge calls.
- `openai/gpt-4o-mini` — known injection-susceptibility baseline; useful as a victim in evals.
- `meta-llama/llama-3.1-70b-instruct` — larger free-capable model for stronger judging.

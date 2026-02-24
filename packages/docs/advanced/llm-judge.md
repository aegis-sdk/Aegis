# LLM Judge

The `LLMJudge` module uses a secondary LLM call to verify whether model output aligns with the original user intent. Deterministic pattern-matching catches explicit injection patterns, but subtle manipulation — where the model's output is syntactically benign but semantically misaligned — requires a deeper check. The judge provides that layer.

## When to Use the Judge

The judge is designed for high-stakes scenarios where a false negative (missed attack) is more costly than the added latency and token cost of a second LLM call. Typical use cases:

- Financial or legal applications where output accuracy is critical
- Applications with tool-calling capabilities where misaligned output could trigger harmful actions
- Multi-turn conversations where context drift may not trigger pattern-based detectors
- Any scenario where you need defense-in-depth beyond deterministic rules

## Provider-Agnostic Design

The judge does not depend on any specific LLM provider. You supply an async function (`llmCall`) that takes a prompt string and returns a response string. This means you can use OpenAI, Anthropic, Google, Mistral, a local model, or any other provider:

```ts
const judge = new LLMJudge({
  llmCall: async (prompt) => {
    // Your provider call here — return a string
    return await callMyModel(prompt);
  },
});
```

## Configuration

### Through Aegis

```ts
import { Aegis } from '@aegis-sdk/core';

const aegis = new Aegis({
  judge: {
    enabled: true,                // Default: true (if llmCall is provided)
    triggerThreshold: 0.5,        // Risk score that triggers the judge
    timeout: 5000,                // Timeout in ms. Default: 5000
    llmCall: async (prompt) => {
      const res = await openai.chat.completions.create({
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0,
      });
      return res.choices[0].message.content ?? '';
    },
  },
});
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | `boolean` | `true` | Whether the judge is active |
| `triggerThreshold` | `number` | `0.5` | Risk score (0-1) above which the judge is invoked |
| `timeout` | `number` | `5000` | Timeout in ms for the LLM call |
| `systemPrompt` | `string` | (built-in) | Custom system prompt for the judge |
| `llmCall` | `(prompt: string) => Promise<string>` | (required) | The function that performs the LLM call |

## When the Judge Triggers

The judge is not invoked on every request. It uses a risk score threshold to decide when a deeper check is warranted:

```ts
// Check manually
if (judge.shouldTrigger(scanResult.score)) {
  const verdict = await judge.evaluate(userRequest, modelOutput);
}
```

With the default `triggerThreshold` of `0.5`, the judge activates when the InputScanner produces a risk score of 0.5 or higher. Lower the threshold to invoke the judge more frequently; raise it to reserve the judge for higher-risk situations.

## Verdict Types

The judge returns a structured `JudgeVerdict`:

| Field | Type | Description |
|-------|------|-------------|
| `approved` | `boolean` | `true` if the output is safe and aligned |
| `confidence` | `number` | 0.0-1.0, the judge's certainty |
| `decision` | `'approved' \| 'rejected' \| 'flagged'` | Categorical decision |
| `reasoning` | `string` | Free-text explanation (1-3 sentences) |
| `executionTimeMs` | `number` | Time taken for the evaluation |

### Decision Categories

- **`approved`** — Output is safe, aligned with user intent, and free of manipulation indicators.
- **`rejected`** — Output is clearly unsafe: misaligned, leaked system prompts, harmful content, or evidence of injection manipulation.
- **`flagged`** — Ambiguous. The judge is not confident enough to approve or reject. This is also the fallback when the judge times out or returns malformed output.

The judge follows a conservative principle: **when uncertain, flag rather than approve.**

## The Default Evaluation Prompt

The built-in system prompt instructs the judge to evaluate four aspects:

1. **Intent alignment** — Does the output genuinely address what the user asked?
2. **Instruction leakage** — Does the output reveal system prompts or internal configuration?
3. **Harmful content** — Does the output contain policy-violating material?
4. **Manipulation indicators** — Are there signs of prompt injection steering (unexpected tool calls, data exfiltration attempts)?

The judge must respond with a JSON object:

```json
{
  "approved": true,
  "confidence": 0.95,
  "decision": "approved",
  "reasoning": "Output directly addresses the user's weather query with factual information."
}
```

## Custom Prompts

Override the default evaluation prompt for domain-specific checks:

```ts
const aegis = new Aegis({
  judge: {
    llmCall: myLlmCall,
    systemPrompt: `You are evaluating AI output for a medical information system.
Check for:
1. Medical accuracy — does the response contain medically sound information?
2. Disclaimer compliance — does it include appropriate disclaimers?
3. Scope adherence — does it stay within general health information, not providing diagnoses?

Respond ONLY with JSON: {"approved": boolean, "confidence": number, "decision": "approved" | "rejected" | "flagged", "reasoning": "string"}`,
  },
});
```

## Timeout Handling

The judge wraps the LLM call in a `Promise.race` with the configured timeout. If the call exceeds the timeout, the verdict defaults to `flagged` with a timeout reasoning:

```ts
{
  approved: false,
  confidence: 0.0,
  decision: 'flagged',
  reasoning: 'Judge evaluation failed: Judge LLM call timed out after 5000ms',
  executionTimeMs: 5002,
}
```

This ensures the judge never blocks your pipeline indefinitely. For time-sensitive applications, set a shorter timeout (2000-3000ms) and handle `flagged` verdicts in your application logic.

## Cost Considerations

The judge adds a second LLM call for every evaluated request. To manage costs:

- **Raise `triggerThreshold`** so the judge only fires on higher-risk inputs. A threshold of 0.7 means only inputs that already triggered significant scanner detections get evaluated.
- **Use a smaller model** for the judge. `gpt-4o-mini` or `claude-3-5-haiku` are fast and inexpensive while still providing useful semantic evaluation.
- **Set `enabled: false`** in development/staging to avoid unnecessary calls.
- **Monitor execution times** via `verdict.executionTimeMs` and adjust timeout accordingly.

## Code Examples

### With OpenAI

```ts
import OpenAI from 'openai';
import { Aegis } from '@aegis-sdk/core';

const openai = new OpenAI();

const aegis = new Aegis({
  policy: 'strict',
  judge: {
    triggerThreshold: 0.4,
    timeout: 8000,
    llmCall: async (prompt) => {
      const res = await openai.chat.completions.create({
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0,
        max_tokens: 256,
      });
      return res.choices[0].message.content ?? '';
    },
  },
});

// Use the convenience method on the Aegis class
const verdict = await aegis.judgeOutput(
  'What is the weather in Tokyo?',
  modelResponse,
  {
    riskScore: 0.6,
    detections: scanResult.detections,
  },
);

if (!verdict.approved) {
  console.warn('Judge rejected output:', verdict.reasoning);
}
```

### With Anthropic

```ts
import Anthropic from '@anthropic-ai/sdk';
import { Aegis } from '@aegis-sdk/core';

const anthropic = new Anthropic();

const aegis = new Aegis({
  judge: {
    llmCall: async (prompt) => {
      const res = await anthropic.messages.create({
        model: 'claude-3-5-haiku-latest',
        max_tokens: 256,
        messages: [{ role: 'user', content: prompt }],
      });
      const block = res.content[0];
      return block.type === 'text' ? block.text : '';
    },
  },
});
```

### Standalone Usage

```ts
import { LLMJudge } from '@aegis-sdk/core';

const judge = new LLMJudge({
  triggerThreshold: 0.3,
  timeout: 5000,
  llmCall: myLlmCall,
});

// Check if the judge should run for this risk level
if (judge.shouldTrigger(riskScore)) {
  const verdict = await judge.evaluate(
    userRequest,
    modelOutput,
    {
      messages: conversationHistory,
      detections: scanResult.detections,
      riskScore,
    },
  );

  switch (verdict.decision) {
    case 'approved':
      // Deliver the output
      break;
    case 'rejected':
      // Block the output, return a safe fallback
      break;
    case 'flagged':
      // Route to human review or sandbox
      break;
  }
}
```

## Error Handling

The judge catches all errors from the LLM call and returns a `flagged` verdict instead of throwing:

```ts
const verdict = await judge.evaluate(userRequest, modelOutput);

// Even if the LLM call throws, you always get a verdict:
// verdict.decision === 'flagged'
// verdict.reasoning === 'Judge evaluation failed: <error message>'
```

This means you never need to `try/catch` around `evaluate()` — but you should handle `flagged` verdicts appropriately in your application logic.

## Related

- [Input Scanner](/guide/input-scanner) — Deterministic pattern-based detection
- [Perplexity Analysis](/advanced/perplexity) — Statistical anomaly detection
- [Auto-Retry](/advanced/auto-retry) — Escalation strategies when scans fail

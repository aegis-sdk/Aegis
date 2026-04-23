# Aegis Production Checklist

Use this before deploying Aegis in a real application. Nothing here is
optional — each item protects against a specific failure mode observed
during the Phase C hardening work.

## 1. Pick your posture

```ts
import { Aegis, productionPreset } from "@aegis-sdk/core";
import { createJudgeCall } from "@aegis-sdk/openrouter"; // or your own

const aegis = new Aegis(productionPreset({
  judgeLlmCall: createJudgeCall({ apiKey: process.env.OPENROUTER_API_KEY! }),
  canaryTokens: ["YOUR-CANARY-STRING"],
  // Defaults: scanner balanced, band [0.25,0.75], breaker threshold 5,
  // cooldown 30s, onBreakerOpen "scanner", budget 100 calls/session.
}));
```

The preset covers 90% of deployments. Override only if you have a reason.

## 2. Measure ASR reduction on YOUR workload

The published numbers (Aegis ASR ~8% on TensorTrust at balanced, ~76%
relative reduction vs. an unprotected baseline) are measured on open
free-tier models. Your victim model, your prompts, and your attacker
distribution are different. Run the harness yourself:

```bash
AEGIS_LIVE_E2E=1 OPENROUTER_API_KEY=... \
  pnpm eval:live --corpus tensortrust --limit 100 \
  --victim <your-provider>/<your-model>
```

If you can't run the harness directly against your victim, run it against
a close proxy and note the caveat in your SLOs.

## 3. Decide the breaker-open policy

When the judge provider degrades, Aegis falls back to one of:

| Policy | What it does | When to choose it |
|---|---|---|
| `"scanner"` (default) | Trust the scanner's own verdict. Scanner-unsafe stays unsafe. | Most apps. Safe default. |
| `"fail-open"` | Approve grey-band inputs when judge is down. | Low-stakes apps where latency > safety. |
| `"fail-closed"` | Block grey-band inputs when judge is down. | High-stakes apps where false positives cost less than misses. |

```ts
const aegis = new Aegis(productionPreset({
  judgeLlmCall,
  onBreakerOpen: "fail-closed",
}));
```

## 4. Pick a budget cap that matches your spend tolerance

The default budget is 100 judge calls per `Aegis` instance. If you reuse
one instance across many users/requests, raise it. If you instantiate
per-request, lower it (or set to 0 for unlimited — use carefully).

```ts
productionPreset({ judgeLlmCall, judgeCallBudget: 1000 });
```

Once the budget is exhausted, subsequent grey-band decisions fall
through to the same `onBreakerOpen` policy. Watch for the audit event
`judge_evaluation` with `context.skipReason === "budget_exhausted"`.

## 5. Wire audit to your real logging pipeline

The preset defaults `audit.transports = ["console", "custom"]`. Replace
console with whatever your observability stack uses:

```ts
aegis.getAuditLog().addTransport(async (entry) => {
  await datadog.log(entry);           // or splunk, bigquery, ...
});
```

Events to alert on:
- `judge_evaluation` with `context.skipReason` present — breaker trips or
  budget exhaustion.
- `scan_block` rate over baseline — a sudden spike suggests an attack
  campaign OR a pattern regression.
- `stream_violation` — canary leak detected in model output.
- `session_quarantine` — any occurrence.

## 6. Monitor judge latency

```ts
const stats = aegis.getJudgeStats();
// { breakerState, breakerFallback, callsUsed, callBudget,
//   latency: { count, mean, p50, p95, p99 } }
```

Expected ranges at the defaults (OpenRouter free tier, ~400 tokens):
- p50: 600-1500ms
- p95: 2000-5000ms
- p99: 5000-10000ms (often the timeout ceiling)

If p95 consistently exceeds 3s, pick a cheaper/faster judge model or
lower the judge band so fewer inputs hit it.

## 7. Canary tokens in your system prompts

Embed unique markers in your system prompt so `StreamMonitor` can detect
prompt-extraction attempts:

```ts
const SYSTEM_PROMPT = `
You are Aegis Assistant. ${"AEGIS-CANARY-7f3a9b".repeat(1)}
... rest of prompt ...
`;

productionPreset({ judgeLlmCall, canaryTokens: ["AEGIS-CANARY-7f3a9b"] });
```

Any output containing the canary triggers a `stream_violation` and
terminates the stream.

## 8. Test the emergency path

Before launch, verify each failure mode end-to-end:

- [ ] Breaker trips: force the judge to fail 5 consecutive times, confirm
      breaker opens, confirm the configured `onBreakerOpen` policy
      takes effect.
- [ ] Budget exhausts: set `judgeCallBudget: 2`, send 3 borderline
      inputs, confirm the 3rd gets the fallback policy.
- [ ] Canary leak: send a prompt designed to extract the system prompt,
      confirm `StreamMonitor` terminates the stream.
- [ ] Scanner-only deployment (judge deliberately disabled): `new Aegis()`
      without a judge config should never throw, should still block
      scanner-unsafe inputs.

Integration tests for each are in `tests/unit/judge-hardening.test.ts`
and `tests/unit/aegis-orchestrator.test.ts`.

## 9. Run the benchmark regression gate in CI

```bash
pnpm benchmark:regression
```

Fails the build if balanced TPR drops >1pp, FPR rises >0.25pp, or mean
latency doubles vs. the committed baseline. Add it to your pipeline.

## 10. Upgrade policy

- **Pattern updates**: Aegis ships new detection patterns with each
  minor. Run `pnpm eval:live` before and after to confirm no regression
  on your victim model.
- **Judge model upgrades**: when moving to a stronger judge, lower the
  judge band (e.g. `{ low: 0.15, high: 0.85 }`) to route more inputs
  through it. Measure the latency and FPR impact.
- **Sensitivity shifts**: moving from balanced → paranoid roughly
  doubles scanner FPR but drops Aegis ASR by ~12pp on TensorTrust. Only
  do it for high-stakes workloads where the FPR cost is acceptable.

## Known limitations

See [SECURITY.md](../SECURITY.md) "Known Detection Limits" for a
complete list. Short version:
- Subtle goal redirects without injection keywords — judge territory.
- Implicit authority claims — judge territory.
- Gradual multi-turn crescendo — limited trajectory coverage.
- Few-shot jailbreaks with <5 examples — scanner misses.
- Keyword-free obfuscation — scanner misses.
- Marginal-perplexity adversarial suffixes — edge case.

The judge was specifically designed to cover these; enable it in
production unless latency is prohibitive.

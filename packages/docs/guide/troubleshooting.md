# Troubleshooting & FAQ

Common problems and questions that come up when integrating Aegis into production applications.

## False Positives

### "My benign queries are getting blocked"

This is the most common issue developers encounter. Start by diagnosing which layer is triggering the block.

**Step 1: Check the scan result details**

```ts
import { Aegis, AegisInputBlocked } from "@aegis-sdk/core";

const aegis = new Aegis({ policy: "balanced" });

try {
  await aegis.guardInput(messages);
} catch (error) {
  if (error instanceof AegisInputBlocked) {
    // Inspect what triggered the block
    console.log("Score:", error.scanResult.score);
    console.log("Detections:", JSON.stringify(error.scanResult.detections, null, 2));
    console.log("Entropy:", error.scanResult.entropy);
    console.log("Language:", error.scanResult.language);
  }
}
```

**Step 2: Identify the cause**

| Detection Type | Likely Cause | Fix |
|----------------|-------------|-----|
| `instruction_override` | User said "ignore" or "disregard" in a benign context | Lower sensitivity or add custom allowlist logic |
| `encoding_attack` | Input contains Base64 or Unicode that is legitimate | Disable `encodingNormalization` if your app expects encoded content |
| `adversarial_suffix` | High-entropy content (e.g. UUIDs, hashes, code) | Raise `entropyThreshold` or disable `entropyAnalysis` |
| `many_shot` | User pasted many Q&A pairs (e.g. FAQs) | Raise `manyShotThreshold` |
| `language_switching` | Multilingual users switching languages naturally | Disable `languageDetection` if your app is multilingual |
| `custom` | Your own `customPatterns` are too broad | Narrow the regex |

**Step 3: Tune sensitivity**

```ts
const aegis = new Aegis({
  scanner: {
    sensitivity: "permissive", // Start here, then tighten
    entropyThreshold: 5.5,     // Default is 4.5 — raise for code/technical content
    manyShotThreshold: 10,     // Default is 5 — raise if users paste examples
  },
});
```

### How to tune sensitivity levels

The three built-in sensitivity levels adjust internal scoring thresholds:

| Sensitivity | Score Threshold | Best For |
|-------------|----------------|----------|
| `paranoid` | Very low (flags aggressively) | Banking, healthcare, high-security |
| `balanced` | Moderate (default) | General-purpose chatbots |
| `permissive` | High (only obvious attacks) | Internal tools, trusted users |

If the presets do not fit, use the `InputScanner` directly and apply your own threshold:

```ts
import { InputScanner, quarantine } from "@aegis-sdk/core";

const scanner = new InputScanner({ sensitivity: "balanced" });
const q = quarantine(userInput, { source: "user_input" });
const result = scanner.scan(q);

// Apply your own threshold instead of the built-in one
if (result.score > 0.7) {
  // Block
} else if (result.score > 0.4) {
  // Flag for review
} else {
  // Allow
}
```

### How to add to the benign corpus for testing

The benign corpus at `tests/benign/` contains 3,184 queries that should pass scanning without false positives. If you find a legitimate query that gets blocked, add it to the corpus:

1. Add your query to `tests/benign/corpus.json` (or the relevant category file)
2. Run `pnpm test` to confirm it passes
3. If it does not pass, that signals either a pattern bug or a sensitivity issue

```bash
# Run the benign corpus tests specifically
pnpm vitest run tests/benign/
```

This is a useful feedback loop: every false positive you find and add to the corpus prevents regressions.

---

## Integration Issues

### "guardInput throws but I just want a score"

`guardInput()` is the high-level API that throws on violations. If you need raw scoring without exception handling, use the `InputScanner` directly:

```ts
import { InputScanner, quarantine } from "@aegis-sdk/core";

const scanner = new InputScanner({
  sensitivity: "balanced",
  encodingNormalization: true,
});

const q = quarantine(userInput, { source: "user_input" });
const result = scanner.scan(q);

// result.safe — boolean
// result.score — 0.0 to 1.0
// result.detections — array of Detection objects
// result.entropy — entropy analysis result
// result.language — language detection result

console.log(`Score: ${result.score}, Safe: ${result.safe}`);
console.log(`Detections: ${result.detections.length}`);
```

This gives you the same scanning logic without the throw/catch flow.

### "Stream monitor kills my stream"

The stream monitor terminates the stream when it detects violations in the LLM output. If your stream is getting killed unexpectedly:

**Check canary tokens:** Make sure you are not accidentally including your canary tokens in content the model is supposed to output.

```ts
const aegis = new Aegis({
  canaryTokens: ["CANARY_abc123"], // This must NOT appear in your model's training data or responses
  monitor: {
    detectPII: true,
    detectSecrets: true,
    onViolation: (violation) => {
      // Log what triggered it before it kills the stream
      console.error("Stream violation:", violation.type, violation.matched);
    },
  },
});
```

**PII detection is too aggressive:** If your application legitimately outputs email addresses or phone numbers, either disable PII detection or switch to redaction mode:

```ts
const aegis = new Aegis({
  monitor: {
    detectPII: true,
    piiRedaction: true, // Redact instead of blocking
  },
});
```

**Debug with the onViolation callback:** Always set `onViolation` during development to understand what is triggering the kill switch.

### "TypeScript errors with Quarantined\<T\>"

The `Quarantined<T>` type is **intentionally restrictive** — that is the point. It prevents you from accidentally passing untrusted content to system prompts or other sensitive operations.

```ts
import { quarantine } from "@aegis-sdk/core";
import type { Quarantined } from "@aegis-sdk/core";

const q: Quarantined<string> = quarantine(userInput, { source: "user_input" });

// This will NOT compile — you cannot use q.value directly
// const systemPrompt = `You are a bot. Context: ${q.value}`;

// You must explicitly unwrap with a reason
const unsafeValue = q.unsafeUnwrap({ reason: "Displaying to admin for review" });
```

If you are getting TypeScript errors, you are probably trying to use quarantined content somewhere it should not be used without explicit unwrapping. This is the type system protecting you.

### "ESM vs CJS import issues"

Aegis ships as dual ESM/CJS. The package.json `exports` map handles resolution automatically for modern bundlers. If you are having issues:

**For ESM (recommended):**
```ts
import { Aegis } from "@aegis-sdk/core";
```

**For CommonJS:**
```ts
const { Aegis } = require("@aegis-sdk/core");
```

**If your bundler cannot resolve the package:**
- Make sure you are on Node 18+ (the minimum supported version)
- Check that `"moduleResolution"` in your tsconfig.json is set to `"bundler"` or `"node16"` — not `"node"` (legacy)
- If using `.js` extensions in your own imports, that is correct and expected for ESM

---

## Performance

### "Scanning is slow"

The input scanner runs in O(n) time and typically completes in under 1ms for inputs up to 10,000 characters. If you are seeing slowness:

**Encoding normalization on large inputs:** The `encodingNormalization` option decodes Base64, Unicode escapes, and other encodings before scanning. For very large inputs (>50KB), this can add measurable time. Disable it if your inputs are known to be plain text:

```ts
const aegis = new Aegis({
  scanner: {
    encodingNormalization: false, // Skip if inputs are plain text
  },
});
```

**Perplexity estimation:** When enabled, the perplexity analyzer runs a sliding-window n-gram analysis. It is O(n) but has a constant factor. If latency is critical and you do not need adversarial suffix detection beyond entropy analysis, leave it disabled (it is off by default):

```ts
const aegis = new Aegis({
  scanner: {
    perplexityEstimation: false, // Default — skip for maximum speed
  },
});
```

### "Stream overhead"

The stream monitor adds negligible overhead. Benchmark data from the test suite:

- **Per-chunk processing:** < 0.01ms per chunk
- **Sliding window maintenance:** O(1) amortized
- **Memory overhead:** Proportional to the sliding window buffer size (a few KB)

The monitor operates as a `TransformStream` — it does not buffer the entire response. Tokens flow through in real time.

### "Bundle size concerns"

Aegis core is designed to be tree-shakeable. If you only need input scanning:

```ts
// Only pulls in InputScanner and quarantine — not the full Aegis class
import { InputScanner, quarantine } from "@aegis-sdk/core";
```

If you are using the full `Aegis` class, all modules are included. The core package has **zero runtime dependencies** — no heavy ML models or bundled weights.

For production bundles, verify with your bundler's analysis tool:

```bash
# Webpack
npx webpack --analyze

# Vite
npx vite-bundle-visualizer
```

---

## Security

### "Is balanced mode secure enough?"

It depends on your threat model.

**`balanced` is appropriate when:**
- Your users are generally trusted (logged-in, authenticated)
- The LLM does not have access to destructive tools (delete, admin)
- You have rate limiting at the API layer
- False positives are a bigger concern than missed attacks

**You should use `strict` or `paranoid` when:**
- Your application is publicly accessible without authentication
- The LLM can trigger actions with real-world consequences (payments, data deletion)
- You are processing untrusted content from external sources (emails, web scrapes, file uploads)
- You are in a regulated industry (finance, healthcare)

**The layered approach:** Even on `balanced` mode, Aegis provides multiple defense layers (input scanning, output monitoring, action validation, audit logging). No single layer needs to be perfect — the combination provides defense-in-depth.

### "What attacks does Aegis NOT catch?"

Aegis is strong against pattern-based and heuristic-detectable attacks, but no defense is perfect. Be aware of these limitations:

**Attacks that are harder to catch:**
- **Semantic-level manipulation** where the attack uses entirely natural-sounding language with no syntactic markers. The LLM Judge (Phase 4) helps with this, but it requires a secondary LLM call.
- **Novel zero-day attack patterns** that do not match any known signatures or heuristic triggers. The adversarial test suite covers known patterns, but new techniques emerge regularly.
- **Attacks embedded in images or media** unless you configure the multi-modal scanner with a text extraction function.
- **Very slow crescendo attacks** that build up over many turns with each individual message being benign. Trajectory analysis helps but requires `scanStrategy: "all-user"` or `"full-history"`.

**Mitigations:**
- Enable the LLM Judge for semantic-level analysis on suspicious inputs
- Use `scanStrategy: "all-user"` for multi-turn conversations
- Keep Aegis updated — new patterns are added with each release
- Layer Aegis with other security controls (authentication, authorization, rate limiting)
- Run the red team test suite regularly against your configuration

### "Should I use LLM Judge in production?"

The LLM Judge adds a secondary LLM call to verify intent alignment. Consider the tradeoffs:

| Factor | Impact |
|--------|--------|
| **Latency** | Adds 200-2000ms per judgment call (depends on model and provider) |
| **Cost** | One additional LLM call per triggered scan (not every request — only when `triggerThreshold` is exceeded) |
| **Accuracy** | Catches semantic-level manipulation that pattern matching misses |
| **Reliability** | LLM calls can fail or timeout — Aegis falls back to "flagged" on failure |

**Recommended approach:**
- Set `triggerThreshold` high (e.g. 0.6-0.8) so the judge only fires on already-suspicious inputs
- Use a fast, cheap model (e.g. `gpt-4o-mini` or `claude-haiku`) for the judge
- Set a tight `timeout` (3000-5000ms) to cap latency impact
- Monitor judge invocation rates via the audit log

```ts
const aegis = new Aegis({
  judge: {
    triggerThreshold: 0.7,
    timeout: 3000,
    llmCall: async (prompt) => {
      const res = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
        temperature: 0,
      });
      return res.choices[0].message.content ?? "";
    },
  },
});
```

---

## Common Error Messages

### `[aegis] Input blocked: N violation(s) detected (score: X.XX)`

This is `AegisInputBlocked`. The input scanner found patterns that exceeded the threshold. Catch this error and inspect `error.scanResult.detections` for details.

### `[aegis] Session quarantined: all input is blocked until session is reset`

This is `AegisSessionQuarantined`. The session was quarantined after a violation (when `recovery.mode` is `"quarantine-session"`). Create a new `Aegis` instance to reset.

### `[aegis] Session terminated: N violation(s) (score: X.XX)`

This is `AegisSessionTerminated`. The session was permanently terminated (when `recovery.mode` is `"terminate-session"`). Create a new `Aegis` instance.

### `[aegis] Multi-modal scanner is not configured`

You called `aegis.scanMedia()` without providing a `multiModal` config with an `extractText` function. The multi-modal scanner requires a user-provided text extraction function.

### `[aegis] LLM-Judge is not configured`

You called `aegis.judgeOutput()` without providing a `judge` config with an `llmCall` function.

---

## Getting More Help

- **GitHub Issues**: [github.com/aegis-sdk/Aegis/issues](https://github.com/aegis-sdk/Aegis/issues)
- **Red Team Testing**: Run `npx aegis red-team --policy balanced` to test your configuration against known attack patterns
- **Audit Log Analysis**: Enable `audit.level: "all"` during development to see every decision Aegis makes

---
"@aegis-sdk/core": minor
---

External-corpus evaluation and pattern expansion.

Added `evals/external-corpora/` — fetchers and runners for TensorTrust,
AdvBench, and CyberSecEval 2 (Meta PurpleLlama). Each run produces a
reproducible JSON with TPR, FPR, per-category breakdown, and latency stats.
Raw corpora are pulled from upstream on first run and cached in
`.cache/corpora/` (gitignored); we do not redistribute raw data.

Running the initial matrix exposed real gaps in the pattern set. Expanded:

- **Instruction override**: `ignore/disregard/forget` patterns now cover
  `directives|orders|commands|directions|training` in addition to the
  existing `instructions|prompts|rules`. Added a shorter `forget <object>`
  shape so "forget previous instructions" matches — previously only the
  rigid "forget everything you were told" shape was caught.
- **Instead-of substitution**: new pattern catches task-hijack attempts
  framed as "instead of doing X, do Y."
- **Output-reflection attacks**: new pattern for "repeat/echo/print the
  above/preceding/previous [text|content|message|conversation]." Scoped
  narrowly to avoid tripping "could you repeat that" in normal
  conversation.
- **Credential extraction**: new pattern for
  "tell me|reveal|show me <the|your> secret|password|passphrase|access
  code|api key|auth token|credentials." Scoped to secret-ish nouns to
  avoid matching "tell me the answer" / "show me the code."
- **Output coercion**: new pattern for
  "say|respond|reply|answer|output|print|write + only|exactly|verbatim|
  just|literally|nothing but" — forces model to emit attacker-controlled
  text.
- **Output-prefix hijack**: new pattern for
  "start|begin|prefix|preface|prepend|open your response|output|answer|
  reply|message with."

Detection deltas on full external corpora:

| Corpus | Sensitivity | Before | After |
|---|---|---:|---:|
| TensorTrust (1,346) | balanced | 42.27% | 66.05% |
| TensorTrust (1,346) | paranoid | 54.83% | 70.73% |
| CyberSecEval 2 (251) | balanced | 11.16% | 16.73% |
| CyberSecEval 2 (251) | paranoid | 11.95% | 17.53% |

Internal benchmark unchanged: balanced TPR 100%, balanced FPR 0.24%,
mean latency 0.017ms. Permissive TPR on the internal 76-payload corpus
went from 52.6% → 55.3% as a small side effect of the expanded patterns.
No new false positives on the 5,000-query benign corpus.

The regression gate only enforces the balanced profile, so the permissive
TPR bump does not require a baseline update. `accuracy-baseline.json`
remains at the previously-frozen values.

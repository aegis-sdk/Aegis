# Plan #4 — Differential Harness vs. Competitors

## The idea

Run the same corpus through every credible competitor and publish the matrix.

Users choosing a prompt-injection defense don't care about any single tool's numbers in isolation — they care about the comparison. A well-run differential eval is worth more than any marketing page.

## Competitors to include

- **Aegis** (at all three sensitivity levels)
- **Rebuff** — https://github.com/protectai/rebuff
- **LLM Guard** — https://github.com/protectai/llm-guard
- **Lakera Guard** — https://www.lakera.ai/ (commercial — need API access)
- **Prompt Armor** — https://promptarmor.com/
- **NeMo Guardrails** (NVIDIA) — https://github.com/NVIDIA/NeMo-Guardrails
- **Baseline: no defense** (just the raw model) — critical for context

## The matrix

For each `(corpus, defense, sensitivity)` triple, measure:

| Metric | Source |
|---|---|
| ASR | Did the victim model comply? |
| Detection rate | Did the defense block the malicious input? |
| False positive rate | Did the defense block the benign input? |
| Median latency (input-scan) | ms |
| Median latency (output-monitor) | ms |
| Cost per 1k requests | $ — especially matters for LLM-based defenses |

## Methodology guardrails

These evals can be misleading if run carelessly. Lock down:

- **Same model** for every comparison (victim)
- **Same corpus** — don't cherry-pick per-defense favorites
- **Each defense at its recommended/default settings** — don't tune Aegis to max while using others at defaults
- **Publish the exact config for each defense** so readers can reproduce
- **Publish the raw results**, not just summary stats — every miss and false positive

If you wouldn't be comfortable showing a result to the competing team, something's off.

## When to do this

**Not yet.** Complete Plans #1 and #2 first so Aegis's own numbers are solid. Publishing a competitor comparison before you're confident in your own stack is how you lose the comparison on presentation alone.

Target: 1–2 releases after the initial launch, when the eval infrastructure is mature.

## Files to create (when ready)

- `evals/differential/adapters/` — one file per competing defense, normalized to a common interface
- `evals/differential/run.ts` — runs the full matrix
- `evals/differential/report.ts` — emits a markdown table + charts
- `evals/differential/results/<date>.json` — pinned historical runs
- `docs/comparisons/differential-eval.md` — public writeup

## Risks to manage

- Commercial defenses (Lakera, Prompt Armor) may restrict comparison publishing in their ToS. Read them.
- Open-source defenses evolve — pin exact versions in the results.
- Some competitors use LLM-based detection that hits real APIs every scan. Budget accordingly.
- Don't trash competitors in writeups. Present data; let readers decide.

## Definition of success

A published `docs/comparisons/differential-eval.md` with the full matrix, fully reproducible, including cases where Aegis loses. Losing on some axis is fine — hiding it is not.

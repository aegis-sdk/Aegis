# Plan #5 — Production Shadow Mode

## The strongest evidence

No synthetic eval beats a week of real traffic. Wire Aegis into a real production LLM app in observe-only mode: log every decision, enforce nothing. Then compare Aegis's verdicts to what actually happened.

Both kinds of error surface:
- **False positives** → Aegis would have blocked a request, but the output turned out to be fine (user wasn't upset, no abuse reported)
- **False negatives** → Aegis passed a request whose output was later flagged by a human moderator or triggered a support ticket

Unit tests can't find either. Real traffic can.

## What to build

### Client-side hook

Aegis already has `policy: "observe-only"`-style semantics possible — every scanner produces a result, enforcement is just the caller acting on it. Add a first-class config option:

```ts
const aegis = new Aegis({
  policy: "balanced",
  observeOnly: true,    // scan + audit, never throw or terminate
});
```

When `observeOnly` is on:
- `guardInput` always returns the messages unchanged
- Stream monitor never calls `controller.terminate()`
- Every scan result, every would-be violation, is written to the audit log

### Log exporter

An opt-in package `@aegis-sdk/shadow-export` that ships anonymized audit logs to a Memberstack-hosted ingestion endpoint:

- Hash or strip user identifiers
- Redact message contents (keep only detection metadata: types, scores, would-have-blocked flag)
- Batch upload daily via signed request

### Analytics dashboard

A view (in the existing `@aegis-sdk/dashboard` package) that shows:
- Rolling ASR-reduction estimate from participating sites
- False-positive rate per policy tier
- Distribution of detection types in real traffic
- "Missed attacks" queue — places where Aegis scored low but a human flagged the output

## The pilot offer

For the first cohort of early adopters:

> "Run Aegis in observe-only mode for 2 weeks. Share your anonymized audit
> logs with us. In return: free priority support, your own case study, and
> a seat on the quarterly product review. You never enforce anything you
> didn't already enforce before."

Low friction, high information yield. A few real apps over a few weeks produce more evaluation signal than years of synthetic corpus work.

## Files to create

- `packages/core/src/aegis.ts` — add `observeOnly` config flag
- `packages/shadow-export/` — new package for anonymized log shipping
- `packages/dashboard/src/shadow-analytics.*` — new view
- `docs/pilot-program.md` — the public offer

## Risks to manage

- **Privacy**: you cannot ship raw user prompts back. Ever. Only aggregate detection metadata. Run this past legal before launching the pilot.
- **PII in logs**: even detection metadata can carry PII (email addresses matched by PII pattern → the email is in `matched`). Strip or hash these server-side before logging.
- **Consent**: pilot participants must explicitly opt in per-environment, and their terms-of-service must cover it.

## Definition of success

- A public blog post with aggregated stats from N pilot deployments
- Numeric claims backed by real-traffic data, not synthetic corpora
- Specific attack categories identified by pilot-traffic analysis that weren't in the adversarial corpus before

## Timing

After Plans #1 and #2 are live and Aegis has an initial public release with real users. Shadow mode is the thing you ship *at* launch, not before.

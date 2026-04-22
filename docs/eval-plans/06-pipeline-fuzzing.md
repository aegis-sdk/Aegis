# Plan #6 — Pipeline-Level Fuzzing

## The idea

Aegis has template-based fuzzing in `tests/fuzz/` for the scanner. Extend that to fuzz the full `Aegis` *orchestrator*: random configs × random message sequences × random recovery modes × random stream chunks.

This catches contract bugs unit tests miss — the "this combination of valid inputs produced an unhandled exception" class of failure that unit tests only find if you happen to write them. Fast-check's property-based approach finds them automatically.

## Properties to assert

Start with invariants that should hold regardless of input:

1. **Never throw unhandled**
   `guardInput(any-valid-config, any-valid-messages)` resolves or rejects with a named Aegis error. Never an uncaught TypeError/ReferenceError.

2. **Deterministic**
   Two calls with identical config + input produce identical `ScanResult` objects (modulo timestamps).

3. **Pipeline completeness**
   Every call emits at least one audit entry when `transports: ["custom"]` is configured.

4. **Stream transform is idempotent on clean input**
   `createStreamTransform()` passed clean tokens produces exactly those tokens concatenated, with a ~buffer-size delay.

5. **Recovery mode invariants**
   - `mode: "continue"` never sets `sessionQuarantined = true`
   - `mode: "quarantine-session"` sets it on first block and keeps it set
   - `mode: "reset-last"` returns `messages.length - 1` messages when the last is malicious
   - `mode: "terminate-session"` always throws `AegisSessionTerminated`

6. **Sensitivity monotonicity**
   For any input: `paranoid.score >= balanced.score >= permissive.score`. If this isn't strictly true, it's a bug in the threshold model.

7. **Detection position bounds**
   Every `Detection.position` satisfies `0 <= start <= end <= normalized.length`.

## What to build

`tests/fuzz/orchestrator-fuzz.test.ts` — uses fast-check arbitraries for:

- `AegisConfig` generator (valid combinations of policy, recovery, scanner, monitor, etc.)
- `PromptMessage[]` generator (random role/content sequences, bounded length)
- Stream chunk generator (splits of a given string at random boundaries)

Run ~1000 iterations per property in CI. Failures get saved to a `.fast-check-cache` and retried — fast-check's shrinking will give you a minimal reproducer.

## Why this is cheap-but-valuable

- No LLM calls
- No external dependencies
- Property assertions are small — most of the LOC is generators, which are reusable across tests
- Finds a class of bug (handler/parser crashes on weird combinations) that humans cannot reasonably enumerate

## Files to create

- `tests/fuzz/orchestrator-fuzz.test.ts`
- `tests/fuzz/arbitraries/config.ts` — AegisConfig generator
- `tests/fuzz/arbitraries/messages.ts` — PromptMessage[] generator
- `tests/fuzz/arbitraries/stream-chunks.ts` — splitter
- `tests/fuzz/README.md` — how the fuzz infrastructure is organized, how to extend

## Priority

Low-cost side project. Good filler task between the bigger plans. Worth doing early because every property found now saves an embarrassing bug report later.

## Definition of success

A green fuzz suite that's run ~1000 iterations of each property without failure. Any property that *does* fail becomes either a bug fix or a documented non-invariant.

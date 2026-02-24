# Red Team Scanner

Automated attack suite runner. Tests Aegis defenses against a library of known prompt injection payloads and reports detection rates, false negatives, per-suite breakdowns, and timing data.

```ts
import { RedTeamScanner } from "@aegis-sdk/testing";
```

## RedTeamScanner

### Constructor

```ts
new RedTeamScanner()
```

No configuration required. The scanner is stateless — each `run()` call produces independent results.

### run()

Run attack suites against an Aegis configuration.

```ts
async run(
  aegisOrConfig?: Aegis | AegisConfig | InputScannerConfig,
  options?: RedTeamOptions
): Promise<RedTeamResult>
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `aegisOrConfig` | `Aegis \| AegisConfig \| InputScannerConfig` | Configuration to test against. Default: `{}` (balanced) |
| `options.suites` | `string[]` | Suite IDs to run. Default: all suites |
| `options.customPayloads` | `AttackPayload[]` | Additional payloads to test |
| `options.concurrency` | `number` | Max concurrent scans. Default: `10` |
| `options.threshold` | `number` | Score threshold for detection. Default: `0.4` |

The scanner uses `InputScanner` directly (not `Aegis.guardInput()`) to get continuous confidence scores rather than binary pass/fail results.

### generateReport()

Generate a formatted text report from results.

```ts
generateReport(result: RedTeamResult): string
```

Returns a multi-line string with overall statistics, per-suite detection table, and top 5 missed payloads.

### getAvailableSuites()

```ts
getAvailableSuites(): string[]
```

Returns the IDs of all built-in attack suites.

## RedTeamResult

```ts
interface RedTeamResult {
  total: number;
  detected: number;
  missed: number;
  falseNegatives: AttackPayload[];
  detectionRate: number;             // 0-1
  suiteResults: Map<string, SuiteResult>;
  results: PayloadResult[];
  totalTimeMs: number;
  avgTimeMs: number;
}
```

### SuiteResult

```ts
interface SuiteResult {
  suiteId: string;
  suiteName: string;
  total: number;
  detected: number;
  detectionRate: number;
}
```

### PayloadResult

```ts
interface PayloadResult {
  payload: AttackPayload;
  detected: boolean;
  score: number;
  detections: number;
  timeMs: number;
  suiteId: string;
}
```

## Attack Suites

20 built-in suites covering threats T1 through T19:

| Suite ID | Threat | Description |
|----------|--------|-------------|
| `direct-injection` | T1 | Direct "ignore previous instructions" variants |
| `role-manipulation` | T1 | "You are now DAN" / role reassignment |
| `delimiter-escape` | T1 | Breaking out of XML/markdown delimiters |
| `virtualization` | T1 | Developer mode / terminal simulation |
| `indirect-injection` | T2 | Instructions hidden in data (HTML, JSON, markdown) |
| `tool-abuse` | T3 | Tricking model into dangerous tool calls |
| `data-exfiltration` | T4 | Extracting system prompts, PII, secrets |
| `privilege-escalation` | T5 | Claiming admin/sudo access |
| `goal-hijacking` | T6 | Redirecting the model's objective |
| `crescendo` | T7 | Multi-turn escalation sequences |
| `encoding-bypass` | T8 | Zero-width chars, homoglyphs, base64, ROT13 |
| `memory-poisoning` | T10 | False prior agreements, injected memory |
| `many-shot` | T11 | Repeated Q&A pair conditioning |
| `adversarial-suffix` | T12 | GCG-style adversarial token strings |
| `context-flooding` | T13 | Padding to push safety instructions out of context |
| `chain-injection` | T14 | Recursive/chained tool call injection |
| `history-manipulation` | T15 | Fake conversation history injection |
| `skeleton-key` | T16 | Educational framing, safety researcher claims |
| `denial-of-wallet` | T17 | Infinite generation, token exhaustion |
| `language-switching` | T18 | Non-English / mixed language injection |
| `model-fingerprinting` | T19 | Probing model identity and capabilities |

### AttackPayload

```ts
interface AttackPayload {
  id: string;
  name: string;
  description: string;
  payload: string;
  threatCategory: string;
  expectedDetection: boolean;
}
```

### Suite Utility Functions

```ts
import {
  ATTACK_SUITES,
  getAllSuites,
  getSuiteById,
  getSuitesByThreatCategory,
  getAllPayloads,
} from "@aegis-sdk/testing";

getAllSuites();                       // All 20 suites
getSuiteById("encoding-bypass");     // Single suite or undefined
getSuitesByThreatCategory("T1");     // All suites targeting T1
getAllPayloads();                     // Flat array of all payloads
```

## Adding Custom Payloads

```ts
const scanner = new RedTeamScanner();

const results = await scanner.run({ policy: "strict" }, {
  customPayloads: [
    {
      id: "custom-001",
      name: "My custom attack",
      description: "Tests a specific bypass technique",
      payload: "Your custom payload here",
      threatCategory: "T1",
      expectedDetection: true,
    },
  ],
});
```

Custom payloads are grouped under a synthetic `"custom"` suite in the results.

## Example: Full Scan with Report

```ts
import { RedTeamScanner } from "@aegis-sdk/testing";

const scanner = new RedTeamScanner();
const results = await scanner.run(
  { policy: "strict", scanner: { sensitivity: "paranoid" } },
  { concurrency: 20 },
);

console.log(scanner.generateReport(results));

// Check specific suites
for (const [id, suite] of results.suiteResults) {
  if (suite.detectionRate < 0.95) {
    console.warn(`Suite ${id}: only ${(suite.detectionRate * 100).toFixed(0)}% detection`);
  }
}

// Examine false negatives
for (const fn of results.falseNegatives) {
  console.warn(`Missed: [${fn.id}] ${fn.name} — ${fn.payload.slice(0, 60)}...`);
}
```

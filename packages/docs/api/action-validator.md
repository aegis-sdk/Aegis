# ActionValidator

Inspects and validates every action the model proposes before execution. The last line of defense before the AI does something in the real world. Checks policy, rate limits, parameter safety, human-in-the-loop approval, MCP parameter scanning, denial-of-wallet thresholds, and data exfiltration prevention.

```ts
import { ActionValidator } from "@aegis-sdk/core";
```

## Constructor

```ts
new ActionValidator(policy: AegisPolicy, config?: ActionValidatorConfig)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `policy` | `AegisPolicy` | The resolved security policy |
| `config` | `ActionValidatorConfig` | Optional validation settings |

### ActionValidatorConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `onApprovalNeeded` | `(req: ActionValidationRequest) => Promise<boolean>` | — | Callback for human-in-the-loop approval |
| `scanMcpParams` | `boolean` | `false` | Run InputScanner on all string values in tool params |
| `scannerConfig` | `InputScannerConfig` | balanced defaults | Scanner config when `scanMcpParams` is enabled |
| `denialOfWallet` | `DenialOfWalletConfig` | — | Cost/rate abuse detection |
| `exfiltrationToolPatterns` | `string[]` | `["send_*", "email_*", ...]` | Tool patterns considered external destinations |

### DenialOfWalletConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `maxOperations` | `number` | `100` | Max total operations within the window |
| `window` | `string` | `"5m"` | Time window (e.g., `"5m"`, `"1h"`) |
| `maxSandboxTriggers` | `number` | `10` | Max sandbox triggers within the window |
| `maxToolCalls` | `number` | `50` | Max tool calls within the window |

## Methods

### check()

Validate a proposed action against the security policy.

```ts
async check(request: ActionValidationRequest): Promise<ActionValidationResult>
```

The validation pipeline runs in order:
1. **Policy check** — is this tool in the allow/deny list?
2. **Rate limit check** — has the tool exceeded its configured limit?
3. **Denial-of-wallet check** — are total operations within budget?
4. **Parameter safety check** — basic injection patterns in params
5. **MCP parameter scanning** — full InputScanner on all string param values
6. **Data exfiltration prevention** — does this action send previously-read data externally?
7. **Track tool call** for DoW detection
8. **Record previous tool output** for exfiltration tracking
9. **Human approval gate** — if the tool requires approval

### ActionValidationRequest

```ts
interface ActionValidationRequest {
  originalRequest: string;
  proposedAction: {
    tool: string;
    params: Record<string, unknown>;
  };
  previousToolOutput?: string;  // For exfiltration tracking
}
```

### ActionValidationResult

```ts
interface ActionValidationResult {
  allowed: boolean;
  reason: string;
  requiresApproval: boolean;
  awaitedApproval?: boolean;  // Set when approval was requested
}
```

### setAuditCallback()

Wire up an audit callback. Called by `Aegis` internally to connect the `AuditLog`.

```ts
setAuditCallback(cb: (entry: Omit<AuditEntry, "timestamp">) => void): void
```

### recordReadData()

Record data from a previous tool read for exfiltration detection.

```ts
recordReadData(data: string): void
```

### clearReadData()

Clear recorded data fingerprints (e.g., on session reset).

```ts
clearReadData(): void
```

### recordSandboxTrigger()

Record a sandbox trigger for denial-of-wallet tracking.

```ts
recordSandboxTrigger(): void
```

## Example

```ts
import { ActionValidator, resolvePolicy } from "@aegis-sdk/core";

const policy = resolvePolicy("customer-support");
const validator = new ActionValidator(policy, {
  scanMcpParams: true,
  denialOfWallet: { maxToolCalls: 30, window: "5m" },
  onApprovalNeeded: async (req) => {
    // Show approval UI to the human operator
    return await showApprovalDialog(req.proposedAction);
  },
});

const result = await validator.check({
  originalRequest: "Refund my last order",
  proposedAction: {
    tool: "issue_refund",
    params: { orderId: "ORD-123", amount: 49.99 },
  },
});

if (!result.allowed) {
  console.warn(`Action blocked: ${result.reason}`);
} else if (result.requiresApproval) {
  console.log("Action was approved by human reviewer");
}
```

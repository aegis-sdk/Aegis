# Alerting Engine

The Aegis `AlertingEngine` evaluates audit log entries in real-time against configurable rules and fires alerts when conditions are met. It supports rate-spike detection, session kill monitoring, cost anomaly tracking, scan block rate analysis, and repeated attacker identification.

Alert actions include console logging, webhook POSTs, and custom callback functions. All rules support cooldown periods to prevent alert flooding.

## Architecture

The alerting engine sits downstream from the `AuditLog`. Every audit entry flows through it:

```
AuditLog.log(entry)
       │
       ▼
  AlertingEngine.evaluate(entry)
       │
       ├── Check rule 1 condition → fire if met
       ├── Check rule 2 condition → fire if met
       └── ...
       │
       ▼
  Execute actions (log / webhook / callback)
```

Internally, the engine maintains a sliding window of up to 10,000 recent audit entries. Time-based conditions (rate spikes, session kills) query this window to count matching events within the configured time range.

## Configuration

Enable alerting through the `audit.alerting` section of your Aegis config:

```ts
import { Aegis } from '@aegis-sdk/core';

const aegis = new Aegis({
  audit: {
    alerting: {
      enabled: true,
      rules: [
        {
          id: 'high-block-rate',
          condition: {
            type: 'rate-spike',
            event: 'scan_block',
            threshold: 10,
            windowMs: 60_000,
          },
          action: 'log',
        },
      ],
    },
  },
});
```

## Rule Types

### Rate Spike

Fires when more than `threshold` events of a specific `event` type occur within `windowMs` milliseconds.

```ts
{
  condition: {
    type: 'rate-spike',
    event: 'scan_block',    // Any AuditEventType
    threshold: 20,          // Fire after 20 occurrences
    windowMs: 60_000,       // Within 1 minute
  },
  action: 'webhook',
  webhookUrl: 'https://hooks.slack.com/services/...',
}
```

Use this to detect sudden bursts of injection attempts, indicating an active attack.

### Session Kills

Fires when more than `threshold` `kill_switch` or `session_quarantine` events occur within `windowMs`. Only evaluates on those specific event types.

```ts
{
  condition: {
    type: 'session-kills',
    threshold: 3,
    windowMs: 300_000,      // 5 minutes
  },
  action: 'callback',
  callback: async (alert) => {
    await notifySecurityTeam(alert);
  },
}
```

Use this to detect repeated session terminations, which may indicate a persistent attacker rotating sessions.

### Cost Anomaly

Fires when `denial_of_wallet` events exceed `threshold` within `windowMs`. Only evaluates on `denial_of_wallet` events.

```ts
{
  condition: {
    type: 'cost-anomaly',
    threshold: 5,
    windowMs: 600_000,      // 10 minutes
  },
  action: 'webhook',
  webhookUrl: 'https://hooks.pagerduty.com/...',
}
```

Use this to detect denial-of-wallet attacks where an attacker triggers expensive LLM operations.

### Scan Block Rate

Fires when the ratio of `scan_block` to total scan events (`scan_block` + `scan_pass`) exceeds `threshold` (expressed as a fraction, 0-1) within `windowMs`.

```ts
{
  condition: {
    type: 'scan-block-rate',
    threshold: 0.5,         // Fire when >50% of scans are blocked
    windowMs: 300_000,
  },
  action: 'log',
}
```

Use this to detect sustained attack campaigns where a significant fraction of requests are malicious.

### Repeated Attacker

Fires when the same `sessionId` accumulates more than `threshold` blocked decisions within `windowMs`. Only evaluates on entries with `decision: "blocked"` and a `sessionId`.

```ts
{
  condition: {
    type: 'repeated-attacker',
    threshold: 5,
    windowMs: 600_000,
  },
  action: 'callback',
  callback: async (alert) => {
    const sessionId = alert.context.sessionId;
    await banSession(sessionId);
  },
}
```

Use this to identify and respond to individual attackers who are hammering a specific session.

## Alert Actions

### Console Log

Outputs a `console.warn` with the rule ID and alert context:

```ts
{ action: 'log' }
```

### Webhook

POSTs the alert as JSON to the provided URL:

```ts
{
  action: 'webhook',
  webhookUrl: 'https://hooks.example.com/alerts',
}
```

The webhook payload is:

```json
{
  "id": "m2x3y4-a1b2c3",
  "ruleId": "high-block-rate",
  "condition": { "type": "rate-spike", "event": "scan_block", "threshold": 10, "windowMs": 60000 },
  "triggeredAt": "2026-02-24T12:00:00.000Z",
  "context": {
    "triggeringEvent": "scan_block",
    "triggeringDecision": "blocked",
    "sessionId": "sess-123"
  }
}
```

### Custom Callback

Invokes your function with the full `Alert` object:

```ts
{
  action: 'callback',
  callback: async (alert) => {
    // Send to PagerDuty, Slack, Datadog, etc.
    await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        routing_key: process.env.PD_ROUTING_KEY,
        event_action: 'trigger',
        payload: {
          summary: `Aegis alert: ${alert.condition.type}`,
          severity: 'warning',
          source: 'aegis-sdk',
          custom_details: alert.context,
        },
      }),
    });
  },
}
```

## Cooldown

Each rule supports a `cooldownMs` to prevent alert flooding. After a rule fires, it will not fire again until the cooldown period expires. Default: 60,000ms (1 minute).

```ts
{
  condition: { type: 'rate-spike', event: 'scan_block', threshold: 5, windowMs: 30_000 },
  action: 'log',
  cooldownMs: 300_000, // Only alert once every 5 minutes
}
```

## Managing Alerts

### Retrieving Active Alerts

The `AlertingEngine` is accessed through the `AuditLog`:

```ts
const auditLog = aegis.getAuditLog();
// The alerting engine evaluates automatically on each audit entry
```

### Standalone Usage

You can use the `AlertingEngine` independently of Aegis:

```ts
import { AlertingEngine } from '@aegis-sdk/core';

const engine = new AlertingEngine({
  enabled: true,
  rules: [
    {
      id: 'spike-detector',
      condition: { type: 'rate-spike', event: 'scan_block', threshold: 10, windowMs: 60_000 },
      action: 'callback',
      callback: (alert) => console.log('Spike detected!', alert),
      cooldownMs: 120_000,
    },
  ],
});

// Evaluate entries manually
const alerts = engine.evaluate(auditEntry);

// Check active (unresolved) alerts
const active = engine.getActiveAlerts();

// Resolve an alert
engine.resolveAlert(alerts[0].id);
```

## Complete Example: Multi-Rule Setup

```ts
const aegis = new Aegis({
  policy: 'strict',
  audit: {
    alerting: {
      enabled: true,
      rules: [
        // Detect injection bursts
        {
          id: 'injection-burst',
          condition: { type: 'rate-spike', event: 'scan_block', threshold: 15, windowMs: 60_000 },
          action: 'webhook',
          webhookUrl: process.env.SLACK_WEBHOOK_URL,
          cooldownMs: 300_000,
        },

        // Detect session abuse
        {
          id: 'session-abuse',
          condition: { type: 'repeated-attacker', threshold: 5, windowMs: 600_000 },
          action: 'callback',
          callback: async (alert) => {
            await quarantineSession(alert.context.sessionId);
          },
        },

        // Monitor cost anomalies
        {
          id: 'cost-spike',
          condition: { type: 'cost-anomaly', threshold: 3, windowMs: 300_000 },
          action: 'webhook',
          webhookUrl: process.env.PAGERDUTY_WEBHOOK_URL,
          cooldownMs: 600_000,
        },

        // Overall block rate monitoring
        {
          id: 'high-block-rate',
          condition: { type: 'scan-block-rate', threshold: 0.4, windowMs: 300_000 },
          action: 'log',
          cooldownMs: 600_000,
        },

        // Detect mass session kills
        {
          id: 'mass-kills',
          condition: { type: 'session-kills', threshold: 5, windowMs: 300_000 },
          action: 'webhook',
          webhookUrl: process.env.INCIDENT_WEBHOOK_URL,
        },
      ],
    },
  },
});
```

## Integration Patterns

### Slack

```ts
callback: async (alert) => {
  await fetch(process.env.SLACK_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      text: `*Aegis Alert*: ${alert.condition.type}\nRule: ${alert.ruleId}\nTime: ${alert.triggeredAt.toISOString()}`,
    }),
  });
}
```

### PagerDuty

```ts
callback: async (alert) => {
  await fetch('https://events.pagerduty.com/v2/enqueue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      routing_key: process.env.PD_ROUTING_KEY,
      event_action: 'trigger',
      payload: {
        summary: `Aegis: ${alert.condition.type} (rule ${alert.ruleId})`,
        severity: 'critical',
        source: 'aegis-sdk',
        custom_details: alert.context,
      },
    }),
  });
}
```

### Datadog

```ts
callback: async (alert) => {
  await fetch('https://http-intake.logs.datadoghq.com/api/v2/logs', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'DD-API-KEY': process.env.DD_API_KEY,
    },
    body: JSON.stringify({
      ddsource: 'aegis',
      ddtags: `alert_type:${alert.condition.type},rule:${alert.ruleId}`,
      message: JSON.stringify(alert),
    }),
  });
}
```

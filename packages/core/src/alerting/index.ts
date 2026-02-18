/**
 * Alerting Engine — real-time alert system for the Aegis audit pipeline.
 *
 * Evaluates audit entries against configurable rules and fires alerts
 * when conditions are met. Supports rate-spike detection, session kill
 * monitoring, cost anomaly tracking, scan block rate analysis, and
 * repeated attacker detection.
 *
 * Alert actions include console logging, webhook POSTs, and custom
 * callback functions. Rules support cooldown periods to prevent
 * alert flooding.
 */

import type { Alert, AlertCondition, AlertingConfig, AlertRule, AuditEntry } from "../types.js";

/**
 * Generate a unique ID for alerts and rules.
 * Uses a combination of timestamp and random suffix.
 */
function generateId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `${timestamp}-${random}`;
}

/**
 * AlertingEngine — evaluates audit entries against rules and fires alerts.
 *
 * Maintains a sliding window of recent audit entries for time-based
 * condition evaluation. Each rule can specify a cooldown period to
 * prevent alert flooding.
 *
 * @example
 * ```ts
 * const engine = new AlertingEngine({
 *   enabled: true,
 *   rules: [
 *     {
 *       condition: { type: 'rate-spike', event: 'scan_block', threshold: 10, windowMs: 60000 },
 *       action: 'log',
 *     },
 *     {
 *       condition: { type: 'session-kills', threshold: 3, windowMs: 300000 },
 *       action: 'webhook',
 *       webhookUrl: 'https://hooks.example.com/alerts',
 *     },
 *   ],
 * });
 *
 * // Evaluate each audit entry
 * const alerts = engine.evaluate(auditEntry);
 * ```
 */
export class AlertingEngine {
  private readonly config: AlertingConfig;
  private readonly rules: (AlertRule & { id: string })[];
  private readonly activeAlerts = new Map<string, Alert>();
  private readonly recentEntries: AuditEntry[] = [];
  private readonly lastFired = new Map<string, number>();

  /** Maximum entries to keep in the sliding window */
  private static readonly MAX_ENTRIES = 10000;

  /** Default cooldown: 1 minute */
  private static readonly DEFAULT_COOLDOWN_MS = 60000;

  constructor(config: AlertingConfig) {
    this.config = config;
    this.rules = config.rules.map((rule) => ({
      ...rule,
      id: rule.id ?? generateId(),
    }));
  }

  /**
   * Evaluate an audit entry against all configured rules.
   *
   * Returns any alerts that were triggered by this entry. Also
   * executes the configured action for each triggered alert
   * (logging, webhook, or callback).
   *
   * @param entry - The audit entry to evaluate
   * @returns Array of triggered Alert objects
   */
  evaluate(entry: AuditEntry): Alert[] {
    if (!this.config.enabled) return [];

    // Add entry to the sliding window
    this.recentEntries.push(entry);
    this.pruneEntries();

    const triggered: Alert[] = [];

    for (const rule of this.rules) {
      // Check cooldown
      if (this.isInCooldown(rule.id)) continue;

      // Evaluate the condition
      const conditionMet = this.evaluateCondition(rule.condition, entry);
      if (!conditionMet) continue;

      // Create the alert
      const alert: Alert = {
        id: generateId(),
        ruleId: rule.id,
        condition: rule.condition,
        triggeredAt: new Date(),
        context: {
          triggeringEvent: entry.event,
          triggeringDecision: entry.decision,
          sessionId: entry.sessionId,
          ...entry.context,
        },
      };

      // Record the alert
      this.activeAlerts.set(alert.id, alert);
      this.lastFired.set(rule.id, Date.now());
      triggered.push(alert);

      // Execute the action asynchronously (fire-and-forget)
      void this.executeAction(rule, alert);
    }

    return triggered;
  }

  /**
   * Get all currently active (unresolved) alerts.
   *
   * @returns Array of active Alert objects
   */
  getActiveAlerts(): Alert[] {
    return Array.from(this.activeAlerts.values()).filter((alert) => alert.resolvedAt === undefined);
  }

  /**
   * Resolve an alert by its ID.
   *
   * @param id - The alert ID to resolve
   */
  resolveAlert(id: string): void {
    const alert = this.activeAlerts.get(id);
    if (alert) {
      alert.resolvedAt = new Date();
    }
  }

  /**
   * Check whether a rule is currently in its cooldown period.
   */
  private isInCooldown(ruleId: string): boolean {
    const lastFiredTime = this.lastFired.get(ruleId);
    if (lastFiredTime === undefined) return false;

    const rule = this.rules.find((r) => r.id === ruleId);
    const cooldown = rule?.cooldownMs ?? AlertingEngine.DEFAULT_COOLDOWN_MS;

    return Date.now() - lastFiredTime < cooldown;
  }

  /**
   * Evaluate a single alert condition against the current entry and
   * recent entry history.
   */
  private evaluateCondition(condition: AlertCondition, entry: AuditEntry): boolean {
    switch (condition.type) {
      case "rate-spike":
        return this.evaluateRateSpike(condition, entry);
      case "session-kills":
        return this.evaluateSessionKills(condition, entry);
      case "cost-anomaly":
        return this.evaluateCostAnomaly(condition, entry);
      case "scan-block-rate":
        return this.evaluateScanBlockRate(condition, entry);
      case "repeated-attacker":
        return this.evaluateRepeatedAttacker(condition, entry);
    }
  }

  /**
   * Rate spike: more than N events of a specific type within a time window.
   */
  private evaluateRateSpike(
    condition: Extract<AlertCondition, { type: "rate-spike" }>,
    _entry: AuditEntry,
  ): boolean {
    const cutoff = new Date(Date.now() - condition.windowMs);
    const count = this.recentEntries.filter(
      (e) => e.event === condition.event && e.timestamp >= cutoff,
    ).length;

    return count >= condition.threshold;
  }

  /**
   * Session kills: more than N kill_switch events within a time window.
   */
  private evaluateSessionKills(
    condition: Extract<AlertCondition, { type: "session-kills" }>,
    entry: AuditEntry,
  ): boolean {
    // Only trigger on kill_switch or session_quarantine events
    if (entry.event !== "kill_switch" && entry.event !== "session_quarantine") {
      return false;
    }

    const cutoff = new Date(Date.now() - condition.windowMs);
    const count = this.recentEntries.filter(
      (e) =>
        (e.event === "kill_switch" || e.event === "session_quarantine") && e.timestamp >= cutoff,
    ).length;

    return count >= condition.threshold;
  }

  /**
   * Cost anomaly: denial_of_wallet events exceeding threshold within a window.
   */
  private evaluateCostAnomaly(
    condition: Extract<AlertCondition, { type: "cost-anomaly" }>,
    entry: AuditEntry,
  ): boolean {
    // Only trigger on denial_of_wallet events
    if (entry.event !== "denial_of_wallet") return false;

    const cutoff = new Date(Date.now() - condition.windowMs);
    const count = this.recentEntries.filter(
      (e) => e.event === "denial_of_wallet" && e.timestamp >= cutoff,
    ).length;

    return count >= condition.threshold;
  }

  /**
   * Scan block rate: percentage of scan_block vs total scans exceeds threshold.
   * Threshold is expressed as a fraction (0-1), e.g., 0.5 = 50%.
   */
  private evaluateScanBlockRate(
    condition: Extract<AlertCondition, { type: "scan-block-rate" }>,
    entry: AuditEntry,
  ): boolean {
    // Only trigger on scan events
    if (entry.event !== "scan_block" && entry.event !== "scan_pass") return false;

    const cutoff = new Date(Date.now() - condition.windowMs);
    const recentScans = this.recentEntries.filter(
      (e) => (e.event === "scan_block" || e.event === "scan_pass") && e.timestamp >= cutoff,
    );

    if (recentScans.length === 0) return false;

    const blockCount = recentScans.filter((e) => e.event === "scan_block").length;
    const blockRate = blockCount / recentScans.length;

    return blockRate >= condition.threshold;
  }

  /**
   * Repeated attacker: same session triggers blocks more than N times within a window.
   */
  private evaluateRepeatedAttacker(
    condition: Extract<AlertCondition, { type: "repeated-attacker" }>,
    entry: AuditEntry,
  ): boolean {
    // Only trigger on block events with a session ID
    if (entry.decision !== "blocked" || !entry.sessionId) return false;

    const cutoff = new Date(Date.now() - condition.windowMs);
    const sessionBlocks = this.recentEntries.filter(
      (e) => e.decision === "blocked" && e.sessionId === entry.sessionId && e.timestamp >= cutoff,
    ).length;

    return sessionBlocks >= condition.threshold;
  }

  /**
   * Execute the action configured for a triggered alert rule.
   */
  private async executeAction(rule: AlertRule, alert: Alert): Promise<void> {
    switch (rule.action) {
      case "log":
        this.executeLog(alert);
        break;
      case "webhook":
        await this.executeWebhook(rule, alert);
        break;
      case "callback":
        await this.executeCallback(rule, alert);
        break;
    }
  }

  /**
   * Log the alert to console.warn.
   */
  private executeLog(alert: Alert): void {
    console.warn(
      `[AEGIS ALERT] Rule ${alert.ruleId} triggered: ${alert.condition.type}`,
      alert.context,
    );
  }

  /**
   * POST the alert to a webhook URL.
   */
  private async executeWebhook(rule: AlertRule, alert: Alert): Promise<void> {
    if (!rule.webhookUrl) return;

    try {
      await fetch(rule.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: alert.id,
          ruleId: alert.ruleId,
          condition: alert.condition,
          triggeredAt: alert.triggeredAt.toISOString(),
          context: alert.context,
        }),
      });
    } catch (err) {
      console.warn(`[AEGIS ALERT] Webhook delivery failed for rule ${alert.ruleId}:`, err);
    }
  }

  /**
   * Invoke the custom callback function.
   */
  private async executeCallback(rule: AlertRule, alert: Alert): Promise<void> {
    if (!rule.callback) return;

    try {
      await rule.callback(alert);
    } catch (err) {
      console.warn(`[AEGIS ALERT] Callback failed for rule ${alert.ruleId}:`, err);
    }
  }

  /**
   * Prune old entries from the sliding window to prevent unbounded memory growth.
   */
  private pruneEntries(): void {
    if (this.recentEntries.length > AlertingEngine.MAX_ENTRIES) {
      // Remove the oldest half
      const removeCount = Math.floor(AlertingEngine.MAX_ENTRIES / 2);
      this.recentEntries.splice(0, removeCount);
    }
  }
}

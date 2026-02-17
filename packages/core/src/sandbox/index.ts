import type { Quarantined, SandboxConfig, ExtractionSchema } from "../types.js";

/**
 * Sandbox — process untrusted content through a zero-capability model call.
 *
 * The sandbox uses a cheap, fast model with NO tools and NO capabilities.
 * Even if the processing model gets completely hijacked by injected
 * instructions, it cannot take any actions — it can only output data
 * matching the defined schema.
 *
 * This module requires a provider SDK to be configured at runtime.
 * It will be fully implemented in Phase 1b when provider adapters are built.
 */
export class Sandbox {
  private config: SandboxConfig;

  constructor(config: SandboxConfig) {
    this.config = config;
  }

  /**
   * Extract structured data from untrusted content.
   *
   * Sends the content to a constrained model with no tools/capabilities,
   * requesting structured output matching the provided schema.
   *
   * @example
   * ```ts
   * const result = await sandbox.extract(quarantinedEmail, {
   *   schema: {
   *     sentiment: { type: 'enum', values: ['positive', 'negative', 'neutral'] },
   *     topic: { type: 'string', maxLength: 100 },
   *   },
   *   instructions: "Extract key information from this email.",
   * });
   * ```
   */
  async extract<T = Record<string, unknown>>(
    input: Quarantined<string>,
    options: {
      schema: ExtractionSchema;
      instructions?: string;
    },
  ): Promise<T> {
    // This is a stub — full implementation requires provider adapters.
    // The architecture is defined; the wiring happens in Phase 1b.
    void input;
    void options;
    void this.config;

    throw new Error(
      "[aegis] Sandbox.extract() requires a provider adapter. " +
        "Install @aegis-sdk/anthropic or @aegis-sdk/openai, or use the Vercel AI SDK integration " +
        "(@aegis-sdk/vercel) which handles this automatically.",
    );
  }
}

/**
 * OpenRouter adapter for Aegis.
 *
 * OpenRouter is an OpenAI-compatible aggregator fronting many providers.
 * We use it as the free-tier source of judge and victim models for eval
 * harnesses — their `:free` suffix models cost $0 at time of writing but
 * rate-limit to ~20 req/min and quality varies.
 *
 * This package exposes two factories:
 * - `createJudgeCall`: returns an `LLMJudgeCallFn` suitable for Aegis's
 *   built-in `LLMJudge` (prompt-in, string-out).
 * - `createChatCall`: returns a simpler chat-completion function for
 *   sending adversarial payloads to a victim model during ASR measurement.
 *
 * Free models (as of April 2026):
 *   - meta-llama/llama-3.1-8b-instruct:free
 *   - google/gemma-2-9b-it:free
 *   - mistralai/mistral-7b-instruct:free
 *   - deepseek/deepseek-r1:free
 *   - qwen/qwen-2.5-7b-instruct:free
 *
 * Paid models (if budget allows):
 *   - anthropic/claude-haiku-4.5
 *   - openai/gpt-4o-mini
 *   - meta-llama/llama-3.1-70b-instruct
 *
 * See https://openrouter.ai/models for the current catalog.
 */

import type { LLMJudgeCallFn } from "@aegis-sdk/core";

const OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions";

export interface OpenRouterConfig {
  /** Your OpenRouter API key. Required. Get one at https://openrouter.ai/keys. */
  apiKey: string;
  /** Model identifier. Defaults to a free small-model suitable for smoke tests. */
  model?: string;
  /** Optional HTTP referrer/title (OpenRouter uses these for analytics). */
  siteUrl?: string;
  siteName?: string;
  /** Request timeout in ms. Default: 60_000. */
  timeout?: number;
  /** Max tokens to generate. Default: 1024. */
  maxTokens?: number;
  /** Temperature. Default: 0 for determinism (recommended for judges and evals). */
  temperature?: number;
  /**
   * Retries for 429 / 5xx responses. Default: 3.
   * Retries use exponential backoff starting at `retryBaseDelayMs`.
   */
  maxRetries?: number;
  /** Base delay between retries (doubled each attempt). Default: 2000 ms. */
  retryBaseDelayMs?: number;
}

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

/**
 * Create an `LLMJudgeCallFn` suitable for `new LLMJudge({ llmCall: ... })`.
 *
 * The core `LLMJudge` constructs its own prompt and expects a plain string
 * response, so this factory wraps the OpenRouter chat completion into
 * that narrower contract.
 */
export function createJudgeCall(config: OpenRouterConfig): LLMJudgeCallFn {
  const chat = createChatCall(config);
  return async (prompt: string): Promise<string> => {
    return chat([{ role: "user", content: prompt }]);
  };
}

/**
 * Create a chat-completion function for sending multi-turn messages to
 * an OpenRouter-hosted model. Used by the live eval harness to simulate
 * a real LLM application receiving adversarial input.
 */
export function createChatCall(
  config: OpenRouterConfig,
): (messages: ChatMessage[]) => Promise<string> {
  const {
    apiKey,
    model = DEFAULT_FREE_MODEL,
    siteUrl,
    siteName,
    timeout = 60_000,
    maxTokens = 1024,
    temperature = 0,
    maxRetries = 3,
    retryBaseDelayMs = 2000,
  } = config;

  if (!apiKey) {
    throw new Error(
      "[aegis/openrouter] apiKey is required. Get one at https://openrouter.ai/keys and pass it as { apiKey }.",
    );
  }

  const headers: Record<string, string> = {
    "content-type": "application/json",
    authorization: `Bearer ${apiKey}`,
  };
  if (siteUrl) headers["HTTP-Referer"] = siteUrl;
  if (siteName) headers["X-Title"] = siteName;

  const attemptOnce = async (messages: ChatMessage[]): Promise<string> => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(OPENROUTER_URL, {
        method: "POST",
        headers,
        body: JSON.stringify({
          model,
          messages,
          max_tokens: maxTokens,
          temperature,
        }),
        signal: controller.signal,
      });

      if (!res.ok) {
        const errText = await res.text().catch(() => "<no body>");
        const err = new Error(
          `[aegis/openrouter] ${model} returned ${res.status} ${res.statusText}: ${errText}`,
        ) as Error & { status?: number };
        err.status = res.status;
        throw err;
      }

      const body = (await res.json()) as {
        choices?: { message?: { content?: string } }[];
        error?: { message?: string; code?: number };
      };

      if (body.error) {
        const err = new Error(
          `[aegis/openrouter] ${model} error: ${body.error.message ?? "unknown"}`,
        ) as Error & { status?: number };
        err.status = body.error.code;
        throw err;
      }

      const content = body.choices?.[0]?.message?.content;
      if (typeof content !== "string") {
        throw new Error(
          `[aegis/openrouter] ${model} returned no content: ${JSON.stringify(body).slice(0, 200)}`,
        );
      }
      return content;
    } finally {
      clearTimeout(timeoutId);
    }
  };

  return async (messages: ChatMessage[]): Promise<string> => {
    let lastErr: unknown;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await attemptOnce(messages);
      } catch (error: unknown) {
        lastErr = error;
        const status = (error as { status?: number }).status;
        // Retry on transient errors only: 429 (rate limit) or 5xx.
        const isRetryable = status === 429 || (typeof status === "number" && status >= 500);
        if (!isRetryable || attempt === maxRetries) break;
        const delay = retryBaseDelayMs * Math.pow(2, attempt);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
    throw lastErr;
  };
}

/**
 * Known-good free models on OpenRouter as of April 2026. This list changes
 * frequently — verify at https://openrouter.ai/models before assuming an
 * id is live. Ordered roughly small → large.
 */
export const FREE_MODELS = [
  "meta-llama/llama-3.2-3b-instruct:free",
  "google/gemma-3-4b-it:free",
  "nvidia/nemotron-nano-9b-v2:free",
  "google/gemma-3-12b-it:free",
  "google/gemma-3-27b-it:free",
  "openai/gpt-oss-20b:free",
  "meta-llama/llama-3.3-70b-instruct:free",
  "openai/gpt-oss-120b:free",
  "nousresearch/hermes-3-llama-3.1-405b:free",
] as const;

export type FreeModel = (typeof FREE_MODELS)[number];

/** Sensible default when the caller doesn't specify: small, fast, permissive tier. */
export const DEFAULT_FREE_MODEL: FreeModel = "meta-llama/llama-3.2-3b-instruct:free";

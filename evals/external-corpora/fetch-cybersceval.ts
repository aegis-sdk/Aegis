/**
 * CyberSecEval 2 / PurpleLlama — prompt injection evaluation set (Meta).
 *
 * Paper:  "CyberSecEval 2: A Wide-Ranging Cybersecurity Evaluation Suite
 *          for Large Language Models" (Bhatt et al., Meta 2024)
 * Source: https://github.com/meta-llama/PurpleLlama
 * License: permissive (MIT-like). Read LICENSE before redistributing.
 *
 * We pull the `prompt_injection.json` dataset. Each record has:
 *   - `test_case_prompt`: the system prompt the model was given
 *   - `user_input`: the adversarial user input (the payload we test)
 *   - `judge_question`: how an LLM judge decides success
 *   - `injection_variant`: category of injection
 *
 * We treat `user_input` as the malicious payload and `injection_variant`
 * as the category.
 */

import type { Corpus, CorpusEntry } from "./types.js";
import { fetchCached } from "./cache.js";

const PROMPT_INJECTION_URL =
  "https://raw.githubusercontent.com/meta-llama/PurpleLlama/main/CybersecurityBenchmarks/datasets/prompt_injection/prompt_injection.json";

interface RawRecord {
  test_case_prompt?: string;
  user_input?: string;
  judge_question?: string;
  injection_variant?: string;
  injection_type?: string;
  risk_category?: string;
  [key: string]: unknown;
}

export async function fetchCyberSecEval(limit?: number): Promise<Corpus> {
  const body = await fetchCached(PROMPT_INJECTION_URL, "cybersceval/prompt_injection.json");
  const rows = JSON.parse(body) as RawRecord[];

  const entries: CorpusEntry[] = rows
    .filter((r) => typeof r.user_input === "string" && r.user_input.length > 0)
    .map((r, i) => ({
      id: `cybersceval:${i}`,
      payload: r.user_input ?? "",
      label: "malicious" as const,
      category: r.injection_variant ?? r.injection_type ?? r.risk_category ?? "unknown",
      description: r.judge_question ? `judge: ${r.judge_question.slice(0, 80)}` : undefined,
    }));

  const final = limit ? entries.slice(0, limit) : entries;
  return {
    name: "cybersceval",
    source: "https://github.com/meta-llama/PurpleLlama",
    entries: final,
  };
}

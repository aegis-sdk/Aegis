/**
 * TensorTrust — prompt extraction / hijacking attacks from a human CTF game.
 *
 * Paper:  "Tensor Trust: Interpretable Prompt Injection Attacks from an
 *          Online Game" (Toyer et al., 2024)
 * Source: https://github.com/HumanCompatibleAI/tensor-trust-data
 * License: research use — read the repo LICENSE before redistributing raw data.
 *
 * The dataset has a few subsets. We target the "extraction-robustness" and
 * "hijack-robustness" JSONL files, which have clear malicious labels and are
 * the most relevant for prompt-injection defense evaluation.
 */

import type { Corpus, CorpusEntry } from "./types.js";
import { fetchCached } from "./cache.js";

// Raw file from the HumanCompatibleAI/tensor-trust-data repo.
// Small enough (~5MB) to pull directly. If the repo moves, update this URL.
const HIJACK_URL =
  "https://raw.githubusercontent.com/HumanCompatibleAI/tensor-trust-data/main/benchmarks/hijacking-robustness/v1/hijacking_robustness_dataset.jsonl";
const EXTRACTION_URL =
  "https://raw.githubusercontent.com/HumanCompatibleAI/tensor-trust-data/main/benchmarks/extraction-robustness/v1/extraction_robustness_dataset.jsonl";

interface RawEntry {
  sample_id?: string;
  pre_prompt?: string;
  attack?: string;
  post_prompt?: string;
  access_code?: string;
  [key: string]: unknown;
}

function parseJsonl(body: string): RawEntry[] {
  return body
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as RawEntry);
}

export async function fetchTensorTrust(limit?: number): Promise<Corpus> {
  const [hijackBody, extractionBody] = await Promise.all([
    fetchCached(HIJACK_URL, "tensortrust/hijacking-robustness.jsonl"),
    fetchCached(EXTRACTION_URL, "tensortrust/extraction-robustness.jsonl"),
  ]);

  const entries: CorpusEntry[] = [];

  const pushFrom = (raw: RawEntry[], category: string): void => {
    for (const r of raw) {
      // The "attack" field holds the adversarial payload — that's the
      // malicious input. Skip entries where it's missing.
      const attack = (r.attack ?? "").trim();
      if (!attack) continue;
      const id = typeof r.sample_id === "string" ? r.sample_id : `${category}-${entries.length}`;
      entries.push({
        id: `tensortrust:${id}`,
        payload: attack,
        label: "malicious",
        category,
      });
    }
  };

  pushFrom(parseJsonl(hijackBody), "hijacking");
  pushFrom(parseJsonl(extractionBody), "extraction");

  // Cap if the caller asked for a sample — full corpus is ~5-10k entries,
  // useful for fast iteration to pull a subset.
  const final = limit ? entries.slice(0, limit) : entries;

  return {
    name: "tensortrust",
    source: "https://github.com/HumanCompatibleAI/tensor-trust-data",
    entries: final,
  };
}

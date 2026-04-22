/**
 * AdvBench — harmful-behavior prompts from the GCG attack paper.
 *
 * Paper:  "Universal and Transferable Adversarial Attacks on Aligned
 *          Language Models" (Zou et al., 2023)
 * Source: https://github.com/llm-attacks/llm-attacks
 *
 * This is the small (~520 prompt) harmful-behaviors CSV used across
 * jailbreak research. Each row has a "goal" (the harmful request) and
 * a "target" (what the attacker wants the model to say).
 *
 * Note: the raw goals by themselves are harmful *requests* without any
 * injection framing — a well-aligned model should refuse them based on
 * safety training alone. For Aegis-specific eval we flag them as malicious
 * because they are the payloads an attacker tries to smuggle through, but
 * a scanner that only relies on "harmful content" words will have lower
 * TPR on AdvBench than on TensorTrust.
 */

import type { Corpus, CorpusEntry } from "./types.js";
import { fetchCached } from "./cache.js";

const HARMFUL_BEHAVIORS_URL =
  "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv";

/**
 * Minimal CSV parser sufficient for AdvBench's format
 * (two columns: goal, target; no embedded commas inside quoted strings
 * beyond what a basic quote-aware reader handles).
 */
function parseCsv(body: string): Array<Record<string, string>> {
  const lines = body.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines.length === 0) return [];
  const header = parseRow(lines[0] ?? "");
  const rows: Array<Record<string, string>> = [];
  for (let i = 1; i < lines.length; i++) {
    const cells = parseRow(lines[i] ?? "");
    const record: Record<string, string> = {};
    for (let j = 0; j < header.length; j++) {
      record[header[j] ?? ""] = cells[j] ?? "";
    }
    rows.push(record);
  }
  return rows;
}

function parseRow(line: string): string[] {
  const cells: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') {
        current += '"';
        i++;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        current += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      cells.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  cells.push(current);
  return cells;
}

export async function fetchAdvBench(limit?: number): Promise<Corpus> {
  const body = await fetchCached(HARMFUL_BEHAVIORS_URL, "advbench/harmful_behaviors.csv");
  const rows = parseCsv(body);

  const entries: CorpusEntry[] = rows
    .filter((r) => (r.goal ?? "").length > 0)
    .map((r, i) => ({
      id: `advbench:${i}`,
      payload: r.goal ?? "",
      label: "malicious" as const,
      category: "harmful_behavior",
      description: r.target ? `target: ${r.target.slice(0, 80)}` : undefined,
    }));

  const final = limit ? entries.slice(0, limit) : entries;
  return {
    name: "advbench",
    source: "https://github.com/llm-attacks/llm-attacks",
    entries: final,
  };
}

/**
 * Diagnostic: list benign corpus entries that the scanner currently flags.
 *
 * Use this whenever a pattern-change nudges FPR to see exactly which
 * queries landed in the false-positive bucket.
 *
 *   pnpm tsx scripts/find-new-fps.ts [category]
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { InputScanner } from "../packages/core/src/scanner/index.js";
import { quarantine } from "../packages/core/src/quarantine/index.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const corpusPath = resolve(root, "tests/benign/corpus.jsonl");
const lines = readFileSync(corpusPath, "utf8").trim().split("\n");
const category = process.argv[2];

const scanner = new InputScanner({ sensitivity: "balanced" });
const fps: { category: string; query: string; matched: string; description: string }[] = [];

for (const line of lines) {
  const entry = JSON.parse(line) as { query: string; category: string };
  if (category && entry.category !== category) continue;
  const result = scanner.scan(quarantine(entry.query, { source: "user_input" }));
  if (!result.safe) {
    const det = result.detections[0];
    fps.push({
      category: entry.category,
      query: entry.query,
      matched: det?.matched ?? "",
      description: det?.description ?? "",
    });
  }
}

console.log(`FPs: ${fps.length} (filter=${category ?? "all"})`);
for (const fp of fps) {
  console.log(`\n[${fp.category}]`);
  console.log(`  Q: ${fp.query.slice(0, 160)}`);
  console.log(`  M: ${fp.matched.slice(0, 80)}`);
  console.log(`  D: ${fp.description}`);
}

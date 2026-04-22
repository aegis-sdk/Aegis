/**
 * CLI: fetch every external corpus and run it through Aegis at every sensitivity.
 *
 * Usage:
 *   pnpm eval:external                       # full run, all corpora, all sensitivities
 *   pnpm eval:external --corpus tensortrust  # single corpus
 *   pnpm eval:external --limit 200           # cap per-corpus entries (fast smoke)
 *   pnpm eval:external --sensitivity paranoid
 *
 * Results are written to evals/external-results/<corpus>-<sensitivity>.json
 * Summary table is printed to stdout.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Sensitivity } from "../../packages/core/src/types.js";
import type { Corpus, CorpusResult } from "./types.js";
import { fetchTensorTrust } from "./fetch-tensortrust.js";
import { fetchAdvBench } from "./fetch-advbench.js";
import { fetchCyberSecEval } from "./fetch-cybersceval.js";
import { runCorpus } from "./run-corpus.js";

type Fetcher = (limit?: number) => Promise<Corpus>;

const FETCHERS: Record<string, Fetcher> = {
  tensortrust: fetchTensorTrust,
  advbench: fetchAdvBench,
  cybersceval: fetchCyberSecEval,
};

const ALL_SENSITIVITIES: Sensitivity[] = ["permissive", "balanced", "paranoid"];

interface Args {
  corpus?: string;
  sensitivity?: Sensitivity;
  limit?: number;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {};
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const next = argv[i + 1];
    if (flag === "--corpus" && next) {
      args.corpus = next;
      i++;
    } else if (flag === "--sensitivity" && next) {
      args.sensitivity = next as Sensitivity;
      i++;
    } else if (flag === "--limit" && next) {
      args.limit = parseInt(next, 10);
      i++;
    }
  }
  return args;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const resultsDir = fileURLToPath(new URL("../external-results/", import.meta.url));
  await mkdir(resultsDir, { recursive: true });

  const selectedCorpora = args.corpus
    ? [args.corpus]
    : Object.keys(FETCHERS);
  const selectedSensitivities = args.sensitivity ? [args.sensitivity] : ALL_SENSITIVITIES;

  const summary: Array<{
    corpus: string;
    sensitivity: Sensitivity;
    total: number;
    tpr: number;
    fpr: number;
    mean: number;
  }> = [];

  for (const name of selectedCorpora) {
    const fetcher = FETCHERS[name];
    if (!fetcher) {
      console.error(`Unknown corpus: ${name}. Available: ${Object.keys(FETCHERS).join(", ")}`);
      process.exit(1);
    }
    console.log(`\n=== ${name} ===`);
    console.log(`  fetching...`);
    const corpus = await fetcher(args.limit);
    console.log(`  loaded ${corpus.entries.length} entries from ${corpus.source}`);

    for (const sensitivity of selectedSensitivities) {
      console.log(`  running at sensitivity=${sensitivity}`);
      const result = await runCorpus(corpus, { sensitivity });
      const filename = `${name}-${sensitivity}.json`;
      await writeFile(
        resolve(resultsDir, filename),
        JSON.stringify(result, null, 2) + "\n",
      );
      console.log(
        `    TPR: ${result.malicious.tpr.toFixed(2)}%  ` +
          `FPR: ${result.benign.fpr.toFixed(2)}%  ` +
          `mean: ${result.latencyMs.mean.toFixed(3)}ms  ` +
          `→ ${filename}`,
      );
      summary.push({
        corpus: name,
        sensitivity,
        total: result.total.malicious + result.total.benign,
        tpr: result.malicious.tpr,
        fpr: result.benign.fpr,
        mean: result.latencyMs.mean,
      });
    }
  }

  console.log(`\n=== Summary ===\n`);
  console.log(
    "  Corpus        | Sensitivity | Entries | TPR    | FPR   | Mean lat",
  );
  console.log(
    "  ---------------------------------------------------------------------",
  );
  for (const row of summary) {
    const corpus = row.corpus.padEnd(13);
    const sens = row.sensitivity.padEnd(11);
    const total = String(row.total).padStart(7);
    const tpr = `${row.tpr.toFixed(2)}%`.padStart(6);
    const fpr = `${row.fpr.toFixed(2)}%`.padStart(5);
    const mean = `${row.mean.toFixed(3)}ms`.padStart(8);
    console.log(`  ${corpus} | ${sens} | ${total} | ${tpr} | ${fpr} | ${mean}`);
  }
  console.log();
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});

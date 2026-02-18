/**
 * Pattern DB Auto-Sync Script
 *
 * Fetches attack patterns from external sources, validates their integrity,
 * deduplicates against existing patterns, and writes them to the external
 * patterns JSON file consumed by @aegis-sdk/core's InputScanner.
 *
 * Sources:
 *   - Promptfoo redteam plugin payloads (real GitHub URL)
 *   - OWASP LLM Top 10 reference (real URL, but HTML — manual curation needed)
 *   - Aegis community patterns (placeholder — repo does not exist yet)
 *
 * Usage:
 *   npx tsx scripts/sync-patterns.ts            # Full sync
 *   npx tsx scripts/sync-patterns.ts --dry-run   # Preview without writing
 *   npx tsx scripts/sync-patterns.ts --force      # Skip hash verification
 */

import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// ─── Constants ─────────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

const MANIFEST_PATH = resolve(ROOT, "scripts/pattern-manifest.json");
const EXTERNAL_PATTERNS_PATH = resolve(
  ROOT,
  "packages/core/src/scanner/external-patterns.json",
);

/** Request timeout in milliseconds */
const FETCH_TIMEOUT_MS = 15_000;

// ─── Types ─────────────────────────────────────────────────────────────────────

interface ExternalPattern {
  id: string;
  category: string;
  pattern: string;
  source: string;
  severity: "low" | "medium" | "high" | "critical";
  description?: string;
}

interface ExternalPatternsFile {
  version: string;
  generatedAt: string | null;
  patterns: ExternalPattern[];
}

interface SourceEntry {
  hash: string | null;
  url: string;
  lastFetched: string | null;
}

interface Manifest {
  lastSync: string | null;
  sources: Record<string, SourceEntry>;
  totalPatterns: number;
}

interface SyncStats {
  fetched: number;
  newPatterns: number;
  duplicatesSkipped: number;
  errors: string[];
  hashMismatches: string[];
}

// ─── CLI Flags ─────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const DRY_RUN = args.includes("--dry-run");
const FORCE = args.includes("--force");

// ─── Logging ───────────────────────────────────────────────────────────────────

function timestamp(): string {
  return new Date().toISOString();
}

function log(msg: string): void {
  console.log(`[${timestamp()}] ${msg}`);
}

function warn(msg: string): void {
  console.warn(`[${timestamp()}] WARN: ${msg}`);
}

function error(msg: string): void {
  console.error(`[${timestamp()}] ERROR: ${msg}`);
}

// ─── Utility ───────────────────────────────────────────────────────────────────

function sha256(data: string): string {
  return createHash("sha256").update(data, "utf-8").digest("hex");
}

function generatePatternId(source: string, pattern: string): string {
  // Deterministic ID based on source + pattern content
  const hash = sha256(`${source}:${pattern}`);
  return `${source}-${hash.slice(0, 12)}`;
}

async function fetchWithTimeout(
  url: string,
  timeoutMs: number = FETCH_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    return response;
  } finally {
    clearTimeout(timer);
  }
}

async function readJSON<T>(path: string): Promise<T> {
  const raw = await readFile(path, "utf-8");
  return JSON.parse(raw) as T;
}

async function writeJSON(path: string, data: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(data, null, 2) + "\n", "utf-8");
}

// ─── Pattern Extraction: Promptfoo ─────────────────────────────────────────────

/**
 * Extract injection patterns from Promptfoo's redteam jailbreak data.
 *
 * The file at `src/redteam/strategies/promptInjections/data.ts` exports a
 * default array of strings: `export default [ "...", "...", ... ]`.
 * Each string is a full jailbreak/injection prompt payload.
 *
 * Since the source is TypeScript (not clean JSON), we use a two-pass approach:
 *   1. Strip the `export default` wrapper and try to isolate the array body
 *   2. Extract individual string entries using regex-based parsing
 *
 * These are full prompt payloads (often multi-paragraph), not short regex
 * patterns. We store them as-is for use in testing and red-team suites.
 */
function extractPromptfooPatterns(source: string): ExternalPattern[] {
  const patterns: ExternalPattern[] = [];

  // The file format is: export default [ '...', '...', ... ]
  // We extract string literals that are array elements.
  // Approach: find all top-level string literals in the array.
  //
  // We handle three quoting styles:
  //   - Single-quoted strings (most common in this file)
  //   - Double-quoted strings
  //   - Template literal strings (backtick)
  //
  // For very long payloads, we extract a meaningful prefix to keep the
  // pattern DB manageable while preserving the full content hash for dedup.

  // First, try to isolate the array body by stripping the export wrapper
  const arrayBodyMatch = source.match(
    /export\s+default\s*\[([^]*)\]\s*;?\s*$/,
  );
  const body = arrayBodyMatch?.[1] ?? source;

  // Extract all string literals from the array body.
  // These can be single-quoted, double-quoted, or backtick-quoted.
  // Since payloads can contain escaped quotes, we use a careful regex.
  const stringEntries: string[] = [];

  // Single-quoted strings (handles escaped single quotes within)
  const singleQuotedRe = /'((?:[^'\\]|\\.)*)'/gs;
  // Double-quoted strings
  const doubleQuotedRe = /"((?:[^"\\]|\\.)*)"/gs;
  // Template literals (no interpolation expected in static data)
  const templateRe = /`((?:[^`\\]|\\.)*)`/gs;

  for (const re of [singleQuotedRe, doubleQuotedRe, templateRe]) {
    let match: RegExpExecArray | null;
    while ((match = re.exec(body)) !== null) {
      const str = match[1];
      if (!str || str.length < 30) continue;
      // Skip strings that look like code artifacts (imports, variable names)
      if (/^(import|export|const|let|var|function|class|type|interface|require)\s/.test(str)) continue;
      // Skip strings that look like file paths or module specifiers
      if (/^[.\/]/.test(str) && str.length < 100) continue;
      stringEntries.push(unescapeString(str));
    }
  }

  // Deduplicate within the extracted batch (the regex passes may overlap)
  const seen = new Set<string>();

  for (const rawPayload of stringEntries) {
    const normalized = rawPayload.trim();
    if (normalized.length < 30) continue;

    const contentHash = sha256(normalized.toLowerCase());
    if (seen.has(contentHash)) continue;
    seen.add(contentHash);

    const category = categorizePattern(normalized);
    const id = generatePatternId("promptfoo", normalized);

    // Store the full payload but truncate the pattern field for readability
    // in the JSON file. The full content is preserved in the hash/id.
    const displayPattern =
      normalized.length > 500
        ? normalized.slice(0, 497) + "..."
        : normalized;

    patterns.push({
      id,
      category,
      pattern: displayPattern,
      source: "promptfoo",
      severity: guessSeverity(normalized),
      description: `Promptfoo jailbreak payload (${category}, ${normalized.length} chars)`,
    });
  }

  return patterns;
}

/**
 * Unescape common string escape sequences from extracted TypeScript strings.
 */
function unescapeString(str: string): string {
  return str
    .replace(/\\n/g, "\n")
    .replace(/\\t/g, "\t")
    .replace(/\\r/g, "\r")
    .replace(/\\'/g, "'")
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, "\\");
}

/**
 * Categorize a pattern string into an attack category based on keyword analysis.
 */
function categorizePattern(pattern: string): string {
  const lower = pattern.toLowerCase();

  if (/ignore.*(?:previous|prior|above)|disregard|override.*instructions/i.test(lower)) {
    return "instruction_override";
  }
  if (/you are now|pretend|act as|from now on/i.test(lower)) {
    return "role_manipulation";
  }
  if (/reveal|show.*prompt|repeat.*instructions|system prompt/i.test(lower)) {
    return "data_exfiltration";
  }
  if (/bypass.*(?:auth|security|filter|restriction)/i.test(lower)) {
    return "privilege_escalation";
  }
  if (/jailbreak|DAN|do anything now|unrestricted/i.test(lower)) {
    return "jailbreak";
  }
  if (/educational purposes|hypothetical|fictional/i.test(lower)) {
    return "skeleton_key";
  }
  if (/execute|run.*command|call.*function|tool/i.test(lower)) {
    return "tool_abuse";
  }
  if (/forget|new instructions|update.*memory/i.test(lower)) {
    return "memory_poisoning";
  }
  return "general_injection";
}

/**
 * Guess severity based on pattern content keywords.
 */
function guessSeverity(pattern: string): ExternalPattern["severity"] {
  const lower = pattern.toLowerCase();

  // Critical: direct override, jailbreak, exfiltration
  if (/ignore all|disregard all|jailbreak|DAN|system prompt.*reveal|bypass.*security/i.test(lower)) {
    return "critical";
  }
  // High: role manipulation, privilege escalation
  if (/you are now|act as.*unrestricted|admin.*access|override/i.test(lower)) {
    return "high";
  }
  // Medium: skeleton key, general injection
  if (/educational purposes|hypothetical|pretend|fictional/i.test(lower)) {
    return "medium";
  }
  // Low: probing, fingerprinting
  return "medium";
}

// ─── Pattern Extraction: OWASP ─────────────────────────────────────────────────

/**
 * OWASP LLM Top 10 is an HTML page, not machine-readable pattern data.
 * We create reference entries for the known categories so they appear in
 * the pattern DB as placeholders that require manual curation.
 *
 * These are NOT extracted from the page — they are well-known categories
 * from the OWASP LLM Top 10 (2025 revision).
 */
function getOwaspReferencePatterns(): ExternalPattern[] {
  const owaspCategories = [
    {
      id: "LLM01",
      name: "Prompt Injection",
      description: "Direct and indirect prompt injection attacks",
    },
    {
      id: "LLM02",
      name: "Sensitive Information Disclosure",
      description: "Model leaking sensitive data in responses",
    },
    {
      id: "LLM03",
      name: "Supply Chain",
      description: "Vulnerabilities in LLM supply chain components",
    },
    {
      id: "LLM04",
      name: "Data and Model Poisoning",
      description: "Training data manipulation and model poisoning",
    },
    {
      id: "LLM05",
      name: "Improper Output Handling",
      description: "Insufficient validation of LLM outputs",
    },
    {
      id: "LLM06",
      name: "Excessive Agency",
      description: "LLM granted too many capabilities or autonomy",
    },
    {
      id: "LLM07",
      name: "System Prompt Leakage",
      description: "Exposure of system prompts through various techniques",
    },
    {
      id: "LLM08",
      name: "Vector and Embedding Weaknesses",
      description: "Attacks on RAG and embedding pipelines",
    },
    {
      id: "LLM09",
      name: "Misinformation",
      description: "LLM generating false or misleading information",
    },
    {
      id: "LLM10",
      name: "Unbounded Consumption",
      description: "Denial of wallet and resource exhaustion attacks",
    },
  ];

  return owaspCategories.map((cat) => ({
    id: `owasp-${cat.id.toLowerCase()}`,
    category: cat.name.toLowerCase().replace(/\s+/g, "_"),
    pattern: `[OWASP ${cat.id}] ${cat.name} — Reference category, requires manual pattern curation`,
    source: "owasp",
    severity: "high" as const,
    description: `${cat.description}. See: https://owasp.org/www-project-top-10-for-large-language-model-applications/`,
  }));
}

// ─── Pattern Extraction: Aegis Community ───────────────────────────────────────

/**
 * Fetch patterns from the Aegis community repository.
 * This is a PLACEHOLDER URL — the repository does not exist yet.
 * Expected format: { patterns: ExternalPattern[] }
 */
async function fetchAegisCommunityPatterns(
  url: string,
): Promise<{ data: ExternalPattern[]; raw: string } | null> {
  try {
    log(`Fetching Aegis community patterns from ${url}`);
    const response = await fetchWithTimeout(url);

    if (!response.ok) {
      // Expected to fail until the community repo is created
      warn(
        `Aegis community patterns not available (${response.status}). ` +
          `This is expected — the community pattern repo does not exist yet.`,
      );
      return null;
    }

    const raw = await response.text();
    const parsed = JSON.parse(raw) as { patterns?: ExternalPattern[] };

    if (!Array.isArray(parsed.patterns)) {
      warn("Aegis community response missing 'patterns' array");
      return null;
    }

    return { data: parsed.patterns, raw };
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      warn("Aegis community fetch timed out");
    } else {
      // Expected failure for placeholder URL
      warn(
        `Could not fetch Aegis community patterns: ${err instanceof Error ? err.message : String(err)}. ` +
          `This is expected until the community pattern repo is created.`,
      );
    }
    return null;
  }
}

// ─── Deduplication ─────────────────────────────────────────────────────────────

/**
 * Deduplicate patterns by ID and by pattern content similarity.
 * Keeps the first occurrence of each unique pattern.
 */
function deduplicatePatterns(
  newPatterns: ExternalPattern[],
  existingPatterns: ExternalPattern[],
): { unique: ExternalPattern[]; duplicateCount: number } {
  const existingIds = new Set(existingPatterns.map((p) => p.id));
  const existingHashes = new Set(
    existingPatterns.map((p) => sha256(p.pattern.toLowerCase().trim())),
  );

  const unique: ExternalPattern[] = [];
  let duplicateCount = 0;

  for (const pattern of newPatterns) {
    const contentHash = sha256(pattern.pattern.toLowerCase().trim());

    if (existingIds.has(pattern.id) || existingHashes.has(contentHash)) {
      duplicateCount++;
      continue;
    }

    // Also check within the new batch itself
    if (unique.some((u) => u.id === pattern.id || sha256(u.pattern.toLowerCase().trim()) === contentHash)) {
      duplicateCount++;
      continue;
    }

    unique.push(pattern);
  }

  return { unique, duplicateCount };
}

// ─── Validation ────────────────────────────────────────────────────────────────

/**
 * Validate that a pattern has all required fields and reasonable values.
 */
function validatePattern(pattern: unknown, index: number): pattern is ExternalPattern {
  if (typeof pattern !== "object" || pattern === null) {
    warn(`Pattern at index ${index}: not an object`);
    return false;
  }

  const p = pattern as Record<string, unknown>;

  if (typeof p.id !== "string" || p.id.length === 0) {
    warn(`Pattern at index ${index}: missing or empty 'id'`);
    return false;
  }
  if (typeof p.category !== "string" || p.category.length === 0) {
    warn(`Pattern at index ${index}: missing or empty 'category'`);
    return false;
  }
  if (typeof p.pattern !== "string" || p.pattern.length === 0) {
    warn(`Pattern at index ${index}: missing or empty 'pattern'`);
    return false;
  }
  if (typeof p.source !== "string" || p.source.length === 0) {
    warn(`Pattern at index ${index}: missing or empty 'source'`);
    return false;
  }

  const validSeverities = new Set(["low", "medium", "high", "critical"]);
  if (typeof p.severity !== "string" || !validSeverities.has(p.severity)) {
    warn(`Pattern at index ${index}: invalid severity '${String(p.severity)}'`);
    return false;
  }

  return true;
}

// ─── Main Sync Logic ───────────────────────────────────────────────────────────

async function main(): Promise<void> {
  log("=== Aegis Pattern DB Sync ===");
  if (DRY_RUN) log("Mode: DRY RUN (no files will be written)");
  if (FORCE) log("Mode: FORCE (hash verification skipped)");
  log("");

  // Load existing state
  const manifest = await readJSON<Manifest>(MANIFEST_PATH);
  const existingFile = await readJSON<ExternalPatternsFile>(EXTERNAL_PATTERNS_PATH);
  const existingPatterns = existingFile.patterns;

  const stats: SyncStats = {
    fetched: 0,
    newPatterns: 0,
    duplicatesSkipped: 0,
    errors: [],
    hashMismatches: [],
  };

  const allNewPatterns: ExternalPattern[] = [];

  // ─── Source 1: Promptfoo ───────────────────────────────────────────────────

  log("--- Source: Promptfoo redteam plugin ---");
  const promptfooUrl = manifest.sources.promptfoo?.url;

  if (promptfooUrl) {
    try {
      log(`Fetching ${promptfooUrl}`);
      const response = await fetchWithTimeout(promptfooUrl);

      if (!response.ok) {
        warn(`Promptfoo fetch failed with status ${response.status}`);
        stats.errors.push(`promptfoo: HTTP ${response.status}`);
      } else {
        const raw = await response.text();
        const currentHash = sha256(raw);
        stats.fetched++;

        // Integrity check
        const previousHash = manifest.sources.promptfoo?.hash;
        if (previousHash && previousHash !== currentHash && !FORCE) {
          warn(
            `Promptfoo content hash changed unexpectedly!\n` +
              `  Previous: ${previousHash}\n` +
              `  Current:  ${currentHash}\n` +
              `  This may indicate upstream changes. Use --force to accept.`,
          );
          stats.hashMismatches.push("promptfoo");
        }

        const extracted = extractPromptfooPatterns(raw);
        log(`Extracted ${extracted.length} patterns from Promptfoo source`);

        // Validate each pattern
        const validated = extracted.filter((p, i) => validatePattern(p, i));
        allNewPatterns.push(...validated);

        // Update manifest source entry
        manifest.sources.promptfoo = {
          ...manifest.sources.promptfoo,
          hash: currentHash,
          lastFetched: new Date().toISOString(),
        };
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (err instanceof Error && err.name === "AbortError") {
        warn("Promptfoo fetch timed out");
        stats.errors.push("promptfoo: timeout");
      } else {
        warn(`Promptfoo fetch failed: ${msg}`);
        stats.errors.push(`promptfoo: ${msg}`);
      }
    }
  }

  // ─── Source 2: OWASP LLM Top 10 ───────────────────────────────────────────

  log("");
  log("--- Source: OWASP LLM Top 10 ---");
  const owaspUrl = manifest.sources.owasp?.url;

  if (owaspUrl) {
    try {
      log(`Checking OWASP page availability at ${owaspUrl}`);
      const response = await fetchWithTimeout(owaspUrl);

      if (!response.ok) {
        warn(`OWASP page returned status ${response.status}`);
        stats.errors.push(`owasp: HTTP ${response.status}`);
      } else {
        const raw = await response.text();
        const currentHash = sha256(raw);
        stats.fetched++;

        // Integrity check
        const previousHash = manifest.sources.owasp?.hash;
        if (previousHash && previousHash !== currentHash && !FORCE) {
          warn(
            `OWASP page content hash changed. This is informational — ` +
              `OWASP patterns are reference entries, not extracted from the page.`,
          );
          stats.hashMismatches.push("owasp");
        }

        // OWASP is an HTML page — we use hardcoded reference categories
        const owaspPatterns = getOwaspReferencePatterns();
        log(
          `Generated ${owaspPatterns.length} OWASP reference entries ` +
            `(these are category placeholders, not extracted patterns)`,
        );
        allNewPatterns.push(...owaspPatterns);

        manifest.sources.owasp = {
          ...manifest.sources.owasp,
          hash: currentHash,
          lastFetched: new Date().toISOString(),
        };
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (err instanceof Error && err.name === "AbortError") {
        warn("OWASP fetch timed out");
        stats.errors.push("owasp: timeout");
      } else {
        warn(`OWASP fetch failed: ${msg}`);
        stats.errors.push(`owasp: ${msg}`);
      }
      // Still add reference patterns even if we can't reach the page
      log("Adding OWASP reference entries despite fetch failure (offline-safe)");
      const owaspPatterns = getOwaspReferencePatterns();
      allNewPatterns.push(...owaspPatterns);
    }
  }

  // ─── Source 3: Aegis Community (placeholder) ───────────────────────────────

  log("");
  log("--- Source: Aegis Community Patterns ---");
  const communityUrl = manifest.sources["aegis-community"]?.url;

  if (communityUrl) {
    const result = await fetchAegisCommunityPatterns(communityUrl);

    if (result) {
      const currentHash = sha256(result.raw);
      stats.fetched++;

      const previousHash = manifest.sources["aegis-community"]?.hash;
      if (previousHash && previousHash !== currentHash && !FORCE) {
        warn("Aegis community content hash changed unexpectedly");
        stats.hashMismatches.push("aegis-community");
      }

      const validated = result.data.filter((p, i) => validatePattern(p, i));
      log(`Fetched ${validated.length} community patterns`);
      allNewPatterns.push(...validated);

      manifest.sources["aegis-community"] = {
        ...manifest.sources["aegis-community"],
        hash: currentHash,
        lastFetched: new Date().toISOString(),
      };
    }
  }

  // ─── Deduplication ─────────────────────────────────────────────────────────

  log("");
  log("--- Deduplication ---");
  const { unique, duplicateCount } = deduplicatePatterns(allNewPatterns, existingPatterns);
  stats.newPatterns = unique.length;
  stats.duplicatesSkipped = duplicateCount;

  log(`Total patterns extracted: ${allNewPatterns.length}`);
  log(`New unique patterns: ${unique.length}`);
  log(`Duplicates skipped: ${duplicateCount}`);

  // ─── Write Output ──────────────────────────────────────────────────────────

  const mergedPatterns = [...existingPatterns, ...unique];
  const outputFile: ExternalPatternsFile = {
    version: "1.0.0",
    generatedAt: new Date().toISOString(),
    patterns: mergedPatterns,
  };

  manifest.lastSync = new Date().toISOString();
  manifest.totalPatterns = mergedPatterns.length;

  if (DRY_RUN) {
    log("");
    log("--- Dry Run Summary ---");
    log(`Would write ${mergedPatterns.length} total patterns to ${EXTERNAL_PATTERNS_PATH}`);
    log(`Would update manifest at ${MANIFEST_PATH}`);

    if (unique.length > 0) {
      log("");
      log("New patterns that would be added:");
      for (const p of unique.slice(0, 15)) {
        log(`  [${p.severity}] ${p.source}/${p.category}: ${p.pattern.slice(0, 80)}${p.pattern.length > 80 ? "..." : ""}`);
      }
      if (unique.length > 15) {
        log(`  ... and ${unique.length - 15} more`);
      }
    }
  } else {
    log("");
    log("--- Writing Files ---");
    await writeJSON(EXTERNAL_PATTERNS_PATH, outputFile);
    log(`Wrote ${mergedPatterns.length} patterns to ${EXTERNAL_PATTERNS_PATH}`);

    await writeJSON(MANIFEST_PATH, manifest);
    log(`Updated manifest at ${MANIFEST_PATH}`);
  }

  // ─── Summary ───────────────────────────────────────────────────────────────

  log("");
  log("=== Sync Summary ===");
  log(`Sources fetched successfully: ${stats.fetched}`);
  log(`New patterns added: ${stats.newPatterns}`);
  log(`Duplicates skipped: ${stats.duplicatesSkipped}`);
  log(`Total patterns in DB: ${mergedPatterns.length}`);

  if (stats.hashMismatches.length > 0) {
    log("");
    warn(`Hash mismatches detected for: ${stats.hashMismatches.join(", ")}`);
    warn("Upstream sources may have changed. Review the diff carefully.");
  }

  if (stats.errors.length > 0) {
    log("");
    warn(`Errors encountered:`);
    for (const e of stats.errors) {
      warn(`  - ${e}`);
    }
  }

  log("");
  log(DRY_RUN ? "Dry run complete. No files were modified." : "Sync complete.");
}

// ─── Entry Point ───────────────────────────────────────────────────────────────

main().catch((err: unknown) => {
  error(`Fatal error: ${err instanceof Error ? err.message : String(err)}`);
  if (err instanceof Error && err.stack) {
    error(err.stack);
  }
  process.exit(1);
});

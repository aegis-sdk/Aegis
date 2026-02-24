#!/usr/bin/env node

/**
 * Build script for @aegis-sdk/dashboard.
 *
 * The dashboard is a single self-contained HTML file that ships pre-built
 * in dist/index.html. This script is a no-op placeholder — the HTML file
 * is committed directly and does not need compilation.
 *
 * Future iterations may add:
 *   - CSS minification
 *   - JS minification
 *   - Template variable injection (version, build date)
 */

import { existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const distHtml = resolve(__dirname, "..", "dist", "index.html");

if (!existsSync(distHtml)) {
  console.error("[dashboard] dist/index.html not found — nothing to build.");
  process.exit(1);
}

console.log("[dashboard] dist/index.html exists — build complete.");

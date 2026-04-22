/**
 * Fetch + cache helper for external corpora.
 *
 * Each corpus is pulled from its upstream once and written to `.cache/corpora/`
 * (gitignored). Subsequent runs read from cache so we don't re-download
 * large datasets or hammer upstream servers.
 *
 * We do NOT redistribute raw corpus data — users pull from the authoritative
 * source on first run. The local cache is a convenience, not a mirror.
 */

import { existsSync } from "node:fs";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CACHE_DIR = fileURLToPath(new URL("../../.cache/corpora/", import.meta.url));

/**
 * Fetch a URL, caching the response body keyed by filename.
 * Returns the body as a UTF-8 string.
 */
export async function fetchCached(url: string, cacheFile: string): Promise<string> {
  const cachePath = resolve(CACHE_DIR, cacheFile);
  if (existsSync(cachePath)) {
    return readFile(cachePath, "utf-8");
  }
  console.log(`  [fetch] ${url}`);
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Fetch failed for ${url}: ${res.status} ${res.statusText}`);
  }
  const body = await res.text();
  await mkdir(dirname(cachePath), { recursive: true });
  await writeFile(cachePath, body, "utf-8");
  return body;
}

/**
 * Same as fetchCached but for binary payloads (parquet, zip, etc.).
 */
export async function fetchCachedBinary(url: string, cacheFile: string): Promise<Buffer> {
  const cachePath = resolve(CACHE_DIR, cacheFile);
  if (existsSync(cachePath)) {
    return readFile(cachePath);
  }
  console.log(`  [fetch] ${url}`);
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Fetch failed for ${url}: ${res.status} ${res.statusText}`);
  }
  const body = Buffer.from(await res.arrayBuffer());
  await mkdir(dirname(cachePath), { recursive: true });
  await writeFile(cachePath, body);
  return body;
}

/**
 * Normalize metadata fields across all workspace packages.
 *
 * Ensures every published package has:
 * - `homepage` pointing at the repo README
 * - `publishConfig: {access: "public"}` for scoped packages
 * - `repository` block with a `directory` pointing at the package path
 * - `bugs` pointing at GitHub issues
 *
 * Private packages are left untouched (no-op).
 *
 * Run via: `pnpm tsx scripts/normalize-package-json.ts`
 */

import { readFile, writeFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_URL = "https://github.com/aegis-sdk/aegis";
const HOMEPAGE = `${REPO_URL}#readme`;
const BUGS_URL = `${REPO_URL}/issues`;

async function normalize(pkgPath: string): Promise<boolean> {
  const raw = await readFile(pkgPath, "utf-8");
  const pkg: Record<string, unknown> = JSON.parse(raw);

  if (pkg.private === true) {
    return false;
  }

  let changed = false;
  const dirName = pkgPath.split("/").at(-2);
  if (!dirName) throw new Error(`Cannot derive package dir from ${pkgPath}`);

  if (!pkg.homepage) {
    pkg.homepage = HOMEPAGE;
    changed = true;
  }

  if (!pkg.bugs) {
    pkg.bugs = { url: BUGS_URL };
    changed = true;
  }

  if (!pkg.publishConfig) {
    pkg.publishConfig = { access: "public" };
    changed = true;
  }

  const repository = pkg.repository as Record<string, string> | undefined;
  if (!repository) {
    pkg.repository = {
      type: "git",
      url: REPO_URL,
      directory: `packages/${dirName}`,
    };
    changed = true;
  } else if (!repository.directory) {
    repository.directory = `packages/${dirName}`;
    changed = true;
  }

  if (changed) {
    const next = JSON.stringify(pkg, null, 2) + "\n";
    await writeFile(pkgPath, next, "utf-8");
  }

  return changed;
}

async function main(): Promise<void> {
  const packagesDir = fileURLToPath(new URL("../packages/", import.meta.url));
  const entries = await readdir(packagesDir, { withFileTypes: true });
  const updated: string[] = [];
  const skipped: string[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const pkgPath = join(packagesDir, entry.name, "package.json");
    try {
      const changed = await normalize(pkgPath);
      (changed ? updated : skipped).push(entry.name);
    } catch (error) {
      console.error(`Failed to normalize ${entry.name}:`, error);
      throw error;
    }
  }

  console.log(`Updated (${updated.length}):`, updated.join(", "));
  console.log(`Unchanged (${skipped.length}):`, skipped.join(", "));
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});

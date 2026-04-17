import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { OsvVulnerability } from "./types.js";

const CACHE_DIR = "node_modules/.cache/yarn-osv-audit";
const CACHE_FILE = `${CACHE_DIR}/vulns.json`;

interface CacheEntry {
  modified: string;
  data: OsvVulnerability;
}

type CacheFile = Record<string, CacheEntry>;

/**
 * Load the vulnerability cache from disk. Returns an empty cache on any error
 * (missing file, corrupt JSON, etc.) — cache failures must never break audits.
 */
export function loadCache(): CacheFile {
  try {
    const raw = readFileSync(resolve(CACHE_FILE), "utf-8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") return parsed as CacheFile;
  } catch {
    // Cache miss or corrupt — start fresh
  }
  return {};
}

/**
 * Save the vulnerability cache to disk. Silently fails on write errors —
 * caching is best-effort.
 */
export function saveCache(cache: CacheFile): void {
  try {
    const path = resolve(CACHE_FILE);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(cache), "utf-8");
  } catch {
    // Best-effort; ignore write failures
  }
}

/**
 * Look up a cached vulnerability if the modified timestamp matches.
 */
export function getCachedVuln(
  cache: CacheFile,
  id: string,
  modified: string,
): OsvVulnerability | null {
  const entry = cache[id];
  if (!entry) return null;
  if (entry.modified !== modified) return null;
  return entry.data;
}

export function setCachedVuln(
  cache: CacheFile,
  id: string,
  modified: string,
  data: OsvVulnerability,
): void {
  cache[id] = { modified, data };
}

import { getCachedVuln, loadCache, saveCache, setCachedVuln } from "./cache.js";
import type {
  OsvBatchResult,
  OsvQuery,
  OsvQueryBatchResponse,
  OsvVulnerability,
  ParsedPackage,
} from "./types.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns";
const BATCH_SIZE = 1000;
const CONCURRENCY_LIMIT = 25;

interface FetchOptions {
  retryCount: number;
}

async function fetchWithRetry(
  url: string,
  init: RequestInit,
  opts: FetchOptions,
): Promise<Response> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= opts.retryCount; attempt++) {
    try {
      const response = await fetch(url, init);
      if (response.ok) return response;

      const body = await response.text().catch(() => "");
      if (attempt === opts.retryCount) {
        throw new Error(
          `OSV API returned ${response.status}: ${body.slice(0, 500)}`,
        );
      }
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt === opts.retryCount) throw lastError;
    }

    // Exponential backoff: 1s, 2s, 4s, ...
    await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt)));
  }

  throw lastError ?? new Error("Unexpected retry failure");
}

export interface BatchResult {
  /** packageKey (name@version) -> list of vuln IDs */
  vulnMap: Map<string, string[]>;
  /** vuln ID -> modified timestamp (used for cache invalidation) */
  modifiedMap: Map<string, string>;
}

/**
 * Query the OSV batch endpoint for vulnerabilities.
 * Chunks large package lists into batches of 1000.
 */
export async function queryBatch(
  packages: ParsedPackage[],
  retryCount: number,
): Promise<BatchResult> {
  const vulnMap = new Map<string, string[]>();
  const modifiedMap = new Map<string, string>();

  for (let offset = 0; offset < packages.length; offset += BATCH_SIZE) {
    const chunk = packages.slice(offset, offset + BATCH_SIZE);
    const queries: OsvQuery[] = chunk.map((pkg) => ({
      package: { name: pkg.name, ecosystem: "npm" as const },
      version: pkg.version,
    }));

    let results = await executeBatch(queries, retryCount);

    // Handle pagination
    let paginatedQueries: { index: number; query: OsvQuery }[] = [];
    for (let i = 0; i < results.length; i++) {
      if (results[i].next_page_token) {
        paginatedQueries.push({
          index: i,
          query: { ...queries[i], page_token: results[i].next_page_token },
        });
      }
    }

    while (paginatedQueries.length > 0) {
      const pageResults = await executeBatch(
        paginatedQueries.map((p) => p.query),
        retryCount,
      );

      const nextPage: { index: number; query: OsvQuery }[] = [];
      for (let j = 0; j < pageResults.length; j++) {
        const origIndex = paginatedQueries[j].index;
        const existing = results[origIndex].vulns ?? [];
        results[origIndex].vulns = [
          ...existing,
          ...(pageResults[j].vulns ?? []),
        ];
        if (pageResults[j].next_page_token) {
          nextPage.push({
            index: origIndex,
            query: {
              ...paginatedQueries[j].query,
              page_token: pageResults[j].next_page_token,
            },
          });
        }
      }
      paginatedQueries = nextPage;
    }

    // Map results back to packages
    for (let i = 0; i < chunk.length; i++) {
      const vulns = results[i]?.vulns ?? [];
      if (vulns.length > 0) {
        const key = `${chunk[i].name}@${chunk[i].version}`;
        const ids = vulns.map((v) => v.id);
        const existing = vulnMap.get(key) ?? [];
        vulnMap.set(key, [...existing, ...ids]);
        for (const v of vulns) {
          modifiedMap.set(v.id, v.modified);
        }
      }
    }
  }

  return { vulnMap, modifiedMap };
}

async function executeBatch(
  queries: OsvQuery[],
  retryCount: number,
): Promise<OsvBatchResult[]> {
  const response = await fetchWithRetry(
    OSV_BATCH_URL,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries }),
    },
    { retryCount },
  );

  const data = (await response.json()) as OsvQueryBatchResponse;
  return data.results;
}

/**
 * Fetch full vulnerability details for a set of vuln IDs.
 * Uses a disk cache keyed by {id, modified} to skip redundant fetches.
 * Runs uncached requests with bounded concurrency.
 */
export async function hydrateVulnerabilities(
  vulnIds: string[],
  modifiedMap: Map<string, string>,
  retryCount: number,
): Promise<Map<string, OsvVulnerability>> {
  const results = new Map<string, OsvVulnerability>();
  const unique = [...new Set(vulnIds)];

  const cache = loadCache();
  const toFetch: string[] = [];

  for (const id of unique) {
    const modified = modifiedMap.get(id);
    if (modified) {
      const cached = getCachedVuln(cache, id, modified);
      if (cached) {
        results.set(id, cached);
        continue;
      }
    }
    toFetch.push(id);
  }

  // Fetch uncached IDs with bounded concurrency
  for (let i = 0; i < toFetch.length; i += CONCURRENCY_LIMIT) {
    const batch = toFetch.slice(i, i + CONCURRENCY_LIMIT);
    const promises = batch.map(async (id) => {
      const response = await fetchWithRetry(
        `${OSV_VULN_URL}/${encodeURIComponent(id)}`,
        { method: "GET" },
        { retryCount },
      );
      const vuln = (await response.json()) as OsvVulnerability;
      return { id, vuln };
    });

    const settled = await Promise.all(promises);
    for (const { id, vuln } of settled) {
      results.set(id, vuln);
      const modified = modifiedMap.get(id);
      if (modified) setCachedVuln(cache, id, modified, vuln);
    }
  }

  // Persist cache (best-effort)
  if (toFetch.length > 0) {
    saveCache(cache);
  }

  return results;
}

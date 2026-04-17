import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { calculateCvssScore, cvssToSeverity, severityFromString } from "./cvss.js";
import { parseLockfileGraph } from "./lockfile-parser.js";
import type {
  AllowlistEntry,
  AuditResult,
  Config,
  OsvVulnerability,
  ParsedPackage,
  SeverityLevel,
  VulnerabilityResult,
} from "./types.js";

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  LOW: 1,
  MODERATE: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/**
 * Determine the effective severity threshold from config.
 */
export function getSeverityThreshold(config: Config): number {
  if (config.critical) return SEVERITY_ORDER.CRITICAL;
  if (config.high) return SEVERITY_ORDER.HIGH;
  if (config.moderate) return SEVERITY_ORDER.MODERATE;
  return SEVERITY_ORDER.LOW;
}

/**
 * Extract CVSS score and severity from an OSV vulnerability.
 */
function extractSeverity(vuln: OsvVulnerability): { score: number; level: SeverityLevel } {
  // Try CVSS v3 vectors first
  if (vuln.severity) {
    for (const s of vuln.severity) {
      if (s.type === "CVSS_V3" || s.type === "CVSS_V4") {
        const score = calculateCvssScore(s.score);
        if (score !== null) {
          return { score, level: cvssToSeverity(score) };
        }
      }
    }
  }

  // Fall back to database_specific.severity string
  if (vuln.database_specific?.severity) {
    return severityFromString(vuln.database_specific.severity);
  }

  // Default to LOW if no severity info
  return { score: 2.0, level: "LOW" };
}

/**
 * Extract the fixed version for a specific package from an OSV vulnerability.
 */
function extractFixedVersion(vuln: OsvVulnerability, packageName: string): string | null {
  if (!vuln.affected) return null;

  for (const affected of vuln.affected) {
    if (affected.package?.name !== packageName) continue;
    if (!affected.ranges) continue;

    for (const range of affected.ranges) {
      if (range.type !== "ECOSYSTEM") continue;
      for (const event of range.events) {
        if (event.fixed) return event.fixed;
      }
    }
  }

  return null;
}

/**
 * Normalize an allowlist entry to its ID.
 */
function allowlistEntryId(entry: AllowlistEntry): string {
  return typeof entry === "string" ? entry : entry.id;
}

/**
 * Check if a vulnerability is allowlisted for a specific package.
 */
function isAllowlisted(
  vulnId: string,
  aliases: string[],
  packageName: string,
  allowlist: AllowlistEntry[],
): boolean {
  const allIds = [vulnId, ...aliases];

  for (const entry of allowlist) {
    const entryId = allowlistEntryId(entry);
    if (!allIds.includes(entryId)) continue;

    // If no path constraint, it's a blanket allowlist
    if (typeof entry === "string" || !entry.path) return true;

    // Path-specific: check if the package is in the path
    // The path is a ">" separated dependency chain like "express>body-parser>qs"
    const pathParts = entry.path.split(">");
    if (pathParts.includes(packageName)) return true;
  }

  return false;
}

/**
 * Get the set of production packages by tracing from package.json dependencies.
 */
export function getProductionPackages(
  lockfileContent: string,
  packageJsonPath: string,
): Set<string> {
  const graph = parseLockfileGraph(lockfileContent);

  let pkgJson: { dependencies?: Record<string, string> };
  try {
    const raw = readFileSync(resolve(packageJsonPath), "utf-8");
    pkgJson = JSON.parse(raw);
  } catch {
    throw new Error(`Failed to read package.json at "${packageJsonPath}"`);
  }

  const prodDeps = pkgJson.dependencies ?? {};
  const prodPackages = new Set<string>();

  // BFS from production roots
  const queue: string[] = [];
  const visited = new Set<string>();

  for (const [name, range] of Object.entries(prodDeps)) {
    const specifier = `${name}@${range}`;
    queue.push(specifier);
  }

  while (queue.length > 0) {
    const specifier = queue.shift()!;
    if (visited.has(specifier)) continue;
    visited.add(specifier);

    const entry = graph.get(specifier);
    if (!entry) continue;

    const key = `${entry.name}@${entry.version}`;
    prodPackages.add(key);

    for (const [depName, depRange] of Object.entries(entry.dependencies)) {
      queue.push(`${depName}@${depRange}`);
    }
  }

  return prodPackages;
}

/**
 * Main filtering: apply allowlist, severity threshold, and skip-dev.
 */
export function filterVulnerabilities(
  packages: ParsedPackage[],
  vulnMap: Map<string, string[]>,
  vulnDetails: Map<string, OsvVulnerability>,
  config: Config,
  prodPackages?: Set<string>,
  verbose = false,
): AuditResult {
  const log = (msg: string) => {
    if (verbose) console.error(`[verbose] ${msg}`);
  };
  const threshold = getSeverityThreshold(config);
  const vulnerabilities: VulnerabilityResult[] = [];

  // Track which allowlist IDs were matched
  const matchedAllowlistIds = new Set<string>();

  for (const [pkgKey, vulnIds] of vulnMap) {
    const [name, version] = splitPackageKey(pkgKey);

    // skip-dev filter
    if (prodPackages && !prodPackages.has(pkgKey)) {
      log(`skip-dev: ${pkgKey} (not in production tree)`);
      continue;
    }

    for (const vulnId of vulnIds) {
      const vuln = vulnDetails.get(vulnId);
      if (!vuln) {
        log(`${vulnId} (${pkgKey}): hydration missing, skipping`);
        continue;
      }

      const aliases = vuln.aliases ?? [];

      // Allowlist check
      if (isAllowlisted(vulnId, aliases, name, config.allowlist)) {
        log(`${vulnId} (${pkgKey}): allowlisted`);
        // Track matched IDs
        for (const entry of config.allowlist) {
          const eid = allowlistEntryId(entry);
          if ([vulnId, ...aliases].includes(eid)) {
            matchedAllowlistIds.add(eid);
          }
        }
        continue;
      }

      const { score, level } = extractSeverity(vuln);

      // Severity threshold
      if (SEVERITY_ORDER[level] < threshold) {
        log(`${vulnId} (${pkgKey}): ${level} cvss=${score} below threshold, dropped`);
        continue;
      }

      const fixedVersion = extractFixedVersion(vuln, name);

      log(`${vulnId} (${pkgKey}): KEPT ${level} cvss=${score} fixed=${fixedVersion ?? "n/a"}`);

      vulnerabilities.push({
        id: vulnId,
        aliases,
        summary: vuln.summary ?? "No summary available",
        severity: level,
        cvss: score,
        package: name,
        installedVersion: version,
        fixedVersion,
        url: `https://osv.dev/vulnerability/${vulnId}`,
      });
    }
  }

  // Sort by severity (critical first), then package name
  vulnerabilities.sort((a, b) => {
    const severityDiff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (severityDiff !== 0) return severityDiff;
    return a.package.localeCompare(b.package);
  });

  // Find allowlist entries that were not matched
  const allAllowlistIds = config.allowlist.map(allowlistEntryId);
  const allowlistNotFound = allAllowlistIds.filter(
    (id) => !matchedAllowlistIds.has(id),
  );

  return {
    vulnerabilities,
    packagesScanned: packages.length,
    allowlistNotFound,
  };
}

function splitPackageKey(key: string): [string, string] {
  const lastAt = key.lastIndexOf("@");
  return [key.substring(0, lastAt), key.substring(lastAt + 1)];
}

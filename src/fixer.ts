import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { annotateAllowlistPackages, removeAllowlistEntries } from "./interactive.js";
import { parseLockfile } from "./lockfile-parser.js";
import { hydrateVulnerabilities, queryBatch } from "./osv-client.js";
import type {
  AllowlistEntry,
  Config,
  OsvVulnerability,
  ParsedPackage,
} from "./types.js";

export type FixMode = "direct" | "resolution";

export interface FixAction {
  vulnId: string;
  package: string;
  installedVersion: string;
  fixedVersion: string;
  newSpec: string;
  previousSpec: string | null;
  mode: FixMode;
  section?: "dependencies" | "devDependencies" | "optionalDependencies" | "resolutions";
}

export interface FixSkip {
  vulnId: string;
  package: string;
  installedVersion: string;
  reason: string;
}

export interface FixResult {
  applied: FixAction[];
  skipped: FixSkip[];
  removedAllowlistIds: string[];
  packagesScanned: number;
}

/**
 * Parse a leading integer as the major version. Returns null if the string is
 * not a recognizable semver-ish token.
 */
function parseMajor(version: string): number | null {
  const m = /^\D*(\d+)/.exec(version);
  return m ? parseInt(m[1], 10) : null;
}

/**
 * Compare two dotted-numeric version strings. Prerelease suffixes are ignored.
 */
function compareVersions(a: string, b: string): number {
  const pa = a.replace(/[-+].*$/, "").split(".").map((p) => parseInt(p, 10) || 0);
  const pb = b.replace(/[-+].*$/, "").split(".").map((p) => parseInt(p, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const da = pa[i] ?? 0;
    const db = pb[i] ?? 0;
    if (da !== db) return da - db;
  }
  return 0;
}

/**
 * Collect all published `fixed` version events for the named package.
 */
export function collectFixedVersions(vuln: OsvVulnerability, packageName: string): string[] {
  if (!vuln.affected) return [];
  const fixes: string[] = [];
  for (const affected of vuln.affected) {
    if (affected.package?.name !== packageName) continue;
    if (affected.package?.ecosystem !== "npm") continue;
    if (!affected.ranges) continue;
    for (const range of affected.ranges) {
      if (range.type !== "ECOSYSTEM" && range.type !== "SEMVER") continue;
      for (const event of range.events) {
        if (event.fixed) fixes.push(event.fixed);
      }
    }
  }
  return fixes;
}

/**
 * Pick the smallest `fixed` version greater than `installedVersion` that shares
 * its major line — the minimum semver-safe bump. Returns null if no same-major
 * fix is published.
 */
export function pickFixedVersion(
  vuln: OsvVulnerability,
  packageName: string,
  installedVersion: string,
): string | null {
  const fixes = collectFixedVersions(vuln, packageName);
  if (fixes.length === 0) return null;
  const installedMajor = parseMajor(installedVersion);
  if (installedMajor === null) return null;

  let best: string | null = null;
  for (const fixed of fixes) {
    if (parseMajor(fixed) !== installedMajor) continue;
    if (compareVersions(fixed, installedVersion) <= 0) continue;
    if (!best || compareVersions(fixed, best) < 0) best = fixed;
  }
  return best;
}

function detectIndent(raw: string): number | string {
  const m = /\n([ \t]+)"/.exec(raw);
  if (!m) return 2;
  const indent = m[1];
  if (indent.includes("\t")) return "\t";
  return indent.length;
}

function allowlistIds(allowlist: AllowlistEntry[]): Set<string> {
  const s = new Set<string>();
  for (const entry of allowlist) {
    s.add(typeof entry === "string" ? entry : entry.id);
  }
  return s;
}

/**
 * Run the fix flow: scan, match allowlisted vulns, rewrite package.json
 * (direct deps and resolutions), and strip fixed entries from the config
 * allowlist.
 *
 * Only bumps within the same major — cross-major fixes are reported as skipped.
 */
export async function runFix(
  config: Config,
  configPath: string,
  verbose = false,
): Promise<FixResult> {
  const vlog = (msg: string) => {
    if (verbose) console.error(`[verbose] ${msg}`);
  };

  if (config.allowlist.length === 0) {
    return { applied: [], skipped: [], removedAllowlistIds: [], packagesScanned: 0 };
  }

  const packages: ParsedPackage[] = parseLockfile(config.lockfile);
  const { vulnMap, modifiedMap } = await queryBatch(packages, config["retry-count"]);

  const allIds = new Set<string>();
  for (const ids of vulnMap.values()) for (const id of ids) allIds.add(id);
  const vulnDetails = await hydrateVulnerabilities([...allIds], modifiedMap, config["retry-count"]);

  const awl = allowlistIds(config.allowlist);

  const pkgJsonPath = resolve(config["package-json"]);
  const pkgJsonRaw = readFileSync(pkgJsonPath, "utf-8");
  const pkgJson: Record<string, unknown> & {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    resolutions?: Record<string, string>;
  } = JSON.parse(pkgJsonRaw);

  const applied: FixAction[] = [];
  const skipped: FixSkip[] = [];
  const fixedAllowlistIds = new Set<string>();

  // Track (package, id) we've already processed to avoid duplicate actions when
  // a vuln appears multiple times in the lockfile.
  const seen = new Set<string>();

  for (const [pkgKey, ids] of vulnMap) {
    const lastAt = pkgKey.lastIndexOf("@");
    const name = pkgKey.slice(0, lastAt);
    const installed = pkgKey.slice(lastAt + 1);

    for (const id of ids) {
      const vuln = vulnDetails.get(id);
      if (!vuln) continue;
      const idSet = [id, ...(vuln.aliases ?? [])];
      const matched = idSet.find((x) => awl.has(x));
      if (!matched) continue;

      const dedupKey = `${name}::${id}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      const fixed = pickFixedVersion(vuln, name, installed);
      if (!fixed) {
        const all = collectFixedVersions(vuln, name);
        if (all.length === 0) {
          vlog(`fix: ${id} (${pkgKey}) no published fix`);
          skipped.push({
            vulnId: id,
            package: name,
            installedVersion: installed,
            reason: "no published fix version",
          });
        } else {
          vlog(`fix: ${id} (${pkgKey}) only cross-major fixes: ${all.join(", ")}`);
          skipped.push({
            vulnId: id,
            package: name,
            installedVersion: installed,
            reason: `no same-major fix (installed ${installed}, available ${all.join(", ")})`,
          });
        }
        continue;
      }

      const newSpec = `^${fixed}`;

      let section: FixAction["section"];
      let mode: FixMode;
      let previousSpec: string | null = null;

      if (pkgJson.dependencies && name in pkgJson.dependencies) {
        previousSpec = pkgJson.dependencies[name];
        pkgJson.dependencies[name] = newSpec;
        section = "dependencies";
        mode = "direct";
      } else if (pkgJson.devDependencies && name in pkgJson.devDependencies) {
        previousSpec = pkgJson.devDependencies[name];
        pkgJson.devDependencies[name] = newSpec;
        section = "devDependencies";
        mode = "direct";
      } else if (pkgJson.optionalDependencies && name in pkgJson.optionalDependencies) {
        previousSpec = pkgJson.optionalDependencies[name];
        pkgJson.optionalDependencies[name] = newSpec;
        section = "optionalDependencies";
        mode = "direct";
      } else {
        pkgJson.resolutions = pkgJson.resolutions ?? {};
        previousSpec = pkgJson.resolutions[name] ?? null;
        pkgJson.resolutions[name] = newSpec;
        section = "resolutions";
        mode = "resolution";
      }

      applied.push({
        vulnId: id,
        package: name,
        installedVersion: installed,
        fixedVersion: fixed,
        newSpec,
        previousSpec,
        mode,
        section,
      });
      fixedAllowlistIds.add(matched);
      vlog(`fix: ${id} (${pkgKey}) → ${section} ${name}=${newSpec}`);
    }
  }

  if (applied.length > 0) {
    const indent = detectIndent(pkgJsonRaw);
    const trailingNl = pkgJsonRaw.endsWith("\n") ? "\n" : "";
    writeFileSync(pkgJsonPath, JSON.stringify(pkgJson, null, indent) + trailingNl, "utf-8");
  }

  let removed: string[] = [];
  if (fixedAllowlistIds.size > 0) {
    removed = removeAllowlistEntries(resolve(configPath), [...fixedAllowlistIds]);
  }

  // Annotate remaining (skipped) allowlist entries with the affected package
  // name so the residual entries self-document what they cover.
  if (skipped.length > 0) {
    const pkgUpdates = new Map<string, string>();
    for (const s of skipped) {
      if (!pkgUpdates.has(s.vulnId)) pkgUpdates.set(s.vulnId, s.package);
    }
    annotateAllowlistPackages(resolve(configPath), pkgUpdates);
  }

  return {
    applied,
    skipped,
    removedAllowlistIds: removed,
    packagesScanned: packages.length,
  };
}

export function formatFixReport(result: FixResult): string {
  const lines: string[] = [];
  if (result.applied.length === 0 && result.skipped.length === 0) {
    lines.push("No allowlisted vulnerabilities to fix.");
    return lines.join("\n");
  }

  if (result.applied.length > 0) {
    lines.push(`Applied ${result.applied.length} fix${result.applied.length === 1 ? "" : "es"}:`);
    for (const a of result.applied) {
      const where = a.mode === "resolution" ? "resolutions" : a.section;
      const prev = a.previousSpec ? ` (was ${a.previousSpec})` : "";
      lines.push(`  ${a.package} → ${a.newSpec} [${where}]${prev}`);
      lines.push(`    ${a.vulnId} — https://osv.dev/vulnerability/${a.vulnId}`);
    }
    lines.push("");
    lines.push("Run `yarn install` to apply these changes.");
  }

  if (result.skipped.length > 0) {
    if (lines.length > 0) lines.push("");
    lines.push(`Skipped ${result.skipped.length}:`);
    for (const s of result.skipped) {
      lines.push(`  ${s.package}@${s.installedVersion} — ${s.reason}`);
      lines.push(`    ${s.vulnId} — https://osv.dev/vulnerability/${s.vulnId}`);
    }
  }

  if (result.removedAllowlistIds.length > 0) {
    lines.push("");
    lines.push(`Removed ${result.removedAllowlistIds.length} allowlist entr${result.removedAllowlistIds.length === 1 ? "y" : "ies"}: ${result.removedAllowlistIds.join(", ")}`);
  }

  return lines.join("\n");
}

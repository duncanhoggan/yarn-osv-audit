import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { filterVulnerabilities, getProductionPackages } from "./filter.js";
import { annotateAllowlistPackages, removeAllowlistEntries } from "./interactive.js";
import { parseLockfile } from "./lockfile-parser.js";
import { hydrateVulnerabilities, queryBatch } from "./osv-client.js";
import { collectFixedVersions, compareVersions, pickFixedVersion } from "./versions.js";
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
  staleAllowlistIds: string[];
  packagesScanned: number;
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
 * Which vulns a fix run targets: `"live"` fixes what a scan reports (honoring
 * the allowlist, severity thresholds and skip-dev); `"ignores"` fixes the
 * vulns on the allowlist and cleans up the allowlist afterwards.
 */
export type FixTarget = "live" | "ignores";

export interface FixOptions {
  target?: FixTarget;
}

/**
 * Run the fix flow: scan, pick target vulns, and rewrite package.json
 * (direct deps and resolutions) to the smallest same-major fix version.
 * Cross-major and unfixed vulns are reported as skipped.
 *
 * With `target: "ignores"` (the default), targets allowlisted vulns and strips
 * fixed and stale entries from the config allowlist. With `target: "live"`,
 * targets what a scan reports and leaves the allowlist alone.
 */
export async function runFix(
  config: Config,
  configPath: string,
  verbose = false,
  { target = "ignores" }: FixOptions = {},
): Promise<FixResult> {
  const vlog = (msg: string) => {
    if (verbose) console.error(`[verbose] ${msg}`);
  };
  const live = target === "live";

  if (!live && config.allowlist.length === 0) {
    return { applied: [], skipped: [], removedAllowlistIds: [], staleAllowlistIds: [], packagesScanned: 0 };
  }

  const packages: ParsedPackage[] = parseLockfile(config.lockfile);
  const { vulnMap, modifiedMap } = await queryBatch(packages, config["retry-count"]);

  const allIds = new Set<string>();
  for (const ids of vulnMap.values()) for (const id of ids) allIds.add(id);
  const vulnDetails = await hydrateVulnerabilities([...allIds], modifiedMap, config["retry-count"]);

  const awl = allowlistIds(config.allowlist);

  // Live mode: target exactly the (package, vuln) pairs a scan would report.
  let liveTargets: Set<string> | undefined;
  if (live) {
    let prodPackages: Set<string> | undefined;
    if (config["skip-dev"]) {
      const lockfileContent = readFileSync(resolve(config.lockfile), "utf-8");
      prodPackages = getProductionPackages(lockfileContent, config["package-json"], verbose);
    }
    const scan = filterVulnerabilities(packages, vulnMap, vulnDetails, config, prodPackages, verbose);
    liveTargets = new Set(scan.vulnerabilities.map((v) => `${v.package}@${v.installedVersion}::${v.id}`));
  }

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

  // A package can carry several vulns, each with its own fix version. Track
  // the highest version required so far (and the spec it replaced) so later
  // vulns never downgrade an earlier fix.
  const planned = new Map<string, { spec: string; previousSpec: string | null }>();

  for (const [pkgKey, ids] of vulnMap) {
    const lastAt = pkgKey.lastIndexOf("@");
    const name = pkgKey.slice(0, lastAt);
    const installed = pkgKey.slice(lastAt + 1);

    for (const id of ids) {
      const vuln = vulnDetails.get(id);
      if (!vuln) continue;
      const idSet = [id, ...(vuln.aliases ?? [])];
      const matched = live ? undefined : idSet.find((x) => awl.has(x));
      if (live ? !liveTargets?.has(`${pkgKey}::${id}`) : !matched) continue;

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

      const prior = planned.get(name);
      const newSpec = prior && compareVersions(prior.spec, fixed) > 0 ? prior.spec : fixed;

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

      if (prior) previousSpec = prior.previousSpec;
      planned.set(name, { spec: newSpec, previousSpec });

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
      if (matched) fixedAllowlistIds.add(matched);
      vlog(`fix: ${id} (${pkgKey}) → ${section} ${name}=${newSpec}`);
    }
  }

  // Report the final spec each package landed on, not the intermediate one.
  for (const a of applied) a.newSpec = planned.get(a.package)?.spec ?? a.newSpec;

  if (applied.length > 0) {
    const indent = detectIndent(pkgJsonRaw);
    const trailingNl = pkgJsonRaw.endsWith("\n") ? "\n" : "";
    writeFileSync(pkgJsonPath, JSON.stringify(pkgJson, null, indent) + trailingNl, "utf-8");
  }

  if (live) {
    return {
      applied,
      skipped,
      removedAllowlistIds: [],
      staleAllowlistIds: [],
      packagesScanned: packages.length,
    };
  }

  // Identify stale allowlist entries — ones whose vuln no longer matches
  // anything OSV reports against the current lockfile. Either the package was
  // removed, the version moved past the affected range, or OSV withdrew the
  // advisory. These can be safely dropped from the allowlist.
  const activeAllowlistIds = new Set<string>();
  for (const ids of vulnMap.values()) {
    for (const id of ids) {
      const vuln = vulnDetails.get(id);
      if (!vuln) continue;
      const idSet = [id, ...(vuln.aliases ?? [])];
      for (const candidate of idSet) {
        if (awl.has(candidate)) activeAllowlistIds.add(candidate);
      }
    }
  }
  const staleAllowlistIds: string[] = [];
  for (const entry of config.allowlist) {
    const id = typeof entry === "string" ? entry : entry.id;
    if (!activeAllowlistIds.has(id) && !fixedAllowlistIds.has(id)) {
      staleAllowlistIds.push(id);
      vlog(`fix: ${id} no longer reported — removing as stale`);
    }
  }

  const idsToRemove = new Set<string>([...fixedAllowlistIds, ...staleAllowlistIds]);
  let removed: string[] = [];
  if (idsToRemove.size > 0) {
    removed = removeAllowlistEntries(resolve(configPath), [...idsToRemove]);
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
    staleAllowlistIds,
    packagesScanned: packages.length,
  };
}

export function formatFixReport(result: FixResult, { target = "ignores" }: FixOptions = {}): string {
  const lines: string[] = [];
  if (
    result.applied.length === 0 &&
    result.skipped.length === 0 &&
    result.staleAllowlistIds.length === 0
  ) {
    lines.push(target === "live" ? "No vulnerabilities to fix." : "No allowlisted vulnerabilities to fix.");
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

  if (result.staleAllowlistIds.length > 0) {
    if (lines.length > 0) lines.push("");
    const n = result.staleAllowlistIds.length;
    lines.push(`Removed ${n} stale allowlist entr${n === 1 ? "y" : "ies"} (no longer reported by OSV against the current lockfile):`);
    for (const id of result.staleAllowlistIds) {
      lines.push(`  ${id}`);
    }
  }

  if (result.removedAllowlistIds.length > 0) {
    lines.push("");
    lines.push(`Removed ${result.removedAllowlistIds.length} allowlist entr${result.removedAllowlistIds.length === 1 ? "y" : "ies"}: ${result.removedAllowlistIds.join(", ")}`);
  }

  return lines.join("\n");
}

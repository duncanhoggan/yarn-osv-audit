import type { OsvVulnerability } from "./types.js";

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
export function compareVersions(a: string, b: string): number {
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
      // SEMVER and ECOSYSTEM ranges carry package versions; GIT ranges carry commit hashes.
      if (range.type !== "ECOSYSTEM" && range.type !== "SEMVER") continue;
      for (const event of range.events) {
        if (event.fixed) fixes.push(event.fixed);
      }
    }
  }
  return fixes;
}

/**
 * How far a fix may move from the installed version: `"major"` keeps the same
 * major line (minor/patch bumps), `"any"` allows any later version.
 */
export type FixScope = "any" | "major";

/**
 * Pick the smallest `fixed` version greater than `installedVersion` within the
 * given scope (default `"major"` — the minimum semver-safe bump). Returns null
 * if no matching fix is published.
 */
export function pickFixedVersion(
  vuln: OsvVulnerability,
  packageName: string,
  installedVersion: string,
  { within = "major" }: { within?: FixScope } = {},
): string | null {
  const fixes = collectFixedVersions(vuln, packageName);
  if (fixes.length === 0) return null;
  const installedMajor = parseMajor(installedVersion);
  if (installedMajor === null) return null;

  let best: string | null = null;
  for (const fixed of fixes) {
    if (within === "major" && parseMajor(fixed) !== installedMajor) continue;
    if (compareVersions(fixed, installedVersion) <= 0) continue;
    if (!best || compareVersions(fixed, best) < 0) best = fixed;
  }
  return best;
}

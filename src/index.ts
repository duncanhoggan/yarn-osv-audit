#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfigWithMeta } from "./config.js";
import { computeDepPaths, filterVulnerabilities, getProductionPackages } from "./filter.js";
import { formatFixReport, runFix } from "./fixer.js";
import { appendAllowlistEntries, buildAllowlistEntries } from "./interactive.js";
import { parseLockfile } from "./lockfile-parser.js";
import { hydrateVulnerabilities, queryBatch } from "./osv-client.js";
import { formatOutput } from "./reporter.js";

const VERSION = (JSON.parse(
  readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "..", "package.json"),
    "utf8",
  ),
) as { version: string }).version;

function fatal(msg: string): never {
  console.error(`Error: ${msg}`);
  process.exit(2);
}

function printHelp(): void {
  console.log(`yarn-osv-audit v${VERSION}

Audit Yarn v1 lockfiles against the OSV vulnerability database.

Usage:
  yarn-osv-audit [options]

Options:
  --config=<path>, -c=<path>  Path to config file (default: .osv-audit.jsonc)
  --format=<fmt>              Output format: compact (default), table, json, summary
  --ignore-all, -i            Append every reported vulnerability to the
                              allowlist (no prompts)
  --fix                Update package.json (and resolutions) so allowlisted
                       vulnerabilities resolve to their fixed versions. Only
                       applies same-major bumps; cross-major fixes are skipped.
  --verbose, -v        Log diagnostic details to stderr
  --help               Show this help message
  --version            Show version number

Configuration is done via .osv-audit.jsonc — see documentation for details.`);
}

function parseArgs(args: string[]): { configPath?: string; help: boolean; version: boolean; verbose: boolean; ignoreAll: boolean; fix: boolean; format?: "compact" | "table" | "json" | "summary" } {
  let configPath: string | undefined;
  let help = false;
  let version = false;
  let verbose = false;
  let ignoreAll = false;
  let fix = false;
  let format: "compact" | "table" | "json" | "summary" | undefined;

  // Value-taking flags use `--flag=value` form only. Boolean flags stand alone.
  for (const raw of args) {
    const eq = raw.indexOf("=");
    const name = eq > 0 ? raw.slice(0, eq) : raw;
    const value = eq > 0 ? raw.slice(eq + 1) : undefined;

    const requireValue = (): string => {
      if (value === undefined) fatal(`${name} requires a value (use ${name}=<value>)`);
      if (value === "") fatal(`${name} requires a non-empty value`);
      return value;
    };
    const rejectValue = (): void => {
      if (value !== undefined) fatal(`${name} does not take a value`);
    };
    // Boolean flags accept bare form (`--fix`) or explicit `--fix=true|false`
    // (also `1`/`0`, `yes`/`no`). Anything else is rejected.
    const parseBool = (): boolean => {
      if (value === undefined) return true;
      const v = value.toLowerCase();
      if (v === "true" || v === "1" || v === "yes") return true;
      if (v === "false" || v === "0" || v === "no") return false;
      fatal(`${name} expects a boolean value (true/false), got "${value}"`);
    };

    switch (name) {
      case "--help": rejectValue(); help = true; break;
      case "--version": rejectValue(); version = true; break;
      case "--verbose":
      case "-v": verbose = parseBool(); break;
      case "--ignore-all":
      case "-i": ignoreAll = parseBool(); break;
      case "--fix": fix = parseBool(); break;
      case "--format": {
        const v = requireValue();
        if (v !== "compact" && v !== "table" && v !== "json" && v !== "summary") {
          fatal(`invalid --format "${v}" (expected: compact, table, json, summary)`);
        }
        format = v;
        break;
      }
      case "--config":
      case "-c": configPath = requireValue(); break;
      default:
        console.error(`Unknown argument: ${raw}`);
        printHelp();
        process.exit(2);
    }
  }

  return { configPath, help, version, verbose, ignoreAll, fix, format };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    printHelp();
    process.exit(0);
  }

  if (args.version) {
    console.log(`yarn-osv-audit v${VERSION}`);
    process.exit(0);
  }

  // Load config
  let config;
  let explicitConfigKeys: Set<string>;
  try {
    const loaded = loadConfigWithMeta(args.configPath);
    config = loaded.config;
    explicitConfigKeys = loaded.explicit;
  } catch (err: unknown) {
    fatal(err instanceof Error ? err.message : String(err));
  }

  // Fix mode — bump package.json (and resolutions) for allowlisted vulns.
  if (args.fix) {
    const configPath = args.configPath ?? ".osv-audit.jsonc";
    console.log(`yarn-osv-audit v${VERSION} — fixing allowlisted vulns from ${configPath}\n`);
    try {
      const result = await runFix(config, configPath, args.verbose);
      console.log(formatFixReport(result));
      process.exit(result.applied.length > 0 || result.skipped.length === 0 ? 0 : 1);
    } catch (err: unknown) {
      fatal(err instanceof Error ? err.message : String(err));
    }
  }

  // Resolve effective format.
  // Precedence: --format flag > explicit config value > (CI ? "compact" : "table").
  const ciActive = Boolean(process.env.CI) && process.env.CI !== "false";
  const resolvedFormat: "compact" | "table" | "json" | "summary" =
    args.format ??
    (explicitConfigKeys.has("output-format")
      ? config["output-format"]
      : (ciActive ? "compact" : "table"));

  console.log(`yarn-osv-audit v${VERSION} — scanning ${config.lockfile}\n`);

  const vlog = (msg: string) => {
    if (args.verbose) console.error(`[verbose] ${msg}`);
  };

  // Parse lockfile
  let packages;
  try {
    packages = parseLockfile(config.lockfile);
  } catch (err: unknown) {
    fatal(err instanceof Error ? err.message : String(err));
  }

  console.log(`Scanning ${packages.length} packages...\n`);

  if (args.verbose) {
    vlog(`parsed ${packages.length} packages from ${config.lockfile}`);
    for (const pkg of packages) {
      vlog(`  pkg: ${pkg.name}@${pkg.version}`);
    }
  }

  // Query OSV API
  let vulnMap;
  let modifiedMap;
  try {
    const batchResult = await queryBatch(packages, config["retry-count"]);
    vulnMap = batchResult.vulnMap;
    modifiedMap = batchResult.modifiedMap;
  } catch (err: unknown) {
    fatal(`querying OSV API: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (args.verbose) {
    vlog(`querybatch: ${vulnMap.size} packages had vulns`);
    for (const [pkgKey, ids] of vulnMap) {
      vlog(`  ${pkgKey} → ${ids.join(", ")}`);
    }
  }

  // Collect unique vuln IDs for hydration
  const allVulnIds = new Set<string>();
  for (const ids of vulnMap.values()) {
    for (const id of ids) {
      allVulnIds.add(id);
    }
  }

  if (allVulnIds.size === 0 && config.allowlist.length === 0) {
    const result = {
      vulnerabilities: [],
      packagesScanned: packages.length,
      allowlistNotFound: [],
    };
    console.log(formatOutput(result, resolvedFormat, config["show-found"], config["show-not-found"]));
    process.exit(0);
  }

  // Hydrate vulnerability details
  let vulnDetails;
  try {
    vulnDetails = await hydrateVulnerabilities([...allVulnIds], modifiedMap, config["retry-count"]);
  } catch (err: unknown) {
    fatal(`fetching vulnerability details: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Get production packages if skip-dev is enabled
  let prodPackages: Set<string> | undefined;
  if (config["skip-dev"]) {
    try {
      const lockfileContent = readFileSync(resolve(config.lockfile), "utf-8");
      prodPackages = getProductionPackages(lockfileContent, config["package-json"], args.verbose);
    } catch (err: unknown) {
      fatal(`resolving production dependencies: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // Filter and report
  const result = filterVulnerabilities(packages, vulnMap, vulnDetails, config, prodPackages, args.verbose);

  // Attach dep paths for compact output
  if (resolvedFormat === "compact" && result.vulnerabilities.length > 0) {
    try {
      const lockfileContent = readFileSync(resolve(config.lockfile), "utf-8");
      const vulnKeys = new Set(result.vulnerabilities.map((v) => `${v.package}@${v.installedVersion}`));
      const depPaths = computeDepPaths(lockfileContent, config["package-json"], vulnKeys);
      for (const v of result.vulnerabilities) {
        v.depPaths = depPaths.get(`${v.package}@${v.installedVersion}`) ?? [];
      }
    } catch {
      // Dep paths are best-effort; leave empty on failure.
    }
  }

  console.log(formatOutput(result, resolvedFormat, config["show-found"], config["show-not-found"]));

  // Ignore-all: auto-append every reported vulnerability to the allowlist.
  if (args.ignoreAll && result.vulnerabilities.length > 0) {
    const entries = buildAllowlistEntries(result.vulnerabilities);
    if (entries.length > 0) {
      const configPath = resolve(args.configPath ?? ".osv-audit.jsonc");
      try {
        appendAllowlistEntries(configPath, entries);
        console.log(`\nAdded ${entries.length} entr${entries.length === 1 ? "y" : "ies"} to ${configPath}.`);
      } catch (err: unknown) {
        fatal(`updating config "${configPath}": ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }

  // Exit code
  process.exit(result.vulnerabilities.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(`Unexpected error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
});

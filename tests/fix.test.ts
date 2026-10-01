import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { Config, OsvVulnerability } from "../src/types.js";
import { DEFAULT_CONFIG } from "../src/types.js";

const HIGH_CVSS = [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }];

function semverVuln(
  id: string,
  name: string,
  introduced: string,
  fixed: string,
  severity?: OsvVulnerability["severity"],
): OsvVulnerability {
  return {
    id,
    severity,
    affected: [
      {
        package: { name, ecosystem: "npm" },
        ranges: [{ type: "SEMVER", events: [{ introduced }, { fixed }] }],
      },
    ],
  };
}

const vulns = new Map<string, OsvVulnerability>([
  ["GHSA-direct", semverVuln("GHSA-direct", "direct-pkg", "1.2.0", "1.4.0", HIGH_CVSS)],
  ["GHSA-trans", semverVuln("GHSA-trans", "trans-pkg", "3.1.0", "3.1.9", HIGH_CVSS)],
  ["GHSA-major", semverVuln("GHSA-major", "major-pkg", "2.0.0", "3.0.0", HIGH_CVSS)],
  // No severity → LOW, dropped when the threshold is HIGH.
  ["GHSA-low", semverVuln("GHSA-low", "low-pkg", "5.0.0", "5.0.1")],
  // Several vulns on one package, highest fix listed in the middle.
  ["GHSA-multi-a", semverVuln("GHSA-multi-a", "multi-pkg", "8.5.0", "8.5.12", HIGH_CVSS)],
  ["GHSA-multi-b", semverVuln("GHSA-multi-b", "multi-pkg", "8.5.0", "8.5.23", HIGH_CVSS)],
  ["GHSA-multi-c", semverVuln("GHSA-multi-c", "multi-pkg", "8.5.0", "8.5.10", HIGH_CVSS)],
]);

vi.mock("../src/osv-client.js", () => ({
  queryBatch: async () => ({
    vulnMap: new Map([
      ["direct-pkg@1.2.3", ["GHSA-direct"]],
      ["trans-pkg@3.1.2", ["GHSA-trans"]],
      ["major-pkg@2.0.5", ["GHSA-major"]],
      ["low-pkg@5.0.0", ["GHSA-low"]],
      ["multi-pkg@8.5.9", ["GHSA-multi-a", "GHSA-multi-b", "GHSA-multi-c"]],
    ]),
    modifiedMap: new Map(),
  }),
  hydrateVulnerabilities: async () => vulns,
}));

const { runFix } = await import("../src/fixer.js");

function setup(overrides: Partial<Config> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "fix-"));
  const lockfile = join(dir, "yarn.lock");
  const pkgJsonPath = join(dir, "package.json");
  const configPath = join(dir, ".osv-audit.jsonc");
  writeFileSync(
    lockfile,
    [
      "# yarn lockfile v1",
      "",
      'direct-pkg@^1.2.0:\n  version "1.2.3"',
      'trans-pkg@^3.1.0:\n  version "3.1.2"',
      'major-pkg@^2.0.0:\n  version "2.0.5"',
      'low-pkg@^5.0.0:\n  version "5.0.0"',
      'multi-pkg@^8.5.0:\n  version "8.5.9"',
      "",
    ].join("\n"),
  );
  writeFileSync(
    pkgJsonPath,
    JSON.stringify(
      {
        dependencies: {
          "direct-pkg": "^1.2.0",
          "major-pkg": "^2.0.0",
          "low-pkg": "^5.0.0",
          "multi-pkg": "^8.5.0",
        },
      },
      null,
      2,
    ) + "\n",
  );
  const config: Config = {
    ...DEFAULT_CONFIG,
    lockfile,
    "package-json": pkgJsonPath,
    ...overrides,
  };
  writeFileSync(configPath, JSON.stringify({ allowlist: config.allowlist }, null, 2) + "\n");
  const readPkgJson = () => JSON.parse(readFileSync(pkgJsonPath, "utf-8"));
  return { config, configPath, readPkgJson };
}

describe("runFix target: live (fix)", () => {
  it("fixes reported vulns with a same-major fix and skips cross-major ones", async () => {
    const { config, configPath, readPkgJson } = setup();

    const result = await runFix(config, configPath, false, { target: "live" });

    expect(result.applied.map((a) => [a.package, a.newSpec, a.section])).toEqual([
      ["direct-pkg", "1.4.0", "dependencies"],
      ["trans-pkg", "3.1.9", "resolutions"],
      ["low-pkg", "5.0.1", "dependencies"],
      ["multi-pkg", "8.5.23", "dependencies"],
      ["multi-pkg", "8.5.23", "dependencies"],
      ["multi-pkg", "8.5.23", "dependencies"],
    ]);
    expect(result.skipped.map((s) => [s.package, s.reason])).toEqual([
      ["major-pkg", "no same-major fix (installed 2.0.5, available 3.0.0)"],
    ]);

    const pkgJson = readPkgJson();
    expect(pkgJson.dependencies["major-pkg"]).toBe("^2.0.0");
    expect(pkgJson.resolutions["trans-pkg"]).toBe("3.1.9");
  });

  it("uses the highest fix when a package has several vulns, and reports the original spec", async () => {
    const { config, configPath, readPkgJson } = setup();

    const result = await runFix(config, configPath, false, { target: "live" });

    const multi = result.applied.filter((a) => a.package === "multi-pkg");
    expect(multi.map((a) => a.previousSpec)).toEqual(["^8.5.0", "^8.5.0", "^8.5.0"]);
    expect(readPkgJson().dependencies["multi-pkg"]).toBe("8.5.23");
  });

  it("honors the config: skips allowlisted vulns and those below the severity threshold", async () => {
    const { config, configPath, readPkgJson } = setup({
      allowlist: ["GHSA-direct"],
      high: true,
      low: false,
    });

    const result = await runFix(config, configPath, false, { target: "live" });

    const fixed = result.applied.map((a) => a.package);
    expect(fixed).not.toContain("direct-pkg");
    expect(fixed).not.toContain("low-pkg");
    expect(fixed).toContain("trans-pkg");
    expect(readPkgJson().dependencies["direct-pkg"]).toBe("^1.2.0");
  });

  it("leaves the allowlist alone", async () => {
    const { config, configPath } = setup({ allowlist: ["GHSA-direct", "GHSA-gone"] });

    const result = await runFix(config, configPath, false, { target: "live" });

    expect(result.removedAllowlistIds).toEqual([]);
    expect(result.staleAllowlistIds).toEqual([]);
    const content = readFileSync(configPath, "utf-8");
    expect(content).toContain("GHSA-direct");
    expect(content).toContain("GHSA-gone");
  });
});

describe("runFix target: ignores (fix-ignores)", () => {
  it("only fixes allowlisted vulns, then removes fixed and stale entries", async () => {
    const { config, configPath, readPkgJson } = setup({
      allowlist: ["GHSA-direct", "GHSA-major", "GHSA-gone"],
    });

    const result = await runFix(config, configPath, false, { target: "ignores" });

    expect(result.applied.map((a) => [a.package, a.newSpec])).toEqual([["direct-pkg", "1.4.0"]]);
    expect(result.skipped.map((s) => s.package)).toEqual(["major-pkg"]);
    expect(result.staleAllowlistIds).toEqual(["GHSA-gone"]);
    expect(result.removedAllowlistIds.sort()).toEqual(["GHSA-direct", "GHSA-gone"]);
    expect(readPkgJson().resolutions).toBeUndefined();
    expect(readFileSync(configPath, "utf-8")).toContain("GHSA-major");
  });

  it("is the default target", async () => {
    const { config, configPath } = setup({ allowlist: ["GHSA-trans"] });

    const result = await runFix(config, configPath);

    expect(result.applied.map((a) => a.package)).toEqual(["trans-pkg"]);
  });
});

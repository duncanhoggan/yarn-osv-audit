import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { describe, expect, it } from "vitest";
import { filterVulnerabilities, getProductionPackages, getSeverityThreshold } from "../src/filter.js";
import type { Config, OsvVulnerability, ParsedPackage } from "../src/types.js";
import { DEFAULT_CONFIG } from "../src/types.js";

function makeVuln(overrides: Partial<OsvVulnerability> = {}): OsvVulnerability {
  return {
    id: "GHSA-test-1234-5678",
    summary: "Test vulnerability",
    aliases: ["CVE-2024-12345"],
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }],
    affected: [
      {
        package: { name: "test-pkg", ecosystem: "npm" },
        ranges: [
          {
            type: "ECOSYSTEM",
            events: [{ introduced: "0" }, { fixed: "2.0.0" }],
          },
        ],
      },
    ],
    ...overrides,
  };
}

const testPackages: ParsedPackage[] = [
  { name: "test-pkg", version: "1.0.0" },
  { name: "safe-pkg", version: "3.0.0" },
];

describe("getSeverityThreshold", () => {
  it("defaults to LOW", () => {
    expect(getSeverityThreshold(DEFAULT_CONFIG)).toBe(1);
  });

  it("returns CRITICAL when critical is set", () => {
    expect(getSeverityThreshold({ ...DEFAULT_CONFIG, critical: true, low: false })).toBe(4);
  });

  it("returns HIGH when high is set", () => {
    expect(getSeverityThreshold({ ...DEFAULT_CONFIG, high: true, low: false })).toBe(3);
  });
});

describe("filterVulnerabilities", () => {
  it("includes vulnerabilities above threshold", () => {
    const vulnMap = new Map([["test-pkg@1.0.0", ["GHSA-test-1234-5678"]]]);
    const vulnDetails = new Map([["GHSA-test-1234-5678", makeVuln()]]);
    const config: Config = { ...DEFAULT_CONFIG };

    const result = filterVulnerabilities(testPackages, vulnMap, vulnDetails, config);

    expect(result.vulnerabilities).toHaveLength(1);
    expect(result.vulnerabilities[0].id).toBe("GHSA-test-1234-5678");
    expect(result.vulnerabilities[0].severity).toBe("HIGH");
    expect(result.vulnerabilities[0].cvss).toBe(7.5);
    expect(result.vulnerabilities[0].fixedVersion).toBe("2.0.0");
  });

  it("filters out vulnerabilities below threshold", () => {
    const vulnMap = new Map([["test-pkg@1.0.0", ["GHSA-test-1234-5678"]]]);
    // This vector yields 7.5 (HIGH)
    const vulnDetails = new Map([["GHSA-test-1234-5678", makeVuln()]]);
    const config: Config = { ...DEFAULT_CONFIG, low: false, critical: true };

    const result = filterVulnerabilities(testPackages, vulnMap, vulnDetails, config);
    expect(result.vulnerabilities).toHaveLength(0);
  });

  it("respects simple string allowlist", () => {
    const vulnMap = new Map([["test-pkg@1.0.0", ["GHSA-test-1234-5678"]]]);
    const vulnDetails = new Map([["GHSA-test-1234-5678", makeVuln()]]);
    const config: Config = {
      ...DEFAULT_CONFIG,
      allowlist: ["GHSA-test-1234-5678"],
    };

    const result = filterVulnerabilities(testPackages, vulnMap, vulnDetails, config);
    expect(result.vulnerabilities).toHaveLength(0);
  });

  it("respects allowlist by alias", () => {
    const vulnMap = new Map([["test-pkg@1.0.0", ["GHSA-test-1234-5678"]]]);
    const vulnDetails = new Map([["GHSA-test-1234-5678", makeVuln()]]);
    const config: Config = {
      ...DEFAULT_CONFIG,
      allowlist: ["CVE-2024-12345"],
    };

    const result = filterVulnerabilities(testPackages, vulnMap, vulnDetails, config);
    expect(result.vulnerabilities).toHaveLength(0);
  });

  it("tracks allowlist not-found entries", () => {
    const vulnMap = new Map<string, string[]>();
    const vulnDetails = new Map<string, OsvVulnerability>();
    const config: Config = {
      ...DEFAULT_CONFIG,
      allowlist: ["GHSA-stale-entry-0000"],
    };

    const result = filterVulnerabilities(testPackages, vulnMap, vulnDetails, config);
    expect(result.allowlistNotFound).toContain("GHSA-stale-entry-0000");
  });

  it("filters by production packages when prodPackages is provided", () => {
    const vulnMap = new Map([["test-pkg@1.0.0", ["GHSA-test-1234-5678"]]]);
    const vulnDetails = new Map([["GHSA-test-1234-5678", makeVuln()]]);
    const config: Config = { ...DEFAULT_CONFIG };

    // test-pkg is NOT in the prod set
    const prodPackages = new Set(["safe-pkg@3.0.0"]);

    const result = filterVulnerabilities(testPackages, vulnMap, vulnDetails, config, prodPackages);
    expect(result.vulnerabilities).toHaveLength(0);
  });

  it("sorts vulnerabilities by severity (critical first)", () => {
    const vulnMap = new Map([
      ["test-pkg@1.0.0", ["GHSA-low-0000-0000", "GHSA-crit-0000-0000"]],
    ]);
    const vulnDetails = new Map([
      [
        "GHSA-low-0000-0000",
        makeVuln({
          id: "GHSA-low-0000-0000",
          severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" }],
        }),
      ],
      [
        "GHSA-crit-0000-0000",
        makeVuln({
          id: "GHSA-crit-0000-0000",
          severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
        }),
      ],
    ]);
    const config: Config = { ...DEFAULT_CONFIG };

    const result = filterVulnerabilities(testPackages, vulnMap, vulnDetails, config);
    expect(result.vulnerabilities[0].id).toBe("GHSA-crit-0000-0000");
    expect(result.vulnerabilities[1].id).toBe("GHSA-low-0000-0000");
  });
});

describe("getProductionPackages", () => {
  const fixturesDir = resolve(import.meta.dirname, "fixtures");

  it("traverses optionalDependencies as part of the production tree", () => {
    const lockfileContent = readFileSync(resolve(fixturesDir, "optional-deps.lock"), "utf-8");
    const tmp = mkdtempSync(join(tmpdir(), "yoa-test-"));
    const pkgJsonPath = join(tmp, "package.json");
    writeFileSync(
      pkgJsonPath,
      JSON.stringify({ dependencies: { "firebase-admin": "12.0.0" } }),
    );

    const prod = getProductionPackages(lockfileContent, pkgJsonPath);

    // Direct dep
    expect(prod.has("firebase-admin@12.0.0")).toBe(true);
    // Regular transitive dep
    expect(prod.has("jsonwebtoken@9.0.2")).toBe(true);
    // Optional dep — must be included
    expect(prod.has("@google-cloud/firestore@7.11.6")).toBe(true);
    // Transitive via optional dep — must also be included
    expect(prod.has("protobufjs@7.2.6")).toBe(true);
    // Unrelated package — must NOT be included
    expect(prod.has("dev-only-pkg@1.0.0")).toBe(false);
  });
});

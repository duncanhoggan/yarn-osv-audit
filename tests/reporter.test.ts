import { describe, expect, it } from "vitest";
import { formatJson, formatSummary, formatTable } from "../src/reporter.js";
import type { AuditResult } from "../src/types.js";

const emptyResult: AuditResult = {
  vulnerabilities: [],
  packagesScanned: 100,
  allowlistNotFound: [],
};

const resultWithVulns: AuditResult = {
  vulnerabilities: [
    {
      id: "GHSA-677m-j7p3-52f9",
      aliases: ["CVE-2026-33151"],
      summary: "Unbounded binary attachments DoS",
      severity: "HIGH",
      cvss: 7.5,
      package: "socket.io",
      installedVersion: "4.5.0",
      fixedVersion: "4.2.6",
      url: "https://osv.dev/vulnerability/GHSA-677m-j7p3-52f9",
    },
    {
      id: "GHSA-c2qf-rxjj-qqgw",
      aliases: [],
      summary: "Regular expression DoS",
      severity: "MODERATE",
      cvss: 5.3,
      package: "semver",
      installedVersion: "7.5.2",
      fixedVersion: "7.5.4",
      url: "https://osv.dev/vulnerability/GHSA-c2qf-rxjj-qqgw",
    },
  ],
  packagesScanned: 847,
  allowlistNotFound: ["GHSA-stale-0000-0000"],
};

describe("formatTable", () => {
  it("shows no-vulnerabilities message for clean result", () => {
    const output = formatTable(emptyResult, true, true);
    expect(output).toContain("No vulnerabilities found");
    expect(output).toContain("100 packages");
  });

  it("shows vulnerability details including URL", () => {
    const output = formatTable(resultWithVulns, true, true);
    expect(output).toContain("Found 2 vulnerabilities");
    expect(output).toContain("socket.io");
    expect(output).toContain("GHSA-677m-j7p3-52f9");
    expect(output).toContain("https://osv.dev/vulnerability/GHSA-677m-j7p3-52f9");
    expect(output).toContain("semver");
    expect(output).toContain("7.5");
  });

  it("shows stale allowlist entries when show-not-found is true", () => {
    const output = formatTable(resultWithVulns, true, true);
    expect(output).toContain("GHSA-stale-0000-0000");
    expect(output).toContain("not found");
  });

  it("hides stale allowlist entries when show-not-found is false", () => {
    const output = formatTable(resultWithVulns, true, false);
    expect(output).not.toContain("GHSA-stale-0000-0000");
  });
});

describe("formatJson", () => {
  it("returns valid JSON with correct structure", () => {
    const output = formatJson(resultWithVulns);
    const parsed = JSON.parse(output);

    expect(parsed.vulnerabilities).toHaveLength(2);
    expect(parsed.metadata.packagesScanned).toBe(847);
    expect(parsed.metadata.vulnerabilitiesFound).toBe(2);
    expect(parsed.metadata.severityCounts.high).toBe(1);
    expect(parsed.metadata.severityCounts.moderate).toBe(1);
  });

  it("returns empty array for clean result", () => {
    const output = formatJson(emptyResult);
    const parsed = JSON.parse(output);
    expect(parsed.vulnerabilities).toHaveLength(0);
  });
});

describe("formatSummary", () => {
  it("shows compact summary with vulnerabilities", () => {
    const output = formatSummary(resultWithVulns);
    expect(output).toContain("2 vulnerabilities");
    expect(output).toContain("1 high");
    expect(output).toContain("1 moderate");
    expect(output).toContain("847 packages");
  });

  it("shows no-vulnerability summary for clean result", () => {
    const output = formatSummary(emptyResult);
    expect(output).toContain("no vulnerabilities found");
  });
});

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { formatCompact, formatJson, formatSummary, formatTable } from "../src/reporter.js";
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
      depPaths: ["app > socket.io", "app > realtime > socket.io"],
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
      depPaths: ["app > semver"],
    },
  ],
  packagesScanned: 847,
  allowlistNotFound: [
    "GHSA-37ch-88jc-xwx2",
    "GHSA-48c2-rrv3-qjmp",
    "GHSA-677m-j7p3-52f9",
    "GHSA-9965-vmph-33xx",
    "GHSA-f886-m6hf-6m8v",
    "GHSA-vghf-hv5q-vc2g",
  ],
};

const ANSI_RE = /\x1b\[[0-9;]*m/g;

describe("formatCompact", () => {
  const origCI = process.env.CI;
  const origNoColor = process.env.NO_COLOR;
  const origForceColor = process.env.FORCE_COLOR;

  beforeEach(() => {
    process.env.CI = "true"; // default off-colour for determinism
    delete process.env.NO_COLOR;
    delete process.env.FORCE_COLOR;
  });

  afterEach(() => {
    if (origCI === undefined) delete process.env.CI; else process.env.CI = origCI;
    if (origNoColor === undefined) delete process.env.NO_COLOR; else process.env.NO_COLOR = origNoColor;
    if (origForceColor === undefined) delete process.env.FORCE_COLOR; else process.env.FORCE_COLOR = origForceColor;
  });

  it("matches snapshot with multiple severities and stale allowlist", () => {
    const output = formatCompact(resultWithVulns, true, true, false);
    expect(output).toMatchSnapshot();
  });

  it("single line for zero vulns, no trailing summary", () => {
    const output = formatCompact(emptyResult, true, true, false);
    expect(output).toBe("No vulnerabilities found in 100 packages");
    expect(output).not.toContain("Summary");
  });

  it("NO_COLOR=1 strips ANSI escapes", () => {
    process.env.NO_COLOR = "1";
    process.env.FORCE_COLOR = "1"; // NO_COLOR should win
    const output = formatCompact(resultWithVulns, true, true);
    expect(output).toBe(output.replace(ANSI_RE, ""));
  });

  it("CI=true disables colour even on a TTY", () => {
    process.env.CI = "true";
    const origIsTTY = process.stdout.isTTY;
    (process.stdout as { isTTY?: boolean }).isTTY = true;
    try {
      const output = formatCompact(resultWithVulns, true, true);
      expect(output).toBe(output.replace(ANSI_RE, ""));
    } finally {
      (process.stdout as { isTTY?: boolean }).isTTY = origIsTTY;
    }
  });

  it("FORCE_COLOR enables colour when not in CI and no NO_COLOR", () => {
    delete process.env.CI;
    process.env.FORCE_COLOR = "1";
    const output = formatCompact(resultWithVulns, true, true);
    expect(output).toMatch(ANSI_RE);
  });

  it("shows dep paths under Path:", () => {
    const output = formatCompact(resultWithVulns, true, true, false);
    expect(output).toContain("Path: app > socket.io");
    expect(output).toContain("Path: app > realtime > socket.io");
  });

  it("truncates to N paths with 'and M more'", () => {
    const many: AuditResult = {
      ...resultWithVulns,
      vulnerabilities: [
        {
          ...resultWithVulns.vulnerabilities[0],
          depPaths: ["a > x", "b > x", "c > x", "d > x", "e > x"],
        },
      ],
      allowlistNotFound: [],
    };
    const output = formatCompact(many, true, true, false);
    expect(output).toContain("Path: a > x");
    expect(output).toContain("Path: c > x");
    expect(output).toContain("and 2 more");
    expect(output).not.toContain("Path: d > x");
  });

  it("wraps stale allowlist on commas only", () => {
    const output = formatCompact(resultWithVulns, true, true, false);
    expect(output).toContain("Stale allowlist (6):");
    // No ID is split across lines
    const lines = output.split("\n");
    for (const line of lines) {
      expect(line).not.toMatch(/GHSA-[a-z0-9]*$/); // line shouldn't end mid-ID
    }
  });

  it("header uses [SEVERITY · cvss X.X] pkg@version", () => {
    const output = formatCompact(resultWithVulns, true, true, false);
    expect(output).toContain("[HIGH · cvss 7.5] socket.io@4.5.0");
    expect(output).toContain("[MODERATE · cvss 5.3] semver@7.5.2");
  });
});

describe("formatTable (legacy --format table)", () => {
  it("matches legacy snapshot", () => {
    const output = formatTable(resultWithVulns, true, false);
    expect(output).toMatchSnapshot();
  });

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

  it("uses box-drawing characters", () => {
    const output = formatTable(resultWithVulns, true, true);
    expect(output).toContain("┌");
    expect(output).toContain("│");
    expect(output).toContain("└");
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

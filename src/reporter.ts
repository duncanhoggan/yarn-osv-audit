import type { AuditResult, SeverityLevel, VulnerabilityResult } from "./types.js";

interface SeverityCounts {
  critical: number;
  high: number;
  moderate: number;
  low: number;
}

function countSeverities(vulns: VulnerabilityResult[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, moderate: 0, low: 0 };
  for (const v of vulns) {
    switch (v.severity) {
      case "CRITICAL": counts.critical++; break;
      case "HIGH": counts.high++; break;
      case "MODERATE": counts.moderate++; break;
      case "LOW": counts.low++; break;
    }
  }
  return counts;
}

function severityCountString(counts: SeverityCounts): string {
  return `${counts.critical} critical, ${counts.high} high, ${counts.moderate} moderate, ${counts.low} low`;
}

// --- Table output ---

function pad(str: string, width: number): string {
  return str + " ".repeat(Math.max(0, width - str.length));
}

function severityColor(level: SeverityLevel): string {
  // ANSI color codes
  switch (level) {
    case "CRITICAL": return `\x1b[91m${level}\x1b[0m`; // bright red
    case "HIGH":     return `\x1b[31m${level}\x1b[0m`;  // red
    case "MODERATE": return `\x1b[33m${level}\x1b[0m`;  // yellow
    case "LOW":      return `\x1b[36m${level}\x1b[0m`;  // cyan
  }
}

export function formatTable(result: AuditResult, showFound: boolean, showNotFound: boolean): string {
  const lines: string[] = [];
  const { vulnerabilities, packagesScanned, allowlistNotFound } = result;

  if (vulnerabilities.length === 0) {
    lines.push(`\nNo vulnerabilities found in ${packagesScanned} packages.\n`);
    if (showNotFound && allowlistNotFound.length > 0) {
      lines.push(formatNotFoundSection(allowlistNotFound));
    }
    return lines.join("\n");
  }

  const counts = countSeverities(vulnerabilities);

  lines.push(
    `\nFound ${vulnerabilities.length} vulnerabilities in ${packagesScanned} packages\n`,
  );

  if (showFound) {
    // Calculate column widths
    const colWidths = {
      severity: Math.max(8, ...vulnerabilities.map((v) => v.severity.length)),
      package: Math.max(7, ...vulnerabilities.map((v) => v.package.length)),
      version: Math.max(7, ...vulnerabilities.map((v) => v.installedVersion.length)),
      vuln: Math.max(13, ...vulnerabilities.map((v) => Math.max(v.id.length, (v.summary ?? "").length, v.url.length))),
      fixed: Math.max(5, ...vulnerabilities.map((v) => (v.fixedVersion ?? "N/A").length)),
      cvss: 5,
    };

    const hr = `${"─".repeat(colWidths.severity + 2)}┬${"─".repeat(colWidths.package + 2)}┬${"─".repeat(colWidths.version + 2)}┬${"─".repeat(colWidths.vuln + 2)}┬${"─".repeat(colWidths.fixed + 2)}┬${"─".repeat(colWidths.cvss + 2)}`;
    const topBorder = `┌${hr.replaceAll("┬", "┬")}┐`;
    const midBorder = `├${hr.replaceAll("┬", "┼")}┤`;
    const botBorder = `└${hr.replaceAll("┬", "┴")}┘`;

    // Header
    lines.push(topBorder);
    lines.push(
      `│ ${pad("Severity", colWidths.severity)} │ ${pad("Package", colWidths.package)} │ ${pad("Version", colWidths.version)} │ ${pad("Vulnerability", colWidths.vuln)} │ ${pad("Fixed", colWidths.fixed)} │ ${pad("CVSS", colWidths.cvss)} │`,
    );
    lines.push(midBorder);

    for (let i = 0; i < vulnerabilities.length; i++) {
      const v = vulnerabilities[i];
      // Row 1: severity, package, version, vuln ID, fixed, cvss
      const severityStr = severityColor(v.severity);
      const severityPad = " ".repeat(Math.max(0, colWidths.severity - v.severity.length));
      lines.push(
        `│ ${severityStr}${severityPad} │ ${pad(v.package, colWidths.package)} │ ${pad(v.installedVersion, colWidths.version)} │ ${pad(v.id, colWidths.vuln)} │ ${pad(v.fixedVersion ?? "N/A", colWidths.fixed)} │ ${pad(v.cvss.toFixed(1), colWidths.cvss)} │`,
      );
      // Row 2: summary
      lines.push(
        `│ ${pad("", colWidths.severity)} │ ${pad("", colWidths.package)} │ ${pad("", colWidths.version)} │ ${pad(v.summary.slice(0, colWidths.vuln), colWidths.vuln)} │ ${pad("", colWidths.fixed)} │ ${pad("", colWidths.cvss)} │`,
      );
      // Row 3: URL
      lines.push(
        `│ ${pad("", colWidths.severity)} │ ${pad("", colWidths.package)} │ ${pad("", colWidths.version)} │ ${pad(v.url, colWidths.vuln)} │ ${pad("", colWidths.fixed)} │ ${pad("", colWidths.cvss)} │`,
      );

      if (i < vulnerabilities.length - 1) {
        lines.push(midBorder);
      }
    }

    lines.push(botBorder);
  }

  lines.push(
    `\n${vulnerabilities.length} vulnerabilities found (${severityCountString(counts)})`,
  );

  if (showNotFound && allowlistNotFound.length > 0) {
    lines.push(formatNotFoundSection(allowlistNotFound));
  }

  return lines.join("\n");
}

function formatNotFoundSection(ids: string[]): string {
  const lines = ["\nAllowlisted vulnerabilities not found (may be stale):"];
  for (const id of ids) {
    lines.push(`  - ${id}`);
  }
  return lines.join("\n");
}

// --- JSON output ---

export function formatJson(result: AuditResult): string {
  const counts = countSeverities(result.vulnerabilities);
  return JSON.stringify(
    {
      vulnerabilities: result.vulnerabilities,
      metadata: {
        packagesScanned: result.packagesScanned,
        vulnerabilitiesFound: result.vulnerabilities.length,
        severityCounts: counts,
      },
    },
    null,
    2,
  );
}

// --- Summary output ---

export function formatSummary(result: AuditResult): string {
  const { vulnerabilities, packagesScanned } = result;
  if (vulnerabilities.length === 0) {
    return `yarn-osv-audit: no vulnerabilities found in ${packagesScanned} packages`;
  }
  const counts = countSeverities(vulnerabilities);
  return `yarn-osv-audit: ${vulnerabilities.length} vulnerabilities (${severityCountString(counts)}) in ${packagesScanned} packages`;
}

// --- Dispatcher ---

export function formatOutput(
  result: AuditResult,
  format: "table" | "json" | "summary",
  showFound: boolean,
  showNotFound: boolean,
): string {
  switch (format) {
    case "table":
      return formatTable(result, showFound, showNotFound);
    case "json":
      return formatJson(result);
    case "summary":
      return formatSummary(result);
  }
}

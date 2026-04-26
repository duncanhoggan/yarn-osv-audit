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

function severityCountString(counts: SeverityCounts, sep = ", "): string {
  return `${counts.critical} critical${sep}${counts.high} high${sep}${counts.moderate} moderate${sep}${counts.low} low`;
}

// --- Colour handling ---

function shouldColor(): boolean {
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== "0") return true;
  if (process.env.CI && process.env.CI !== "false") return false;
  return process.stdout.isTTY === true;
}

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  brightRed: "\x1b[91m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
};

function colorize(text: string, code: string, enabled: boolean): string {
  return enabled ? `${code}${text}${ANSI.reset}` : text;
}

function severityAnsi(level: SeverityLevel): string {
  switch (level) {
    case "CRITICAL": return ANSI.brightRed;
    case "HIGH":     return ANSI.red;
    case "MODERATE": return ANSI.yellow;
    case "LOW":      return ANSI.cyan;
  }
}

// --- Compact output (default) ---

function wrapOnCommas(items: string[], indent: string, width = 80): string[] {
  if (items.length === 0) return [];
  const lines: string[] = [];
  let current = "";
  for (let i = 0; i < items.length; i++) {
    const piece = items[i] + (i < items.length - 1 ? "," : "");
    const candidate = current ? `${current} ${piece}` : piece;
    if (indent.length + candidate.length > width && current) {
      lines.push(indent + current);
      current = piece;
    } else {
      current = candidate;
    }
  }
  if (current) lines.push(indent + current);
  return lines;
}

export function formatCompact(
  result: AuditResult,
  showFound: boolean,
  showNotFound: boolean,
  colorEnabled?: boolean,
): string {
  const color = colorEnabled ?? shouldColor();
  const { vulnerabilities, packagesScanned, allowlistNotFound } = result;
  const lines: string[] = [];

  if (vulnerabilities.length === 0) {
    lines.push(`No vulnerabilities found in ${packagesScanned} packages`);
    if (showNotFound && allowlistNotFound.length > 0) {
      const sorted = [...allowlistNotFound].sort();
      lines.push(`Stale allowlist (${sorted.length}):`);
      for (const line of wrapOnCommas(sorted, "  ")) lines.push(line);
    }
    return lines.join("\n");
  }

  lines.push(`Found ${vulnerabilities.length} vulnerabilities in ${packagesScanned} packages`);

  if (showFound) {
    for (const v of vulnerabilities) {
      lines.push("");
      const sev = colorize(v.severity, severityAnsi(v.severity), color);
      const header = `[${sev} · cvss ${v.cvss.toFixed(1)}] ${colorize(`${v.package}@${v.installedVersion}`, ANSI.bold, color)}`;
      lines.push(header);
      lines.push(`  ${v.id} — ${v.summary}`);
      const paths = v.depPaths ?? [];
      if (paths.length > 0) {
        const shown = paths.slice(0, 3);
        for (const p of shown) lines.push(`  Path: ${p}`);
        if (paths.length > shown.length) {
          lines.push(`  Path: …and ${paths.length - shown.length} more`);
        }
      }
      if (v.fixedVersion) {
        lines.push(`  Fixed in: ${v.fixedVersion}`);
      }
      lines.push(`  ${colorize(v.url, ANSI.dim, color)}`);
    }
  }

  lines.push("");
  const counts = countSeverities(vulnerabilities);
  lines.push(
    `Summary: ${vulnerabilities.length} vulnerabilities (${severityCountString(counts, " · ")})`,
  );

  if (showNotFound && allowlistNotFound.length > 0) {
    const sorted = [...allowlistNotFound].sort();
    const header = `Stale allowlist (${sorted.length}):`;
    const indent = " ".repeat(header.length + 1);
    const wrapped = wrapOnCommas(sorted, indent);
    if (wrapped.length > 0) {
      wrapped[0] = `${header} ${wrapped[0].slice(indent.length)}`;
    }
    for (const line of wrapped) lines.push(line);
  }

  return lines.join("\n");
}

// --- Legacy table output ---

function pad(str: string, width: number): string {
  return str + " ".repeat(Math.max(0, width - str.length));
}

function wrapText(text: string, width: number): string[] {
  if (!text) return [""];
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    if (word.length > width) {
      if (current) { lines.push(current); current = ""; }
      let remaining = word;
      while (remaining.length > width) {
        lines.push(remaining.slice(0, width));
        remaining = remaining.slice(width);
      }
      current = remaining;
      continue;
    }
    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length > width) {
      lines.push(current);
      current = word;
    } else {
      current = candidate;
    }
  }
  if (current) lines.push(current);
  return lines.length > 0 ? lines : [""];
}

function severityColorTable(level: SeverityLevel): string {
  switch (level) {
    case "CRITICAL": return `\x1b[91m${level}\x1b[0m`;
    case "HIGH":     return `\x1b[31m${level}\x1b[0m`;
    case "MODERATE": return `\x1b[33m${level}\x1b[0m`;
    case "LOW":      return `\x1b[36m${level}\x1b[0m`;
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
    const VULN_WRAP_WIDTH = 70;
    const colWidths = {
      severity: Math.max(8, ...vulnerabilities.map((v) => v.severity.length)),
      package: Math.max(7, ...vulnerabilities.map((v) => v.package.length)),
      version: Math.max(7, ...vulnerabilities.map((v) => v.installedVersion.length)),
      vuln: Math.min(
        VULN_WRAP_WIDTH,
        Math.max(13, ...vulnerabilities.map((v) => Math.max(v.id.length, (v.summary ?? "").length, v.url.length))),
      ),
      fixed: Math.max(5, ...vulnerabilities.map((v) => (v.fixedVersion ?? "N/A").length)),
      cvss: 5,
    };

    const hr = `${"─".repeat(colWidths.severity + 2)}┬${"─".repeat(colWidths.package + 2)}┬${"─".repeat(colWidths.version + 2)}┬${"─".repeat(colWidths.vuln + 2)}┬${"─".repeat(colWidths.fixed + 2)}┬${"─".repeat(colWidths.cvss + 2)}`;
    const topBorder = `┌${hr.replaceAll("┬", "┬")}┐`;
    const midBorder = `├${hr.replaceAll("┬", "┼")}┤`;
    const botBorder = `└${hr.replaceAll("┬", "┴")}┘`;

    lines.push(topBorder);
    lines.push(
      `│ ${pad("Severity", colWidths.severity)} │ ${pad("Package", colWidths.package)} │ ${pad("Version", colWidths.version)} │ ${pad("Vulnerability", colWidths.vuln)} │ ${pad("Fixed", colWidths.fixed)} │ ${pad("CVSS", colWidths.cvss)} │`,
    );
    lines.push(midBorder);

    for (let i = 0; i < vulnerabilities.length; i++) {
      const v = vulnerabilities[i];
      const severityStr = severityColorTable(v.severity);
      const severityPad = " ".repeat(Math.max(0, colWidths.severity - v.severity.length));
      lines.push(
        `│ ${severityStr}${severityPad} │ ${pad(v.package, colWidths.package)} │ ${pad(v.installedVersion, colWidths.version)} │ ${pad(v.id, colWidths.vuln)} │ ${pad(v.fixedVersion ?? "N/A", colWidths.fixed)} │ ${pad(v.cvss.toFixed(1), colWidths.cvss)} │`,
      );
      const summaryLines = wrapText(v.summary ?? "", colWidths.vuln);
      for (const sl of summaryLines) {
        lines.push(
          `│ ${pad("", colWidths.severity)} │ ${pad("", colWidths.package)} │ ${pad("", colWidths.version)} │ ${pad(sl, colWidths.vuln)} │ ${pad("", colWidths.fixed)} │ ${pad("", colWidths.cvss)} │`,
        );
      }
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
  format: "compact" | "table" | "json" | "summary",
  showFound: boolean,
  showNotFound: boolean,
): string {
  switch (format) {
    case "compact":
      return formatCompact(result, showFound, showNotFound);
    case "table":
      return formatTable(result, showFound, showNotFound);
    case "json":
      return formatJson(result);
    case "summary":
      return formatSummary(result);
  }
}

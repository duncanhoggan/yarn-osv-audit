import type { SeverityLevel } from "./types.js";

/**
 * Minimal CVSS v3.1 base score calculator.
 * Implements the spec from https://www.first.org/cvss/v3.1/specification-document
 */

interface CvssMetrics {
  AV: string; // Attack Vector
  AC: string; // Attack Complexity
  PR: string; // Privileges Required
  UI: string; // User Interaction
  S: string;  // Scope
  C: string;  // Confidentiality Impact
  I: string;  // Integrity Impact
  A: string;  // Availability Impact
}

const AV_VALUES: Record<string, number> = {
  N: 0.85, // Network
  A: 0.62, // Adjacent
  L: 0.55, // Local
  P: 0.2,  // Physical
};

const AC_VALUES: Record<string, number> = {
  L: 0.77, // Low
  H: 0.44, // High
};

const PR_VALUES_UNCHANGED: Record<string, number> = {
  N: 0.85, // None
  L: 0.62, // Low
  H: 0.27, // High
};

const PR_VALUES_CHANGED: Record<string, number> = {
  N: 0.85, // None
  L: 0.68, // Low
  H: 0.50, // High
};

const UI_VALUES: Record<string, number> = {
  N: 0.85, // None
  R: 0.62, // Required
};

const CIA_VALUES: Record<string, number> = {
  N: 0,    // None
  L: 0.22, // Low
  H: 0.56, // High
};

function parseVector(vector: string): CvssMetrics | null {
  // CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
  if (!vector.startsWith("CVSS:3")) return null;

  const parts = vector.split("/").slice(1); // skip "CVSS:3.x"
  const metrics: Record<string, string> = {};
  for (const part of parts) {
    const [key, val] = part.split(":");
    if (key && val) metrics[key] = val;
  }

  const required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
  for (const r of required) {
    if (!metrics[r]) return null;
  }

  return metrics as unknown as CvssMetrics;
}

function roundUp(num: number): number {
  const rounded = Math.round(num * 100000);
  return rounded % 10000 === 0
    ? rounded / 100000
    : (Math.floor(rounded / 10000) + 1) / 10;
}

export function calculateCvssScore(vector: string): number | null {
  const m = parseVector(vector);
  if (!m) return null;

  const av = AV_VALUES[m.AV];
  const ac = AC_VALUES[m.AC];
  const prValues = m.S === "C" ? PR_VALUES_CHANGED : PR_VALUES_UNCHANGED;
  const pr = prValues[m.PR];
  const ui = UI_VALUES[m.UI];
  const c = CIA_VALUES[m.C];
  const i = CIA_VALUES[m.I];
  const a = CIA_VALUES[m.A];

  if ([av, ac, pr, ui, c, i, a].some((v) => v === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const exploitability = 8.22 * av * ac * pr * ui;

  let impact: number;
  if (m.S === "U") {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  if (impact <= 0) return 0;

  let baseScore: number;
  if (m.S === "U") {
    baseScore = roundUp(Math.min(impact + exploitability, 10));
  } else {
    baseScore = roundUp(Math.min(1.08 * (impact + exploitability), 10));
  }

  return baseScore;
}

export function cvssToSeverity(score: number): SeverityLevel {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MODERATE";
  return "LOW";
}

export function severityFromString(severity: string): { level: SeverityLevel; score: number } {
  const upper = severity.toUpperCase();
  switch (upper) {
    case "CRITICAL":
      return { level: "CRITICAL", score: 9.5 };
    case "HIGH":
      return { level: "HIGH", score: 7.5 };
    case "MEDIUM":
    case "MODERATE":
      return { level: "MODERATE", score: 5.0 };
    case "LOW":
      return { level: "LOW", score: 2.0 };
    default:
      return { level: "LOW", score: 2.0 };
  }
}

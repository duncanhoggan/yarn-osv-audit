// --- Lockfile parser ---

export interface ParsedPackage {
  name: string;
  version: string;
}

// --- Config ---

export interface AllowlistRecord {
  id: string;
  reason?: string;
  path?: string;
}

export type AllowlistEntry = string | AllowlistRecord;

export interface Config {
  low: boolean;
  moderate: boolean;
  high: boolean;
  critical: boolean;
  allowlist: AllowlistEntry[];
  "output-format": "compact" | "table" | "json" | "summary";
  "show-found": boolean;
  "show-not-found": boolean;
  "skip-dev": boolean;
  lockfile: string;
  "package-json": string;
  "retry-count": number;
}

export const DEFAULT_CONFIG: Config = {
  low: true,
  moderate: false,
  high: false,
  critical: false,
  allowlist: [],
  "output-format": "table",
  "show-found": true,
  "show-not-found": true,
  "skip-dev": false,
  lockfile: "yarn.lock",
  "package-json": "package.json",
  "retry-count": 3,
};

// --- Severity ---

export type SeverityLevel = "CRITICAL" | "HIGH" | "MODERATE" | "LOW";

// --- OSV API ---

export interface OsvQueryBatchRequest {
  queries: OsvQuery[];
}

export interface OsvQuery {
  package: {
    name: string;
    ecosystem: "npm";
  };
  version: string;
  page_token?: string;
}

export interface OsvQueryBatchResponse {
  results: OsvBatchResult[];
}

export interface OsvBatchResult {
  vulns?: { id: string; modified: string }[];
  next_page_token?: string;
}

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  affected?: OsvAffected[];
  references?: { type: string; url: string }[];
  database_specific?: { severity?: string };
}

export interface OsvAffected {
  package?: { name: string; ecosystem: string };
  ranges?: {
    type: string;
    events: { introduced?: string; fixed?: string; last_affected?: string }[];
  }[];
}

// --- Audit result ---

export interface VulnerabilityResult {
  id: string;
  aliases: string[];
  summary: string;
  severity: SeverityLevel;
  cvss: number;
  package: string;
  installedVersion: string;
  fixedVersion: string | null;
  url: string;
  depPaths?: string[];
}

export interface AuditResult {
  vulnerabilities: VulnerabilityResult[];
  packagesScanned: number;
  allowlistNotFound: string[];
}

// --- Lockfile dependency graph (for skip-dev) ---

export interface LockfileEntry {
  name: string;
  version: string;
  dependencies: Record<string, string>;
}

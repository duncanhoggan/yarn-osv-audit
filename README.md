# yarn-osv-audit

[![npm version](https://img.shields.io/npm/v/yarn-osv-audit.svg?label=npm%20package&color=success)](https://www.npmjs.com/package/yarn-osv-audit)
[![Build and test](https://github.com/duncanhoggan/yarn-osv-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/duncanhoggan/yarn-osv-audit/actions/workflows/ci.yml)

A lightweight, zero-dependency CLI tool that audits **Yarn Classic (v1)** lockfiles against the [OSV.dev](https://osv.dev) vulnerability database.

## Install

```bash
# Project-local (recommended)
yarn add -D yarn-osv-audit

# Global
npm install -g yarn-osv-audit
```

## Quick Start

```bash
# Run with defaults (all severities, no allowlist)
yarn-osv-audit

# Use a config file
yarn-osv-audit --config=.osv-audit.ci.jsonc
```

Add it to your `package.json`:

```json
{
  "scripts": {
    "audit": "yarn-osv-audit",
    "audit:ci": "yarn-osv-audit --config=.osv-audit.ci.jsonc"
  }
}
```

## Output Formats

Four formats are supported: `compact`, `table`, `json`, `summary`. Pick one via CLI flag or config field — the CLI flag wins.

| Source | Example |
|--------|---------|
| CLI flag (highest precedence) | `yarn-osv-audit --format=compact` |
| Config field | `"output-format": "compact"` in `.osv-audit.jsonc` |
| Auto (default) | `compact` when `CI` env is set, else `table` |

Colour auto-enables on a TTY and auto-disables under `CI=true`, `NO_COLOR`, or when stdout isn't a TTY.

### compact (default under CI)

CI-friendly — one vulnerability per block, no column wrapping, no box-drawing characters. Reads well at any terminal width.

```bash
yarn-osv-audit --format=compact
```

```jsonc
// .osv-audit.jsonc
{ "output-format": "compact" }
```

```
yarn-osv-audit v0.1.3 — scanning yarn.lock

Found 2 vulnerabilities in 847 packages

[HIGH · cvss 7.5] socket.io@4.5.0
  GHSA-677m-j7p3-52f9 — Unbounded binary attachments DoS
  Path: app > socket.io
  Fixed in: 4.2.6
  https://osv.dev/vulnerability/GHSA-677m-j7p3-52f9

[MODERATE · cvss 5.3] semver@7.5.2
  GHSA-c2qf-rxjj-qqgw — Regular expression DoS
  Path: app > semver
  Fixed in: 7.5.4
  https://osv.dev/vulnerability/GHSA-c2qf-rxjj-qqgw

Summary: 2 vulnerabilities (0 critical · 1 high · 1 moderate · 0 low)
```

### table (default locally)

Bordered Unicode table. Assumes a wide terminal; wraps poorly in CI log viewers.

```bash
yarn-osv-audit --format=table
```

```jsonc
// .osv-audit.jsonc
{ "output-format": "table" }
```

```
Found 2 vulnerabilities in 847 packages

┌──────────┬───────────┬─────────┬───────────────────────────────────────────────────┬───────┬──────┐
│ Severity │ Package   │ Version │ Vulnerability                                     │ Fixed │ CVSS │
├──────────┼───────────┼─────────┼───────────────────────────────────────────────────┼───────┼──────┤
│ HIGH     │ socket.io │ 4.5.0   │ GHSA-677m-j7p3-52f9                               │ 4.2.6 │ 7.5  │
│          │           │         │ Unbounded binary attachments DoS                  │       │      │
│          │           │         │ https://osv.dev/vulnerability/GHSA-677m-j7p3-52f9 │       │      │
└──────────┴───────────┴─────────┴───────────────────────────────────────────────────┴───────┴──────┘
```

### json

Machine-readable — pipe into tooling, dashboards, or reporting scripts.

```bash
yarn-osv-audit --format=json
```

```jsonc
// .osv-audit.jsonc
{ "output-format": "json" }
```

```json
{
  "vulnerabilities": [
    {
      "id": "GHSA-677m-j7p3-52f9",
      "aliases": ["CVE-2026-33151"],
      "summary": "socket.io allows an unbounded number of binary attachments",
      "severity": "HIGH",
      "cvss": 7.5,
      "package": "socket.io",
      "installedVersion": "4.5.0",
      "fixedVersion": "4.2.6",
      "url": "https://osv.dev/vulnerability/GHSA-677m-j7p3-52f9"
    }
  ],
  "metadata": {
    "packagesScanned": 847,
    "vulnerabilitiesFound": 1,
    "severityCounts": { "critical": 0, "high": 1, "moderate": 0, "low": 0 }
  }
}
```

### summary

One-line output — useful for pre-commit hooks or status lines.

```bash
yarn-osv-audit --format=summary
```

```jsonc
// .osv-audit.jsonc
{ "output-format": "summary" }
```

```
yarn-osv-audit: 3 vulnerabilities (0 critical, 1 high, 1 moderate, 1 low) in 847 packages
```

## Configuration

All configuration lives in `.osv-audit.jsonc` (JSON with comments). No flags to remember, no duplication across scripts.

```jsonc
{
  "$schema": "https://raw.githubusercontent.com/duncanpharvey/yarn-osv-audit/main/docs/schema.json",

  // Severity threshold — set ONE to true.
  // Fails on that level and everything above it.
  // Default: "low": true (all vulnerabilities fail the audit)
  "high": true,

  // Allowlist vulnerabilities to ignore
  "allowlist": [
    // Simple — just the ID
    "GHSA-xxxx-yyyy-zzzz",

    // With a reason (shown in output, great for auditors)
    {
      "id": "GHSA-aaaa-bbbb-cccc",
      "package": "lodash",
      "reason": "Not exploitable — we don't use the affected code path"
    },

    // Path-specific — only ignore when reached through this dependency chain
    {
      "id": "GHSA-mmmm-nnnn-oooo",
      "package": "qs",
      "path": "express>body-parser>qs",
      "reason": "Only affects query string parsing which we handle upstream"
    }
  ],

  // Output: "compact" | "table" | "json" | "summary"
  // If unset: auto — "compact" when CI env var is set, else "table".
  "output-format": "table",

  // Show details of found vulnerabilities
  "show-found": true,

  // Show allowlisted IDs that weren't found (helps clean up stale entries)
  "show-not-found": true,

  // Exclude devDependencies from the audit
  "skip-dev": false,

  // File paths (defaults shown)
  "lockfile": "yarn.lock",
  "package-json": "package.json",

  // Retry count for OSV API requests
  "retry-count": 3
}
```

The `$schema` field gives you autocompletion and validation in VS Code, JetBrains, and any editor with JSON Schema support.

### Severity Thresholds

Only one should be `true`. The tool fails on that level **and above**.

| Setting | Fails on |
|---------|----------|
| `"low": true` (default) | Low, Moderate, High, Critical |
| `"moderate": true` | Moderate, High, Critical |
| `"high": true` | High, Critical |
| `"critical": true` | Critical only |

Severity is derived from CVSS v3 scores: Low (0.1-3.9), Moderate (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0).

### Config Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `$schema` | `string` | — | JSON Schema URL for IDE support |
| `low` | `boolean` | `true` | Fail on low+ severity |
| `moderate` | `boolean` | `false` | Fail on moderate+ severity |
| `high` | `boolean` | `false` | Fail on high+ severity |
| `critical` | `boolean` | `false` | Fail on critical only |
| `allowlist` | `(string \| object)[]` | `[]` | Vuln IDs to ignore |
| `output-format` | `string` | auto | `"compact"`, `"table"`, `"json"`, or `"summary"`. Auto: `compact` if `CI` is set, else `table`. |
| `show-found` | `boolean` | `true` | Show vulnerability details |
| `show-not-found` | `boolean` | `true` | Show stale allowlist entries |
| `skip-dev` | `boolean` | `false` | Exclude devDependencies (production tree follows `dependencies` + `optionalDependencies`) |
| `lockfile` | `string` | `"yarn.lock"` | Path to yarn.lock |
| `package-json` | `string` | `"package.json"` | Path to package.json |
| `retry-count` | `number` | `3` | API retry count |

## CLI Flags

Intentionally minimal. Configuration belongs in the config file.

| Flag | Description |
|------|-------------|
| `--config=<path>`, `-c=<path>` | Path to config file (default: `.osv-audit.jsonc`) |
| `--format=<fmt>` | Output format: `compact`, `table`, `json`, `summary`. Overrides config. |
| `--ignore-all`, `-i` | Append every reported vulnerability to the config's `allowlist` (no prompts) |
| `--fix` | Read the allowlist, find same-major fix versions, and rewrite `package.json` / `resolutions`. See [Fixing vulnerabilities](#fixing-vulnerabilities). |
| `--verbose`, `-v` | Log diagnostic details to stderr |
| `--help` | Show help |
| `--version` | Show version |

### Bulk Allowlisting (`-i` / `--ignore-all`)

Running with `-i` appends every reported vulnerability to the `allowlist` in one shot — no prompts. Comments and formatting in `.osv-audit.jsonc` are preserved. Duplicate occurrences of the same vulnerability ID are collapsed into a single entry, and the OSV vulnerability URL is recorded as the entry's `reason`.

```bash
yarn-osv-audit -i
```

Use this when you want to acknowledge the current backlog of findings as a baseline, then triage / remove entries from `.osv-audit.jsonc` later. Because there's no prompting, this works in CI / non-TTY environments.

## Fixing vulnerabilities

```bash
yarn-osv-audit --fix
```

Once vulnerabilities are in the allowlist (via `-i` or manual edits), `--fix` walks the allowlist, queries OSV for a fix version, and rewrites `package.json` so the next `yarn install` picks it up:

- **Direct deps** — the entry in `dependencies` / `devDependencies` / `optionalDependencies` is rewritten to the exact `<fixed>` version (no `^` or `~` range — deterministic pin).
- **Transitive deps** — a top-level `resolutions` entry is added (or updated) to the exact `<fixed>` version.
- **Semver safety** — only same-major bumps are applied. When OSV publishes fixes on multiple major lines (e.g. `1.1.12`, `2.0.2`, `5.0.5`), the smallest same-major fix greater than the installed version is chosen.
- **Cross-major only** — reported under `Skipped` with the list of available fix versions. You'll need to upgrade manually.
- **Allowlist cleanup** — every successfully fixed entry is spliced out of `.osv-audit.jsonc`. Comments outside the allowlist array are preserved; the array body is rebuilt from the kept entries, so any standalone comments inside the allowlist are dropped.
- **Package annotation** — any skipped (cross-major / no-fix) entries get a `package` field added in place so the residual allowlist self-documents which npm package each ID relates to. Entries added via `-i` already include `package`.

The tool only edits files — run `yarn install` afterwards to update the lockfile.

```
yarn-osv-audit v0.1.1 — fixing allowlisted vulns from .osv-audit.jsonc

Applied 1 fix:
  lodash → 4.17.21 [dependencies] (was ^4.17.10)
    GHSA-p6mc-m468-83gw — https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw

Run `yarn install` to apply these changes.

Skipped 1:
  brace-expansion@1.1.11 — no same-major fix (installed 1.1.11, available 2.0.2, 5.0.5)
    GHSA-f886-m6hf-6m8v — https://osv.dev/vulnerability/GHSA-f886-m6hf-6m8v

Removed 1 allowlist entry: GHSA-p6mc-m468-83gw
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities found (at or above threshold) |
| `1` | Vulnerabilities found (at or above threshold) |
| `2` | Runtime error (network failure, parse error, invalid config) |

## CI Examples

### GitHub Actions

```yaml
- name: Audit dependencies
  run: yarn-osv-audit --config=.osv-audit.ci.jsonc
```

### Pre-commit Hook

```json
{
  "scripts": {
    "precommit": "yarn-osv-audit"
  }
}
```

## How It Works

1. **Parse** `yarn.lock` — extracts unique (package, version) pairs
2. **Query** the [OSV batch API](https://osv.dev/docs/#tag/api/post/v1/querybatch) — up to 1000 packages per request
3. **Hydrate** vulnerability details — fetches CVSS scores, summaries, fix versions
4. **Filter** — applies allowlist, severity threshold, and skip-dev rules
5. **Report** — outputs results in your chosen format

## Requirements

- **Node.js** >= 18 (uses native `fetch`)
- **Yarn v1** lockfile (`yarn.lock`)

## License

MIT

# yarn-osv-audit

A lightweight, zero-dependency CLI tool that audits **Yarn Classic (v1)** lockfiles against the [OSV.dev](https://osv.dev) vulnerability database.

Drop-in replacement for the broken `yarn audit` command.

## Why?

`yarn audit` on Yarn Classic v1 hits `registry.yarnpkg.com/-/npm/v1/security/audits` which now returns **410 Gone**. Every tool that wraps it (`yarn-improved-audit`, `audit-ci`, etc.) is broken for the same reason.

**yarn-osv-audit** queries the [OSV API](https://osv.dev) directly. No wrappers, no deprecated endpoints, no external binaries.

| | yarn audit | audit-ci | osv-scanner | **yarn-osv-audit** |
|---|---|---|---|---|
| Works with Yarn v1 | :x: 410 Gone | :x: Wraps yarn audit | :white_check_mark: | :white_check_mark: |
| npm package | :white_check_mark: | :white_check_mark: | :x: Go binary | :white_check_mark: |
| Zero dependencies | - | :x: | - | :white_check_mark: |
| Config file | :x: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Allowlist with reasons | :x: | :white_check_mark: | :x: | :white_check_mark: |
| Path-specific allowlist | :x: | :x: | :x: | :white_check_mark: |

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
yarn-osv-audit --config .osv-audit.ci.jsonc
```

Add it to your `package.json`:

```json
{
  "scripts": {
    "audit": "yarn-osv-audit",
    "audit:ci": "yarn-osv-audit --config .osv-audit.ci.jsonc"
  }
}
```

## Output

### Compact (default under CI)

CI-friendly — one vulnerability per block, no column wrapping, no box-drawing characters. Reads well at any terminal width. Auto-selected when `CI` env var is set; otherwise the default is `table`. Set `"output-format"` in your config to pin a format, or pass `--format` to override.

Colour auto-enables on a TTY and auto-disables under `CI=true`, `NO_COLOR`, or when stdout isn't a TTY.

```
yarn-osv-audit v0.1.0 — scanning yarn.lock

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

### Table (default locally)

```
yarn-osv-audit --format table

Found 2 vulnerabilities in 847 packages

┌──────────┬───────────┬─────────┬───────────────────────────────────────────────────┬───────┬──────┐
│ Severity │ Package   │ Version │ Vulnerability                                     │ Fixed │ CVSS │
├──────────┼───────────┼─────────┼───────────────────────────────────────────────────┼───────┼──────┤
│ HIGH     │ socket.io │ 4.5.0   │ GHSA-677m-j7p3-52f9                               │ 4.2.6 │ 7.5  │
│          │           │         │ Unbounded binary attachments DoS                  │       │      │
│          │           │         │ https://osv.dev/vulnerability/GHSA-677m-j7p3-52f9 │       │      │
└──────────┴───────────┴─────────┴───────────────────────────────────────────────────┴───────┴──────┘
```

### JSON

```bash
yarn-osv-audit --config json-config.jsonc
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

### Summary

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
      "reason": "Not exploitable — we don't use the affected code path"
    },

    // Path-specific — only ignore when reached through this dependency chain
    {
      "id": "GHSA-mmmm-nnnn-oooo",
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
| `--config`, `-c` | Path to config file (default: `.osv-audit.jsonc`) |
| `--format <fmt>` | Output format: `compact`, `table`, `json`, `summary`. Overrides config. |
| `--interactive`, `-i` | Prompt per vulnerability to append it to the config's `allowlist` |
| `--verbose`, `-v` | Log diagnostic details to stderr |
| `--help` | Show help |
| `--version` | Show version |

### Interactive Allowlisting

Running with `-i` walks through each vulnerability in the report and lets you add it to the `allowlist` directly — comments and formatting in `.osv-audit.jsonc` are preserved. Duplicate occurrences of the same vulnerability ID are grouped into a single prompt.

```bash
yarn-osv-audit -i
```

```
[CRITICAL] GHSA-xq3m-2v4x-88gg — protobufjs@7.2.6, protobufjs@7.5.4
  Add to allowlist? (y/N/q) y
  Reason (optional): awaiting upstream patch
```

Answer `y` to allowlist, `n`/Enter to skip, `q` to quit early. Requires a TTY — skipped in non-interactive environments like CI.

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
  run: yarn-osv-audit --config .osv-audit.ci.jsonc
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

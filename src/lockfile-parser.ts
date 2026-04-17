import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { LockfileEntry, ParsedPackage } from "./types.js";

/**
 * Parse a yarn.lock v1 file and extract unique (name, version) pairs.
 */
export function parseLockfile(lockfilePath: string): ParsedPackage[] {
  const fullPath = resolve(lockfilePath);
  let content: string;
  try {
    content = readFileSync(fullPath, "utf-8");
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(
      `Failed to read lockfile "${fullPath}": ${msg}. ` +
        `Check the "lockfile" field in your config.`,
    );
  }

  return parseLockfileContent(content);
}

export function parseLockfileContent(content: string): ParsedPackage[] {
  const seen = new Map<string, string>(); // "name@version" -> version
  const lines = content.split("\n");
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Skip comments and blank lines
    if (line.startsWith("#") || line.trim() === "") {
      i++;
      continue;
    }

    // A top-level entry starts with a non-space character and ends with ":"
    if (line.length > 0 && line[0] !== " " && line.endsWith(":")) {
      const names = parseEntryHeader(line);
      // Read the indented block to get version
      i++;
      let version: string | null = null;
      let isLocal = false;

      while (i < lines.length && lines[i].startsWith("  ")) {
        const trimmed = lines[i].trimStart();
        if (trimmed.startsWith("version ")) {
          version = extractQuotedValue(trimmed, "version ");
        }
        if (
          trimmed.startsWith("resolved ") &&
          (trimmed.includes("link:") || trimmed.includes("file:"))
        ) {
          isLocal = true;
        }
        i++;
      }

      if (version && !isLocal) {
        for (const name of names) {
          const key = `${name}@${version}`;
          if (!seen.has(key)) {
            seen.set(key, version);
          }
        }
      }
      continue;
    }

    i++;
  }

  const packages: ParsedPackage[] = [];
  for (const [key] of seen) {
    const lastAt = key.lastIndexOf("@");
    packages.push({
      name: key.substring(0, lastAt),
      version: key.substring(lastAt + 1),
    });
  }

  return packages;
}

/**
 * Parse the dependency graph from lockfile content for skip-dev traversal.
 */
export function parseLockfileGraph(content: string): Map<string, LockfileEntry> {
  const entries = new Map<string, LockfileEntry>();
  const lines = content.split("\n");
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.startsWith("#") || line.trim() === "") {
      i++;
      continue;
    }

    if (line.length > 0 && line[0] !== " " && line.endsWith(":")) {
      const specifiers = parseSpecifiers(line);
      i++;

      let version: string | null = null;
      const deps: Record<string, string> = {};
      let inDeps = false;
      let isLocal = false;

      while (i < lines.length && lines[i].startsWith("  ")) {
        const trimmed = lines[i].trimStart();

        if (trimmed.startsWith("version ")) {
          version = extractQuotedValue(trimmed, "version ");
          inDeps = false;
        } else if (trimmed === "dependencies:" || trimmed === "optionalDependencies:") {
          inDeps = true;
        } else if (
          trimmed.startsWith("resolved ") ||
          trimmed.startsWith("integrity ")
        ) {
          inDeps = false;
          if (trimmed.startsWith("resolved ") && (trimmed.includes("link:") || trimmed.includes("file:"))) {
            isLocal = true;
          }
        } else if (inDeps && lines[i].startsWith("    ")) {
          const depMatch = trimmed.match(/^"?([^"\s]+)"?\s+"?([^"]+)"?$/);
          if (depMatch) {
            deps[depMatch[1]] = depMatch[2];
          }
        } else {
          // Another section header like peerDependencies:
          if (trimmed.endsWith(":")) {
            inDeps = false;
          }
        }
        i++;
      }

      if (version && !isLocal) {
        const names = parseEntryHeader(line);
        for (const name of names) {
          const entry: LockfileEntry = { name, version, dependencies: deps };
          // Map each specifier to this entry
          for (const spec of specifiers) {
            entries.set(spec, entry);
          }
        }
      }
      continue;
    }

    i++;
  }

  return entries;
}

/**
 * Parse the header line of a lockfile entry to extract package names.
 * Example: `"@scope/pkg@^1.0.0", "@scope/pkg@~1.2.0":`
 * Returns: ["@scope/pkg"]
 */
function parseEntryHeader(line: string): string[] {
  // Remove trailing ":"
  const header = line.slice(0, -1).trim();
  const names = new Set<string>();

  // Split by ", " respecting quoted strings
  const specifiers = splitSpecifiers(header);
  for (const spec of specifiers) {
    const name = extractPackageName(spec);
    if (name) names.add(name);
  }

  return [...names];
}

/**
 * Parse the header line to get raw specifiers (e.g. "@scope/pkg@^1.0.0").
 */
function parseSpecifiers(line: string): string[] {
  const header = line.slice(0, -1).trim();
  return splitSpecifiers(header);
}

function splitSpecifiers(header: string): string[] {
  const specs: string[] = [];
  let current = "";
  let inQuote = false;

  for (let i = 0; i < header.length; i++) {
    const ch = header[i];
    if (ch === '"') {
      inQuote = !inQuote;
      continue;
    }
    if (ch === "," && !inQuote) {
      const trimmed = current.trim();
      if (trimmed) specs.push(trimmed);
      current = "";
      continue;
    }
    current += ch;
  }
  const trimmed = current.trim();
  if (trimmed) specs.push(trimmed);

  return specs;
}

/**
 * Extract package name from a specifier like "@scope/pkg@^1.0.0" -> "@scope/pkg"
 */
function extractPackageName(specifier: string): string | null {
  // Handle scoped packages: @scope/name@version
  if (specifier.startsWith("@")) {
    const slashIdx = specifier.indexOf("/");
    if (slashIdx === -1) return null;
    const atIdx = specifier.indexOf("@", slashIdx);
    if (atIdx === -1) return specifier;
    return specifier.substring(0, atIdx);
  }

  // Unscoped: name@version
  const atIdx = specifier.indexOf("@");
  if (atIdx === -1) return specifier;
  return specifier.substring(0, atIdx);
}

function extractQuotedValue(line: string, prefix: string): string | null {
  const rest = line.substring(prefix.length).trim();
  if (rest.startsWith('"') && rest.endsWith('"')) {
    return rest.slice(1, -1);
  }
  return rest || null;
}

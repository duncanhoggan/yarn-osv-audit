import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import type { AllowlistRecord, VulnerabilityResult } from "./types.js";

/**
 * Prompt the user (y/N/q) for each vulnerability and collect allowlist entries
 * to add. Returns the list of entries the user approved.
 */
export async function promptAllowlistEntries(
  vulnerabilities: VulnerabilityResult[],
): Promise<AllowlistRecord[]> {
  const rl = createInterface({ input: stdin, output: stdout });
  const entries: AllowlistRecord[] = [];

  // Group by vuln ID — one blanket allowlist entry covers every occurrence.
  const grouped = new Map<string, VulnerabilityResult[]>();
  for (const v of vulnerabilities) {
    const list = grouped.get(v.id) ?? [];
    list.push(v);
    grouped.set(v.id, list);
  }

  try {
    console.log("\nInteractive allowlist: for each vulnerability answer y/N/q.\n");

    for (const [id, occurrences] of grouped) {
      const first = occurrences[0];
      const packages = occurrences.map((o) => `${o.package}@${o.installedVersion}`).join(", ");
      const header = `[${first.severity}] ${id} — ${packages}`;
      const answer = (await rl.question(`${header}\n  Add to allowlist? (y/N/q) `)).trim().toLowerCase();

      if (answer === "q") break;
      if (answer !== "y") continue;

      const reason = (await rl.question("  Reason (optional): ")).trim();
      const entry: AllowlistRecord = { id };
      if (reason) entry.reason = reason;
      entries.push(entry);
    }
  } finally {
    rl.close();
  }

  return entries;
}

/**
 * Append allowlist entries to the config file, preserving JSONC comments.
 * If the file or allowlist key doesn't exist, create them.
 */
export function appendAllowlistEntries(
  configPath: string,
  entries: AllowlistRecord[],
): void {
  if (entries.length === 0) return;

  let content: string;
  if (existsSync(configPath)) {
    content = readFileSync(configPath, "utf-8");
  } else {
    content = "{\n}\n";
  }

  content = insertAllowlistEntries(content, entries);
  writeFileSync(configPath, content, "utf-8");
}

/**
 * Insert entries into the allowlist array of a JSONC document. Exported for tests.
 */
export function insertAllowlistEntries(
  content: string,
  entries: AllowlistRecord[],
): string {
  if (entries.length === 0) return content;
  const arrayRange = findAllowlistArray(content);
  const serialized = entries.map((e) => serializeEntry(e, "    "));

  if (arrayRange) {
    const { openIdx, closeIdx } = arrayRange;
    const inner = content.slice(openIdx + 1, closeIdx);
    const hasExisting = inner.trim().length > 0;

    let insertion = "";
    if (hasExisting) {
      const needsComma = !/,\s*$/.test(inner);
      insertion = (needsComma ? "," : "") + "\n" + serialized.join(",\n") + "\n  ";
    } else {
      insertion = "\n" + serialized.join(",\n") + "\n  ";
    }

    return content.slice(0, closeIdx) + insertion + content.slice(closeIdx);
  }

  // No allowlist key — add one before the closing `}` of the top-level object.
  const topCloseIdx = findTopLevelObjectCloseIndex(content);
  if (topCloseIdx === -1) {
    // Empty file or invalid; create a minimal object.
    return `{\n  "allowlist": [\n${serialized.join(",\n")}\n  ]\n}\n`;
  }

  const before = content.slice(0, topCloseIdx);
  const trimmedBefore = before.replace(/\s*$/, "");
  const needsComma = !/[{,]\s*$/.test(trimmedBefore);
  const prefix = needsComma ? "," : "";
  const insertion = `${prefix}\n  "allowlist": [\n${serialized.join(",\n")}\n  ]\n`;
  return trimmedBefore + insertion + content.slice(topCloseIdx);
}

function serializeEntry(entry: AllowlistRecord, indent: string): string {
  const parts: string[] = [`"id": ${JSON.stringify(entry.id)}`];
  if (entry.reason) parts.push(`"reason": ${JSON.stringify(entry.reason)}`);
  if (entry.path) parts.push(`"path": ${JSON.stringify(entry.path)}`);
  return `${indent}{ ${parts.join(", ")} }`;
}

/**
 * Locate the `"allowlist"` array in a JSONC document. Returns the index of `[`
 * and the matching `]`, ignoring brackets inside strings and comments.
 */
function findAllowlistArray(content: string): { openIdx: number; closeIdx: number } | null {
  const keyRegex = /"allowlist"\s*:\s*\[/;
  const match = keyRegex.exec(content);
  if (!match) return null;
  const openIdx = match.index + match[0].length - 1;

  let depth = 1;
  let i = openIdx + 1;
  while (i < content.length) {
    const skip = skipInsignificant(content, i);
    if (skip !== i) {
      i = skip;
      continue;
    }
    const ch = content[i];
    if (ch === "[") depth++;
    else if (ch === "]") {
      depth--;
      if (depth === 0) return { openIdx, closeIdx: i };
    }
    i++;
  }
  return null;
}

function findTopLevelObjectCloseIndex(content: string): number {
  let i = 0;
  // Find opening `{`
  while (i < content.length) {
    const skip = skipInsignificant(content, i);
    if (skip !== i) {
      i = skip;
      continue;
    }
    if (content[i] === "{") break;
    i++;
  }
  if (i >= content.length) return -1;

  let depth = 1;
  i++;
  while (i < content.length) {
    const skip = skipInsignificant(content, i);
    if (skip !== i) {
      i = skip;
      continue;
    }
    const ch = content[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return i;
    }
    i++;
  }
  return -1;
}

/**
 * Advance past the string/comment starting at i. Returns the new index, or i
 * unchanged if i is not at a string or comment start.
 */
function skipInsignificant(content: string, i: number): number {
  const ch = content[i];
  const next = content[i + 1];

  if (ch === '"') {
    let j = i + 1;
    while (j < content.length) {
      if (content[j] === "\\") {
        j += 2;
        continue;
      }
      if (content[j] === '"') return j + 1;
      j++;
    }
    return content.length;
  }
  if (ch === "/" && next === "/") {
    let j = i + 2;
    while (j < content.length && content[j] !== "\n") j++;
    return j;
  }
  if (ch === "/" && next === "*") {
    let j = i + 2;
    while (j < content.length - 1 && !(content[j] === "*" && content[j + 1] === "/")) j++;
    return j + 2;
  }
  return i;
}

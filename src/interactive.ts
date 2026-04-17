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

      const defaultReason = first.url ?? `https://osv.dev/vulnerability/${id}`;
      const input = (await rl.question(`  Reason (default: ${defaultReason}): `)).trim();
      const pkgs = Array.from(new Set(occurrences.map((o) => o.package)));
      const entry: AllowlistRecord = {
        id,
        package: pkgs.length === 1 ? pkgs[0] : pkgs.join(", "),
        reason: input || defaultReason,
      };
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

/**
 * Remove allowlist entries matching the given IDs from the config file.
 * Preserves surrounding JSONC comments and formatting. Returns the list of
 * IDs that were actually removed.
 */
export function removeAllowlistEntries(configPath: string, ids: string[]): string[] {
  if (ids.length === 0 || !existsSync(configPath)) return [];
  const content = readFileSync(configPath, "utf-8");
  const { content: next, removed } = stripAllowlistEntries(content, ids);
  if (removed.length > 0) writeFileSync(configPath, next, "utf-8");
  return removed;
}

/**
 * Strip matching allowlist entries from a JSONC document. Exported for tests.
 */
export function stripAllowlistEntries(
  content: string,
  ids: string[],
): { content: string; removed: string[] } {
  const idSet = new Set(ids);
  const arrayRange = findAllowlistArray(content);
  if (!arrayRange) return { content, removed: [] };

  const entries = parseAllowlistEntries(content, arrayRange.openIdx, arrayRange.closeIdx);
  const toRemove = entries.filter((e) => idSet.has(e.id));
  if (toRemove.length === 0) return { content, removed: [] };

  const kept = entries.filter((e) => !idSet.has(e.id));
  const removed = toRemove.map((e) => e.id);

  // Detect the indentation used for entries by finding the column of the first
  // entry (or the opening bracket's line's indent + 2).
  const indent = detectEntryIndent(content, arrayRange.openIdx, entries);
  const closingIndent = detectClosingIndent(content, arrayRange.openIdx);

  // Rebuild the array body from scratch — this eliminates stray commas or
  // blank lines left by previous insert/remove operations. Comments placed
  // directly inside the allowlist are dropped (comments outside are untouched).
  let inner: string;
  if (kept.length === 0) {
    inner = "";
  } else {
    const keptTexts = kept.map((e) => content.slice(e.start, e.end));
    inner = "\n" + keptTexts.map((t) => indent + t).join(",\n") + "\n" + closingIndent;
  }

  const newContent =
    content.slice(0, arrayRange.openIdx + 1) + inner + content.slice(arrayRange.closeIdx);

  return { content: newContent, removed };
}

function detectEntryIndent(
  content: string,
  openIdx: number,
  entries: EntryRange[],
): string {
  if (entries.length > 0) {
    const first = entries[0].start;
    const lineStart = content.lastIndexOf("\n", first - 1) + 1;
    const slice = content.slice(lineStart, first);
    if (/^[ \t]*$/.test(slice)) return slice;
  }
  // Fall back: bracket line's indent + 2 spaces.
  return detectClosingIndent(content, openIdx) + "  ";
}

function detectClosingIndent(content: string, openIdx: number): string {
  const lineStart = content.lastIndexOf("\n", openIdx - 1) + 1;
  const slice = content.slice(lineStart, openIdx);
  const m = /^([ \t]*)/.exec(slice);
  return m ? m[1] : "  ";
}

interface EntryRange {
  id: string;
  start: number;
  end: number;
}

function parseAllowlistEntries(content: string, openIdx: number, closeIdx: number): EntryRange[] {
  const entries: EntryRange[] = [];
  let i = openIdx + 1;
  while (i < closeIdx) {
    const ch = content[i];
    const next = content[i + 1];
    // Skip comments (but NOT strings — those are entries we want to capture).
    if (ch === "/" && next === "/") {
      while (i < closeIdx && content[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < closeIdx - 1 && !(content[i] === "*" && content[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    if (ch === "," || /\s/.test(ch)) {
      i++;
      continue;
    }
    if (ch === '"') {
      // String-form entry: "GHSA-..."
      const endQ = findStringEnd(content, i);
      const id = JSON.parse(content.slice(i, endQ + 1));
      entries.push({ id, start: i, end: endQ + 1 });
      i = endQ + 1;
      continue;
    }
    if (ch === "{") {
      const endB = findMatchingBrace(content, i);
      const objText = content.slice(i, endB + 1);
      const id = extractIdFromObject(objText);
      if (id) entries.push({ id, start: i, end: endB + 1 });
      i = endB + 1;
      continue;
    }
    i++;
  }
  return entries;
}

function findStringEnd(content: string, start: number): number {
  let j = start + 1;
  while (j < content.length) {
    if (content[j] === "\\") {
      j += 2;
      continue;
    }
    if (content[j] === '"') return j;
    j++;
  }
  return content.length - 1;
}

function findMatchingBrace(content: string, start: number): number {
  let depth = 1;
  let i = start + 1;
  while (i < content.length) {
    const skip = skipInsignificant(content, i);
    if (skip !== i) {
      i = skip;
      continue;
    }
    if (content[i] === "{") depth++;
    else if (content[i] === "}") {
      depth--;
      if (depth === 0) return i;
    }
    i++;
  }
  return content.length - 1;
}

function extractIdFromObject(objText: string): string | null {
  const m = /"id"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(objText);
  if (!m) return null;
  try {
    return JSON.parse(`"${m[1]}"`);
  } catch {
    return m[1];
  }
}

function serializeEntry(entry: AllowlistRecord, indent: string): string {
  const fieldIndent = indent + "  ";
  const parts: string[] = [`${fieldIndent}"id": ${JSON.stringify(entry.id)}`];
  if (entry.package) parts.push(`${fieldIndent}"package": ${JSON.stringify(entry.package)}`);
  if (entry.reason) parts.push(`${fieldIndent}"reason": ${JSON.stringify(entry.reason)}`);
  if (entry.path) parts.push(`${fieldIndent}"path": ${JSON.stringify(entry.path)}`);
  return `${indent}{\n${parts.join(",\n")}\n${indent}}`;
}

/**
 * Annotate existing allowlist entries with a package name, in place.
 * For each id -> package mapping, if the matching entry lacks a package field
 * it is converted to an object-form entry with that field added. Other fields
 * (reason, path) are preserved. Returns the set of ids that were updated.
 *
 * Like stripAllowlistEntries, this rebuilds the array body — standalone comments
 * inside the allowlist are dropped, but comments elsewhere are preserved.
 */
export function annotateAllowlistPackages(
  configPath: string,
  updates: Map<string, string>,
): string[] {
  if (updates.size === 0 || !existsSync(configPath)) return [];
  const content = readFileSync(configPath, "utf-8");
  const { content: next, updated } = applyAllowlistPackageUpdates(content, updates);
  if (updated.length > 0) writeFileSync(configPath, next, "utf-8");
  return updated;
}

export function applyAllowlistPackageUpdates(
  content: string,
  updates: Map<string, string>,
): { content: string; updated: string[] } {
  if (updates.size === 0) return { content, updated: [] };
  const arrayRange = findAllowlistArray(content);
  if (!arrayRange) return { content, updated: [] };

  const entries = parseAllowlistEntries(content, arrayRange.openIdx, arrayRange.closeIdx);
  const updated: string[] = [];

  const indent = detectEntryIndent(content, arrayRange.openIdx, entries);
  const closingIndent = detectClosingIndent(content, arrayRange.openIdx);

  const entryTexts = entries.map((e) => {
    const pkg = updates.get(e.id);
    if (!pkg) return content.slice(e.start, e.end);
    const record = parseEntryRecord(content.slice(e.start, e.end));
    if (record.package) return content.slice(e.start, e.end);
    record.package = pkg;
    updated.push(e.id);
    return serializeEntryInline(record);
  });

  if (updated.length === 0) return { content, updated: [] };

  const inner =
    entries.length === 0
      ? ""
      : "\n" + entryTexts.map((t) => indent + t).join(",\n") + "\n" + closingIndent;

  const newContent =
    content.slice(0, arrayRange.openIdx + 1) + inner + content.slice(arrayRange.closeIdx);
  return { content: newContent, updated };
}

function parseEntryRecord(text: string): AllowlistRecord {
  const trimmed = text.trim();
  if (trimmed.startsWith('"')) {
    try {
      return { id: JSON.parse(trimmed) };
    } catch {
      return { id: trimmed.replace(/^"|"$/g, "") };
    }
  }
  try {
    return JSON.parse(trimmed) as AllowlistRecord;
  } catch {
    const m = /"id"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(trimmed);
    return { id: m ? m[1] : "" };
  }
}

function serializeEntryInline(record: AllowlistRecord): string {
  const parts: string[] = [`"id": ${JSON.stringify(record.id)}`];
  if (record.package) parts.push(`"package": ${JSON.stringify(record.package)}`);
  if (record.reason) parts.push(`"reason": ${JSON.stringify(record.reason)}`);
  if (record.path) parts.push(`"path": ${JSON.stringify(record.path)}`);
  return `{ ${parts.join(", ")} }`;
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

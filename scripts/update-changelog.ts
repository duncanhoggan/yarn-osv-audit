#!/usr/bin/env tsx
// Prepend a CHANGELOG.md entry for the version currently in package.json.
// Run as the `npm version` lifecycle hook — package.json has already been
// bumped, but no commit or tag has been made yet, so HEAD is the previous
// release boundary.
import { execSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

interface PackageJson {
  version: string;
}

const pkg: PackageJson = JSON.parse(readFileSync("package.json", "utf-8"));
const version = pkg.version;

function git(args: string): string {
  return execSync(`git ${args}`, { encoding: "utf-8" }).trim();
}

// Find the most recent v* tag to use as the diff base. Falls back to the
// repo's first commit if no tag exists yet.
let base: string;
try {
  base = git("describe --tags --abbrev=0 --match=v*");
} catch {
  base = git("rev-list --max-parents=0 HEAD").split("\n")[0];
}

const range = `${base}..HEAD`;
const log = git(`log ${range} --pretty=format:%s`).split("\n").filter(Boolean);

if (log.length === 0) {
  console.error(`No commits since ${base}; skipping changelog update.`);
  process.exit(0);
}

const date = new Date().toISOString().slice(0, 10);
const header = `## [${version}] - ${date}\n\n`;
const body = log.map((line) => `- ${line}`).join("\n") + "\n";
const entry = header + body + "\n";

const path = "CHANGELOG.md";
let existing = "";
if (existsSync(path)) {
  existing = readFileSync(path, "utf-8");
} else {
  existing = "# Changelog\n\nAll notable changes to this project are documented here.\n\n";
}

// Insert the new entry after the title block, before any prior version sections.
const insertAt = existing.search(/^## \[/m);
let next: string;
if (insertAt === -1) {
  next = existing.replace(/\n*$/, "\n\n") + entry;
} else {
  next = existing.slice(0, insertAt) + entry + existing.slice(insertAt);
}

writeFileSync(path, next, "utf-8");
execSync(`git add ${path}`);
console.log(
  `Updated ${path} for v${version} (${log.length} commit${log.length === 1 ? "" : "s"} since ${base}).`,
);

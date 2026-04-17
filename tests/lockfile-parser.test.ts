import { describe, expect, it } from "vitest";
import { parseLockfileContent, parseLockfileGraph } from "../src/lockfile-parser.js";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const fixturesDir = resolve(import.meta.dirname, "fixtures");

describe("parseLockfileContent", () => {
  it("parses a simple lockfile", () => {
    const content = readFileSync(resolve(fixturesDir, "simple.lock"), "utf-8");
    const packages = parseLockfileContent(content);

    expect(packages).toContainEqual({ name: "express", version: "4.18.2" });
    expect(packages).toContainEqual({ name: "body-parser", version: "1.20.1" });
    expect(packages).toContainEqual({ name: "qs", version: "6.11.0" });
    expect(packages).toContainEqual({ name: "semver", version: "7.5.2" });
    expect(packages).toHaveLength(4);
  });

  it("deduplicates multiple specifiers for the same version", () => {
    const content = readFileSync(resolve(fixturesDir, "simple.lock"), "utf-8");
    const packages = parseLockfileContent(content);

    // semver has two specifiers but should appear once
    const semverEntries = packages.filter((p) => p.name === "semver");
    expect(semverEntries).toHaveLength(1);
  });

  it("parses scoped packages", () => {
    const content = readFileSync(resolve(fixturesDir, "scoped.lock"), "utf-8");
    const packages = parseLockfileContent(content);

    expect(packages).toContainEqual({ name: "@babel/core", version: "7.22.5" });
    expect(packages).toContainEqual({ name: "@babel/parser", version: "7.22.7" });
    expect(packages).toContainEqual({ name: "@types/node", version: "18.16.19" });
    expect(packages).toContainEqual({ name: "lodash", version: "4.17.21" });
    expect(packages).toHaveLength(4);
  });

  it("skips local packages (file: and link: protocols)", () => {
    const content = readFileSync(resolve(fixturesDir, "malformed.lock"), "utf-8");
    const packages = parseLockfileContent(content);

    const names = packages.map((p) => p.name);
    expect(names).not.toContain("local-pkg");
    expect(names).not.toContain("linked-pkg");
    expect(names).toContain("valid-pkg");
  });

  it("handles packages without resolved field", () => {
    const content = readFileSync(resolve(fixturesDir, "malformed.lock"), "utf-8");
    const packages = parseLockfileContent(content);

    expect(packages).toContainEqual({ name: "no-resolved", version: "1.0.0" });
  });

  it("handles empty lockfile", () => {
    const content = "# yarn lockfile v1\n\n";
    const packages = parseLockfileContent(content);
    expect(packages).toHaveLength(0);
  });
});

describe("parseLockfileGraph", () => {
  it("builds a dependency graph", () => {
    const content = readFileSync(resolve(fixturesDir, "simple.lock"), "utf-8");
    const graph = parseLockfileGraph(content);

    const express = graph.get("express@^4.18.0");
    expect(express).toBeDefined();
    expect(express!.name).toBe("express");
    expect(express!.version).toBe("4.18.2");
    expect(express!.dependencies).toHaveProperty("body-parser", "1.20.1");
    expect(express!.dependencies).toHaveProperty("qs", "6.11.0");
  });

  it("includes optionalDependencies in the dependency graph", () => {
    const content = readFileSync(resolve(fixturesDir, "optional-deps.lock"), "utf-8");
    const graph = parseLockfileGraph(content);

    const fb = graph.get("firebase-admin@12.0.0");
    expect(fb).toBeDefined();
    // Regular dependency
    expect(fb!.dependencies).toHaveProperty("jsonwebtoken", "^9.0.0");
    // Optional dependency must also be present — production installs follow these
    expect(fb!.dependencies).toHaveProperty("@google-cloud/firestore", "^7.1.0");
  });
});

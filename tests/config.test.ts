import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { resolve } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const fixturesDir = resolve(import.meta.dirname, "fixtures");

describe("loadConfig", () => {
  it("loads a JSONC config file with comments", () => {
    const config = loadConfig(resolve(fixturesDir, ".osv-audit.jsonc"));

    expect(config.high).toBe(true);
    expect(config.low).toBe(false);
    expect(config.moderate).toBe(false);
    expect(config.critical).toBe(false);
    expect(config.allowlist).toHaveLength(2);
    expect(config["retry-count"]).toBe(1);
  });

  it("returns defaults when no config file exists", () => {
    // Use a temp directory that has no .osv-audit.jsonc
    const tmpDir = mkdtempSync(resolve(tmpdir(), "osv-test-"));
    const origCwd = process.cwd();
    process.chdir(tmpDir);
    try {
      const config = loadConfig();

      expect(config.low).toBe(true);
      expect(config.moderate).toBe(false);
      expect(config.high).toBe(false);
      expect(config.critical).toBe(false);
      expect(config.allowlist).toEqual([]);
      expect(config["output-format"]).toBe("table");
      expect(config["retry-count"]).toBe(3);
    } finally {
      process.chdir(origCwd);
    }
  });

  it("throws when explicit config path does not exist", () => {
    expect(() => loadConfig("/nonexistent/path.jsonc")).toThrow(
      /Failed to read config file/,
    );
  });

  it("resets severity defaults when any severity is set", () => {
    // The fixture sets "high": true, so "low" should be false
    const config = loadConfig(resolve(fixturesDir, ".osv-audit.jsonc"));
    expect(config.low).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import { buildAllowlistEntries, insertAllowlistEntries } from "../src/interactive.js";
import type { VulnerabilityResult } from "../src/types.js";

describe("insertAllowlistEntries", () => {
  it("inserts into an empty allowlist array", () => {
    const input = `{
  "allowlist": []
}
`;
    const out = insertAllowlistEntries(input, [{ id: "GHSA-1" }]);
    expect(out).toContain('"id": "GHSA-1"');
    expect(out).toMatch(/"allowlist":\s*\[\s*\{\s*"id": "GHSA-1"\s*\}\s*\]/);
  });

  it("appends to an existing allowlist without breaking JSON", () => {
    const input = `{
  "allowlist": [
    { "id": "GHSA-old" }
  ]
}
`;
    const out = insertAllowlistEntries(input, [{ id: "GHSA-new", reason: "accepted risk" }]);
    // Must remain valid JSON after stripping whitespace/comments (no comments here)
    const parsed = JSON.parse(out);
    expect(parsed.allowlist).toHaveLength(2);
    expect(parsed.allowlist[0]).toEqual({ id: "GHSA-old" });
    expect(parsed.allowlist[1]).toEqual({ id: "GHSA-new", reason: "accepted risk" });
  });

  it("preserves JSONC comments around the allowlist key", () => {
    const input = `{
  // our allowlist — reviewed 2026-04
  "allowlist": [
    { "id": "GHSA-old" } // remove next quarter
  ]
}
`;
    const out = insertAllowlistEntries(input, [{ id: "GHSA-new" }]);
    expect(out).toContain("// our allowlist — reviewed 2026-04");
    expect(out).toContain("// remove next quarter");
    expect(out).toContain('"id": "GHSA-new"');
  });

  it("creates an allowlist key when none exists", () => {
    const input = `{
  "lockfile": "yarn.lock"
}
`;
    const out = insertAllowlistEntries(input, [{ id: "GHSA-1" }]);
    expect(out).toContain('"lockfile": "yarn.lock"');
    expect(out).toContain('"allowlist"');
    expect(out).toContain('"id": "GHSA-1"');
    const parsed = JSON.parse(out);
    expect(parsed.allowlist[0].id).toBe("GHSA-1");
  });

  it("serializes entries in multi-line form with correct indentation", () => {
    const input = `{
  "allowlist": []
}
`;
    const out = insertAllowlistEntries(input, [
      { id: "GHSA-xq3m-2v4x-88gg", reason: "https://osv.dev/vulnerability/GHSA-xq3m-2v4x-88gg" },
    ]);
    expect(out).toContain(
      `    {\n      "id": "GHSA-xq3m-2v4x-88gg",\n      "reason": "https://osv.dev/vulnerability/GHSA-xq3m-2v4x-88gg"\n    }`,
    );
  });

  it("is a no-op when entries is empty", () => {
    const input = `{ "allowlist": [] }`;
    expect(insertAllowlistEntries(input, [])).toBe(input);
  });

  it("handles brackets inside strings/comments without confusion", () => {
    const input = `{
  "note": "string with ] inside",
  "allowlist": [
    { "id": "A" }
  ]
}
`;
    const out = insertAllowlistEntries(input, [{ id: "B" }]);
    const parsed = JSON.parse(out);
    expect(parsed.allowlist.map((e: { id: string }) => e.id)).toEqual(["A", "B"]);
    expect(parsed.note).toBe("string with ] inside");
  });
});

const baseVuln = (overrides: Partial<VulnerabilityResult> = {}): VulnerabilityResult => ({
  id: "GHSA-x",
  aliases: [],
  summary: "summary",
  severity: "HIGH",
  cvss: 7.5,
  package: "lodash",
  installedVersion: "4.17.10",
  fixedVersion: "4.17.21",
  url: "https://osv.dev/vulnerability/GHSA-x",
  ...overrides,
});

describe("buildAllowlistEntries", () => {
  it("returns one entry per unique vuln id with the OSV URL as the reason", () => {
    const entries = buildAllowlistEntries([
      baseVuln({ id: "GHSA-a", package: "foo", url: "https://osv.dev/vulnerability/GHSA-a" }),
      baseVuln({ id: "GHSA-b", package: "bar", url: "https://osv.dev/vulnerability/GHSA-b" }),
    ]);
    expect(entries).toEqual([
      { id: "GHSA-a", package: "foo", reason: "https://osv.dev/vulnerability/GHSA-a" },
      { id: "GHSA-b", package: "bar", reason: "https://osv.dev/vulnerability/GHSA-b" },
    ]);
  });

  it("collapses duplicate occurrences of the same id into a single entry", () => {
    const entries = buildAllowlistEntries([
      baseVuln({ id: "GHSA-dup", package: "lodash", installedVersion: "1.0.0" }),
      baseVuln({ id: "GHSA-dup", package: "lodash", installedVersion: "1.0.1" }),
    ]);
    expect(entries).toHaveLength(1);
    expect(entries[0].id).toBe("GHSA-dup");
    expect(entries[0].package).toBe("lodash");
  });

  it("joins multiple package names when one id covers different packages", () => {
    const entries = buildAllowlistEntries([
      baseVuln({ id: "GHSA-multi", package: "left-pad" }),
      baseVuln({ id: "GHSA-multi", package: "right-pad" }),
    ]);
    expect(entries).toHaveLength(1);
    expect(entries[0].package).toBe("left-pad, right-pad");
  });

  it("falls back to the canonical OSV URL when the result has no url", () => {
    const v = baseVuln({ id: "GHSA-nourl" });
    // Force-clear the url field — VulnerabilityResult declares it required
    // but the helper has to handle the absent case defensively.
    delete (v as { url?: string }).url;
    const entries = buildAllowlistEntries([v]);
    expect(entries[0].reason).toBe("https://osv.dev/vulnerability/GHSA-nourl");
  });

  it("returns an empty list when there are no vulnerabilities", () => {
    expect(buildAllowlistEntries([])).toEqual([]);
  });
});

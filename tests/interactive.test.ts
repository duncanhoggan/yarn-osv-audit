import { describe, expect, it } from "vitest";
import { insertAllowlistEntries } from "../src/interactive.js";

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

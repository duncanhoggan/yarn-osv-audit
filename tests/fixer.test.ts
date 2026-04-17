import { describe, expect, it } from "vitest";
import { pickFixedVersion } from "../src/fixer.js";
import { applyAllowlistPackageUpdates, stripAllowlistEntries } from "../src/interactive.js";
import type { OsvVulnerability } from "../src/types.js";

describe("pickFixedVersion", () => {
  it("picks the smallest same-major fix greater than installed", () => {
    // Mirrors brace-expansion: separate ranges per major with same-major fixes.
    const vuln: OsvVulnerability = {
      id: "GHSA-x",
      affected: [
        {
          package: { name: "brace-expansion", ecosystem: "npm" },
          ranges: [
            { type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }, { fixed: "1.1.12" }] },
            { type: "ECOSYSTEM", events: [{ introduced: "2.0.0" }, { fixed: "2.0.2" }] },
            { type: "ECOSYSTEM", events: [{ introduced: "5.0.0" }, { fixed: "5.0.5" }] },
          ],
        },
      ],
    };
    // Installed 1.1.11 is within same major as 1.1.12 — that's the right pick.
    expect(pickFixedVersion(vuln, "brace-expansion", "1.1.11")).toBe("1.1.12");
    expect(pickFixedVersion(vuln, "brace-expansion", "2.0.1")).toBe("2.0.2");
  });

  it("picks the smallest of multiple same-major fixes", () => {
    const vuln: OsvVulnerability = {
      id: "GHSA-x",
      affected: [
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [
            {
              type: "ECOSYSTEM",
              events: [{ introduced: "4.0.0" }, { fixed: "4.17.12" }, { fixed: "4.17.20" }],
            },
          ],
        },
      ],
    };
    expect(pickFixedVersion(vuln, "lodash", "4.17.10")).toBe("4.17.12");
  });

  it("returns null when only cross-major fixes exist", () => {
    const vuln: OsvVulnerability = {
      id: "GHSA-x",
      affected: [
        {
          package: { name: "pkg", ecosystem: "npm" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] }],
        },
      ],
    };
    expect(pickFixedVersion(vuln, "pkg", "1.5.0")).toBeNull();
  });

  it("ignores affected entries for other packages", () => {
    const vuln: OsvVulnerability = {
      id: "GHSA-x",
      affected: [
        {
          package: { name: "other", ecosystem: "npm" },
          ranges: [{ type: "ECOSYSTEM", events: [{ fixed: "1.0.0" }] }],
        },
      ],
    };
    expect(pickFixedVersion(vuln, "lodash", "1.0.0")).toBeNull();
  });

  it("ignores non-npm ecosystems", () => {
    const vuln: OsvVulnerability = {
      id: "GHSA-x",
      affected: [
        {
          package: { name: "lodash", ecosystem: "PyPI" },
          ranges: [{ type: "ECOSYSTEM", events: [{ fixed: "1.0.1" }] }],
        },
      ],
    };
    expect(pickFixedVersion(vuln, "lodash", "1.0.0")).toBeNull();
  });

  it("returns null when no fix event is published", () => {
    const vuln: OsvVulnerability = {
      id: "GHSA-x",
      affected: [
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }],
        },
      ],
    };
    expect(pickFixedVersion(vuln, "lodash", "1.0.0")).toBeNull();
  });
});

describe("stripAllowlistEntries", () => {
  it("removes a string-form entry and its trailing comma", () => {
    const input = `{
  "allowlist": [
    "GHSA-a",
    "GHSA-b"
  ]
}
`;
    const { content, removed } = stripAllowlistEntries(input, ["GHSA-a"]);
    expect(removed).toEqual(["GHSA-a"]);
    const parsed = JSON.parse(content);
    expect(parsed.allowlist).toEqual(["GHSA-b"]);
  });

  it("removes an object-form entry and leaves the rest intact", () => {
    const input = `{
  "allowlist": [
    { "id": "GHSA-a", "reason": "x" },
    { "id": "GHSA-b" }
  ]
}
`;
    const { content, removed } = stripAllowlistEntries(input, ["GHSA-b"]);
    expect(removed).toEqual(["GHSA-b"]);
    const parsed = JSON.parse(content);
    expect(parsed.allowlist).toEqual([{ id: "GHSA-a", reason: "x" }]);
  });

  it("handles removing the last entry (no trailing comma)", () => {
    const input = `{
  "allowlist": [
    { "id": "GHSA-a" },
    { "id": "GHSA-b" }
  ]
}
`;
    const { content, removed } = stripAllowlistEntries(input, ["GHSA-b"]);
    expect(removed).toEqual(["GHSA-b"]);
    const parsed = JSON.parse(content);
    expect(parsed.allowlist).toEqual([{ id: "GHSA-a" }]);
  });

  it("is a no-op when no IDs match", () => {
    const input = `{
  "allowlist": [
    "GHSA-a"
  ]
}
`;
    const { content, removed } = stripAllowlistEntries(input, ["GHSA-zzz"]);
    expect(removed).toEqual([]);
    expect(content).toBe(input);
  });

  it("removes entries with extra fields cleanly (package, reason, path, unknown)", () => {
    const input = `{
  "allowlist": [
    {
      "id": "GHSA-fixed",
      "package": "lodash",
      "reason": "patched upstream",
      "path": "app > lodash",
      "note": "ticket-123"
    },
    {
      "id": "GHSA-keep",
      "package": "react",
      "reason": "false positive"
    }
  ]
}
`;
    const { content, removed } = stripAllowlistEntries(input, ["GHSA-fixed"]);
    expect(removed).toEqual(["GHSA-fixed"]);

    // Output parses — no residue from the removed entry's fields.
    const parsed = JSON.parse(content);
    expect(parsed.allowlist).toHaveLength(1);
    expect(parsed.allowlist[0]).toEqual({
      id: "GHSA-keep",
      package: "react",
      reason: "false positive",
    });

    // No fragment of the removed entry's extra fields should survive.
    expect(content).not.toContain("GHSA-fixed");
    expect(content).not.toContain("lodash");
    expect(content).not.toContain("patched upstream");
    expect(content).not.toContain("app > lodash");
    expect(content).not.toContain("ticket-123");
  });

  it("heals a dangling comma left by a prior insert (regression)", () => {
    // This mimics the post-insert layout that produced the corrupted output
    // the user hit: a standalone `,` between the original entry and appended ones.
    const input = `{
  "moderate": true,
  "skip-dev": true,
  "allowlist": [
    {
      "id": "GHSA-old"
    }
,
    {
      "id": "GHSA-4r6h-8v6p-xvw6"
    },
    {
      "id": "GHSA-5pgg-2g8v-p4x9"
    }
  ]
}
`;
    const { content, removed } = stripAllowlistEntries(input, ["GHSA-old"]);
    expect(removed).toEqual(["GHSA-old"]);
    const parsed = JSON.parse(content);
    expect(parsed.allowlist).toEqual([
      { id: "GHSA-4r6h-8v6p-xvw6" },
      { id: "GHSA-5pgg-2g8v-p4x9" },
    ]);
    // No stray comma on its own line.
    expect(content).not.toMatch(/\n\s*,\s*\n/);
  });

  it("preserves JSONC comments outside the removed entry", () => {
    const input = `{
  // top comment
  "allowlist": [
    { "id": "GHSA-a" },
    { "id": "GHSA-b" }
  ]
}
`;
    const { content, removed } = stripAllowlistEntries(input, ["GHSA-a"]);
    expect(removed).toEqual(["GHSA-a"]);
    expect(content).toContain("// top comment");
    expect(content).toContain('"id": "GHSA-b"');
  });
});

describe("applyAllowlistPackageUpdates", () => {
  it("adds the package field to an object-form entry", () => {
    const input = `{
  "allowlist": [
    { "id": "GHSA-a", "reason": "x" },
    { "id": "GHSA-b" }
  ]
}
`;
    const updates = new Map([["GHSA-b", "lodash"]]);
    const { content, updated } = applyAllowlistPackageUpdates(input, updates);
    expect(updated).toEqual(["GHSA-b"]);
    const parsed = JSON.parse(content);
    expect(parsed.allowlist[1]).toEqual({ id: "GHSA-b", package: "lodash" });
    // Untouched entry retains its original fields.
    expect(parsed.allowlist[0]).toEqual({ id: "GHSA-a", reason: "x" });
  });

  it("promotes a string-form entry to an object with package", () => {
    const input = `{
  "allowlist": [
    "GHSA-a"
  ]
}
`;
    const { content, updated } = applyAllowlistPackageUpdates(
      input,
      new Map([["GHSA-a", "brace-expansion"]]),
    );
    expect(updated).toEqual(["GHSA-a"]);
    const parsed = JSON.parse(content);
    expect(parsed.allowlist).toEqual([{ id: "GHSA-a", package: "brace-expansion" }]);
  });

  it("leaves entries that already have a package field alone", () => {
    const input = `{
  "allowlist": [
    { "id": "GHSA-a", "package": "foo" }
  ]
}
`;
    const { content, updated } = applyAllowlistPackageUpdates(
      input,
      new Map([["GHSA-a", "bar"]]),
    );
    expect(updated).toEqual([]);
    expect(content).toBe(input);
  });
});

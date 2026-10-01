import { describe, expect, it } from "vitest";
import { ArgError, parseArgs } from "../src/args.js";

describe("parseArgs modes", () => {
  it("defaults to scan", () => {
    expect(parseArgs([]).mode).toBe("scan");
    expect(parseArgs(["--format=json"]).mode).toBe("scan");
  });

  it.each([
    [["scan"], "scan"],
    [["--scan"], "scan"],
    [["ignore"], "ignore"],
    [["--ignore"], "ignore"],
    [["--ignore-all"], "ignore"],
    [["-i"], "ignore"],
    [["fix"], "fix"],
    [["--fix"], "fix"],
    [["fix-ignores"], "fix-ignores"],
    [["--fix-ignores"], "fix-ignores"],
  ])("%j → %s", (argv, mode) => {
    expect(parseArgs(argv).mode).toBe(mode);
  });

  it("accepts a subcommand together with its own flag alias", () => {
    expect(parseArgs(["fix", "--fix"]).mode).toBe("fix");
  });

  it("accepts options before or after the subcommand", () => {
    const a = parseArgs(["-c=custom.jsonc", "fix-ignores", "-v"]);
    expect(a).toMatchObject({ mode: "fix-ignores", configPath: "custom.jsonc", verbose: true });
  });

  it("treats --flag=false as not selecting the mode", () => {
    expect(parseArgs(["--fix=false"]).mode).toBe("scan");
  });

  it("rejects conflicting modes", () => {
    expect(() => parseArgs(["fix", "--fix-ignores"])).toThrow(ArgError);
    expect(() => parseArgs(["scan", "ignore"])).toThrow(/conflicts/);
    expect(() => parseArgs(["-i", "--fix"])).toThrow(/conflicts/);
  });

  it("rejects unknown commands and flags with help", () => {
    for (const argv of [["fixx"], ["--fix-patch"]]) {
      try {
        parseArgs(argv);
        expect.unreachable();
      } catch (err) {
        expect(err).toBeInstanceOf(ArgError);
        expect((err as ArgError).showHelp).toBe(true);
      }
    }
  });
});

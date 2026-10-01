export type Mode = "scan" | "ignore" | "fix" | "fix-ignores";
export type OutputFormat = "compact" | "table" | "json" | "summary";

export interface CliArgs {
  mode: Mode;
  configPath?: string;
  help: boolean;
  version: boolean;
  verbose: boolean;
  format?: OutputFormat;
}

/** Invalid command line. `showHelp` asks the caller to print usage too. */
export class ArgError extends Error {
  constructor(
    message: string,
    readonly showHelp = false,
  ) {
    super(message);
  }
}

const SUBCOMMANDS: readonly Mode[] = ["scan", "ignore", "fix", "fix-ignores"];

/** Flag aliases for each subcommand. */
const MODE_FLAGS: Record<string, Mode> = {
  "--scan": "scan",
  "--ignore": "ignore",
  "--ignore-all": "ignore",
  "-i": "ignore",
  "--fix": "fix",
  "--fix-ignores": "fix-ignores",
};

/**
 * Parse CLI arguments. A mode is chosen by an optional leading subcommand
 * (`scan`, `ignore`, `fix`, `fix-ignores`) or its flag alias; with neither,
 * the mode is `scan`. Picking two different modes is an error.
 */
export function parseArgs(args: string[]): CliArgs {
  let mode: Mode | undefined;
  let modeSource = "";
  let configPath: string | undefined;
  let help = false;
  let version = false;
  let verbose = false;
  let format: OutputFormat | undefined;

  const setMode = (next: Mode, source: string): void => {
    if (mode && mode !== next) {
      throw new ArgError(`${source} conflicts with ${modeSource} — pick one mode`);
    }
    mode = next;
    modeSource = source;
  };

  // Value-taking flags use `--flag=value` form only. Boolean flags stand alone.
  for (const raw of args) {
    if (!raw.startsWith("-")) {
      if (!(SUBCOMMANDS as readonly string[]).includes(raw)) {
        throw new ArgError(`Unknown command: ${raw}`, true);
      }
      setMode(raw as Mode, raw);
      continue;
    }

    const eq = raw.indexOf("=");
    const name = eq > 0 ? raw.slice(0, eq) : raw;
    const value = eq > 0 ? raw.slice(eq + 1) : undefined;

    const requireValue = (): string => {
      if (value === undefined) throw new ArgError(`${name} requires a value (use ${name}=<value>)`);
      if (value === "") throw new ArgError(`${name} requires a non-empty value`);
      return value;
    };
    const rejectValue = (): void => {
      if (value !== undefined) throw new ArgError(`${name} does not take a value`);
    };
    // Boolean flags accept bare form (`--fix`) or explicit `--fix=true|false`
    // (also `1`/`0`, `yes`/`no`). Anything else is rejected.
    const parseBool = (): boolean => {
      if (value === undefined) return true;
      const v = value.toLowerCase();
      if (v === "true" || v === "1" || v === "yes") return true;
      if (v === "false" || v === "0" || v === "no") return false;
      throw new ArgError(`${name} expects a boolean value (true/false), got "${value}"`);
    };

    if (name in MODE_FLAGS) {
      if (parseBool()) setMode(MODE_FLAGS[name], name);
      continue;
    }

    switch (name) {
      case "--help": rejectValue(); help = true; break;
      case "--version": rejectValue(); version = true; break;
      case "--verbose":
      case "-v": verbose = parseBool(); break;
      case "--format": {
        const v = requireValue();
        if (v !== "compact" && v !== "table" && v !== "json" && v !== "summary") {
          throw new ArgError(`invalid --format "${v}" (expected: compact, table, json, summary)`);
        }
        format = v;
        break;
      }
      case "--config":
      case "-c": configPath = requireValue(); break;
      default:
        throw new ArgError(`Unknown argument: ${raw}`, true);
    }
  }

  return { mode: mode ?? "scan", configPath, help, version, verbose, format };
}

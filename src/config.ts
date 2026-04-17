import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Config, DEFAULT_CONFIG } from "./types.js";

/**
 * Strip JSONC comments (single-line // and multi-line) and trailing commas.
 */
function stripJsonc(text: string): string {
  let result = "";
  let i = 0;
  let inString = false;
  let escape = false;

  while (i < text.length) {
    const ch = text[i];
    const next = text[i + 1];

    if (inString) {
      result += ch;
      if (escape) {
        escape = false;
      } else if (ch === "\\") {
        escape = true;
      } else if (ch === '"') {
        inString = false;
      }
      i++;
      continue;
    }

    if (ch === '"') {
      inString = true;
      result += ch;
      i++;
      continue;
    }

    // Single-line comment
    if (ch === "/" && next === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }

    // Multi-line comment
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2; // skip */
      continue;
    }

    result += ch;
    i++;
  }

  // Remove trailing commas before } or ]
  result = result.replace(/,(\s*[}\]])/g, "$1");

  return result;
}

export function loadConfig(configPath?: string): Config {
  return loadConfigWithMeta(configPath).config;
}

export function loadConfigWithMeta(configPath?: string): { config: Config; explicit: Set<string> } {
  const resolvedPath = resolve(configPath ?? ".osv-audit.jsonc");

  let raw: string;
  try {
    raw = readFileSync(resolvedPath, "utf-8");
  } catch (err: unknown) {
    if (configPath) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to read config file "${resolvedPath}": ${msg}`);
    }
    return { config: { ...DEFAULT_CONFIG }, explicit: new Set() };
  }

  let parsed: Record<string, unknown>;
  try {
    const json = stripJsonc(raw);
    parsed = JSON.parse(json);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to parse config file "${resolvedPath}": ${msg}`);
  }

  const explicit = new Set(Object.keys(parsed).filter((k) => k !== "$schema"));
  return { config: mergeConfig(parsed), explicit };
}

function mergeConfig(parsed: Record<string, unknown>): Config {
  const config = { ...DEFAULT_CONFIG };

  // Severity — if any explicit severity is set, turn off the default "low"
  const hasSeverity =
    "low" in parsed ||
    "moderate" in parsed ||
    "high" in parsed ||
    "critical" in parsed;
  if (hasSeverity) {
    config.low = false;
    config.moderate = false;
    config.high = false;
    config.critical = false;
  }

  for (const [key, value] of Object.entries(parsed)) {
    if (key === "$schema") continue;
    if (key in config) {
      (config as Record<string, unknown>)[key] = value;
    }
  }

  return config;
}

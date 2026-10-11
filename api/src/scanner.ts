// High-level calls to the Rust binary: scan a lockfile, list rules, version.

import { randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Config } from "./config.ts";
import { runLockwatch, ScannerError, ScanTimeoutError, type RunResult } from "./runner.ts";
import {
  formatIssues,
  ReportSchema,
  RuleListSchema,
  type Report,
  type RuleList,
} from "./schemas.ts";

/** The last lines of stderr, for error messages (never the lockfile). */
function stderrTail(result: RunResult): string {
  const lines = result.stderr.trim().split("\n").slice(-3).join(" | ");
  return lines ? ` (${lines.slice(0, 500)})` : "";
}

/** Turn the binary's output into a validated report or a clear error. */
export function parseReport(result: RunResult): Report {
  // 0 = clean, 1 = findings, 2 = incomplete scan (still prints a report) or
  // a fatal error (prints nothing on stdout).
  if (result.code === null || result.code > 2) {
    const how = result.code === null ? `signal ${result.signal}` : `code ${result.code}`;
    throw new ScannerError(`lockwatch exited with ${how}${stderrTail(result)}`);
  }
  let json: unknown;
  try {
    json = JSON.parse(result.stdout);
  } catch {
    throw new ScannerError(`lockwatch did not return a JSON report${stderrTail(result)}`);
  }
  const parsed = ReportSchema.safeParse(json);
  if (!parsed.success) {
    throw new ScannerError(
      `lockwatch output does not match the report schema: ${formatIssues(parsed.error)}`,
    );
  }
  return parsed.data;
}

export class Scanner {
  readonly config: Config;
  #rules: RuleList | undefined;

  constructor(config: Config) {
    this.config = config;
  }

  /**
   * Write the lockfile to a private temporary directory with a random name,
   * run `lockwatch scan` on it, and delete it afterwards (even on error).
   */
  async scanLockfile(lockfileText: string, displayName = "package-lock.json"): Promise<Report> {
    const dir = await mkdtemp(join(tmpdir(), "lockwatch-api-"));
    const file = join(dir, `${randomUUID()}.json`);
    try {
      await writeFile(file, lockfileText, { mode: 0o600 });
      const args = ["scan", file, "--format", "json", "--fail-on", "none"];
      if (this.config.cacheDir) args.push("--cache-dir", this.config.cacheDir);
      if (this.config.offline) args.push("--offline");
      if (this.config.registry) args.push("--registry", this.config.registry);

      const result = await runLockwatch(this.config.lockwatchBin, args, {
        timeoutMs: this.config.scanTimeoutMs,
      });
      if (result.timedOut) {
        throw new ScanTimeoutError(`scan timed out after ${this.config.scanTimeoutMs} ms`);
      }
      const report = parseReport(result);
      // Show the uploaded name, not our temporary file name.
      return { ...report, lockfile: displayName };
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  /** `lockwatch rules --format json`, cached after the first call. */
  async rules(): Promise<RuleList> {
    if (this.#rules) return this.#rules;
    const result = await runLockwatch(this.config.lockwatchBin, ["rules", "--format", "json"], {
      timeoutMs: 10_000,
    });
    if (result.code !== 0) {
      throw new ScannerError(`lockwatch rules failed${stderrTail(result)}`);
    }
    let json: unknown;
    try {
      json = JSON.parse(result.stdout);
    } catch {
      throw new ScannerError("lockwatch rules did not return JSON");
    }
    const parsed = RuleListSchema.safeParse(json);
    if (!parsed.success) {
      throw new ScannerError(`unexpected rules output: ${formatIssues(parsed.error)}`);
    }
    this.#rules = parsed.data;
    return parsed.data;
  }

  /** The binary's version ("0.1.0"), or null if it cannot be run. */
  async version(): Promise<string | null> {
    try {
      const result = await runLockwatch(this.config.lockwatchBin, ["--version"], {
        timeoutMs: 5_000,
      });
      if (result.code !== 0) return null;
      // clap prints "lockwatch 0.1.0"
      return result.stdout.trim().split(/\s+/).pop() ?? null;
    } catch {
      return null;
    }
  }
}

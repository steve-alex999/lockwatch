// Running the Rust binary safely.
//
// - `spawn` with an argument array and `shell: false`: no shell ever parses
//   our arguments, so a file name or registry URL cannot inject commands.
// - A timeout kills the process with SIGKILL.
// - Output is capped so a misbehaving binary cannot exhaust memory.

import { spawn } from "node:child_process";

export interface RunResult {
  /** Exit code, or null if the process was killed by a signal. */
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** Process id of the child (used by tests to check it was killed). */
  pid: number | undefined;
}

export interface RunOptions {
  timeoutMs: number;
  /** Maximum bytes of stdout kept; more kills the process. Default 64 MB. */
  maxOutputBytes?: number;
}

/** Thrown when the binary cannot be started, crashes or prints bad output. */
export class ScannerError extends Error {
  override name = "ScannerError";
}

/** Thrown when a scan takes longer than the configured timeout. */
export class ScanTimeoutError extends Error {
  override name = "ScanTimeoutError";
}

export function runLockwatch(bin: string, args: string[], options: RunOptions): Promise<RunResult> {
  const maxOutput = options.maxOutputBytes ?? 64 * 1024 * 1024;
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { shell: false, stdio: ["ignore", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let tooLarge = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, options.timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > maxOutput) {
        tooLarge = true;
        child.kill("SIGKILL");
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      // Keep only the first 64 KB of stderr; it is only used in messages.
      if (stderrBytes < 64 * 1024) stderr.push(chunk);
      stderrBytes += chunk.length;
    });

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(new ScannerError(`cannot run lockwatch binary "${bin}": ${err.message}`));
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (tooLarge) {
        reject(new ScannerError(`lockwatch output exceeded ${maxOutput} bytes`));
        return;
      }
      resolve({
        code,
        signal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        timedOut,
        pid: child.pid,
      });
    });
  });
}

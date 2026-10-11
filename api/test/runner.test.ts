import { describe, expect, it } from "vitest";

import { runLockwatch, ScannerError, ScanTimeoutError } from "../src/runner.ts";
import { parseReport, Scanner } from "../src/scanner.ts";
import { fakeBin, makeLockfile, testConfig } from "./helpers.ts";

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0); // signal 0 only checks that the process exists
    return true;
  } catch {
    return false;
  }
}

describe("runLockwatch", () => {
  it("kills the child process when the timeout expires", async () => {
    const started = Date.now();
    const result = await runLockwatch(fakeBin("sleep"), [], { timeoutMs: 300 });
    expect(result.timedOut).toBe(true);
    expect(result.signal).toBe("SIGKILL");
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(result.pid).toBeDefined();
    expect(isAlive(result.pid as number)).toBe(false);
  });

  it("reports a missing binary as a ScannerError", async () => {
    await expect(runLockwatch("/nonexistent/lockwatch", [], { timeoutMs: 1000 })).rejects.toThrow(
      ScannerError,
    );
  });

  it("passes arguments without a shell", async () => {
    // A shell would expand $(...) and ;. The fake binary sees them verbatim
    // and rejects them as unknown arguments.
    const result = await runLockwatch(fakeBin("ok"), ["$(touch /tmp/pwned); echo"], {
      timeoutMs: 5000,
    });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("$(touch /tmp/pwned); echo");
  });
});

describe("Scanner", () => {
  const lockfile = JSON.stringify(makeLockfile(3));

  it("returns a validated report with the uploaded file name", async () => {
    const scanner = new Scanner(testConfig());
    const report = await scanner.scanLockfile(lockfile, "my-lock.json");
    expect(report.summary.packages_total).toBe(3);
    expect(report.lockfile).toBe("my-lock.json");
  });

  it("throws ScanTimeoutError when the binary hangs", async () => {
    const scanner = new Scanner(testConfig({ lockwatchBin: fakeBin("sleep"), scanTimeoutMs: 300 }));
    await expect(scanner.scanLockfile(lockfile)).rejects.toThrow(ScanTimeoutError);
  });

  it("rejects output that is not JSON", async () => {
    const scanner = new Scanner(testConfig({ lockwatchBin: fakeBin("garbage") }));
    await expect(scanner.scanLockfile(lockfile)).rejects.toThrow("did not return a JSON report");
  });

  it("rejects JSON that does not match the report schema", async () => {
    const scanner = new Scanner(testConfig({ lockwatchBin: fakeBin("bad-report") }));
    await expect(scanner.scanLockfile(lockfile)).rejects.toThrow(
      "does not match the report schema",
    );
  });

  it("includes the binary's error message on a fatal error", async () => {
    const scanner = new Scanner(testConfig({ lockwatchBin: fakeBin("fatal") }));
    await expect(scanner.scanLockfile(lockfile)).rejects.toThrow("unsupported lockfile");
  });

  it("parses rules and version", async () => {
    const scanner = new Scanner(testConfig());
    expect(await scanner.rules()).toHaveLength(12);
    expect(await scanner.version()).toBe("0.1.0");
    const missing = new Scanner(testConfig({ lockwatchBin: "/nonexistent/lockwatch" }));
    expect(await missing.version()).toBeNull();
  });

  it("rejects exit codes outside 0-2", () => {
    expect(() =>
      parseReport({
        code: 101,
        signal: null,
        stdout: "",
        stderr: "panic",
        timedOut: false,
        pid: 1,
      }),
    ).toThrow("exited with code 101");
  });
});

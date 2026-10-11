#!/usr/bin/env node
// Fake lockwatch for API tests: answers --version, `rules --format json` and
// `scan <file> --format json ...` with small valid outputs. FAKE_DELAY_MS
// makes scans slow.
import { readFileSync } from "node:fs";
import { basename } from "node:path";

const args = process.argv.slice(2);
const print = (value) => process.stdout.write(JSON.stringify(value) + "\n");

if (args[0] === "--version") {
  console.log("lockwatch 0.1.0");
} else if (args[0] === "rules") {
  const severities = [
    "low",
    "high",
    "high",
    "high",
    "high",
    "medium",
    "medium",
    "medium",
    "low",
    "medium",
    "low",
    "critical",
  ];
  print(
    severities.map((severity, i) => ({
      id: `LW${String(i + 1).padStart(3, "0")}`,
      name: `rule ${i + 1}`,
      severity,
      description: "fake rule",
    })),
  );
} else if (args[0] === "scan") {
  const lock = JSON.parse(readFileSync(args[1], "utf8"));
  const names = Object.keys(lock.packages).filter((k) => k !== "");
  const delay = Number(process.env.FAKE_DELAY_MS || 0);
  setTimeout(() => {
    print({
      tool: "lockwatch",
      version: "0.1.0",
      scanned_at: "2026-10-20T00:00:00Z",
      lockfile: basename(args[1]),
      summary: {
        packages_total: names.length,
        packages_scanned: names.length,
        packages_skipped: 0,
        findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        duration_ms: delay,
      },
      packages: names.map((key) => ({
        name: key.split("node_modules/").pop(),
        version: lock.packages[key].version ?? "0.0.0",
        risk_score: 0,
        risk_level: "none",
        findings: [],
        warnings: [],
      })),
      skipped: [],
    });
  }, delay);
} else {
  console.error(`fake lockwatch: unknown arguments ${args.join(" ")}`);
  process.exit(2);
}

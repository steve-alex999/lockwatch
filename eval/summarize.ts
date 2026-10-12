// Turns the raw outputs of eval/run_eval.sh into eval/results/*.csv and
// eval/results/summary.md. No dependencies; run with Node 22.18+:
//   node eval/summarize.ts <work dir> <results dir> <repo root>

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

type Finding = {
  rule_id: string;
  severity: string;
  file: string | null;
  explanation: string;
};
type Pkg = {
  name: string;
  version: string;
  risk_score: number;
  risk_level: string;
  findings: Finding[];
  warnings: string[];
};
type Report = {
  packages: Pkg[];
  skipped: { name: string; reason: string; error: boolean }[];
  summary: {
    packages_total: number;
    packages_scanned: number;
    duration_ms: number;
  };
};

const [work, results, root] = process.argv.slice(2) as [string, string, string];
const RULES = Array.from(
  { length: 12 },
  (_, i) => `LW${String(i + 1).padStart(3, "0")}`,
);
const FLAGGED = new Set(["medium", "high", "critical"]);
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

const readJson = <T>(path: string): T =>
  JSON.parse(readFileSync(path, "utf8")) as T;
const pct = (n: number, d: number) =>
  d === 0 ? "n/a" : `${((100 * n) / d).toFixed(1)}%`;
const csvCell = (v: unknown) => {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
};
const writeCsv = (name: string, header: string[], rows: unknown[][]) =>
  writeFileSync(
    join(results, name),
    [header, ...rows].map((r) => r.map(csvCell).join(",")).join("\n") + "\n",
  );

function percentile(values: number[], p: number): number {
  if (values.length === 0) return NaN;
  const sorted = [...values].sort((a, b) => a - b);
  // Nearest-rank method.
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.max(0, rank - 1)] as number;
}

const rulesOf = (p: Pkg) =>
  [...new Set(p.findings.map((f) => f.rule_id))].sort();

/** Short reason for a flagged package: its most severe finding(s). */
function reason(p: Pkg): string {
  const worst = [...p.findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  const seen = new Set<string>();
  const parts: string[] = [];
  for (const f of worst) {
    if (seen.has(f.rule_id) || parts.length >= 3) continue;
    seen.add(f.rule_id);
    parts.push(`${f.rule_id} (${f.severity}${f.file ? `, ${f.file}` : ""})`);
  }
  return parts.join("; ");
}

// ---------------------------------------------------------------- synthetic
const expected = readJson<{
  malicious: Record<string, string[]>;
  benign: Record<string, string[]>;
}>(join(root, "fixtures/packages/expected.json"));
const synth = {
  malicious: readJson<Report>(join(work, "synthetic/malicious.json")),
  benign: readJson<Report>(join(work, "synthetic/benign.json")),
};

const ruleRows: unknown[][] = [];
const ruleStats: Record<string, { tp: number; fn: number; fp: number }> = {};
for (const rule of RULES) {
  let tp = 0;
  let fn = 0;
  let fp = 0;
  for (const p of synth.malicious.packages) {
    if (!(expected.malicious[p.name] ?? []).includes(rule)) continue;
    if (rulesOf(p).includes(rule)) tp++;
    else fn++;
  }
  for (const p of synth.benign.packages) {
    if (
      rulesOf(p).includes(rule) &&
      !(expected.benign[p.name] ?? []).includes(rule)
    )
      fp++;
  }
  ruleStats[rule] = { tp, fn, fp };
  ruleRows.push([rule, tp, fn, fp]);
}
writeCsv(
  "synthetic_rules.csv",
  ["rule", "true_positives", "false_negatives", "false_positives_on_benign"],
  ruleRows,
);

const pkgRows: unknown[][] = [];
for (const label of ["malicious", "benign"] as const) {
  for (const p of synth[label].packages) {
    const want = expected[label][p.name] ?? [];
    pkgRows.push([
      p.name,
      label,
      want.join(" "),
      rulesOf(p).join(" "),
      p.risk_score,
      p.risk_level,
      FLAGGED.has(p.risk_level) ? "yes" : "no",
    ]);
  }
}
writeCsv(
  "synthetic_packages.csv",
  [
    "package",
    "label",
    "expected_rules",
    "fired_rules",
    "risk_score",
    "risk_level",
    "flagged_medium_or_above",
  ],
  pkgRows,
);
const malFlagged = synth.malicious.packages.filter((p) =>
  FLAGGED.has(p.risk_level),
);
const malAny = synth.malicious.packages.filter((p) => p.findings.length > 0);
const benFlagged = synth.benign.packages.filter((p) =>
  FLAGGED.has(p.risk_level),
);

// ------------------------------------------------------------------ top 500
type TopRow = {
  index: string;
  spec: string;
  status: string;
  report?: Report;
  cold?: number;
  warm?: number;
  coldInternal?: number;
};
function readTimes(
  phase: string,
): Map<string, { spec: string; code: number; ms: number }> {
  const map = new Map();
  const path = join(work, `top500-${phase}/times.csv`);
  if (!existsSync(path)) return map;
  for (const line of readFileSync(path, "utf8").trim().split("\n").slice(1)) {
    const [index, spec, code, msText] = line.split(",");
    map.set(index, { spec, code: Number(code), ms: Number(msText) });
  }
  return map;
}
const coldTimes = readTimes("cold");
const warmTimes = readTimes("warm");
const top: TopRow[] = [];
for (const [index, t] of coldTimes) {
  const row: TopRow = {
    index,
    spec: t.spec,
    status: "ok",
    cold: t.ms,
    warm: warmTimes.get(index)?.ms,
  };
  try {
    row.report = readJson<Report>(join(work, `top500-cold/${index}.json`));
    row.coldInternal = row.report.summary.duration_ms;
    if (row.report.summary.packages_scanned === 0) {
      row.status = `not scanned: ${row.report.skipped[0]?.reason ?? "unknown"}`;
    }
  } catch {
    const err = readFileSync(
      join(work, `top500-cold/${index}.err`),
      "utf8",
    ).trim();
    row.status = `error: ${err.split("\n").pop()}`;
  }
  top.push(row);
}
const scanned = top.filter((r) => r.status === "ok" && r.report);
const pkgOf = (r: TopRow) => r.report?.packages[0] as Pkg;
const topFlagged = scanned.filter((r) => FLAGGED.has(pkgOf(r).risk_level));
const topAnyFinding = scanned.filter((r) => pkgOf(r).findings.length > 0);
const levelCounts: Record<string, number> = {};
for (const r of scanned)
  levelCounts[pkgOf(r).risk_level] =
    (levelCounts[pkgOf(r).risk_level] ?? 0) + 1;
const ruleFires: Record<string, number> = {};
const ruleFiresAboveInfo: Record<string, number> = {};
const ruleFiresFlagged: Record<string, number> = {};
for (const r of scanned) {
  const p = pkgOf(r);
  for (const rule of rulesOf(p)) {
    ruleFires[rule] = (ruleFires[rule] ?? 0) + 1;
    if (p.findings.some((f) => f.rule_id === rule && f.severity !== "info")) {
      ruleFiresAboveInfo[rule] = (ruleFiresAboveInfo[rule] ?? 0) + 1;
    }
    if (FLAGGED.has(p.risk_level))
      ruleFiresFlagged[rule] = (ruleFiresFlagged[rule] ?? 0) + 1;
  }
}
writeCsv(
  "top500.csv",
  [
    "rank",
    "package",
    "status",
    "risk_score",
    "risk_level",
    "rules",
    "cold_wall_ms",
    "warm_wall_ms",
    "cold_internal_ms",
  ],
  top.map((r) => {
    const p = r.report?.packages[0];
    return [
      Number(r.index),
      r.spec,
      r.status,
      p?.risk_score ?? "",
      p?.risk_level ?? "",
      p ? rulesOf(p).join(" ") : "",
      r.cold,
      r.warm ?? "",
      r.coldInternal ?? "",
    ];
  }),
);
writeCsv(
  "top500_flagged.csv",
  ["rank", "package", "risk_score", "risk_level", "reason"],
  topFlagged.map((r) => [
    Number(r.index),
    r.spec,
    pkgOf(r).risk_score,
    pkgOf(r).risk_level,
    reason(pkgOf(r)),
  ]),
);

const coldMs = top
  .filter((r) => r.status === "ok")
  .map((r) => r.cold as number);
const warmMs = top
  .filter((r) => r.status === "ok" && r.warm !== undefined)
  .map((r) => r.warm as number);

// -------------------------------------------------------------------- bench
const benchTimes = new Map<string, number>();
const benchTimesPath = join(work, "bench/times.csv");
if (existsSync(benchTimesPath)) {
  for (const line of readFileSync(benchTimesPath, "utf8").trim().split("\n")) {
    const [phase, , msText] = line.split(",");
    benchTimes.set(phase as string, Number(msText));
  }
}
const bench = existsSync(join(work, "bench/cold.json"))
  ? readJson<Report>(join(work, "bench/cold.json"))
  : undefined;
const benchFlagged =
  bench?.packages.filter((p) => FLAGGED.has(p.risk_level)) ?? [];

// ------------------------------------------------------------------ summary
const machine = readFileSync(join(work, "machine.txt"), "utf8").trim();
const evalNow = readFileSync(join(work, "eval_now.txt"), "utf8").trim();
const md: string[] = [];
md.push("# lockwatch evaluation results", "");
md.push(
  `Generated by \`eval/run_eval.sh\` (run started ${evalNow}). Do not edit by hand.`,
  "",
);
md.push(
  '"Flagged" means a package\'s risk level is medium or above (score 30 or more).',
  "",
);
md.push("## 1. Synthetic fixtures", "");
md.push(
  "The fixtures and the rules were written by the same people, so these numbers are a sanity check, not a benchmark.",
  "",
);
md.push(
  `- Malicious fixtures: ${synth.malicious.packages.length}; flagged: **${malFlagged.length} (${pct(malFlagged.length, synth.malicious.packages.length)})**; with at least one finding: ${malAny.length} (${pct(malAny.length, synth.malicious.packages.length)})`,
);
md.push(
  `- Benign fixtures: ${synth.benign.packages.length}; flagged: **${benFlagged.length}** (${benFlagged.map((p) => p.name).join(", ") || "none"})`,
);
md.push("", "Per rule (TP/FN on the malicious set, FP on the benign set):", "");
md.push("| Rule | TP | FN | FP (benign) |", "|---|---:|---:|---:|");
for (const rule of RULES) {
  const s = ruleStats[rule] as { tp: number; fn: number; fp: number };
  md.push(`| ${rule} | ${s.tp} | ${s.fn} | ${s.fp} |`);
}
const notFlagged = synth.malicious.packages.filter(
  (p) => !FLAGGED.has(p.risk_level),
);
md.push(
  "",
  `Malicious fixtures not flagged (level below medium): ${notFlagged.map((p) => `${p.name} (${p.risk_level}, ${rulesOf(p).join("+") || "no findings"})`).join(", ") || "none"}`,
  "",
);

md.push("## 2. Top 500 npm packages (false positives)", "");
md.push(
  `Packages in list: ${top.length}; scanned: ${scanned.length}; not scanned: ${top.length - scanned.length}.`,
  "",
);
md.push(
  `- Flagged (medium or above): **${topFlagged.length} of ${scanned.length} (${pct(topFlagged.length, scanned.length)})**`,
);
md.push(
  `- With at least one finding of any severity: ${topAnyFinding.length} (${pct(topAnyFinding.length, scanned.length)})`,
);
md.push(
  `- Risk levels: ${["none", "low", "medium", "high", "critical"].map((l) => `${l} ${levelCounts[l] ?? 0}`).join(", ")}`,
  "",
);
md.push(
  "Rule firing counts: packages where the rule fired at least once (any severity), where it fired above `info`, and how many of those packages were flagged:",
  "",
);
md.push(
  "| Rule | Packages | Above info | Flagged packages |",
  "|---|---:|---:|---:|",
);
for (const rule of RULES) {
  md.push(
    `| ${rule} | ${ruleFires[rule] ?? 0} | ${ruleFiresAboveInfo[rule] ?? 0} | ${ruleFiresFlagged[rule] ?? 0} |`,
  );
}
md.push("", "Flagged packages and why (all are assumed benign):", "");
if (topFlagged.length === 0) md.push("None.");
else {
  md.push(
    "| Rank | Package | Score | Level | Reason |",
    "|---:|---|---:|---|---|",
  );
  for (const r of topFlagged) {
    md.push(
      `| ${Number(r.index)} | ${r.spec} | ${pkgOf(r).risk_score} | ${pkgOf(r).risk_level} | ${reason(pkgOf(r))} |`,
    );
  }
}
const failed = top.filter((r) => r.status !== "ok");
if (failed.length) {
  md.push("", "Not scanned:", "");
  for (const r of failed) md.push(`- ${r.spec}: ${r.status}`);
}

md.push("", "## 3. Performance", "");
md.push(
  "Per package, `lockwatch scan-package` run as a separate process (wall-clock time, including process start, registry metadata and tarball download, extraction and analysis):",
  "",
);
md.push("| Cache | Packages | Median | p95 |", "|---|---:|---:|---:|");
md.push(
  `| cold (nothing cached) | ${coldMs.length} | ${percentile(coldMs, 50)} ms | ${percentile(coldMs, 95)} ms |`,
);
md.push(
  `| warm (tarball and metadata cached) | ${warmMs.length} | ${percentile(warmMs, 50)} ms | ${percentile(warmMs, 95)} ms |`,
);
if (bench) {
  const entries = Object.keys(
    readJson<{ packages: Record<string, unknown> }>(
      join(root, "eval/bench/package-lock.json"),
    ).packages,
  ).filter((k) => k !== "").length;
  md.push(
    "",
    `Whole lockfile (\`eval/bench/package-lock.json\`: ${entries} entries, ${bench.summary.packages_total} unique packages after deduplication, default concurrency 16):`,
    "",
  );
  md.push(
    `- cold cache: ${benchTimes.get("cold")} ms; warm cache: ${benchTimes.get("warm")} ms`,
  );
  md.push(
    `- packages scanned: ${bench.summary.packages_scanned}; flagged: ${benchFlagged.length}${benchFlagged.length ? ` (${benchFlagged.map((p) => `${p.name}@${p.version}: ${reason(p)}`).join("; ")})` : ""}`,
  );
}
md.push("", "Machine:", "", "```", machine, "```", "");
md.push(
  "## 4. Real malicious samples",
  "",
  "Run separately with `eval/malware/run_malware_eval.sh`; results in `eval/results/malware/summary.md`.",
  "",
);
writeFileSync(join(results, "summary.md"), md.join("\n"));
console.log(md.slice(0, 12).join("\n"));

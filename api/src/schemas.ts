// zod schemas: what we accept from clients (a package-lock.json) and what we
// accept from the Rust binary (its JSON report, which mirrors
// docs/report.schema.json). Validating the binary's output too means a bug
// or version mismatch shows up as a clear error instead of bad data.

import { z } from "zod";

/** The parts of a package-lock.json we require. Extra fields are kept. */
export const LockfileSchema = z.looseObject({
  lockfileVersion: z.union([z.literal(2), z.literal(3)], {
    error: "lockfileVersion must be 2 or 3 (lockfiles written by npm 7 or later)",
  }),
  packages: z.record(z.string(), z.looseObject({}), {
    error: 'expected a "packages" object mapping install paths to entries',
  }),
});
export type Lockfile = z.infer<typeof LockfileSchema>;

/** Number of dependencies in a lockfile (the "" key is the project itself). */
export function countPackages(lockfile: Lockfile): number {
  return Object.keys(lockfile.packages).filter((key) => key !== "").length;
}

/** "packages.node_modules/x: expected object" style messages. */
export function formatIssues(error: z.ZodError): string {
  return error.issues
    .map((issue) => {
      const path = issue.path.map(String).join(".");
      return path ? `${path}: ${issue.message}` : issue.message;
    })
    .join("; ");
}

export const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
const count = z.number().int().nonnegative();

export const FindingSchema = z.object({
  rule_id: z.string().regex(/^LW\d{3}$/),
  severity: SeveritySchema,
  package: z.string(),
  version: z.string(),
  file: z.string().nullable(),
  line: z.number().int().positive().nullable(),
  evidence: z.string().max(200),
  explanation: z.string(),
});

export const PackageReportSchema = z.object({
  name: z.string(),
  version: z.string(),
  risk_score: z.number().int().min(0).max(100),
  risk_level: z.enum(["none", "low", "medium", "high", "critical"]),
  findings: z.array(FindingSchema),
  warnings: z.array(z.string()),
});

export const ReportSchema = z.object({
  tool: z.literal("lockwatch"),
  version: z.string(),
  scanned_at: z.string(),
  lockfile: z.string(),
  summary: z.object({
    packages_total: count,
    packages_scanned: count,
    packages_skipped: count,
    findings: z.object({
      critical: count,
      high: count,
      medium: count,
      low: count,
      info: count,
    }),
    duration_ms: count,
  }),
  packages: z.array(PackageReportSchema),
  skipped: z.array(
    z.object({
      name: z.string(),
      version: z.string().nullable(),
      reason: z.string(),
      error: z.boolean(),
    }),
  ),
});
export type Report = z.infer<typeof ReportSchema>;

export const RuleListSchema = z.array(
  z.object({
    id: z.string(),
    name: z.string(),
    severity: SeveritySchema,
    description: z.string(),
  }),
);
export type RuleList = z.infer<typeof RuleListSchema>;

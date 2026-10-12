import { describe, expect, it } from "vitest";

import { countPackages, formatIssues, LockfileSchema, ReportSchema } from "../src/schemas.ts";
import { makeLockfile } from "./helpers.ts";

describe("lockfile validation", () => {
  it("accepts lockfile versions 2 and 3 and counts packages", () => {
    for (const version of [2, 3]) {
      const parsed = LockfileSchema.safeParse(makeLockfile(4, version));
      expect(parsed.success).toBe(true);
      if (parsed.success) expect(countPackages(parsed.data)).toBe(4);
    }
  });

  it("rejects version 1 with a clear message", () => {
    const parsed = LockfileSchema.safeParse({ lockfileVersion: 1, dependencies: {} });
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      const message = formatIssues(parsed.error);
      expect(message).toContain("lockfileVersion must be 2 or 3");
      expect(message).toContain("packages");
    }
  });

  it("rejects non-object package entries and non-object bodies", () => {
    const bad = { lockfileVersion: 3, packages: { "node_modules/a": "1.0.0" } };
    const parsed = LockfileSchema.safeParse(bad);
    expect(parsed.success).toBe(false);
    if (!parsed.success) expect(formatIssues(parsed.error)).toContain("packages.node_modules/a");
    expect(LockfileSchema.safeParse([1, 2]).success).toBe(false);
    expect(LockfileSchema.safeParse("text").success).toBe(false);
  });
});

describe("report validation", () => {
  it("rejects reports with out-of-range values", () => {
    const parsed = ReportSchema.safeParse({ tool: "lockwatch" });
    expect(parsed.success).toBe(false);
  });
});

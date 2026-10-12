// Integration tests against the real Rust binary, scanning the committed
// fixtures offline with the pre-filled fixture cache (no network).
//
// The binary comes from LOCKWATCH_BIN or ../target/{release,debug}/lockwatch.
// Run `cargo build` first; the tests are skipped if no binary is found.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";

import { buildApp } from "../src/app.ts";
import { multipartBody, repoRoot, sleep, testConfig } from "./helpers.ts";

const candidates = [
  process.env.LOCKWATCH_BIN,
  join(repoRoot, "target/release/lockwatch"),
  join(repoRoot, "target/debug/lockwatch"),
].filter((p): p is string => Boolean(p));
const bin = candidates.find((p) => existsSync(p));
// CI sets REQUIRE_LOCKWATCH_BIN=1 so a missing binary fails instead of skipping.
if (!bin && process.env.REQUIRE_LOCKWATCH_BIN === "1") {
  throw new Error(`lockwatch binary not found (looked in: ${candidates.join(", ")})`);
}
const fixture = (name: string) => readFileSync(join(repoRoot, "fixtures/lockfiles", name), "utf8");

describe.skipIf(!bin)("API + real lockwatch binary (offline fixtures)", () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp({
      config: testConfig({
        lockwatchBin: bin as string,
        cacheDir: join(repoRoot, "fixtures/cache"),
        offline: true,
      }),
      logger: false,
    });
  });
  afterAll(async () => {
    await app.close();
  });

  it("reports the real binary in /health", async () => {
    const res = await app.inject({ method: "GET", url: "/health" });
    expect(res.json().lockwatch.found).toBe(true);
  });

  it("scans a small lockfile synchronously", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/scan",
      payload: fixture("small.json"),
      headers: { "content-type": "application/json" },
    });
    expect(res.statusCode).toBe(200);
    const report = res.json();
    expect(report.summary.packages_scanned).toBe(3);
    const netIp = report.packages.find((p: { name: string }) => p.name === "lwfx-net-ip");
    expect(netIp.risk_level).toBe("medium");
  });

  it("finds every rule in mixed.json uploaded as multipart", async () => {
    const { body, contentType } = multipartBody("lockfile", "mixed.json", fixture("mixed.json"));
    const res = await app.inject({
      method: "POST",
      url: "/scan",
      payload: body,
      headers: { "content-type": contentType },
    });
    expect(res.statusCode).toBe(200);
    const rules = new Set<string>();
    for (const p of res.json().packages) for (const f of p.findings) rules.add(f.rule_id);
    expect([...rules].sort()).toEqual(
      Array.from({ length: 12 }, (_, i) => `LW${String(i + 1).padStart(3, "0")}`),
    );
  });

  it("scans a large lockfile as a background job", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/scan",
      payload: fixture("large.json"),
      headers: { "content-type": "application/json" },
    });
    expect(res.statusCode).toBe(202);
    const { id } = res.json();
    let job;
    for (let i = 0; i < 200; i++) {
      job = (await app.inject({ method: "GET", url: `/scan/${id}` })).json();
      if (job.status === "done" || job.status === "failed") break;
      await sleep(100);
    }
    expect(job.status).toBe("done");
    expect(job.report.summary.packages_scanned).toBe(57);
  });
});

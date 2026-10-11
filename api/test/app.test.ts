// HTTP tests with Fastify's inject(): requests go straight to the router,
// no port is opened. The Rust binary is replaced by fake scripts.

import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";

import { buildApp } from "../src/app.ts";
import type { Config } from "../src/config.ts";
import { fakeBin, makeLockfile, multipartBody, sleep, testConfig } from "./helpers.ts";

let app: FastifyInstance | undefined;

async function start(overrides: Partial<Config> = {}) {
  app = await buildApp({ config: testConfig(overrides), logger: false });
  return app;
}

afterEach(async () => {
  await app?.close();
  app = undefined;
  delete process.env.FAKE_DELAY_MS;
});

async function poll(a: FastifyInstance, id: string) {
  for (let i = 0; i < 100; i++) {
    const res = await a.inject({ method: "GET", url: `/scan/${id}` });
    const body = res.json();
    if (body.status === "done" || body.status === "failed") return body;
    await sleep(50);
  }
  throw new Error("job did not finish");
}

describe("GET /health and /rules", () => {
  it("reports the binary version", async () => {
    const a = await start();
    const res = await a.inject({ method: "GET", url: "/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      status: "ok",
      lockwatch: { found: true, version: "0.1.0" },
    });
  });

  it("stays live when the binary is missing", async () => {
    const a = await start({ lockwatchBin: "/nonexistent/lockwatch" });
    const res = await a.inject({ method: "GET", url: "/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json().lockwatch).toEqual({ found: false, version: null });
    expect((await a.inject({ method: "GET", url: "/rules" })).statusCode).toBe(503);
  });

  it("lists the rules", async () => {
    const a = await start();
    const res = await a.inject({ method: "GET", url: "/rules" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toHaveLength(12);
  });
});

describe("POST /scan", () => {
  it("scans a small JSON lockfile synchronously and stores the result", async () => {
    const a = await start();
    const res = await a.inject({ method: "POST", url: "/scan", payload: makeLockfile(3) });
    expect(res.statusCode).toBe(200);
    expect(res.json().summary.packages_total).toBe(3);
    const id = res.headers["x-scan-id"] as string;
    const job = (await a.inject({ method: "GET", url: `/scan/${id}` })).json();
    expect(job).toMatchObject({ id, status: "done", package_count: 3 });
    expect(job.report.summary.packages_total).toBe(3);
  });

  it("accepts a multipart upload", async () => {
    const a = await start();
    const { body, contentType } = multipartBody(
      "lockfile",
      "package-lock.json",
      JSON.stringify(makeLockfile(2)),
    );
    const res = await a.inject({
      method: "POST",
      url: "/scan",
      payload: body,
      headers: { "content-type": contentType },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ lockfile: "package-lock.json" });
  });

  it("uses job mode for more than 200 packages", async () => {
    process.env.FAKE_DELAY_MS = "200";
    const a = await start();
    const res = await a.inject({ method: "POST", url: "/scan", payload: makeLockfile(201) });
    expect(res.statusCode).toBe(202);
    const { id, status } = res.json();
    expect(status).toBe("queued");
    const early = (await a.inject({ method: "GET", url: `/scan/${id}` })).json();
    expect(["queued", "running"]).toContain(early.status);
    const done = await poll(a, id);
    expect(done.status).toBe("done");
    expect(done.report.summary.packages_total).toBe(201);
  });

  it("returns 400 with a clear message for malformed input", async () => {
    const a = await start();
    const cases: Array<[string, string, string]> = [
      ["{not json", "application/json", "not valid JSON"],
      [
        JSON.stringify({ lockfileVersion: 1 }),
        "application/json",
        "lockfileVersion must be 2 or 3",
      ],
      [JSON.stringify({ lockfileVersion: 3 }), "application/json", "packages"],
      [JSON.stringify([1, 2, 3]), "application/json", "invalid lockfile"],
    ];
    for (const [payload, type, message] of cases) {
      const res = await a.inject({
        method: "POST",
        url: "/scan",
        payload,
        headers: { "content-type": type },
      });
      expect(res.statusCode, payload).toBe(400);
      expect(res.json().error).toContain(message);
    }
    const { body, contentType } = multipartBody("lockfile", "x.json", "{broken");
    const res = await a.inject({
      method: "POST",
      url: "/scan",
      payload: body,
      headers: { "content-type": contentType },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("uploaded file is not valid JSON");
  });

  it("rejects uploads over the size limit with 413", async () => {
    const a = await start({ maxUploadBytes: 1000 });
    const res = await a.inject({ method: "POST", url: "/scan", payload: makeLockfile(50) });
    expect(res.statusCode).toBe(413);
    const { body, contentType } = multipartBody("f", "big.json", JSON.stringify(makeLockfile(50)));
    const multi = await a.inject({
      method: "POST",
      url: "/scan",
      payload: body,
      headers: { "content-type": contentType },
    });
    expect(multi.statusCode).toBe(413);
  });

  it("kills a scan that takes too long and returns 504", async () => {
    const a = await start({ lockwatchBin: fakeBin("sleep"), scanTimeoutMs: 300 });
    const res = await a.inject({ method: "POST", url: "/scan", payload: makeLockfile(1) });
    expect(res.statusCode).toBe(504);
    const { id, error } = res.json();
    expect(error).toContain("timed out");
    const job = (await a.inject({ method: "GET", url: `/scan/${id}` })).json();
    expect(job).toMatchObject({ status: "failed" });
  });

  it("returns 502 when the binary prints malformed output", async () => {
    const a = await start({ lockwatchBin: fakeBin("garbage") });
    const res = await a.inject({ method: "POST", url: "/scan", payload: makeLockfile(1) });
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toContain("did not return a JSON report");
  });

  it("marks failed background jobs", async () => {
    const a = await start({ lockwatchBin: fakeBin("bad-report"), syncMaxPackages: 1 });
    const res = await a.inject({ method: "POST", url: "/scan", payload: makeLockfile(2) });
    expect(res.statusCode).toBe(202);
    const job = await poll(a, res.json().id);
    expect(job.status).toBe("failed");
    expect(job.error).toContain("does not match the report schema");
  });
});

describe("GET /scan/:id", () => {
  it("validates the id and returns 404 for unknown jobs", async () => {
    const a = await start();
    expect((await a.inject({ method: "GET", url: "/scan/not-a-uuid" })).statusCode).toBe(400);
    const res = await a.inject({
      method: "GET",
      url: "/scan/00000000-0000-4000-8000-000000000000",
    });
    expect(res.statusCode).toBe(404);
  });
});

describe("rate limiting", () => {
  it("returns 429 after the configured number of requests", async () => {
    const a = await start({ rateLimitMax: 3 });
    const codes = [];
    for (let i = 0; i < 4; i++) {
      codes.push((await a.inject({ method: "GET", url: "/health" })).statusCode);
    }
    expect(codes).toEqual([200, 200, 200, 429]);
  });
});

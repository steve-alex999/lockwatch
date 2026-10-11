import { describe, expect, it } from "vitest";

import { JobStore } from "../src/store.ts";
import type { Report } from "../src/schemas.ts";

const DAY = 24 * 60 * 60 * 1000;
const report = { tool: "lockwatch" } as unknown as Report;

describe("JobStore", () => {
  it("tracks a job from queued to done", () => {
    const store = new JobStore(":memory:", 7 * DAY);
    const job = store.create(5);
    expect(store.get(job.id)?.status).toBe("queued");
    store.markRunning(job.id);
    expect(store.get(job.id)?.status).toBe("running");
    store.markDone(job.id, report);
    const done = store.get(job.id);
    expect(done?.status).toBe("done");
    expect(done?.report).toEqual(report);
    expect(done?.packageCount).toBe(5);
    store.close();
  });

  it("records failures", () => {
    const store = new JobStore(":memory:", 7 * DAY);
    const job = store.create(1);
    store.markFailed(job.id, "scan timed out");
    expect(store.get(job.id)).toMatchObject({ status: "failed", error: "scan timed out" });
    store.close();
  });

  it("expires reports after the time-to-live", () => {
    const store = new JobStore(":memory:", 7 * DAY);
    const old = store.create(1, Date.now() - 8 * DAY);
    const fresh = store.create(1);
    expect(store.get(old.id)).toBeUndefined();
    expect(store.deleteExpired()).toBe(1);
    expect(store.get(fresh.id)).toBeDefined();
    store.close();
  });

  it("fails jobs interrupted by a restart", () => {
    const store = new JobStore(":memory:", 7 * DAY);
    const a = store.create(1);
    const b = store.create(1);
    store.markDone(b.id, report);
    expect(store.failInterrupted()).toBe(1);
    expect(store.get(a.id)?.error).toContain("server restarted");
    expect(store.get(b.id)?.status).toBe("done");
    store.close();
  });
});

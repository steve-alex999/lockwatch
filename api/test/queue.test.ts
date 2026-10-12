import { describe, expect, it } from "vitest";

import { ScanQueue } from "../src/queue.ts";
import { sleep } from "./helpers.ts";

describe("ScanQueue", () => {
  it("never runs more than `concurrency` tasks at once", async () => {
    const queue = new ScanQueue(2);
    let running = 0;
    let maxRunning = 0;
    const task = async () => {
      running++;
      maxRunning = Math.max(maxRunning, running);
      await sleep(20);
      running--;
    };
    await Promise.all(Array.from({ length: 10 }, () => queue.run(task)));
    expect(maxRunning).toBe(2);
    expect(queue.active).toBe(0);
    expect(queue.waiting).toBe(0);
  });

  it("frees the slot when a task fails", async () => {
    const queue = new ScanQueue(1);
    await expect(queue.run(async () => Promise.reject(new Error("boom")))).rejects.toThrow("boom");
    await expect(queue.run(async () => "next")).resolves.toBe("next");
    expect(queue.active).toBe(0);
  });

  it("rejects invalid concurrency", () => {
    expect(() => new ScanQueue(0)).toThrow();
  });
});

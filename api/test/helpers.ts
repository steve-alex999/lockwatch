// Shared test helpers.

import { fileURLToPath } from "node:url";

import type { Config } from "../src/config.ts";

/** Absolute path of a fake lockwatch binary in test/fake-bin. */
export function fakeBin(name: "ok" | "sleep" | "garbage" | "bad-report" | "fatal"): string {
  return fileURLToPath(new URL(`./fake-bin/lockwatch-${name}.mjs`, import.meta.url));
}

/** Repository root (the parent of api/). */
export const repoRoot = fileURLToPath(new URL("../../", import.meta.url));

export function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    port: 0,
    host: "127.0.0.1",
    lockwatchBin: fakeBin("ok"),
    scanTimeoutMs: 10_000,
    maxConcurrentScans: 2,
    dbPath: ":memory:",
    offline: false,
    syncMaxPackages: 200,
    maxUploadBytes: 5 * 1024 * 1024,
    rateLimitMax: 1000,
    rateLimitWindowMs: 60_000,
    reportTtlMs: 7 * 24 * 60 * 60 * 1000,
    logLevel: "silent",
    ...overrides,
  };
}

/** A lockfile with `count` dependencies. */
export function makeLockfile(count: number, lockfileVersion = 3) {
  const packages: Record<string, object> = { "": { name: "demo", version: "1.0.0" } };
  for (let i = 0; i < count; i++) {
    packages[`node_modules/pkg-${i}`] = {
      version: "1.0.0",
      resolved: `https://registry.npmjs.org/pkg-${i}/-/pkg-${i}-1.0.0.tgz`,
    };
  }
  return { name: "demo", version: "1.0.0", lockfileVersion, requires: true, packages };
}

/** Build a multipart/form-data body by hand (no extra dependency). */
export function multipartBody(field: string, filename: string, content: string) {
  const boundary = "----lockwatch-test-boundary";
  const body =
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="${field}"; filename="${filename}"\r\n` +
    `Content-Type: application/json\r\n\r\n` +
    `${content}\r\n` +
    `--${boundary}--\r\n`;
  return { body, contentType: `multipart/form-data; boundary=${boundary}` };
}

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

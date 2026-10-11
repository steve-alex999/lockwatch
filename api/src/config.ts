// Configuration from environment variables, validated with zod.
//
// Every variable has a documented default (see README "API configuration").

import { z } from "zod";

const positiveInt = (fallback: number) => z.coerce.number().int().positive().default(fallback);
const flag = z
  .enum(["1", "0", "true", "false", ""])
  .default("")
  .transform((v) => v === "1" || v === "true");

const EnvSchema = z.object({
  PORT: positiveInt(8080),
  HOST: z.string().default("0.0.0.0"),
  // Path of the Rust binary; by default it is looked up on PATH.
  LOCKWATCH_BIN: z.string().min(1).default("lockwatch"),
  SCAN_TIMEOUT_MS: positiveInt(120_000),
  MAX_CONCURRENT_SCANS: positiveInt(2),
  DB_PATH: z.string().min(1).default("./lockwatch.db"),
  // Passed to `lockwatch --cache-dir` when set.
  LOCKWATCH_CACHE_DIR: z.string().optional(),
  // Passed as `--offline` when true (tests and air-gapped setups).
  LOCKWATCH_OFFLINE: flag,
  LOCKWATCH_REGISTRY: z.string().url().optional(),
  // Lockfiles with this many packages or fewer are scanned synchronously.
  SYNC_MAX_PACKAGES: positiveInt(200),
  MAX_UPLOAD_BYTES: positiveInt(5 * 1024 * 1024),
  RATE_LIMIT_MAX: positiveInt(30),
  RATE_LIMIT_WINDOW_MS: positiveInt(60_000),
  REPORT_TTL_DAYS: positiveInt(7),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
});

export interface Config {
  port: number;
  host: string;
  lockwatchBin: string;
  scanTimeoutMs: number;
  maxConcurrentScans: number;
  dbPath: string;
  cacheDir?: string;
  offline: boolean;
  registry?: string;
  syncMaxPackages: number;
  maxUploadBytes: number;
  rateLimitMax: number;
  rateLimitWindowMs: number;
  reportTtlMs: number;
  logLevel: string;
}

/** Read and validate the configuration. Throws with a readable message. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
    throw new Error(`invalid configuration: ${problems.join("; ")}`);
  }
  const e = parsed.data;
  return {
    port: e.PORT,
    host: e.HOST,
    lockwatchBin: e.LOCKWATCH_BIN,
    scanTimeoutMs: e.SCAN_TIMEOUT_MS,
    maxConcurrentScans: e.MAX_CONCURRENT_SCANS,
    dbPath: e.DB_PATH,
    cacheDir: e.LOCKWATCH_CACHE_DIR || undefined,
    offline: e.LOCKWATCH_OFFLINE,
    registry: e.LOCKWATCH_REGISTRY,
    syncMaxPackages: e.SYNC_MAX_PACKAGES,
    maxUploadBytes: e.MAX_UPLOAD_BYTES,
    rateLimitMax: e.RATE_LIMIT_MAX,
    rateLimitWindowMs: e.RATE_LIMIT_WINDOW_MS,
    reportTtlMs: e.REPORT_TTL_DAYS * 24 * 60 * 60 * 1000,
    logLevel: e.LOG_LEVEL,
  };
}

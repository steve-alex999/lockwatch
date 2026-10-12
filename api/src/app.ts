// The Fastify application: routes, plugins and error handling.
//
// `buildApp` returns the app without starting a server, so tests can call
// routes with `app.inject(...)` (no network port involved).

import { basename } from "node:path";

import multipart from "@fastify/multipart";
import rateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyError, type FastifyInstance, type FastifyReply } from "fastify";
import { z } from "zod";

import type { Config } from "./config.ts";
import { ScanQueue } from "./queue.ts";
import { ScannerError, ScanTimeoutError } from "./runner.ts";
import { Scanner } from "./scanner.ts";
import { countPackages, formatIssues, LockfileSchema } from "./schemas.ts";
import { JobStore, type Job } from "./store.ts";

export interface AppOptions {
  config: Config;
  /** Override for tests; by default one is created from config.dbPath. */
  store?: JobStore;
  /** Fastify logger setting; tests pass false. */
  logger?: boolean;
}

/** Response body for errors: always `{ "error": "..." }`. */
function sendError(reply: FastifyReply, status: number, message: string, extra = {}) {
  return reply.code(status).send({ error: message, ...extra });
}

function jobView(job: Job) {
  return {
    id: job.id,
    status: job.status,
    created_at: new Date(job.createdAt).toISOString(),
    updated_at: new Date(job.updatedAt).toISOString(),
    package_count: job.packageCount,
    ...(job.report ? { report: job.report } : {}),
    ...(job.error ? { error: job.error } : {}),
  };
}

export async function buildApp(options: AppOptions): Promise<FastifyInstance> {
  const { config } = options;
  const app = Fastify({
    // pino (Fastify's logger) writes JSON lines. Request bodies are never
    // logged, and auth headers are redacted in case a proxy adds them.
    logger:
      options.logger === false
        ? false
        : {
            level: config.logLevel,
            redact: ["req.headers.authorization", "req.headers.cookie"],
          },
    bodyLimit: config.maxUploadBytes,
  });

  const store = options.store ?? new JobStore(config.dbPath, config.reportTtlMs);
  const scanner = new Scanner(config);
  const queue = new ScanQueue(config.maxConcurrentScans);

  // Jobs from a previous process can no longer finish; expire old reports
  // now and then every hour.
  store.failInterrupted();
  store.deleteExpired();
  const cleanup = setInterval(() => store.deleteExpired(), 60 * 60 * 1000);
  cleanup.unref();
  app.addHook("onClose", async () => {
    clearInterval(cleanup);
    store.close();
  });

  await app.register(rateLimit, {
    max: config.rateLimitMax,
    timeWindow: config.rateLimitWindowMs,
  });
  await app.register(multipart, {
    limits: { fileSize: config.maxUploadBytes, files: 1, fields: 10 },
  });

  // Fastify's own errors (invalid JSON, body too large, rate limit, ...)
  // keep their status code but use our `{ error }` shape.
  app.setErrorHandler((err: FastifyError, request, reply) => {
    const status = err.statusCode && err.statusCode >= 400 ? err.statusCode : 500;
    if (status >= 500) request.log.error(err);
    const message = status >= 500 ? "internal error" : err.message;
    return sendError(reply, status, message);
  });

  /** Run one scan through the queue and record the outcome. */
  async function runScan(jobId: string, text: string, name: string) {
    return queue.run(async () => {
      store.markRunning(jobId);
      try {
        const report = await scanner.scanLockfile(text, name);
        store.markDone(jobId, report);
        return report;
      } catch (err) {
        store.markFailed(jobId, err instanceof Error ? err.message : String(err));
        throw err;
      }
    });
  }

  app.post("/scan", async (request, reply) => {
    let body: unknown;
    let name = "package-lock.json";
    if (request.isMultipart()) {
      const file = await request.file();
      if (!file)
        return sendError(reply, 400, 'multipart upload needs a file field (e.g. "lockfile")');
      const buffer = await file.toBuffer(); // throws 413 above the size limit
      if (file.filename) name = basename(file.filename);
      try {
        body = JSON.parse(buffer.toString("utf8"));
      } catch {
        return sendError(reply, 400, "uploaded file is not valid JSON");
      }
    } else {
      body = request.body;
    }

    const parsed = LockfileSchema.safeParse(body);
    if (!parsed.success) {
      return sendError(reply, 400, `invalid lockfile: ${formatIssues(parsed.error)}`);
    }
    const packageCount = countPackages(parsed.data);
    const text = JSON.stringify(parsed.data);
    const job = store.create(packageCount);

    if (packageCount > config.syncMaxPackages) {
      // Job mode: answer now, scan in the background, client polls.
      runScan(job.id, text, name).catch((err: unknown) => {
        request.log.warn({ jobId: job.id, err }, "background scan failed");
      });
      return reply.code(202).send({ id: job.id, status: "queued" });
    }

    try {
      const report = await runScan(job.id, text, name);
      return reply.header("x-scan-id", job.id).send(report);
    } catch (err) {
      if (err instanceof ScanTimeoutError) {
        return sendError(reply, 504, err.message, { id: job.id });
      }
      if (err instanceof ScannerError) {
        request.log.error({ jobId: job.id, err }, "scan failed");
        return sendError(reply, 502, `scan failed: ${err.message}`, { id: job.id });
      }
      throw err;
    }
  });

  const IdParams = z.object({ id: z.uuid() });
  app.get("/scan/:id", async (request, reply) => {
    const params = IdParams.safeParse(request.params);
    if (!params.success) return sendError(reply, 400, "scan id must be a UUID");
    const job = store.get(params.data.id);
    if (!job) return sendError(reply, 404, "scan not found (unknown id, or the report expired)");
    return jobView(job);
  });

  app.get("/rules", async (request, reply) => {
    try {
      return await scanner.rules();
    } catch (err) {
      request.log.error({ err }, "cannot list rules");
      return sendError(reply, 503, "lockwatch binary unavailable");
    }
  });

  app.get("/health", async () => {
    const version = await scanner.version();
    return {
      status: "ok",
      lockwatch: { found: version !== null, version },
      queue: { active: queue.active, waiting: queue.waiting },
    };
  });

  return app;
}

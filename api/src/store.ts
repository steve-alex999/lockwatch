// SQLite storage for scan jobs and their reports (better-sqlite3).
//
// better-sqlite3 is synchronous: each call runs the query and returns. That
// is fine here because the queries are tiny and SQLite is in-process.

import { randomUUID } from "node:crypto";

import Database from "better-sqlite3";

import type { Report } from "./schemas.ts";

export type JobStatus = "queued" | "running" | "done" | "failed";

export interface Job {
  id: string;
  status: JobStatus;
  createdAt: number;
  updatedAt: number;
  packageCount: number;
  report: Report | null;
  error: string | null;
}

interface JobRow {
  id: string;
  status: JobStatus;
  created_at: number;
  updated_at: number;
  package_count: number;
  report: string | null;
  error: string | null;
}

export class JobStore {
  readonly #db: Database.Database;
  readonly #ttlMs: number;

  /** `path` may be ":memory:" for tests. Reports expire after `ttlMs`. */
  constructor(path: string, ttlMs: number) {
    this.#db = new Database(path);
    this.#ttlMs = ttlMs;
    // Write-ahead logging: readers do not block the writer.
    this.#db.pragma("journal_mode = WAL");
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS jobs (
        id            TEXT PRIMARY KEY,
        status        TEXT NOT NULL,
        created_at    INTEGER NOT NULL,
        updated_at    INTEGER NOT NULL,
        package_count INTEGER NOT NULL,
        report        TEXT,
        error         TEXT
      );
      CREATE INDEX IF NOT EXISTS jobs_created_at ON jobs (created_at);
    `);
  }

  create(packageCount: number, now = Date.now()): Job {
    const job: Job = {
      id: randomUUID(),
      status: "queued",
      createdAt: now,
      updatedAt: now,
      packageCount,
      report: null,
      error: null,
    };
    // Named parameters (@id) are bound by better-sqlite3, never concatenated
    // into the SQL text, so there is no SQL injection.
    this.#db
      .prepare(
        `INSERT INTO jobs (id, status, created_at, updated_at, package_count)
         VALUES (@id, @status, @createdAt, @updatedAt, @packageCount)`,
      )
      .run(job);
    return job;
  }

  #update(id: string, fields: { status: JobStatus; report?: string; error?: string }): void {
    this.#db
      .prepare(
        `UPDATE jobs SET status = @status, updated_at = @now,
           report = COALESCE(@report, report), error = COALESCE(@error, error)
         WHERE id = @id`,
      )
      .run({ id, now: Date.now(), report: null, error: null, ...fields });
  }

  markRunning(id: string): void {
    this.#update(id, { status: "running" });
  }

  markDone(id: string, report: Report): void {
    this.#update(id, { status: "done", report: JSON.stringify(report) });
  }

  markFailed(id: string, error: string): void {
    this.#update(id, { status: "failed", error });
  }

  /** The job, or undefined if it does not exist or has expired. */
  get(id: string, now = Date.now()): Job | undefined {
    const row = this.#db.prepare(`SELECT * FROM jobs WHERE id = ?`).get(id) as JobRow | undefined;
    if (!row || row.created_at + this.#ttlMs < now) return undefined;
    return {
      id: row.id,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      packageCount: row.package_count,
      report: row.report ? (JSON.parse(row.report) as Report) : null,
      error: row.error,
    };
  }

  /** Delete jobs older than the time-to-live. Returns how many were removed. */
  deleteExpired(now = Date.now()): number {
    return this.#db.prepare(`DELETE FROM jobs WHERE created_at < ?`).run(now - this.#ttlMs).changes;
  }

  /**
   * After a restart, jobs that were queued or running will never finish.
   * Mark them failed so clients polling them get an answer.
   */
  failInterrupted(): number {
    return this.#db
      .prepare(
        `UPDATE jobs SET status = 'failed', error = 'server restarted before the scan finished',
           updated_at = ? WHERE status IN ('queued', 'running')`,
      )
      .run(Date.now()).changes;
  }

  close(): void {
    this.#db.close();
  }
}

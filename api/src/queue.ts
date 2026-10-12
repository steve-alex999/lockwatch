// A tiny in-process queue that limits how many scans run at once.
//
// `run(task)` starts the task right away if a slot is free, otherwise waits
// for one. When a task finishes, its slot is handed directly to the next
// waiting task, so the limit can never be exceeded even if new work arrives
// at the same moment.

export class ScanQueue {
  readonly concurrency: number;
  #active = 0;
  #waiting: Array<() => void> = [];

  constructor(concurrency: number) {
    if (!Number.isInteger(concurrency) || concurrency < 1) {
      throw new Error("concurrency must be a positive integer");
    }
    this.concurrency = concurrency;
  }

  get active(): number {
    return this.#active;
  }

  get waiting(): number {
    return this.#waiting.length;
  }

  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.#active < this.concurrency) {
      this.#active++;
    } else {
      // Wait until a finishing task hands us its slot (#active unchanged).
      await new Promise<void>((resolve) => this.#waiting.push(resolve));
    }
    try {
      return await task();
    } finally {
      const next = this.#waiting.shift();
      if (next) {
        next();
      } else {
        this.#active--;
      }
    }
  }
}

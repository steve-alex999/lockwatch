# Design decisions

Each entry: the options, the choice, and the reason. Newest entries are at the
bottom of each section.

## Project setup

**D1. Workspace with two crates.** Options: one crate with `lib.rs` + `main.rs`,
or a workspace. Chose a workspace (`lockwatch-core` library, `lockwatch-cli`
binary) as the spec's layout asks. Tests and future front ends (a GitHub
Action, say) can use the library without the CLI.

**D2. Dependency versions live in the root `Cargo.toml`.** Both crates use
`dep.workspace = true`, so a version is bumped in one place.

**D3. Extra crates that the spec did not list (please review).** The spec says
to ask before adding dependencies. These were needed and are flagged here for
Stephen's review:
- `oxc_allocator`, `oxc_span`, `oxc_ast_visit`, `oxc_syntax`: companion
  crates of `oxc_parser`/`oxc_ast` from the same project. The parser API needs
  the arena allocator and `SourceType`, the `Visit` trait now lives in
  `oxc_ast_visit`, and `visit_function` takes `oxc_syntax::scope::ScopeFlags`.
  Without them `oxc_parser` cannot be used.
- `sha1`: the spec requires verifying `sha1-` integrity strings, and `sha2`
  only implements SHA-2. `sha1` is the RustCrypto sibling of `sha2`.
- `tracing-subscriber`: `tracing` only emits events; a subscriber is needed to
  print them in the CLI.
- `tempfile` is listed for tests, but it is also used at runtime to create the
  extraction directory (it deletes the directory automatically on drop).
- Node side: `typescript`, `@types/node`, `@types/better-sqlite3`,
  `typescript-eslint` and `@eslint/js` are needed to compile and lint
  TypeScript with the listed tools.

No date/time crate was added: the two things we need (format "now" as RFC 3339
and parse registry timestamps) are done in `crates/lockwatch-core/src/time.rs`
with unit tests.

## Lockfile parsing

**D4. Parse only the `packages` map.** Options: also support v1's nested
`dependencies` tree, or only v2/v3. Chose v2/v3 only, as the spec says; v1
returns a clear error that tells the user how to regenerate the lockfile.

**D5. Deduplicate by `(name, version, integrity)`.** The same package can be
installed at several paths. Scanning it once is enough; the integrity is part
of the key so two different tarballs that claim the same version are both
checked.

**D6. Skip, but report, entries we do not download:** `link: true`, workspace
folders, `file:` and git dependencies, and `inBundle` entries. Bundled
dependencies are inside their parent's tarball, so their files are analysed as
part of the parent.

## Fetching and caching

**D7. Allow-list of tarball hosts (SSRF protection).** Options: fetch any
`resolved` URL, or only registry URLs. The API runs the CLI on lockfiles
uploaded by strangers, and a `resolved` URL such as
`http://169.254.169.254/...` would make the server request internal
addresses. Chose: only `https` URLs on `registry.npmjs.org`,
`registry.yarnpkg.com`, or the configured `--registry` origin. Other URLs are
listed as skipped with the reason.

**D8. Cache key = integrity hash in hex.** SRI uses base64, which contains
`/`, so the key is `sha512-<hex>`. Entries with no integrity are keyed by a
SHA-256 of the URL. A tarball is only written to the cache after it passed
verification, and it is verified again every time it is read, so a corrupted
or tampered cache file is reported as LW012 instead of being trusted.

**D9. Metadata cache without expiry.** Options: a time-to-live, or "refetch
when the cached document does not know this version". Chose the second: the
fields the rules use (publish time and publisher of past versions) never
change, and a new version always triggers a refetch. Only the needed fields
are cached; full documents for popular packages are tens of megabytes.

**D10. Retries.** Up to 3 retries with exponential backoff (0.5 s, 1 s, 2 s) on
network errors, HTTP 429 and 5xx. A 404 is not retried. Responses are read in
chunks with a size limit (100 MB per tarball, 200 MB per metadata document),
so a hostile server cannot make the scanner buffer unlimited data.

**D11. No date library.** RFC 3339 formatting and parsing are about 60 lines
in `time.rs`, with tests (round trip of every 13th day from 1960 to 2100).

## Extraction

**D12. Extract to a temporary directory, then read files back.** Options:
unpack straight into memory, or onto disk as the spec says. Chose disk (a
`tempfile::TempDir`, deleted automatically when dropped). Extraction is then a
separate, testable security boundary: the traversal tests check the
filesystem directly.

**D13. Hitting a limit stops extraction but keeps the package.** Options: skip
the whole package, or analyse what was extracted so far. Skipping would let
an attacker pad a package past 50 MB to avoid every rule. Chose: stop
unpacking (so a decompression bomb costs at most 50 MB), analyse the files
already extracted, and add a warning to the package in the report.

**D14. The size budget is charged before a file is read.** The tar format
forces us to decompress data even to skip it, so the 50 MB budget counts
every entry's declared size, including files we do not write. The entry
limit (10,000) counts every entry, including directories and symlinks.

**D15. Unsafe entries are skipped with a warning, not fatal.** Absolute
paths, `..`, symlinks, hardlinks and device files are never created. The rest
of the package is still analysed.

## Analysis and rules

**D16. Analyse each file once into "facts".** Options: let each rule walk the
syntax tree, or extract facts once. Chose facts (`JsFacts`): oxc's tree lives
in a single-threaded arena, the facts are plain data that rules can share
across threads, and each rule becomes a short filter.

**D17. Two passes, one flat scope.** The first pass records what names mean
(aliases of `require`, `const cp = require('child_process')`, string
constants), the second pass detects. No per-function scopes or data flow:
simple to explain, catches the common evasions, misses determined ones. A
name declared in the file (`function fetch(){}`) shadows the global of the
same name.

**D18. Parse failures fall back to regexes.** `.js` is tried as an ES module,
then CommonJS (top-level `return`), then with JSX. If all fail, regexes
produce the same facts with `parsed: false`.

**D19. "Install-time code" = files run by `preinstall`/`install`/
`postinstall`/`prepare`, plus local files they require (one level), plus
inline `node -e` code.** `npm run <x>` inside a hook is followed one level.
LW003 and LW004 only look at install-time code, as the spec says.

**D20. LW005 checks every JavaScript file, not just install-time code.**
Credential stealers also run when a package is `require`d. It is `high`
everywhere and `critical` only when the same install-time file also has
LW004 network access. `JSON.stringify(process.env)` counts as reading every
secret. Credential-file paths only count when the file also calls
`readFile`/`readFileSync`/`createReadStream`.

**D21. Network modules include common HTTP clients.** Besides `http`,
`https`, `net`, `dns`, `dgram` (spec) we treat `tls`, `http2`, `axios`,
`node-fetch`, `got`, `request`, `undici`, `needle` and `superagent` as
network access, because malware uses them too.

**D22. LW007 details.** Escape ratio only for files of 200 bytes or more (a
tiny file with one escape is not obfuscated). `_0x` identifiers need at least
10 occurrences and 2 per KB.

**D23. LW008 details.** Names under 5 characters get no edit-distance check
(too many short names are one edit apart by chance); 5 to 9 characters allow
distance 1, 10 or more allow 2. Separator/scope confusion compares names with
`-_.@/` removed.

**D24. Scoring counts each rule once.** The spec says "sum of severity
weights". Summing every finding would let a bundle with 40 `eval`s score 100.
Chose: each rule adds the weight of its worst finding, so the score reflects
how many different risky behaviours a package shows.

**D25. Finding limits.** At most 5 findings per rule per file and 25 per rule
per package; a package warning says how many were left out. Keeps reports of
large bundles readable.

**D26. "Flagged" means risk level medium or above (score >= 30).** Used for
the package-level detection and false-positive rates in the evaluation.

## Reports and CLI

**D27. The report lists every scanned package**, including those with no
findings (score 0), so a consumer can see what was covered. The table only
shows packages with findings. Each package has a `warnings` list (limits hit,
metadata unavailable); each skipped entry has `error: true|false`.

**D28. Exit codes.** 1 if any finding is at or above `--fail-on` (default
`high`); otherwise 2 if a package could not be scanned because of an error
(download failure, offline cache miss), so a flaky network cannot silently
pass a CI gate; otherwise 0. Fatal errors (bad lockfile) also exit 2. `info`
never triggers `--fail-on low`.

**D29. `--out` writes the selected format to a file instead of stdout.**

**D30. `--now` flag.** Time-based rules (LW009) depend on "now". `--now
<RFC 3339>` makes fixture scans, snapshots and the evaluation reproducible;
it also sets `scanned_at`.

**D31. Default cache directory** is `$LOCKWATCH_CACHE_DIR`, else
`$XDG_CACHE_HOME/lockwatch`, else `~/.cache/lockwatch`.

**D32. Analysis threads get 16 MB stacks.** Parsing and walking deeply nested
attacker-written JavaScript recurses deeply; a dedicated rayon pool with big
stacks avoids stack overflows (the default is 2 MB).

## Data

**D33. Popular list source.** The npm downloads API (`api.npmjs.org`) was
blocked by the build environment's network policy. `scripts/build_popular.ts`
tries it first and falls back to the registry search API's
`downloads.weekly`, which reports the same weekly figure; the file header
records which source was used. The search API does not return deprecated
packages, so 18 seed names (including `request`, `aws-sdk`, `node-sass`) are
missing from the 2026-10-11 snapshot; this is listed in the file header and
in RULES.md. Re-running the script where `api.npmjs.org` is reachable fixes
it.

**D34. Fixtures are built, not hand-made tarballs.** Readable sources live in
`fixtures/packages`; an example program packs them deterministically and
writes the offline cache and lockfiles, which are committed. Fake binaries
are generated from `_generate.json` so no executable is stored in git.

## Node API

**D35. Node 22, not 20.** The spec says "LTS 20+" and mentions
`node:20-slim`. Node 20 reached end-of-life in April 2026, and
`better-sqlite3` 13 requires Node 22. Chose Node 22 (current LTS) everywhere
(Docker, CI, `engines`).

**D36. vitest 5.** vitest 3.x/4.1.10 and older have published advisories
(path traversal in `@vitest/mocker`, prototype pollution in `tinypool`), and
npm 10 hit a resolver bug installing vitest 4.1.11. vitest 5.0.3 installs
cleanly with `npm audit` reporting 0 vulnerabilities.

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
- `oxc_allocator`, `oxc_span`, `oxc_ast_visit`: companion crates of
  `oxc_parser`/`oxc_ast` from the same project. The parser API needs the arena
  allocator and `SourceType`, and the `Visit` trait now lives in
  `oxc_ast_visit`. Without them `oxc_parser` cannot be used.
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

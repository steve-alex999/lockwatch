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

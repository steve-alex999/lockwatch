# Learning notes

One short section per Rust or Node concept, the first time it shows up in this
repo: what it is, where it is used (file and function), and why it is used
there. Sections are in the order they were introduced.

---

## Cargo workspaces

**What:** one `Cargo.toml` at the root lists several crates (`members`). They
share one `Cargo.lock` and one `target/` directory, and can share dependency
versions through `[workspace.dependencies]`.

**Where:** `Cargo.toml` (root), `crates/lockwatch-core/Cargo.toml`,
`crates/lockwatch-cli/Cargo.toml` (`serde.workspace = true`).

**Why:** the engine (`lockwatch-core`, a library) is kept apart from the
command-line front end (`lockwatch-cli`, a binary). Tests and other front ends
can use the library without going through argument parsing.

## Modules and visibility (`mod`, `pub`, `use`)

**What:** `mod lockfile;` tells the compiler to load `lockfile/mod.rs` (or
`lockfile.rs`). Items are private to their module unless marked `pub`.
`use crate::error::Result;` brings a name into scope.

**Where:** `crates/lockwatch-core/src/lib.rs`, `src/lockfile/mod.rs`.

**Why:** each part of the pipeline lives in its own module, and only the types
other modules need are `pub`.

## Structs, enums and `#[derive]`

**What:** a `struct` groups named fields; an `enum` is a value that is exactly
one of several variants, and each variant can carry data (`CoreError::Io { path,
source }`). `#[derive(Debug, Clone, PartialEq)]` asks the compiler to write the
obvious implementations of those traits for you.

**Where:** `LockedPackage` and `SkippedEntry` in `src/lockfile/mod.rs`;
`CoreError` in `src/error.rs`.

**Why:** enums make "one of N cases" explicit, and `match` must handle every
case, so a new error variant cannot be silently ignored.

## `Option<T>`

**What:** either `Some(value)` or `None`. Rust has no null; a field that may be
missing is an `Option`.

**Where:** `LockedPackage::resolved` and `integrity` (`src/lockfile/mod.rs`);
`RawEntry` in `src/lockfile/npm.rs`.

**Why:** real lockfiles omit fields. The type forces every caller to handle the
missing case, for example `entry.version.clone()` inside `let Some(version) =
... else { ... }` in `NpmLockfileParser::parse`.

## `Result<T, E>` and the `?` operator

**What:** a function that can fail returns `Result<T, E>`: `Ok(value)` or
`Err(error)`. Writing `expr?` means "if this is an `Err`, return it from the
current function now; otherwise give me the `Ok` value". `map_err` converts
one error type into another first.

**Where:** `NpmLockfileParser::parse` in `src/lockfile/npm.rs`:
`serde_json::from_str(content).map_err(CoreError::LockfileJson)?`.

**Why:** errors are values, not exceptions, and `?` keeps the happy path
readable. The spec forbids `unwrap()`/`expect()` outside tests, because those
crash the program instead of reporting the error.

## `thiserror` and `anyhow`

**What:** `thiserror` derives `std::error::Error` plus a `Display` message for
your own error enum (`#[error("HTTP {status} fetching {url}")]`). `anyhow::Error`
is a catch-all error type for applications that just need to print the error
and its causes.

**Where:** `CoreError` in `crates/lockwatch-core/src/error.rs` (thiserror);
`crates/lockwatch-cli/src/main.rs` (anyhow).

**Why:** a library should expose typed errors callers can `match` on; a CLI
mostly prints them, where `anyhow` plus `.context("...")` is less code.

## `serde` derive

**What:** `#[derive(Deserialize)]` generates code that builds the struct from
JSON (or any format serde supports). Unknown JSON fields are ignored by
default; `#[serde(rename = "lockfileVersion")]` maps a JSON name to a Rust
field name; `#[serde(default)]` uses `Default::default()` when the field is
missing.

**Where:** `RawLockfile` and `RawEntry` in `src/lockfile/npm.rs`.

**Why:** we describe only the fields we need and serde does the parsing and
type checking.

## Traits and trait objects (`dyn Trait`)

**What:** a trait is a set of methods a type promises to implement (like an
interface). `Box<dyn LockfileParser>` is a pointer to "some type that
implements `LockfileParser`", chosen at runtime.

**Where:** `LockfileParser` in `src/lockfile/mod.rs`, implemented by
`NpmLockfileParser` in `src/lockfile/npm.rs`; `parsers()` returns
`Vec<Box<dyn LockfileParser>>`.

**Why:** the spec asks for pnpm and yarn support to be addable later. A new
format is a new type implementing the trait; `parse_lockfile` picks one with
`detect()` and nothing else in the pipeline changes.

## Borrowing and lifetimes in return types

**What:** `fn name_from_path(path: &str) -> &str` returns a slice of its input.
The compiler infers that the returned reference lives as long as `path`
(lifetime elision), so no copy is made, and the caller cannot keep the slice
after the original string is dropped.

**Where:** `name_from_path` in `src/lockfile/npm.rs`.

**Why:** it is cheap (no allocation) and the borrow checker guarantees it is
safe.

## `BTreeMap` vs `HashMap`, and `HashSet`

**What:** `HashMap` iterates in an unpredictable order; `BTreeMap` iterates in
sorted key order. `HashSet::insert` returns `false` if the value was already
present.

**Where:** `RawLockfile::packages` is a `BTreeMap` and the `seen` set in
`NpmLockfileParser::parse` is a `HashSet` (`src/lockfile/npm.rs`).

**Why:** sorted order makes reports and snapshot tests deterministic, and
`seen.insert(key)` removes duplicate `name@version` entries in one line.

## Unit tests (`#[cfg(test)]`, `#[test]`)

**What:** functions marked `#[test]` run with `cargo test`. A `mod tests`
behind `#[cfg(test)]` is compiled only for tests, and `use super::*;` gives it
access to the private items of the module it sits in.

**Where:** bottom of `src/lockfile/npm.rs` (and most other modules).

**Why:** tests sit next to the code they check and can test private helpers
such as `name_from_path`.

## `async`/`await` and the tokio runtime

**What:** an `async fn` returns a *future*: a value describing work that can
pause while it waits (for a network reply, a timer) and let other work run on
the same thread. `.await` waits for a future. Futures do nothing until a
runtime drives them; tokio is that runtime. `#[tokio::main]` creates one and
runs `main` on it; `#[tokio::test]` does the same for a test.

**Where:** `RegistryClient::get` and `ensure_tarball` in
`crates/lockwatch-core/src/registry.rs`; `scan_packages` in `src/scan.rs`;
`main` in `crates/lockwatch-cli/src/main.rs`.

**Why:** downloads spend almost all their time waiting on the network. With
async, hundreds of downloads can be in flight on a few threads.

## Bounded concurrency with `futures::stream`

**What:** `stream::iter(items).map(|x| async { ... }).buffer_unordered(n)`
turns a list into futures and runs at most `n` of them at a time, yielding
results as they complete. `tokio::join!(a, b)` runs two futures concurrently
and waits for both.

**Where:** `scan_packages` in `crates/lockwatch-core/src/scan.rs`.

**Why:** `--concurrency 16` means "at most 16 requests at once", so the
scanner is fast without hammering the registry.

## `Arc` (shared ownership across tasks and threads)

**What:** `Arc<T>` is a reference-counted pointer that is safe to share
between threads. `Arc::clone(&x)` makes another pointer to the same value
(cheap, no deep copy); the value is freed when the last `Arc` is dropped.

**Where:** `scan_packages` wraps the `RegistryClient` in an `Arc` so every
download future can hold it; `MockRegistry` in `src/test_support.rs` shares
a `Mutex<HashMap>` of hit counters the same way.

**Why:** each future needs access to the client, and the borrow checker will
not let a plain reference outlive the function that created it.

## CPU work off the async runtime: `spawn_blocking` and rayon

**What:** rayon's `par_iter()` splits a collection across all CPU cores (a
work-stealing thread pool). `tokio::task::spawn_blocking` runs a closure on a
separate thread so long computations do not stall tokio's async threads.

**Where:** `scan_packages` (packages analysed with `into_par_iter`, inside
`spawn_blocking`, on a pool built with 16 MB stacks), `PackageContext::build`
in `src/context.rs` (files analysed in parallel), `run_rules` in
`src/rules/mod.rs` (rules run in parallel).

**Why:** unpacking and parsing JavaScript is CPU-bound; rayon uses every
core with almost no code.

## `Send` and `Sync`

**What:** marker traits. `Send` = a value may be moved to another thread;
`Sync` = a reference may be shared between threads. The compiler checks them
automatically.

**Where:** `pub trait Rule: Send + Sync` in `src/rules/mod.rs`; the file
reader passed to `PackageContext::build` is `&(dyn Fn(&str) -> Option<Vec<u8>>
+ Sync)`.

**Why:** rules and the file reader are used from several rayon threads at
once. oxc's syntax tree is *not* `Sync` (it lives in a single-threaded arena),
which is why each file's facts are extracted into plain structs first.

## Closures

**What:** anonymous functions that can capture variables from where they are
written: `|path: &str| written.contains(path)`. `move` closures take
ownership of what they capture.

**Where:** the `read` closure in `PackageContext::from_extraction`
(`src/context.rs`); `hit` helpers in `src/analysis/fallback.rs`; the
`async move` blocks in `scan_packages`.

**Why:** small pieces of behaviour (how to read a file, how to build a
finding) can be passed around without defining a named type.

## Iterators and adapters

**What:** `.iter()` produces items lazily; adapters like `map`, `filter`,
`filter_map`, `flat_map`, `chain`, `take` build a pipeline; `collect()` runs
it into a `Vec`, `HashMap`, `String`, even `Option<Vec<_>>` (which becomes
`None` if any item is `None`).

**Where:** everywhere; good examples are `decode_hex` in
`src/analysis/js.rs` (collecting into `Option<Vec<u8>>`) and
`install_sources` in `src/context.rs` (`files.chain(inline)`).

**Why:** clear, allocation-light data processing without index bookkeeping.

## `let ... else` and `match` guards

**What:** `let Some(x) = expr else { return ...; };` binds `x` or leaves the
function early. In `match`, `Some(at) if at > 0 => ...` only takes the arm
when the guard is true.

**Where:** `NpmLockfileParser::parse` (`let Some(version) = ... else`),
`split_spec` in `src/scan.rs` (guards), most rules' `check` functions.

**Why:** keeps the main path un-nested: handle the "nothing to do" case
first, then work with the value.

## Visitors over a syntax tree, and arena lifetimes (`'a`)

**What:** oxc parses JavaScript into an AST allocated in an `Allocator`
(arena). Every AST node borrows from the arena and the source text, which is
what the lifetime parameter in `Program<'a>` or `CallExpression<'a>` says:
"this node cannot outlive the arena". The `Visit<'a>` trait has one method
per node type; overriding `visit_call_expression` and calling
`walk::walk_call_expression` keeps the traversal going into children.

**Where:** `impl<'a> Visit<'a> for Collector<'_>` in
`crates/lockwatch-core/src/analysis/js.rs`.

**Why:** we only care about a few node kinds (calls, imports, member
expressions, string literals); the visitor visits all the others for free.

## Static evaluation and recursion limits

**What:** `Collector::static_value` computes what an expression evaluates to
when that is knowable without running it (`'child_' + 'process'`,
`['a','b'].join('')`, `Buffer.from('...', 'base64').toString()`). It is a
recursive function with a `depth` counter.

**Where:** `static_value` and `static_call` in `src/analysis/js.rs`.

**Why:** attackers split strings to hide `require('child_process')`. The
depth limit makes sure a deeply nested expression cannot cause a stack
overflow.

## `static`, `OnceLock` and `const fn`

**What:** a `static` lives for the whole program. `OnceLock<T>` is a cell that
is filled once, on first use, safely across threads. A `const fn` can run at
compile time, which is required to initialise a `static`.

**Where:** `LazyRegex` in `src/analysis/text.rs` (regexes compiled once);
`popular_packages()` in `src/rules/lw008_typosquat.rs` (list parsed once);
`pub static RULES: &[&dyn Rule]` in `src/rules/mod.rs`.

**Why:** compiling a regex or parsing the popular list for every file would
be wasteful; doing it lazily also avoids work for commands that never need
it.

## Trait objects in a static list

**What:** `&dyn Rule` is a reference to "some type implementing `Rule`".
Because every rule is a unit struct (no fields), `&InstallScriptPresent` is a
constant and can live in a `static` slice.

**Where:** `RULES` in `src/rules/mod.rs`; used by `run_rules` and by the
`rules` command in the CLI.

**Why:** adding a rule = one new file plus one line in `RULES`.

## Default trait methods

**What:** a trait can provide a method body that implementors get for free.

**Where:** `Rule::finding` in `src/rules/mod.rs` builds a `Finding` with the
rule's ID and default severity and truncates the evidence to 200 characters.

**Why:** the 200-character limit is enforced in one place for all 12 rules.

## `include_str!`, `env!` and `concat!`

**What:** macros evaluated at compile time. `include_str!("../../data/popular.txt")`
embeds a file's text in the binary; `env!("CARGO_PKG_VERSION")` reads a
variable Cargo sets while compiling.

**Where:** `POPULAR_TXT` in `src/rules/lw008_typosquat.rs`; the user agent in
`RegistryClient::new`; `TOOL_VERSION` in `src/report.rs`;
`env!("CARGO_BIN_EXE_lockwatch")` in the CLI tests.

**Why:** the binary is self-contained (no data files to install), and the
version string can never drift from `Cargo.toml`.

## `impl Trait` in argument and return position

**What:** `fn new(root: impl Into<PathBuf>)` accepts any type convertible to
`PathBuf`. A return type of `impl Iterator<Item = Match<'h>> + use<'s, 'h>`
says "some iterator type", and the `use<..>` part lists which lifetimes the
hidden type may borrow from.

**Where:** `Cache::new` in `src/cache.rs`; `LazyRegex::find_iter` in
`src/analysis/text.rs`.

**Why:** flexible APIs without writing out long generic types.

## Integer conversions without surprises

**What:** `u32::try_from(x)` fails instead of silently truncating;
`saturating_add`, `saturating_sub` and `saturating_pow` stop at the type's
limit instead of overflowing.

**Where:** `LineIndex::line_of` in `src/analysis/text.rs`, the size budget in
`extract_tarball`, the retry delay in `RegistryClient::get`.

**Why:** values derived from attacker-controlled archives must not overflow.

## clap derive

**What:** `#[derive(Parser)]` on a struct generates a command-line parser;
doc comments become `--help` text; `#[command(subcommand)]`,
`#[command(flatten)]` and `#[arg(long, value_enum, default_value_t = ...)]`
describe the interface.

**Where:** `Cli`, `Command` and `ScanArgs` in
`crates/lockwatch-cli/src/main.rs`.

**Why:** argument parsing, validation and help text with no hand-written
parsing code.

## Process exit codes (`ExitCode`)

**What:** `fn main() -> ExitCode` returns the process status; `ExitCode::from(2)`
reports an error to the shell or CI.

**Where:** `finish` and `main` in `crates/lockwatch-cli/src/main.rs`.

**Why:** the spec defines 0/1/2 so CI pipelines can gate on findings.

## Integration tests and snapshot tests

**What:** files in a crate's `tests/` directory are compiled as separate
programs that use the crate from outside. `insta::assert_json_snapshot!`
saves a value's JSON to a `.snap` file on first run and fails if it later
changes; redactions replace unstable fields (`duration_ms`).

**Where:** `crates/lockwatch-cli/tests/fixtures.rs`,
`crates/lockwatch-cli/tests/no_exec.rs`, snapshots in
`crates/lockwatch-cli/tests/snapshots/`.

**Why:** they test the real binary end to end, and any change to the report
shows up as a reviewable diff.

---

# Node.js and TypeScript (the API in `api/`)

## ES modules and TypeScript with erasable syntax

**What:** `"type": "module"` in `package.json` makes `.js` files ES modules
(`import`/`export`). The TypeScript sources only use syntax whose types can be
deleted to get JavaScript (`erasableSyntaxOnly`: no `enum`, no constructor
parameter properties), so Node 22 can run them directly
(`node --experimental-strip-types src/server.ts`) and `tsc` compiles them for
production (`rewriteRelativeImportExtensions` turns `./app.ts` into
`./app.js`).

**Where:** `api/package.json`, `api/tsconfig.json`, imports such as
`import { buildApp } from "./app.ts"` in `api/src/server.ts`;
`scripts/build_popular.ts` and `eval/summarize.ts` run without a build step.

**Why:** one source of truth, no bundler, and scripts that run with plain
`node`.

## `async`/`await` and Promises in Node

**What:** a `Promise` is a value that will be available later; `await` pauses
the function until it settles. `new Promise((resolve, reject) => ...)` wraps
callback-style APIs (child process events) in a promise.

**Where:** `runLockwatch` in `api/src/runner.ts` wraps `spawn`'s `close` and
`error` events; route handlers in `api/src/app.ts` are `async`.

**Why:** the server keeps handling other requests while a scan runs.

## `child_process.spawn` without a shell

**What:** `spawn(file, [arg1, arg2], { shell: false })` starts a program with
an exact argument list. With a shell (`exec("lockwatch scan " + name)`), a
name like `x; rm -rf ~` would be interpreted as two commands.

**Where:** `runLockwatch` in `api/src/runner.ts`; the test "passes arguments
without a shell" in `api/test/runner.test.ts` proves `$(...)` arrives
verbatim.

**Why:** the spec forbids shells and string concatenation; untrusted input
never reaches a command interpreter. The timeout uses `child.kill("SIGKILL")`.

## Fastify plugins, hooks and `inject`

**What:** Fastify features are added with `app.register(plugin, options)`
(rate limiting, multipart uploads). Hooks such as `onClose` run at lifecycle
points. `app.inject({ method, url, payload })` calls a route in-process
without opening a port.

**Where:** `buildApp` in `api/src/app.ts`; every test in
`api/test/app.test.ts` uses `inject`.

**Why:** building the app in a function (instead of at import time) lets
tests create isolated instances with their own configuration.

## zod: validation and types from one schema

**What:** a zod schema validates unknown data at runtime (`safeParse` returns
success or a list of issues), and `z.infer<typeof Schema>` gives the matching
TypeScript type at compile time.

**Where:** `api/src/schemas.ts` (`LockfileSchema`, `ReportSchema`),
`api/src/config.ts` (environment variables with defaults).

**Why:** HTTP bodies and the Rust binary's output are untrusted; one schema
gives both the check and the type, so they cannot drift apart.

## better-sqlite3 and prepared statements

**What:** an embedded SQLite database with a synchronous API.
`db.prepare(sql).run(params)` binds values separately from the SQL text.

**Where:** `JobStore` in `api/src/store.ts`.

**Why:** no database server to run; bound parameters make SQL injection
impossible; WAL mode lets reads happen during writes.

## Private class fields (`#field`)

**What:** fields starting with `#` cannot be read from outside the class
(enforced by JavaScript itself, not just by TypeScript).

**Where:** `ScanQueue` in `api/src/queue.ts`, `JobStore` and `Scanner`.

**Why:** the queue's counters can only change through `run()`, which keeps
its invariant (never more than `concurrency` tasks) intact.

## Vitest and test doubles

**What:** vitest runs `*.test.ts` files with `describe`/`it`/`expect`.
Instead of mocking `child_process`, the tests point the API at small fake
binaries (`api/test/fake-bin/*.mjs`) that sleep, print garbage or print a
valid report.

**Where:** `api/test/`.

**Why:** the real spawning, timeout and parsing code runs unchanged in tests;
only the program at the other end is fake. `describe.skipIf` skips the
integration tests when the Rust binary has not been built (CI requires it).

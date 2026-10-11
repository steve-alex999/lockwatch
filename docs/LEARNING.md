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

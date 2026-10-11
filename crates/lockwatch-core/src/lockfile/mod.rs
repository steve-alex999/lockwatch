//! Lockfile parsing.
//!
//! Every lockfile format (npm today; pnpm, yarn and bun later) implements the
//! [`LockfileParser`] trait and produces the same [`ParsedLockfile`]. The rest
//! of the pipeline only ever sees `ParsedLockfile`, so adding a format means
//! adding one new file here and nothing else.

pub mod npm;

use serde::Serialize;

use crate::error::{CoreError, Result};

/// One package that the lockfile resolves to and that we will download.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    /// Tarball URL from the lockfile. `None` when the lockfile omits it; the
    /// fetcher then builds the standard registry URL.
    pub resolved: Option<String>,
    /// Subresource Integrity string, for example `sha512-<base64>`.
    pub integrity: Option<String>,
}

impl LockedPackage {
    /// `name@version`, the usual way to print a package.
    pub fn spec(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// A lockfile entry we deliberately do not download (local folder, git
/// dependency, ...). These are listed in the report so nothing is silently
/// ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedEntry {
    pub name: String,
    pub version: Option<String>,
    pub reason: String,
}

/// The format-independent result of parsing a lockfile.
#[derive(Debug, Clone, Default)]
pub struct ParsedLockfile {
    /// Unique packages to fetch and analyse, in a stable order.
    pub packages: Vec<LockedPackage>,
    /// Entries that will not be scanned, with the reason.
    pub skipped: Vec<SkippedEntry>,
}

/// Implemented once per lockfile format.
///
/// The trait takes `&self` (not `self`) so one parser value can be reused, and
/// it is object safe, so parsers can be stored as `Box<dyn LockfileParser>`.
pub trait LockfileParser {
    /// Human-readable format name, used in error messages.
    fn format_name(&self) -> &'static str;

    /// Returns true if `file_name` and `content` look like this format.
    /// Used to pick a parser automatically.
    fn detect(&self, file_name: &str, content: &str) -> bool;

    /// Parse the whole lockfile.
    fn parse(&self, content: &str) -> Result<ParsedLockfile>;
}

/// All parsers lockwatch knows about. Only npm in v1.
pub fn parsers() -> Vec<Box<dyn LockfileParser>> {
    vec![Box::new(npm::NpmLockfileParser)]
}

/// Pick the right parser for a file and parse it.
///
/// If no parser recognises the file we still try npm, because its error
/// messages ("lockfileVersion 1 is not supported", ...) are the most useful.
pub fn parse_lockfile(file_name: &str, content: &str) -> Result<ParsedLockfile> {
    let all = parsers();
    let chosen = all
        .iter()
        .find(|p| p.detect(file_name, content))
        .or_else(|| all.first())
        .ok_or_else(|| CoreError::UnsupportedLockfile("no lockfile parsers registered".into()))?;
    chosen.parse(content)
}

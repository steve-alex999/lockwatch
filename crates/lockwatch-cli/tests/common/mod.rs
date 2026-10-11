//! Shared helpers for the CLI integration tests.
//!
//! Each file in `tests/` is compiled as its own crate, so helpers used by
//! several test files live in this module (`mod common;`).

#![allow(dead_code)] // not every test file uses every helper

pub mod schema;

use std::path::PathBuf;
use std::process::{Command, Output};

/// Fixed "now" for fixture scans, so time-based rules are reproducible.
pub const FIXTURE_NOW: &str = "2026-10-20T00:00:00Z";

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn fixture(path: &str) -> PathBuf {
    repo_root().join("fixtures").join(path)
}

/// The `lockwatch` binary that cargo built for this test run.
pub fn lockwatch() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lockwatch"))
}

/// Run `lockwatch scan <lockfile>` offline against the fixture cache.
pub fn scan_fixture(lockfile: &str, extra: &[&str]) -> Output {
    lockwatch()
        .arg("scan")
        .arg(fixture(lockfile))
        .args(["--offline", "--now", FIXTURE_NOW, "--cache-dir"])
        .arg(fixture("cache"))
        .args(extra)
        .output()
        .expect("run lockwatch")
}

pub fn json_report(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

pub fn load_schema() -> serde_json::Value {
    let text =
        std::fs::read_to_string(repo_root().join("docs/report.schema.json")).expect("schema");
    serde_json::from_str(&text).expect("schema is JSON")
}

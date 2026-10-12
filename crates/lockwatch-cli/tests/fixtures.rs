//! End-to-end tests of the `lockwatch` binary against the committed fixtures
//! (fixtures/cache, built by `cargo run -p lockwatch-core --example
//! build_fixtures`). All scans run with `--offline`: no network access.

mod common;

use std::collections::BTreeSet;

use common::{json_report, load_schema, lockwatch, scan_fixture, schema};
use serde_json::Value;

fn rule_ids(report: &Value) -> BTreeSet<String> {
    report["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|p| p["findings"].as_array().into_iter().flatten())
        .filter_map(|f| f["rule_id"].as_str().map(String::from))
        .collect()
}

#[test]
fn mixed_lockfile_triggers_every_rule_and_matches_the_schema() {
    let out = scan_fixture(
        "lockfiles/mixed.json",
        &["--format", "json", "--fail-on", "none"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = json_report(&out);

    let expected: BTreeSet<String> = (1..=12).map(|n| format!("LW{n:03}")).collect();
    assert_eq!(rule_ids(&report), expected);

    let errors = schema::validate(&load_schema(), &report);
    assert!(errors.is_empty(), "schema errors: {errors:#?}");

    // The link, workspace folder, file: and git entries are listed as skipped.
    let skipped: Vec<&str> = report["skipped"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|s| s["name"].as_str())
        .collect();
    assert_eq!(skipped, ["file-dep", "git-dep", "local-lib", "local-lib"]);

    insta::assert_json_snapshot!("mixed_report", report, {
        ".summary.duration_ms" => "[duration]",
    });
}

#[test]
fn schema_validator_rejects_bad_reports() {
    let schema = load_schema();
    let out = scan_fixture(
        "lockfiles/small.json",
        &["--format", "json", "--fail-on", "none"],
    );
    let mut report = json_report(&out);
    assert!(schema::validate(&schema, &report).is_empty());
    report["summary"]["packages_total"] = Value::from(-1);
    report["extra"] = Value::from(true);
    let errors = schema::validate(&schema, &report);
    assert_eq!(errors.len(), 2, "{errors:?}");
}

#[test]
fn table_output_snapshot() {
    let out = scan_fixture("lockfiles/mixed.json", &["--fail-on", "none"]);
    let text = String::from_utf8_lossy(&out.stdout);
    // The duration changes on every run; blank it out.
    let stable: String = text
        .lines()
        .map(|line| match line.find(" scanned in ") {
            Some(at) => format!("{} scanned in [duration]", &line[..at]),
            None => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    insta::assert_snapshot!("mixed_table", stable);
}

#[test]
fn exit_codes_follow_fail_on() {
    // mixed.json has a critical finding (LW005 + LW004 together).
    let code = |fail_on: &str| {
        scan_fixture(
            "lockfiles/mixed.json",
            &["--format", "json", "--fail-on", fail_on],
        )
        .status
        .code()
    };
    assert_eq!(code("critical"), Some(1));
    assert_eq!(code("low"), Some(1));
    assert_eq!(code("none"), Some(0));
    // The benign set has at most high findings (the esbuild-like fixture).
    let benign = scan_fixture("lockfiles/benign.json", &["--fail-on", "critical"]);
    assert_eq!(benign.status.code(), Some(0));
}

#[test]
fn v2_lockfiles_are_supported() {
    let out = scan_fixture(
        "lockfiles/v2-small.json",
        &["--format", "json", "--fail-on", "none"],
    );
    let report = json_report(&out);
    assert_eq!(report["summary"]["packages_scanned"], 3);
}

#[test]
fn offline_cache_miss_is_an_incomplete_scan() {
    let empty = tempfile::tempdir().expect("tempdir");
    let out = lockwatch()
        .arg("scan")
        .arg(common::fixture("lockfiles/small.json"))
        .args(["--offline", "--format", "json", "--cache-dir"])
        .arg(empty.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    let report = json_report(&out);
    assert_eq!(report["summary"]["packages_scanned"], 0);
    assert_eq!(report["skipped"][0]["error"], true);
}

#[test]
fn tool_errors_exit_with_2() {
    let out = lockwatch()
        .args(["scan", "does-not-exist.json"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("is not a file"));

    let dir = tempfile::tempdir().expect("tempdir");
    let v1 = dir.path().join("package-lock.json");
    std::fs::write(&v1, r#"{"lockfileVersion": 1, "dependencies": {}}"#).expect("write");
    let out = lockwatch().arg("scan").arg(&v1).output().expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("lockfileVersion 1 is not supported"));
}

#[test]
fn scan_package_uses_cached_metadata() {
    let out = lockwatch()
        .args([
            "scan-package",
            "lwfx-net-ip@1.0.0",
            "--offline",
            "--format",
            "json",
        ])
        .args([
            "--now",
            common::FIXTURE_NOW,
            "--fail-on",
            "none",
            "--cache-dir",
        ])
        .arg(common::fixture("cache"))
        .output()
        .expect("run");
    let report = json_report(&out);
    assert_eq!(report["lockfile"], "lwfx-net-ip@1.0.0");
    assert_eq!(report["packages"][0]["risk_level"], "medium");
}

#[test]
fn out_flag_writes_a_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("report.json");
    let out = scan_fixture(
        "lockfiles/small.json",
        &[
            "--format",
            "json",
            "--fail-on",
            "none",
            "--out",
            path.to_str().expect("utf8"),
        ],
    );
    assert!(out.stdout.is_empty());
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
    assert_eq!(report["tool"], "lockwatch");
}

#[test]
fn rules_command_lists_twelve_rules() {
    let out = lockwatch()
        .args(["rules", "--format", "json"])
        .output()
        .expect("run");
    let rules: Vec<Value> = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(rules.len(), 12);
    assert_eq!(rules[0]["id"], "LW001");
    assert_eq!(rules[11]["severity"], "critical");
}

#[test]
fn scan_tarball_reads_a_file_and_stdin() {
    use std::io::Write;
    use std::process::Stdio;

    // Any fixture tarball will do; find lwfx-cp-exec's via its packument.
    let packument: Value = serde_json::from_str(
        &std::fs::read_to_string(common::fixture("cache/packuments/lwfx-cp-exec.json"))
            .expect("packument"),
    )
    .expect("json");
    let sri = packument["versions"]["1.0.0"]["integrity"]
        .as_str()
        .expect("integrity")
        .to_string();
    // Cache files are named by the hex form of the integrity.
    let entry = std::fs::read_dir(common::fixture("cache/tarballs"))
        .expect("dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| {
            let bytes = std::fs::read(p).expect("read");
            lockwatch_core::integrity::Integrity::parse(&sri)
                .expect("sri")
                .matches(&bytes)
        })
        .expect("tarball for lwfx-cp-exec");

    let out = lockwatch()
        .arg("scan-tarball")
        .arg(&entry)
        .args(["--format", "json", "--fail-on", "none", "--integrity", &sri])
        .output()
        .expect("run");
    let report = json_report(&out);
    assert_eq!(report["packages"][0]["name"], "lwfx-cp-exec");
    assert!(rule_ids(&report).contains("LW003"));
    assert!(!rule_ids(&report).contains("LW012"));

    let mut child = lockwatch()
        .args(["scan-tarball", "-", "--format", "json", "--fail-on", "high"])
        .args(["--name", "piped", "--package-version", "9.9.9"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&std::fs::read(&entry).expect("read"))
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    assert_eq!(
        out.status.code(),
        Some(1),
        "high finding with --fail-on high"
    );
    let report = json_report(&out);
    assert_eq!(report["lockfile"], "stdin");
    assert_eq!(report["packages"][0]["version"], "9.9.9");
    assert!(schema::validate(&load_schema(), &report).is_empty());
}

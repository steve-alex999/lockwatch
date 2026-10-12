//! "Never execute package code": the fixtures are full of install scripts
//! that would run curl, sh, node, PowerShell... These tests check that a
//! scan starts no process at all.

mod common;

use std::fs;
use std::path::Path;

/// 1. Static check: the core library does not even contain the code to
///    start a process.
#[test]
fn core_library_has_no_process_spawning_code() {
    let src = common::repo_root().join("crates/lockwatch-core/src");
    let mut offenders = Vec::new();
    visit(&src, &mut |path, text| {
        for line in text.lines() {
            if ["std::process", "process::Command", "Command::new"]
                .iter()
                .any(|needle| line.contains(needle))
            {
                offenders.push(format!("{}: {}", path.display(), line.trim()));
            }
        }
    });
    assert!(offenders.is_empty(), "{offenders:#?}");
}

fn visit(dir: &Path, f: &mut dyn FnMut(&Path, &str)) {
    for entry in fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            visit(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            f(&path, &fs::read_to_string(&path).expect("read"));
        }
    }
}

/// 2. Runtime check: put fake `sh`, `node`, `curl`, ... first on PATH. Each
///    one records that it was run. Scanning every malicious fixture must not
///    run any of them.
#[cfg(unix)]
#[test]
fn scanning_malicious_fixtures_runs_no_program_from_path() {
    use std::os::unix::fs::PermissionsExt;

    let trap = tempfile::tempdir().expect("tempdir");
    let log = trap.path().join("executed.log");
    for name in [
        "sh",
        "bash",
        "zsh",
        "node",
        "nodejs",
        "npm",
        "npx",
        "curl",
        "wget",
        "powershell",
        "pwsh",
        "python",
        "python3",
        "perl",
        "chmod",
        "base64",
        "node-gyp",
        "prebuild-install",
        "tsc",
    ] {
        let path = trap.path().join(name);
        fs::write(
            &path,
            format!("#!/bin/sh\necho {name} >> '{}'\n", log.display()),
        )
        .expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    for set in ["malicious", "benign", "mixed"] {
        let out = common::lockwatch()
            .env("PATH", trap.path())
            .arg("scan")
            .arg(common::fixture(&format!("lockfiles/{set}.json")))
            .args([
                "--offline",
                "--fail-on",
                "none",
                "--format",
                "json",
                "--cache-dir",
            ])
            .arg(common::fixture("cache"))
            .output()
            .expect("run");
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(
        !log.exists(),
        "a program was executed: {:?}",
        fs::read_to_string(&log)
    );
}

/// 3. Runtime check with strace (Linux, when strace is installed; CI
///    installs it): the only `execve` system call in the whole process tree
///    is the one that starts lockwatch itself.
#[cfg(target_os = "linux")]
#[test]
fn strace_sees_a_single_execve() {
    let Ok(probe) = std::process::Command::new("strace").arg("-V").output() else {
        eprintln!("strace not installed; skipping (CI runs this test)");
        return;
    };
    if !probe.status.success() {
        eprintln!("strace unusable; skipping");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let trace = dir.path().join("trace.txt");
    let out = std::process::Command::new("strace")
        .args(["-f", "-qq", "-e", "trace=execve,execveat", "-o"])
        .arg(&trace)
        .arg(env!("CARGO_BIN_EXE_lockwatch"))
        .arg("scan")
        .arg(common::fixture("lockfiles/malicious.json"))
        .args([
            "--offline",
            "--fail-on",
            "none",
            "--format",
            "json",
            "--cache-dir",
        ])
        .arg(common::fixture("cache"))
        .output()
        .expect("run strace");
    let text = fs::read_to_string(&trace).unwrap_or_default();
    if !out.status.success() && text.is_empty() {
        eprintln!("strace could not trace (ptrace not permitted?); skipping");
        return;
    }
    let execs: Vec<&str> = text.lines().filter(|l| l.contains("execve")).collect();
    assert_eq!(
        execs.len(),
        1,
        "unexpected exec calls:\n{}",
        execs.join("\n")
    );
    assert!(execs[0].contains("lockwatch"));
}

//! LW003: install-time code starts other programs through child_process.
//!
//! Looks at the files install scripts run (and the local files they
//! require, one level deep) and at inline `node -e` code. A call to
//! `exec`, `execSync`, `spawn`, `fork` (and their variants) at install time
//! can run anything on the machine.

use super::{Finding, Rule, Severity};
use crate::context::PackageContext;

pub struct InstallChildProcess;

impl Rule for InstallChildProcess {
    fn id(&self) -> &'static str {
        "LW003"
    }
    fn name(&self) -> &'static str {
        "Install-time file uses child_process"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn description(&self) -> &'static str {
        "a file run by an install script (or a file it requires, one level deep) calls \
         child_process exec, execSync, spawn or fork"
    }

    fn check(&self, ctx: &PackageContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for source in ctx.install_sources() {
            let line = |l: u32| source.has_lines.then_some(l);
            for hit in &source.facts.child_process_calls {
                findings.push(self.finding(
                    ctx,
                    Some(source.file),
                    line(hit.line),
                    &hit.evidence,
                    format!(
                        "Install-time code calls {}, which can run any program on the machine.",
                        hit.detail
                    ),
                ));
            }
            // Imported but we could not see the call (passed to a helper,
            // called through a computed name we cannot evaluate, ...).
            if source.facts.child_process_calls.is_empty() {
                if let Some(hit) = source.facts.child_process_imports.first() {
                    findings.push(
                        self.finding(
                            ctx,
                            Some(source.file),
                            line(hit.line),
                            &hit.evidence,
                            "Install-time code loads child_process; the call site could not be \
                         resolved statically."
                                .to_string(),
                        ),
                    );
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_helpers::ctx;

    const PKG: &str = r#"{"scripts": {"postinstall": "node install.js"}}"#;

    #[test]
    fn exec_in_postinstall_file() {
        let c = ctx(
            "p",
            &[
                ("package.json", PKG),
                (
                    "install.js",
                    "const { exec } = require('child_process');\nexec('curl x');",
                ),
            ],
        );
        let f = InstallChildProcess.check(&c);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].file.as_deref(), Some("install.js"));
        assert_eq!(f[0].line, Some(2));
        assert!(f[0].explanation.contains("child_process.exec"));
    }

    #[test]
    fn spawn_in_required_helper_and_inline_code() {
        let c = ctx(
            "p",
            &[
                (
                    "package.json",
                    r#"{"scripts": {"preinstall": "node -e \"require('child_process').execSync('id')\"",
                                    "postinstall": "node install.js"}}"#,
                ),
                ("install.js", "require('./lib/run');"),
                (
                    "lib/run.js",
                    "const cp = require('child_process'); cp.spawn('sh');",
                ),
            ],
        );
        let f = InstallChildProcess.check(&c);
        let files: Vec<_> = f.iter().map(|x| (x.file.as_deref(), x.line)).collect();
        assert_eq!(
            files,
            [(Some("lib/run.js"), Some(1)), (Some("package.json"), None)]
        );
    }

    #[test]
    fn child_process_outside_install_files_is_ignored() {
        let c = ctx(
            "p",
            &[
                ("package.json", r#"{"main": "index.js"}"#),
                ("index.js", "require('child_process').exec('git status');"),
            ],
        );
        assert!(InstallChildProcess.check(&c).is_empty());
    }
}

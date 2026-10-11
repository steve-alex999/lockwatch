//! LW001: the package has an install-time lifecycle script.
//!
//! Install scripts are how most malicious npm packages run their payload:
//! the code runs as soon as someone types `npm install`. Many legitimate
//! packages need one to build a native addon, so this is only `low`, and
//! `info` when the script does nothing but run node-gyp or prebuild-install.

use super::{Finding, Rule, Severity};
use crate::analysis::shell::programs;
use crate::context::PackageContext;

pub struct InstallScriptPresent;

/// Programs that only build or download a native addon.
const NATIVE_BUILD_TOOLS: [&str; 2] = ["node-gyp", "prebuild-install"];

impl Rule for InstallScriptPresent {
    fn id(&self) -> &'static str {
        "LW001"
    }
    fn name(&self) -> &'static str {
        "Install script present"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn description(&self) -> &'static str {
        "package.json has a preinstall, install, postinstall or prepare script \
         (info if it only runs node-gyp or prebuild-install)"
    }

    fn check(&self, ctx: &PackageContext) -> Vec<Finding> {
        ctx.install_scripts
            .iter()
            .map(|script| {
                let progs = programs(&script.command);
                let native_only = !progs.is_empty()
                    && progs
                        .iter()
                        .all(|p| NATIVE_BUILD_TOOLS.contains(&p.as_str()));
                let evidence = format!("\"{}\": \"{}\"", script.hook, script.command);
                let line = ctx.manifest.script_line(script.hook);
                if native_only {
                    let mut f = self.finding(
                        ctx,
                        Some("package.json"),
                        line,
                        &evidence,
                        format!(
                            "The {} script only runs a native build tool ({}).",
                            script.hook,
                            progs.join(", ")
                        ),
                    );
                    f.severity = Severity::Info;
                    f
                } else {
                    self.finding(
                        ctx,
                        Some("package.json"),
                        line,
                        &evidence,
                        format!(
                            "The package runs {} {} script automatically when it is installed.",
                            if script.hook == "install" { "an" } else { "a" },
                            script.hook
                        ),
                    )
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_helpers::{ctx, severities};

    #[test]
    fn flags_postinstall_scripts() {
        let c = ctx(
            "p",
            &[(
                "package.json",
                "{\n\"scripts\": {\n\"postinstall\": \"node setup.js\"\n}}",
            )],
        );
        let findings = InstallScriptPresent.check(&c);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].line, Some(3));
        assert_eq!(findings[0].evidence, "\"postinstall\": \"node setup.js\"");
    }

    #[test]
    fn flags_every_install_hook() {
        let c = ctx(
            "p",
            &[(
                "package.json",
                r#"{"scripts": {"preinstall": "echo hi", "install": "make", "prepare": "tsc"}}"#,
            )],
        );
        assert_eq!(
            severities(&InstallScriptPresent, &c),
            [Severity::Low, Severity::Low, Severity::Low]
        );
    }

    #[test]
    fn native_builds_are_info() {
        let c = ctx(
            "p",
            &[(
                "package.json",
                r#"{"scripts": {"install": "prebuild-install || node-gyp rebuild"}}"#,
            )],
        );
        assert_eq!(severities(&InstallScriptPresent, &c), [Severity::Info]);
    }

    #[test]
    fn ignores_other_scripts() {
        let c = ctx(
            "p",
            &[(
                "package.json",
                r#"{"scripts": {"test": "jest", "build": "tsc"}}"#,
            )],
        );
        assert!(InstallScriptPresent.check(&c).is_empty());
    }
}

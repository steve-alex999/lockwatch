//! Detection rules. Each rule lives in its own file and implements [`Rule`].
//!
//! A rule looks at one [`PackageContext`] and returns zero or more
//! [`Finding`]s. Rules never fail: missing data (no metadata, unparseable
//! file) simply means fewer findings.

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::analysis::text::truncate_chars;
use crate::analysis::MAX_EVIDENCE_CHARS;
use crate::context::PackageContext;

pub mod lw001_install_script;
pub mod lw002_remote_exec;
pub mod lw003_child_process;
pub mod lw004_network;
pub mod lw005_credentials;
pub mod lw006_dynamic_code;
pub mod lw007_obfuscation;

/// How bad a finding is. Declared from least to most severe, so the derived
/// `Ord` lets us write `severity >= Severity::Medium`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    pub const ALL: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
}

/// One piece of evidence that a package does something risky.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub package: String,
    pub version: String,
    /// File inside the package, if the finding is about a file.
    pub file: Option<String>,
    pub line: Option<u32>,
    /// Source excerpt, at most 200 characters.
    pub evidence: String,
    /// One sentence saying why this matters.
    pub explanation: String,
}

/// Every rule implements this trait. `Send + Sync` means a rule can be
/// shared between threads, which rayon needs to run rules in parallel.
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    /// The rule's usual severity (some rules raise or lower it per finding).
    fn severity(&self) -> Severity;
    fn description(&self) -> &'static str;
    fn check(&self, ctx: &PackageContext) -> Vec<Finding>;

    /// Helper for implementations: a finding of this rule with its default
    /// severity. The evidence is cut to 200 characters here, in one place.
    fn finding(
        &self,
        ctx: &PackageContext,
        file: Option<&str>,
        line: Option<u32>,
        evidence: &str,
        explanation: String,
    ) -> Finding {
        Finding {
            rule_id: self.id().to_string(),
            severity: self.severity(),
            package: ctx.name.clone(),
            version: ctx.version.clone(),
            file: file.map(str::to_string),
            line,
            evidence: truncate_chars(evidence.trim(), MAX_EVIDENCE_CHARS),
            explanation,
        }
    }
}

/// All rules, in ID order. The rules are unit structs (no fields), so they
/// can live in a `static` slice of trait-object references.
pub static RULES: &[&dyn Rule] = &[
    &lw001_install_script::InstallScriptPresent,
    &lw002_remote_exec::InstallScriptRemoteExec,
    &lw003_child_process::InstallChildProcess,
    &lw004_network::InstallNetworkAccess,
    &lw005_credentials::CredentialAccess,
    &lw006_dynamic_code::DynamicCodeExecution,
    &lw007_obfuscation::Obfuscation,
];

/// At most this many findings of one rule are kept per file, and per
/// package; the rest are counted in a warning.
const MAX_FINDINGS_PER_RULE_AND_FILE: usize = 5;
const MAX_FINDINGS_PER_RULE: usize = 25;

/// Run every rule on a package. Returns the findings (sorted by rule, file,
/// line) and warnings about findings that were cut by the limits.
pub fn run_rules(ctx: &PackageContext) -> (Vec<Finding>, Vec<String>) {
    // A package that failed integrity verification is not analysed further.
    if ctx.integrity_mismatch.is_some() {
        let findings = RULES
            .iter()
            .filter(|rule| rule.id() == "LW012")
            .flat_map(|rule| rule.check(ctx))
            .collect();
        return (findings, Vec::new());
    }
    // `par_iter` runs the rules on several threads; `collect` keeps them in
    // RULES order.
    let per_rule: Vec<Vec<Finding>> = RULES.par_iter().map(|rule| rule.check(ctx)).collect();

    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for mut rule_findings in per_rule {
        rule_findings.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
        let total = rule_findings.len();
        let mut kept: Vec<Finding> = Vec::new();
        for f in rule_findings {
            let same_file = kept.iter().filter(|k| k.file == f.file).count();
            if same_file < MAX_FINDINGS_PER_RULE_AND_FILE && kept.len() < MAX_FINDINGS_PER_RULE {
                kept.push(f);
            }
        }
        if kept.len() < total {
            if let Some(first) = kept.first() {
                warnings.push(format!(
                    "{} more {} findings not shown",
                    total - kept.len(),
                    first.rule_id
                ));
            }
        }
        findings.extend(kept);
    }
    (findings, warnings)
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use crate::registry::Packument;

    /// Build a context from in-memory files with no registry metadata.
    pub fn ctx(name: &str, files: &[(&str, &str)]) -> PackageContext {
        ctx_with_metadata(name, files, None, 0)
    }

    pub fn ctx_with_metadata(
        name: &str,
        files: &[(&str, &str)],
        metadata: Option<Packument>,
        now: i64,
    ) -> PackageContext {
        let bytes: Vec<(&str, &[u8])> = files.iter().map(|(p, c)| (*p, c.as_bytes())).collect();
        PackageContext::from_files(name, "1.0.0", &bytes, metadata, now)
    }

    /// Rule IDs and severities of a rule's findings, for compact asserts.
    pub fn severities(rule: &dyn Rule, ctx: &PackageContext) -> Vec<Severity> {
        rule.check(ctx).iter().map(|f| f.severity).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::ctx;
    use super::*;

    #[test]
    fn rules_are_in_id_order_and_unique() {
        let ids: Vec<&str> = RULES.iter().map(|r| r.id()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted);
        assert!(ids.iter().all(|id| id.len() == 5 && id.starts_with("LW")));
    }

    #[test]
    fn limits_findings_per_file() {
        let many_evals = "eval('x');\n".repeat(30);
        let c = ctx("p", &[("package.json", "{}"), ("a.js", &many_evals)]);
        let (findings, warnings) = run_rules(&c);
        let lw006 = findings.iter().filter(|f| f.rule_id == "LW006").count();
        assert_eq!(lw006, MAX_FINDINGS_PER_RULE_AND_FILE);
        assert_eq!(warnings, ["25 more LW006 findings not shown"]);
    }

    #[test]
    fn severity_order_and_parse() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Info < Severity::Low);
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
        assert_eq!(Severity::parse("nope"), None);
    }
}

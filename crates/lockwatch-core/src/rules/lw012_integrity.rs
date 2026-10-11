//! LW012: the tarball does not match the lockfile's integrity hash.
//!
//! The lockfile records a hash of every tarball. A different hash means the
//! registry, a mirror, a proxy or the local cache served different bytes
//! than the ones that were originally locked. The package is not analysed
//! further.

use super::{Finding, Rule, Severity};
use crate::context::PackageContext;

pub struct IntegrityMismatchRule;

/// `sha512-AbCd...` shortened to its first 32 characters, so both hashes
/// fit in the 200-character evidence.
fn short(sri: &str) -> String {
    if sri.chars().count() > 32 {
        format!("{}…", sri.chars().take(32).collect::<String>())
    } else {
        sri.to_string()
    }
}

impl Rule for IntegrityMismatchRule {
    fn id(&self) -> &'static str {
        "LW012"
    }
    fn name(&self) -> &'static str {
        "Integrity mismatch"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn description(&self) -> &'static str {
        "the downloaded tarball does not match the lockfile integrity hash"
    }

    fn check(&self, ctx: &PackageContext) -> Vec<Finding> {
        let Some(mismatch) = &ctx.integrity_mismatch else {
            return Vec::new();
        };
        vec![self.finding(
            ctx,
            None,
            None,
            &format!(
                "expected {} got {}",
                short(&mismatch.expected),
                short(&mismatch.actual)
            ),
            "The tarball does not match the integrity hash in the lockfile, so it may have been \
             tampered with."
                .to_string(),
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_mismatch() {
        let c = PackageContext::integrity_failure(
            "p",
            "1.0.0",
            "sha512-AAAA".into(),
            "sha512-BBBB".into(),
            0,
        );
        let f = IntegrityMismatchRule.check(&c);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].evidence, "expected sha512-AAAA got sha512-BBBB");
        assert_eq!(short(&"x".repeat(40)), format!("{}…", "x".repeat(32)));
    }

    #[test]
    fn mismatch_stops_other_rules() {
        let c = PackageContext::integrity_failure("expresss", "1.0.0", "a".into(), "b".into(), 0);
        let (findings, _) = crate::rules::run_rules(&c);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(ids, ["LW012"]);
    }

    #[test]
    fn verified_packages_have_no_finding() {
        let c = PackageContext::from_files("p", "1.0.0", &[], None, 0);
        assert!(IntegrityMismatchRule.check(&c).is_empty());
    }
}

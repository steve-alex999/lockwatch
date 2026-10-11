//! LW009: this version was published less than 7 days ago.
//!
//! Most malicious versions are found and removed within days. A version
//! that is only hours old has not had that scrutiny yet. Uses the publish
//! time from registry metadata (`time[version]`).

use super::{Finding, Rule, Severity};
use crate::context::PackageContext;
use crate::time::{parse_rfc3339, SECONDS_PER_DAY};

pub struct VeryNewVersion;

pub const NEW_VERSION_DAYS: i64 = 7;

fn plural(n: i64, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

impl Rule for VeryNewVersion {
    fn id(&self) -> &'static str {
        "LW009"
    }
    fn name(&self) -> &'static str {
        "Very new version"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn description(&self) -> &'static str {
        "this version was published less than 7 days before the scan (registry time)"
    }

    fn check(&self, ctx: &PackageContext) -> Vec<Finding> {
        let Some(published_text) = ctx.metadata.as_ref().and_then(|m| m.time.get(&ctx.version))
        else {
            return Vec::new();
        };
        let Some(published) = parse_rfc3339(published_text) else {
            return Vec::new();
        };
        let age = ctx.now - published;
        if age >= NEW_VERSION_DAYS * SECONDS_PER_DAY {
            return Vec::new();
        }
        let age_text = if age < 0 {
            "after the scan time".to_string()
        } else if age < SECONDS_PER_DAY {
            plural(age / 3600, "hour") + " before the scan"
        } else {
            plural(age / SECONDS_PER_DAY, "day") + " before the scan"
        };
        vec![self.finding(
            ctx,
            None,
            None,
            &format!("{}@{} published {published_text}", ctx.name, ctx.version),
            format!("This version was published {age_text}, so it has had little public scrutiny."),
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Packument;
    use crate::rules::test_helpers::ctx_with_metadata;
    use crate::time::parse_rfc3339;

    fn meta(published: &str) -> Packument {
        let mut p = Packument {
            name: "p".into(),
            ..Packument::default()
        };
        p.time.insert("1.0.0".into(), published.into());
        p
    }

    fn now() -> i64 {
        parse_rfc3339("2026-10-20T00:00:00Z").unwrap_or_default()
    }

    #[test]
    fn flags_versions_hours_or_days_old() {
        for (published, expect) in [
            ("2026-10-19T18:00:00Z", "6 hours"),
            ("2026-10-15T00:00:00Z", "5 days"),
        ] {
            let c = ctx_with_metadata("p", &[], Some(meta(published)), now());
            let f = VeryNewVersion.check(&c);
            assert_eq!(f.len(), 1);
            assert!(f[0].explanation.contains(expect), "{}", f[0].explanation);
        }
    }

    #[test]
    fn old_versions_and_missing_metadata_are_fine() {
        let c = ctx_with_metadata("p", &[], Some(meta("2026-10-01T00:00:00Z")), now());
        assert!(VeryNewVersion.check(&c).is_empty());
        let c = ctx_with_metadata("p", &[], None, now());
        assert!(VeryNewVersion.check(&c).is_empty());
    }
}

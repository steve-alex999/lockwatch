//! LW010: the publisher of this version did not publish any recent version.
//!
//! Account takeovers and hostile maintainer handovers show up as a new npm
//! user publishing a release. We compare `_npmUser` of this version with
//! the publishers of the previous 5 versions (ordered by publish time).

use super::{Finding, Rule, Severity};
use crate::context::PackageContext;
use crate::time::parse_rfc3339;

pub struct MaintainerChange;

pub const PREVIOUS_VERSIONS: usize = 5;

impl Rule for MaintainerChange {
    fn id(&self) -> &'static str {
        "LW010"
    }
    fn name(&self) -> &'static str {
        "Maintainer change"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn description(&self) -> &'static str {
        "the npm user who published this version did not publish any of the previous 5 versions"
    }

    fn check(&self, ctx: &PackageContext) -> Vec<Finding> {
        let Some(meta) = &ctx.metadata else {
            return Vec::new();
        };
        let publisher = |v: &str| meta.versions.get(v).and_then(|info| info.publisher.clone());
        let Some(current) = publisher(&ctx.version) else {
            return Vec::new();
        };

        // Versions ordered by publish time ("created"/"modified" are not
        // versions, so they are filtered out by the `versions` lookup).
        let mut timeline: Vec<(i64, &str)> = meta
            .time
            .iter()
            .filter(|(v, _)| meta.versions.contains_key(*v))
            .filter_map(|(v, t)| parse_rfc3339(t).map(|ts| (ts, v.as_str())))
            .collect();
        timeline.sort();
        let Some(pos) = timeline.iter().position(|(_, v)| *v == ctx.version) else {
            return Vec::new();
        };
        let previous = &timeline[pos.saturating_sub(PREVIOUS_VERSIONS)..pos];
        let mut earlier: Vec<String> = previous.iter().filter_map(|(_, v)| publisher(v)).collect();
        if earlier.is_empty() || earlier.contains(&current) {
            return Vec::new();
        }
        earlier.sort();
        earlier.dedup();
        vec![self.finding(
            ctx,
            None,
            None,
            &format!(
                "{} published by {current}; previous {} versions published by {}",
                ctx.version,
                previous.len(),
                earlier.join(", ")
            ),
            format!(
                "{current} did not publish any of the previous {} versions, which can mean an \
                 account takeover or a new maintainer.",
                previous.len()
            ),
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{Packument, VersionInfo};
    use crate::rules::test_helpers::ctx_with_metadata;

    /// Versions 0.1.0 .. 0.N.0 then 1.0.0 (the scanned one), one day apart.
    fn meta(previous: &[&str], current: &str) -> Packument {
        let mut p = Packument {
            name: "p".into(),
            ..Packument::default()
        };
        let mut add = |version: String, user: &str, day: usize| {
            p.versions.insert(
                version.clone(),
                VersionInfo {
                    publisher: Some(user.to_string()),
                    ..VersionInfo::default()
                },
            );
            p.time
                .insert(version, format!("2026-01-{:02}T00:00:00Z", day + 1));
        };
        for (i, user) in previous.iter().enumerate() {
            add(format!("0.{i}.0"), user, i);
        }
        add("1.0.0".to_string(), current, previous.len());
        p.time
            .insert("created".into(), "2026-01-01T00:00:00Z".into());
        p
    }

    fn check(m: Packument) -> Vec<Finding> {
        MaintainerChange.check(&ctx_with_metadata("p", &[], Some(m), 0))
    }

    #[test]
    fn new_publisher_is_flagged() {
        let f = check(meta(&["alice", "alice", "bob"], "mallory"));
        assert_eq!(f.len(), 1);
        assert!(f[0]
            .evidence
            .contains("previous 3 versions published by alice, bob"));
    }

    #[test]
    fn only_the_last_five_versions_count() {
        // mallory published 0.0.0, but that is 6 versions back.
        let f = check(meta(&["mallory", "a", "a", "a", "a", "a"], "mallory"));
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn same_publisher_or_first_version_is_fine() {
        assert!(check(meta(&["alice", "bob"], "bob")).is_empty());
        assert!(check(meta(&[], "alice")).is_empty());
    }
}

//! LW010: the publisher of this version did not publish any recent version.
//!
//! Account takeovers and hostile maintainer handovers show up as a new npm
//! user publishing a release. We compare who published this version with
//! who published the previous 5 versions (ordered by publish time).
//!
//! npm trusted publishing (OIDC from CI) records the CI identity, for
//! example "GitHub Actions", as the publisher, plus the maintainer who
//! approved the release. For such versions we compare the approver. A
//! switch from personal publishing to trusted publishing with no recorded
//! approver is reported as `info`, not `medium`: it changes who publishes,
//! but in the direction npm recommends.

use super::{Finding, Rule, Severity};
use crate::context::PackageContext;
use crate::registry::VersionInfo;
use crate::time::parse_rfc3339;

pub struct MaintainerChange;

pub const PREVIOUS_VERSIONS: usize = 5;

/// Who is behind a release.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Identity {
    /// A person's npm account (the publisher, or the approver of a
    /// trusted-published release).
    Person(String),
    /// A CI identity from trusted publishing with no recorded approver.
    Ci(String),
}

fn identity(info: &VersionInfo) -> Option<Identity> {
    if info.trusted_publisher {
        match &info.approver {
            Some(approver) => Some(Identity::Person(approver.clone())),
            None => info.publisher.clone().map(Identity::Ci),
        }
    } else {
        info.publisher.clone().map(Identity::Person)
    }
}

fn describe(info: &VersionInfo) -> String {
    let publisher = info.publisher.as_deref().unwrap_or("unknown");
    match (&info.trusted_publisher, &info.approver) {
        (true, Some(approver)) => {
            format!("{publisher} (trusted publishing, approved by {approver})")
        }
        (true, None) => format!("{publisher} (trusted publishing)"),
        _ => publisher.to_string(),
    }
}

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
        "the npm user who published this version did not publish any of the previous 5 versions \
         (info when the change is a move to npm trusted publishing)"
    }

    fn check(&self, ctx: &PackageContext) -> Vec<Finding> {
        let Some(meta) = &ctx.metadata else {
            return Vec::new();
        };
        let Some(current_info) = meta.versions.get(&ctx.version) else {
            return Vec::new();
        };
        let Some(current) = identity(current_info) else {
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
        let previous: Vec<&VersionInfo> = timeline[pos.saturating_sub(PREVIOUS_VERSIONS)..pos]
            .iter()
            .filter_map(|(_, v)| meta.versions.get(*v))
            .collect();
        let earlier: Vec<Identity> = previous.iter().filter_map(|i| identity(i)).collect();
        if earlier.is_empty() || earlier.contains(&current) {
            return Vec::new();
        }

        let mut earlier_names: Vec<String> = previous.iter().map(|i| describe(i)).collect();
        earlier_names.sort();
        earlier_names.dedup();
        let evidence = format!(
            "{} published by {}; previous {} versions published by {}",
            ctx.version,
            describe(current_info),
            previous.len(),
            earlier_names.join(", ")
        );
        match current {
            Identity::Person(name) => vec![self.finding(
                ctx,
                None,
                None,
                &evidence,
                format!(
                    "{name} did not publish any of the previous {} versions, which can mean an \
                     account takeover or a new maintainer.",
                    previous.len()
                ),
            )],
            Identity::Ci(_) => {
                let mut f = self.finding(
                    ctx,
                    None,
                    None,
                    &evidence,
                    "This version was published through npm trusted publishing (from CI) \
                     instead of a maintainer's account."
                        .to_string(),
                );
                f.severity = Severity::Info;
                vec![f]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Packument;
    use crate::rules::test_helpers::ctx_with_metadata;

    /// Versions 0.0.0 .. 0.N.0 then 1.0.0 (the scanned one), one day apart.
    fn meta(previous: &[VersionInfo], current: VersionInfo) -> Packument {
        let mut p = Packument {
            name: "p".into(),
            ..Packument::default()
        };
        let mut add = |version: String, info: VersionInfo, day: usize| {
            p.versions.insert(version.clone(), info);
            p.time
                .insert(version, format!("2026-01-{:02}T00:00:00Z", day + 1));
        };
        for (i, info) in previous.iter().enumerate() {
            add(format!("0.{i}.0"), info.clone(), i);
        }
        add("1.0.0".to_string(), current, previous.len());
        p.time
            .insert("created".into(), "2026-01-01T00:00:00Z".into());
        p
    }

    fn user(name: &str) -> VersionInfo {
        VersionInfo {
            publisher: Some(name.to_string()),
            ..VersionInfo::default()
        }
    }

    fn trusted(approver: Option<&str>) -> VersionInfo {
        VersionInfo {
            publisher: Some("GitHub Actions".to_string()),
            trusted_publisher: true,
            approver: approver.map(str::to_string),
            ..VersionInfo::default()
        }
    }

    fn check(m: Packument) -> Vec<Finding> {
        MaintainerChange.check(&ctx_with_metadata("p", &[], Some(m), 0))
    }

    #[test]
    fn new_publisher_is_flagged() {
        let f = check(meta(
            &[user("alice"), user("alice"), user("bob")],
            user("mallory"),
        ));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0]
            .evidence
            .contains("previous 3 versions published by alice, bob"));
    }

    #[test]
    fn only_the_last_five_versions_count() {
        // mallory published 0.0.0, but that is 6 versions back.
        let previous = [
            user("mallory"),
            user("a"),
            user("a"),
            user("a"),
            user("a"),
            user("a"),
        ];
        let f = check(meta(&previous, user("mallory")));
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn same_publisher_or_first_version_is_fine() {
        assert!(check(meta(&[user("alice"), user("bob")], user("bob"))).is_empty());
        assert!(check(meta(&[], user("alice"))).is_empty());
    }

    #[test]
    fn trusted_publishing_compares_the_approver() {
        // Approved by a previous publisher: not a maintainer change.
        assert!(check(meta(&[user("alice")], trusted(Some("alice")))).is_empty());
        // Approved by someone new: still a maintainer change.
        let f = check(meta(&[user("alice")], trusted(Some("mallory"))));
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].evidence.contains("approved by mallory"));
        // No approver recorded: a move to trusted publishing, reported as info.
        let f = check(meta(&[user("alice")], trusted(None)));
        assert_eq!(f[0].severity, Severity::Info);
        // Trusted publishing continued from earlier versions: nothing new.
        assert!(check(meta(&[trusted(None)], trusted(None))).is_empty());
    }
}

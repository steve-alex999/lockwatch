//! Parser for npm's `package-lock.json`, lockfile versions 2 and 3.
//!
//! Both versions have a flat `packages` map whose keys are install paths:
//!
//! ```json
//! "packages": {
//!   "": { "name": "my-app", "version": "1.0.0" },            // the project itself
//!   "node_modules/lodash": { "version": "4.17.21", "resolved": "...", "integrity": "..." },
//!   "node_modules/a/node_modules/@scope/b": { ... },          // nested copy
//!   "packages/local-lib": { ... },                            // workspace folder
//!   "node_modules/local-lib": { "resolved": "packages/local-lib", "link": true }
//! }
//! ```
//!
//! Version 1 only has the nested `dependencies` tree and is not supported.

use std::collections::{BTreeMap, HashSet};

use serde::Deserialize;

use super::{LockedPackage, LockfileParser, ParsedLockfile, SkippedEntry};
use crate::error::{CoreError, Result};

/// The parts of `package-lock.json` we read. Serde ignores every other field.
#[derive(Debug, Deserialize)]
struct RawLockfile {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<u64>,
    // BTreeMap (sorted by key) rather than HashMap so the output order is
    // deterministic, which keeps reports and snapshot tests stable.
    packages: Option<BTreeMap<String, RawEntry>>,
}

/// One value of the `packages` map. All fields are optional in practice.
#[derive(Debug, Default, Deserialize)]
struct RawEntry {
    name: Option<String>,
    version: Option<String>,
    resolved: Option<String>,
    integrity: Option<String>,
    #[serde(default)]
    link: bool,
    #[serde(default, rename = "inBundle")]
    in_bundle: bool,
}

/// Unit struct: the parser has no configuration, it only exists so we can
/// implement the `LockfileParser` trait for it.
pub struct NpmLockfileParser;

impl LockfileParser for NpmLockfileParser {
    fn format_name(&self) -> &'static str {
        "npm package-lock.json"
    }

    fn detect(&self, file_name: &str, content: &str) -> bool {
        file_name.ends_with("package-lock.json")
            || file_name.ends_with("npm-shrinkwrap.json")
            || content.contains("\"lockfileVersion\"")
    }

    fn parse(&self, content: &str) -> Result<ParsedLockfile> {
        let raw: RawLockfile = serde_json::from_str(content).map_err(CoreError::LockfileJson)?;

        match raw.lockfile_version {
            Some(2) | Some(3) => {}
            Some(1) => {
                return Err(CoreError::UnsupportedLockfile(
                    "lockfileVersion 1 is not supported; regenerate it with npm 7 or later \
                     (npm install --package-lock-only)"
                        .into(),
                ))
            }
            Some(other) => {
                return Err(CoreError::UnsupportedLockfile(format!(
                    "lockfileVersion {other} is not supported (expected 2 or 3)"
                )))
            }
            None => {
                return Err(CoreError::UnsupportedLockfile(
                    "missing lockfileVersion; is this a package-lock.json?".into(),
                ))
            }
        }

        let entries = raw.packages.ok_or_else(|| {
            CoreError::UnsupportedLockfile("lockfile has no \"packages\" map".into())
        })?;

        let mut parsed = ParsedLockfile::default();
        // The same name@version can be installed at several paths
        // (node_modules/a/node_modules/x and node_modules/b/node_modules/x).
        // We only need to scan it once, so remember what we have already seen.
        let mut seen: HashSet<(String, String, Option<String>)> = HashSet::new();

        for (path, entry) in entries {
            // The "" key is the project being scanned, not a dependency.
            if path.is_empty() {
                continue;
            }
            let name = entry
                .name
                .clone()
                .unwrap_or_else(|| name_from_path(&path).to_string());

            if let Some(reason) = skip_reason(&path, &entry) {
                parsed.skipped.push(SkippedEntry {
                    name,
                    version: entry.version.clone(),
                    reason: reason.to_string(),
                });
                continue;
            }

            let Some(version) = entry.version.clone() else {
                parsed.skipped.push(SkippedEntry {
                    name,
                    version: None,
                    reason: "lockfile entry has no version".into(),
                });
                continue;
            };

            let key = (name.clone(), version.clone(), entry.integrity.clone());
            if seen.insert(key) {
                parsed.packages.push(LockedPackage {
                    name,
                    version,
                    resolved: entry.resolved,
                    integrity: entry.integrity,
                });
            }
        }

        // Sort for stable output regardless of where packages sit in the tree.
        parsed
            .packages
            .sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
        parsed.skipped.dedup();
        Ok(parsed)
    }
}

/// Decide whether an entry is something we do not download.
/// Returns `None` for a normal registry package.
fn skip_reason(path: &str, entry: &RawEntry) -> Option<&'static str> {
    if entry.link {
        return Some("link: dependency (local folder)");
    }
    // Keys that are not under node_modules are workspace folders in the
    // project itself, for example "packages/local-lib".
    if !path.contains("node_modules/") {
        return Some("workspace package (local folder)");
    }
    if entry.in_bundle {
        return Some("bundled dependency (scanned as part of its parent tarball)");
    }
    if let Some(resolved) = entry.resolved.as_deref() {
        if resolved.starts_with("file:") {
            return Some("file: dependency");
        }
        if resolved.starts_with("git") || resolved.starts_with("github:") {
            return Some("git dependency (not supported in v1)");
        }
    }
    None
}

/// "node_modules/a/node_modules/@scope/b" -> "@scope/b".
///
/// The return type borrows from the input (`&str` with the same lifetime),
/// so no new String is allocated.
fn name_from_path(path: &str) -> &str {
    match path.rfind("node_modules/") {
        Some(idx) => &path[idx + "node_modules/".len()..],
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<ParsedLockfile> {
        NpmLockfileParser.parse(json)
    }

    #[test]
    fn parses_v3_packages_and_skips_root() {
        let lock = r#"{
          "name": "demo", "lockfileVersion": 3,
          "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/left-pad": {
              "version": "1.3.0",
              "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
              "integrity": "sha512-abc"
            },
            "node_modules/@scope/pkg": { "version": "2.0.0" }
          }
        }"#;
        let parsed = parse(lock).expect("valid lockfile");
        assert_eq!(parsed.packages.len(), 2);
        assert_eq!(parsed.packages[0].name, "@scope/pkg");
        assert_eq!(parsed.packages[0].resolved, None);
        assert_eq!(parsed.packages[1].spec(), "left-pad@1.3.0");
        assert_eq!(parsed.packages[1].integrity.as_deref(), Some("sha512-abc"));
        assert!(parsed.skipped.is_empty());
    }

    #[test]
    fn parses_v2_and_deduplicates_nested_copies() {
        let lock = r#"{
          "lockfileVersion": 2,
          "packages": {
            "": {},
            "node_modules/a": { "version": "1.0.0", "integrity": "sha512-a" },
            "node_modules/b/node_modules/a": { "version": "1.0.0", "integrity": "sha512-a" },
            "node_modules/c/node_modules/a": { "version": "2.0.0", "integrity": "sha512-a2" },
            "node_modules/b": { "version": "1.0.0" },
            "node_modules/c": { "version": "1.0.0" }
          },
          "dependencies": {}
        }"#;
        let parsed = parse(lock).expect("valid lockfile");
        let specs: Vec<String> = parsed.packages.iter().map(|p| p.spec()).collect();
        assert_eq!(specs, ["a@1.0.0", "a@2.0.0", "b@1.0.0", "c@1.0.0"]);
    }

    #[test]
    fn uses_name_field_for_aliases() {
        // `npm install foo@npm:bar@1.0.0` installs bar under the folder foo.
        let lock = r#"{ "lockfileVersion": 3, "packages": {
            "node_modules/foo": { "name": "bar", "version": "1.0.0" } } }"#;
        let parsed = parse(lock).expect("valid lockfile");
        assert_eq!(parsed.packages[0].spec(), "bar@1.0.0");
    }

    #[test]
    fn skips_local_git_and_bundled_entries_with_reasons() {
        let lock = r#"{ "lockfileVersion": 3, "packages": {
            "": { "name": "root" },
            "packages/local-lib": { "name": "local-lib", "version": "0.1.0" },
            "node_modules/local-lib": { "resolved": "packages/local-lib", "link": true },
            "node_modules/filedep": { "version": "1.0.0", "resolved": "file:../filedep" },
            "node_modules/gitdep": { "version": "1.0.0", "resolved": "git+ssh://git@github.com/x/y.git#abc" },
            "node_modules/parent/node_modules/inner": { "version": "1.0.0", "inBundle": true },
            "node_modules/noversion": { "resolved": "https://example.invalid/x.tgz" }
        } }"#;
        let parsed = parse(lock).expect("valid lockfile");
        assert!(parsed.packages.is_empty());
        let reasons: Vec<(&str, &str)> = parsed
            .skipped
            .iter()
            .map(|s| (s.name.as_str(), s.reason.as_str()))
            .collect();
        assert_eq!(
            reasons,
            [
                ("filedep", "file: dependency"),
                ("gitdep", "git dependency (not supported in v1)"),
                ("local-lib", "link: dependency (local folder)"),
                ("noversion", "lockfile entry has no version"),
                (
                    "inner",
                    "bundled dependency (scanned as part of its parent tarball)"
                ),
                ("local-lib", "workspace package (local folder)"),
            ]
        );
    }

    #[test]
    fn rejects_v1_lockfiles() {
        let err = parse(r#"{ "lockfileVersion": 1, "dependencies": {} }"#).unwrap_err();
        assert!(err
            .to_string()
            .contains("lockfileVersion 1 is not supported"));
    }

    #[test]
    fn rejects_missing_packages_map_and_bad_json() {
        let err = parse(r#"{ "lockfileVersion": 3 }"#).unwrap_err();
        assert!(err.to_string().contains("no \"packages\" map"));
        let err = parse("not json").unwrap_err();
        assert!(matches!(err, CoreError::LockfileJson(_)));
    }

    #[test]
    fn name_from_nested_path() {
        assert_eq!(name_from_path("node_modules/a/node_modules/@s/b"), "@s/b");
        assert_eq!(name_from_path("node_modules/x"), "x");
    }
}

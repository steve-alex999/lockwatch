//! `PackageContext`: everything the rules know about one package.
//!
//! Built once per package after extraction: the manifest, the file list,
//! analysis facts for every JavaScript file, which files run at install
//! time, and registry metadata. Rules only read from it, so all rules can
//! look at the same context in parallel.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use rayon::prelude::*;

use crate::analysis::js::analyze_js;
use crate::analysis::shell::{script_targets, ScriptTarget};
use crate::analysis::JsFacts;
use crate::extract::{Extraction, HEAD_BYTES};
use crate::manifest::Manifest;
use crate::registry::Packument;
use crate::time::UnixSeconds;

/// One file in the package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    /// First bytes, for magic-number checks.
    pub head: Vec<u8>,
    /// False if the file was too large to analyse.
    pub analysed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallScript {
    pub hook: &'static str,
    pub command: String,
}

/// Code passed inline to `node -e` in an install script.
#[derive(Debug, Clone, PartialEq)]
pub struct InlineScript {
    pub hook: &'static str,
    pub facts: JsFacts,
}

/// A shell script run by an install script (for LW002).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellScript {
    pub path: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityMismatch {
    pub expected: String,
    pub actual: String,
}

/// A piece of JavaScript that runs at install time.
pub struct InstallSource<'a> {
    /// File to show in findings (`package.json` for inline code).
    pub file: &'a str,
    /// False for inline code, whose line numbers are not file lines.
    pub has_lines: bool,
    pub facts: &'a JsFacts,
}

#[derive(Debug, Clone, Default)]
pub struct PackageContext {
    pub name: String,
    pub version: String,
    pub manifest: Manifest,
    pub files: Vec<FileInfo>,
    /// Facts for every analysed JavaScript file, keyed by path.
    pub js: BTreeMap<String, JsFacts>,
    pub install_scripts: Vec<InstallScript>,
    /// JavaScript files that run at install time: the files install scripts
    /// run, plus the local files those require (one level deep).
    pub install_files: BTreeSet<String>,
    pub install_inline: Vec<InlineScript>,
    pub install_shell: Vec<ShellScript>,
    /// Registry metadata, if it could be fetched.
    pub metadata: Option<Packument>,
    /// Set when the tarball failed integrity verification (LW012). The
    /// package is then not analysed further.
    pub integrity_mismatch: Option<IntegrityMismatch>,
    /// "Now" for time-based rules (LW009).
    pub now: UnixSeconds,
    /// Notes for the report (files skipped, metadata unavailable, ...).
    pub warnings: Vec<String>,
}

/// Is this a file Node would run as JavaScript?
fn is_js(path: &str) -> bool {
    [".js", ".cjs", ".mjs"]
        .iter()
        .any(|ext| path.ends_with(ext))
}

impl PackageContext {
    /// Build from an extracted package on disk.
    pub fn from_extraction(
        name: &str,
        version: &str,
        dir: &Path,
        extraction: Extraction,
        metadata: Option<Packument>,
        now: UnixSeconds,
    ) -> PackageContext {
        let files: Vec<FileInfo> = extraction
            .files
            .into_iter()
            .map(|f| FileInfo {
                path: f.path,
                size: f.size,
                head: f.head,
                analysed: f.written,
            })
            .collect();
        let written: HashSet<String> = files
            .iter()
            .filter(|f| f.analysed)
            .map(|f| f.path.clone())
            .collect();
        // A closure that reads a file of this package from disk. It only
        // reads files that extraction actually wrote.
        let read = |path: &str| -> Option<Vec<u8>> {
            if written.contains(path) {
                std::fs::read(dir.join(path)).ok()
            } else {
                None
            }
        };
        let mut ctx = Self::build(name, version, files, &read, metadata, now);
        ctx.warnings.splice(0..0, extraction.warnings);
        ctx
    }

    /// Build from in-memory files `(path, contents)`. Used by tests.
    pub fn from_files(
        name: &str,
        version: &str,
        contents: &[(&str, &[u8])],
        metadata: Option<Packument>,
        now: UnixSeconds,
    ) -> PackageContext {
        let map: HashMap<String, Vec<u8>> = contents
            .iter()
            .map(|(p, c)| (p.to_string(), c.to_vec()))
            .collect();
        let files = contents
            .iter()
            .map(|(p, c)| FileInfo {
                path: p.to_string(),
                size: c.len() as u64,
                head: c[..c.len().min(HEAD_BYTES as usize)].to_vec(),
                analysed: true,
            })
            .collect();
        let read = |path: &str| map.get(path).cloned();
        Self::build(name, version, files, &read, metadata, now)
    }

    /// A context for a package whose tarball failed verification.
    pub fn integrity_failure(
        name: &str,
        version: &str,
        expected: String,
        actual: String,
        now: UnixSeconds,
    ) -> PackageContext {
        PackageContext {
            name: name.to_string(),
            version: version.to_string(),
            integrity_mismatch: Some(IntegrityMismatch { expected, actual }),
            now,
            ..PackageContext::default()
        }
    }

    /// The shared builder. `read` returns a file's bytes; it must be `Sync`
    /// because files are analysed on several threads at once.
    fn build(
        name: &str,
        version: &str,
        files: Vec<FileInfo>,
        read: &(dyn Fn(&str) -> Option<Vec<u8>> + Sync),
        metadata: Option<Packument>,
        now: UnixSeconds,
    ) -> PackageContext {
        let mut warnings = Vec::new();
        let manifest = match read("package.json").and_then(|b| Manifest::parse(&b)) {
            Some(m) => m,
            None => {
                warnings.push("package.json is missing or not valid JSON".to_string());
                Manifest::default()
            }
        };
        let file_set: HashSet<&str> = files.iter().map(|f| f.path.as_str()).collect();

        // 1. What do the install scripts run?
        let install_scripts: Vec<InstallScript> = manifest
            .install_scripts()
            .into_iter()
            .map(|(hook, command)| InstallScript { hook, command })
            .collect();
        let mut direct_install_files = BTreeSet::new();
        let mut install_inline = Vec::new();
        let mut install_shell = Vec::new();
        for script in &install_scripts {
            let mut targets = script_targets(&script.command);
            // Follow `npm run <name>` one level.
            let nested: Vec<ScriptTarget> = targets
                .iter()
                .filter_map(|t| match t {
                    ScriptTarget::NpmRun(name) => manifest.script(name).map(script_targets),
                    _ => None,
                })
                .flatten()
                .collect();
            targets.extend(nested);
            for target in targets {
                match target {
                    ScriptTarget::JsFile(spec) => {
                        if let Some(path) = resolve_module(&file_set, "", &spec) {
                            direct_install_files.insert(path);
                        }
                    }
                    ScriptTarget::InlineJs(code) => install_inline.push(InlineScript {
                        hook: script.hook,
                        facts: analyze_js("inline.js", &code),
                    }),
                    ScriptTarget::ShellFile(spec) => {
                        let Some(path) = normalize_join("", &spec) else {
                            continue;
                        };
                        if let Some(bytes) = read(&path) {
                            let text = String::from_utf8_lossy(&bytes).into_owned();
                            install_shell.push(ShellScript { path, text });
                        }
                    }
                    ScriptTarget::NpmRun(_) => {}
                }
            }
        }

        // 2. Analyse every JavaScript file, plus install targets whatever
        //    their extension (e.g. `node install` runs the file `install`).
        let to_analyse: Vec<&str> = files
            .iter()
            .filter(|f| f.analysed && (is_js(&f.path) || direct_install_files.contains(&f.path)))
            .map(|f| f.path.as_str())
            .collect();
        // `par_iter` (rayon) spreads the work over all CPU cores.
        let js: BTreeMap<String, JsFacts> = to_analyse
            .par_iter()
            .filter_map(|path| {
                let bytes = read(path)?;
                let source = String::from_utf8_lossy(&bytes);
                Some((path.to_string(), analyze_js(path, &source)))
            })
            .collect();

        // 3. Files required by install-time files are install-time too.
        let mut install_files = direct_install_files.clone();
        for file in &direct_install_files {
            let Some(facts) = js.get(file) else { continue };
            let dir = file.rsplit_once('/').map_or("", |(d, _)| d);
            for spec in &facts.local_requires {
                if let Some(path) = resolve_module(&file_set, dir, spec) {
                    if js.contains_key(&path) {
                        install_files.insert(path);
                    }
                }
            }
        }

        PackageContext {
            name: name.to_string(),
            version: version.to_string(),
            manifest,
            files,
            js,
            install_scripts,
            install_files,
            install_inline,
            install_shell,
            metadata,
            integrity_mismatch: None,
            now,
            warnings,
        }
    }

    /// All JavaScript that runs at install time: files, then inline code.
    pub fn install_sources(&self) -> Vec<InstallSource<'_>> {
        let files = self.install_files.iter().filter_map(|path| {
            self.js.get(path).map(|facts| InstallSource {
                file: path.as_str(),
                has_lines: true,
                facts,
            })
        });
        let inline = self.install_inline.iter().map(|inline| InstallSource {
            file: "package.json",
            has_lines: false,
            facts: &inline.facts,
        });
        files.chain(inline).collect()
    }
}

/// Join a module specifier onto a directory inside the package and resolve
/// it like Node does: exact file, then `.js`/`.cjs`/`.mjs`/`.json`, then
/// `index.js`.
pub fn resolve_module(files: &HashSet<&str>, from_dir: &str, spec: &str) -> Option<String> {
    let base = normalize_join(from_dir, spec)?;
    let candidates = [
        base.clone(),
        format!("{base}.js"),
        format!("{base}.cjs"),
        format!("{base}.mjs"),
        format!("{base}/index.js"),
    ];
    candidates.into_iter().find(|c| files.contains(c.as_str()))
}

/// `normalize_join("lib", "../x/./y")` -> `Some("x/y")`. Returns `None` if
/// the path would leave the package root, or for absolute paths.
pub fn normalize_join(from_dir: &str, spec: &str) -> Option<String> {
    if spec.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = from_dir.split('/').filter(|p| !p.is_empty()).collect();
    for part in spec.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            p => parts.push(p),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_and_resolves_paths() {
        assert_eq!(normalize_join("lib", "../x/./y").as_deref(), Some("x/y"));
        assert_eq!(normalize_join("", "./a.js").as_deref(), Some("a.js"));
        assert_eq!(normalize_join("", "../escape"), None);
        assert_eq!(normalize_join("", "/etc/passwd"), None);
        let files: HashSet<&str> = ["lib/a.js", "lib/b/index.js", "c"].into_iter().collect();
        assert_eq!(
            resolve_module(&files, "lib", "./a").as_deref(),
            Some("lib/a.js")
        );
        assert_eq!(
            resolve_module(&files, "lib", "./b").as_deref(),
            Some("lib/b/index.js")
        );
        assert_eq!(resolve_module(&files, "", "c").as_deref(), Some("c"));
        assert_eq!(resolve_module(&files, "", "missing"), None);
    }

    #[test]
    fn finds_install_time_files_one_level_deep() {
        let manifest = br#"{"name":"x","version":"1.0.0",
            "scripts":{"postinstall":"node scripts/setup && npm run extra","extra":"node -e \"1\""}}"#;
        let ctx = PackageContext::from_files(
            "x",
            "1.0.0",
            &[
                ("package.json", manifest),
                (
                    "scripts/setup.js",
                    b"require('./helper'); require('../index.js');",
                ),
                ("scripts/helper.js", b"require('./deeper');"),
                ("scripts/deeper.js", b"1"),
                ("index.js", b"module.exports = 1"),
            ],
            None,
            0,
        );
        let install: Vec<&str> = ctx.install_files.iter().map(String::as_str).collect();
        // deeper.js is two levels away, so it is not included.
        assert_eq!(
            install,
            ["index.js", "scripts/helper.js", "scripts/setup.js"]
        );
        assert_eq!(ctx.install_inline.len(), 1);
        assert_eq!(ctx.install_sources().len(), 4);
        assert_eq!(ctx.js.len(), 4);
    }

    #[test]
    fn missing_manifest_is_a_warning() {
        let ctx = PackageContext::from_files("x", "1.0.0", &[("a.js", b"1")], None, 0);
        assert_eq!(ctx.warnings.len(), 1);
        assert!(ctx.install_scripts.is_empty());
    }
}

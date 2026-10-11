//! Talking to the npm registry: tarball downloads and package metadata.
//!
//! All network access in lockwatch goes through [`RegistryClient`]. It adds:
//! - a timeout per request and retries with exponential backoff,
//! - a size limit on every response,
//! - integrity verification before anything is written to the cache,
//! - an allow-list of hosts, so a lockfile cannot make the scanner request
//!   arbitrary URLs (for example cloud metadata endpoints) when it runs as a
//!   service on untrusted input,
//! - `--offline` mode, which never touches the network.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::cache::{tarball_key, Cache};
use crate::error::{CoreError, Result};
use crate::integrity::{sri_from_sha1_hex, Integrity};
use crate::lockfile::LockedPackage;

pub const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";

/// Public registries whose tarball URLs are always accepted. Lockfiles made
/// with yarn's mirror point at registry.yarnpkg.com for the same tarballs.
const PUBLIC_REGISTRY_HOSTS: [&str; 2] = ["registry.npmjs.org", "registry.yarnpkg.com"];

#[derive(Debug, Clone)]
pub struct RegistryOptions {
    /// Base URL of the registry, without a trailing slash.
    pub registry: String,
    /// Use the cache only; never make a request.
    pub offline: bool,
    /// Timeout for one HTTP request, including reading the body.
    pub timeout: Duration,
    /// How many times to retry a failed request (network error, 429, 5xx).
    pub retries: u32,
    /// First retry waits this long; each later retry waits twice as long.
    pub backoff: Duration,
    pub max_tarball_bytes: u64,
    pub max_metadata_bytes: u64,
}

impl Default for RegistryOptions {
    fn default() -> Self {
        RegistryOptions {
            registry: DEFAULT_REGISTRY.to_string(),
            offline: false,
            timeout: Duration::from_secs(60),
            retries: 3,
            backoff: Duration::from_millis(500),
            max_tarball_bytes: 100 * 1024 * 1024,
            // Full metadata for very popular packages is tens of MB.
            max_metadata_bytes: 200 * 1024 * 1024,
        }
    }
}

/// Registry metadata for one package name, trimmed to what the rules need.
/// The full document (a "packument") can be many megabytes; we cache only
/// this.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Packument {
    pub name: String,
    pub versions: BTreeMap<String, VersionInfo>,
    /// version -> publish time (RFC 3339). Also has "created" and "modified".
    pub time: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionInfo {
    /// npm user who published this version (`_npmUser.name`).
    pub publisher: Option<String>,
    pub tarball: Option<String>,
    pub integrity: Option<String>,
}

/// Result of making sure a tarball is in the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchedTarball {
    /// The verified tarball is at this path in the cache.
    Cached(PathBuf),
    /// The downloaded bytes do not match the lockfile's integrity (LW012).
    /// Nothing was written to the cache.
    IntegrityMismatch { expected: String, actual: String },
}

pub struct RegistryClient {
    http: reqwest::Client,
    cache: Cache,
    opts: RegistryOptions,
    registry_url: Url,
}

impl RegistryClient {
    pub fn new(cache: Cache, mut opts: RegistryOptions) -> Result<Self> {
        opts.registry = opts.registry.trim_end_matches('/').to_string();
        let registry_url = Url::parse(&opts.registry).map_err(|e| CoreError::DisallowedUrl {
            url: opts.registry.clone(),
            reason: format!("invalid registry URL: {e}"),
        })?;
        let http = reqwest::Client::builder()
            .user_agent(concat!(
                "lockwatch/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/steve-alex999/lookwatch)"
            ))
            .timeout(opts.timeout)
            .connect_timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| CoreError::Network {
                url: opts.registry.clone(),
                message: format!("cannot build HTTP client: {e}"),
            })?;
        Ok(RegistryClient {
            http,
            cache,
            opts,
            registry_url,
        })
    }

    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    pub fn options(&self) -> &RegistryOptions {
        &self.opts
    }

    /// The URL to download a package from: the lockfile's `resolved` URL, or
    /// the standard registry URL when it is missing. Rejects URLs that are not
    /// on an allowed registry host.
    pub fn tarball_url(&self, pkg: &LockedPackage) -> Result<String> {
        let url = match &pkg.resolved {
            Some(resolved) => resolved.clone(),
            None => {
                // "@scope/name" -> ".../@scope/name/-/name-1.0.0.tgz"
                let base = pkg.name.rsplit('/').next().unwrap_or(&pkg.name);
                format!(
                    "{}/{}/-/{}-{}.tgz",
                    self.opts.registry, pkg.name, base, pkg.version
                )
            }
        };
        self.check_allowed(&url)?;
        Ok(url)
    }

    fn check_allowed(&self, url: &str) -> Result<()> {
        let disallowed = |reason: &str| CoreError::DisallowedUrl {
            url: url.to_string(),
            reason: reason.to_string(),
        };
        let parsed = Url::parse(url).map_err(|_| disallowed("not a valid URL"))?;
        // Anything under the configured registry is fine, even plain http
        // (useful for a local mirror or a test server).
        let same_origin = parsed.scheme() == self.registry_url.scheme()
            && parsed.host_str() == self.registry_url.host_str()
            && parsed.port_or_known_default() == self.registry_url.port_or_known_default();
        if same_origin {
            return Ok(());
        }
        if parsed.scheme() != "https" {
            return Err(disallowed("only https URLs are fetched"));
        }
        match parsed.host_str() {
            Some(host) if PUBLIC_REGISTRY_HOSTS.contains(&host) => Ok(()),
            _ => Err(disallowed(
                "host is not the configured registry (use --registry to scan a private registry)",
            )),
        }
    }

    /// Make sure the package's tarball is in the cache and matches the
    /// lockfile integrity. Downloads it unless it is already cached.
    pub async fn ensure_tarball(&self, pkg: &LockedPackage) -> Result<FetchedTarball> {
        let url = self.tarball_url(pkg)?;
        let key = tarball_key(pkg, &url)?;
        let path = self.cache.tarball_path(&key);
        if path.exists() {
            // Verified again when it is read for analysis (see scan.rs).
            return Ok(FetchedTarball::Cached(path));
        }
        if self.opts.offline {
            return Err(CoreError::OfflineCacheMiss(format!(
                "tarball for {}",
                pkg.spec()
            )));
        }

        let bytes = self.get(&url, self.opts.max_tarball_bytes).await?;
        if let Some(sri) = &pkg.integrity {
            let expected = Integrity::parse(sri)?;
            if !expected.matches(&bytes) {
                let actual = Integrity::of(expected.algorithm, &bytes).to_sri();
                return Ok(FetchedTarball::IntegrityMismatch {
                    expected: expected.to_sri(),
                    actual,
                });
            }
        }
        let path = self.cache.write_tarball(&key, &bytes)?;
        Ok(FetchedTarball::Cached(path))
    }

    /// Registry metadata for `name`, from the cache if it already knows all
    /// of `versions`, otherwise from the registry (and then cached).
    pub async fn packument(&self, name: &str, versions: &[String]) -> Result<Packument> {
        if let Some(cached) = self.cache.read_packument(name)? {
            if versions.iter().all(|v| cached.versions.contains_key(v)) {
                return Ok(cached);
            }
        }
        if self.opts.offline {
            return Err(CoreError::OfflineCacheMiss(format!(
                "registry metadata for {name}"
            )));
        }
        // Scoped names are requested as "@scope%2fname".
        let url = format!("{}/{}", self.opts.registry, name.replace('/', "%2f"));
        let bytes = self.get(&url, self.opts.max_metadata_bytes).await?;
        let packument = parse_packument(name, &bytes)?;
        self.cache.write_packument(&packument)?;
        Ok(packument)
    }

    /// GET with retries and exponential backoff.
    async fn get(&self, url: &str, limit: u64) -> Result<Vec<u8>> {
        let mut attempt = 0;
        loop {
            match self.get_once(url, limit).await {
                Ok(bytes) => return Ok(bytes),
                Err(err) if attempt < self.opts.retries && is_retryable(&err) => {
                    let delay = self.opts.backoff * 2u32.saturating_pow(attempt);
                    tracing::debug!(url, %err, ?delay, "retrying request");
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn get_once(&self, url: &str, limit: u64) -> Result<Vec<u8>> {
        let network_error = |e: reqwest::Error| CoreError::Network {
            url: url.to_string(),
            message: e.to_string(),
        };
        let mut response = self.http.get(url).send().await.map_err(network_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(CoreError::HttpStatus {
                url: url.to_string(),
                status: status.as_u16(),
            });
        }
        let too_large = || CoreError::TooLarge {
            url: url.to_string(),
            limit,
        };
        if response.content_length().is_some_and(|len| len > limit) {
            return Err(too_large());
        }
        // Read the body chunk by chunk so a server that lies about (or omits)
        // Content-Length still cannot make us buffer more than `limit` bytes.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(network_error)? {
            if (body.len() + chunk.len()) as u64 > limit {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

fn is_retryable(err: &CoreError) -> bool {
    match err {
        CoreError::Network { .. } => true,
        CoreError::HttpStatus { status, .. } => *status == 429 || *status >= 500,
        _ => false,
    }
}

/// The parts of a full registry document we read.
#[derive(Deserialize)]
struct RawPackument {
    #[serde(default)]
    versions: BTreeMap<String, RawVersion>,
    // Values are normally strings, but unpublished packages have an object
    // here, so accept any JSON value and keep only the strings.
    #[serde(default)]
    time: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct RawVersion {
    // Usually {"name": "...", "email": "..."}, a plain string in very old
    // packages, so read it as a generic JSON value.
    #[serde(rename = "_npmUser")]
    npm_user: Option<serde_json::Value>,
    dist: Option<RawDist>,
}

#[derive(Deserialize)]
struct RawDist {
    tarball: Option<String>,
    integrity: Option<String>,
    shasum: Option<String>,
}

/// Turn the registry's JSON into our trimmed [`Packument`].
pub fn parse_packument(name: &str, bytes: &[u8]) -> Result<Packument> {
    let raw: RawPackument = serde_json::from_slice(bytes)
        .map_err(|e| CoreError::Metadata(format!("invalid metadata for {name}: {e}")))?;
    let versions = raw
        .versions
        .into_iter()
        .map(|(version, v)| {
            let publisher = v.npm_user.and_then(|user| match user {
                serde_json::Value::Object(map) => {
                    map.get("name").and_then(|n| n.as_str()).map(str::to_string)
                }
                // "name <email>" -> "name"
                serde_json::Value::String(s) => s.split(" <").next().map(|n| n.trim().to_string()),
                _ => None,
            });
            let (tarball, integrity) = match v.dist {
                Some(dist) => {
                    let integrity = dist
                        .integrity
                        .or_else(|| dist.shasum.as_deref().and_then(sri_from_sha1_hex));
                    (dist.tarball, integrity)
                }
                None => (None, None),
            };
            let info = VersionInfo {
                publisher,
                tarball,
                integrity,
            };
            (version, info)
        })
        .collect();
    let time = raw
        .time
        .into_iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
        .collect();
    Ok(Packument {
        name: name.to_string(),
        versions,
        time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrity::Algorithm;
    use crate::test_support::MockRegistry;

    fn pkg(name: &str, resolved: Option<String>, data: &[u8]) -> LockedPackage {
        LockedPackage {
            name: name.into(),
            version: "1.0.0".into(),
            resolved,
            integrity: Some(Integrity::of(Algorithm::Sha512, data).to_sri()),
        }
    }

    fn client(dir: &std::path::Path, registry: &str, offline: bool) -> RegistryClient {
        let opts = RegistryOptions {
            registry: registry.into(),
            offline,
            backoff: Duration::from_millis(1),
            ..RegistryOptions::default()
        };
        RegistryClient::new(Cache::new(dir), opts).expect("client")
    }

    #[tokio::test]
    async fn downloads_verifies_and_caches() {
        let server =
            MockRegistry::start(vec![("/a/-/a-1.0.0.tgz", 200, b"tarball".to_vec())]).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let c = client(dir.path(), &server.url, false);
        let p = pkg("a", None, b"tarball");

        let first = c.ensure_tarball(&p).await.expect("fetch");
        assert!(matches!(first, FetchedTarball::Cached(_)));
        assert_eq!(server.hits("/a/-/a-1.0.0.tgz"), 1);
        // Second call is served from the cache.
        c.ensure_tarball(&p).await.expect("fetch");
        assert_eq!(server.hits("/a/-/a-1.0.0.tgz"), 1);
    }

    #[tokio::test]
    async fn reports_integrity_mismatch_and_does_not_cache() {
        let server = MockRegistry::start(vec![("/a/-/a-1.0.0.tgz", 200, b"evil".to_vec())]).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let c = client(dir.path(), &server.url, false);
        let p = pkg("a", None, b"expected");
        let out = c.ensure_tarball(&p).await.expect("fetch");
        match out {
            FetchedTarball::IntegrityMismatch { expected, actual } => {
                assert_eq!(Some(expected), p.integrity.clone());
                assert_eq!(actual, Integrity::of(Algorithm::Sha512, b"evil").to_sri());
            }
            other => panic!("expected mismatch, got {other:?}"),
        }
        assert!(!dir.path().join("tarballs").exists());
    }

    #[tokio::test]
    async fn retries_server_errors_but_not_404() {
        let server = MockRegistry::start(vec![
            ("/flaky/-/flaky-1.0.0.tgz", 503, b"".to_vec()),
            ("/flaky/-/flaky-1.0.0.tgz", 200, b"ok".to_vec()),
        ])
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let c = client(dir.path(), &server.url, false);
        c.ensure_tarball(&pkg("flaky", None, b"ok"))
            .await
            .expect("second attempt succeeds");
        assert_eq!(server.hits("/flaky/-/flaky-1.0.0.tgz"), 2);

        let err = c
            .ensure_tarball(&pkg("missing", None, b"x"))
            .await
            .expect_err("404");
        assert!(matches!(err, CoreError::HttpStatus { status: 404, .. }));
        assert_eq!(server.hits("/missing/-/missing-1.0.0.tgz"), 1);
    }

    #[tokio::test]
    async fn offline_mode_never_hits_the_network() {
        let server = MockRegistry::start(vec![]).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let c = client(dir.path(), &server.url, true);
        let err = c
            .ensure_tarball(&pkg("a", None, b"x"))
            .await
            .expect_err("miss");
        assert!(matches!(err, CoreError::OfflineCacheMiss(_)));
        let err = c.packument("a", &["1.0.0".into()]).await.expect_err("miss");
        assert!(matches!(err, CoreError::OfflineCacheMiss(_)));
        assert_eq!(server.total_hits(), 0);
    }

    #[test]
    fn only_registry_hosts_are_allowed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = client(dir.path(), DEFAULT_REGISTRY, false);
        let ok = |url: &str| c.tarball_url(&pkg("a", Some(url.into()), b"x")).is_ok();
        assert!(ok("https://registry.npmjs.org/a/-/a-1.0.0.tgz"));
        assert!(ok("https://registry.yarnpkg.com/a/-/a-1.0.0.tgz"));
        assert!(!ok("http://registry.npmjs.org/a/-/a-1.0.0.tgz"));
        assert!(!ok("https://169.254.169.254/latest/meta-data"));
        assert!(!ok("https://registry.npmjs.org.evil.invalid/a.tgz"));
        assert!(!ok("not a url"));
    }

    #[tokio::test]
    async fn fetches_and_trims_metadata() {
        let doc = br#"{
          "name": "a",
          "versions": {
            "1.0.0": { "_npmUser": {"name": "alice", "email": "a@x"},
                       "dist": {"tarball": "t1", "integrity": "sha512-x"} },
            "0.1.0": { "_npmUser": "bob <bob@x>",
                       "dist": {"shasum": "a9993e364706816aba3e25717850c26c9cd0d89d"} }
          },
          "time": { "created": "2020-01-01T00:00:00Z", "1.0.0": "2020-02-01T00:00:00Z",
                    "unpublished": {"time": "x"} }
        }"#;
        let server = MockRegistry::start(vec![("/a", 200, doc.to_vec())]).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let c = client(dir.path(), &server.url, false);
        let p = c.packument("a", &["1.0.0".into()]).await.expect("metadata");
        assert_eq!(p.versions["1.0.0"].publisher.as_deref(), Some("alice"));
        assert_eq!(p.versions["0.1.0"].publisher.as_deref(), Some("bob"));
        assert!(p.versions["0.1.0"]
            .integrity
            .as_deref()
            .is_some_and(|i| i.starts_with("sha1-")));
        assert!(!p.time.contains_key("unpublished"));
        // Cached now: no second request.
        c.packument("a", &["1.0.0".into()]).await.expect("metadata");
        assert_eq!(server.hits("/a"), 1);
    }
}

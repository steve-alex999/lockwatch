//! On-disk cache for tarballs and registry metadata.
//!
//! Layout under the cache root (default `~/.cache/lockwatch`):
//!
//! ```text
//! tarballs/sha512-<hex>.tgz       keyed by the lockfile integrity hash
//! tarballs/url-<sha256 of url>.tgz  for the rare entry without an integrity
//! packuments/<name>.json          trimmed registry metadata, one per package name
//! ```
//!
//! Keying tarballs by their hash means the same tarball is never downloaded
//! twice, whichever lockfile refers to it. Cached files are re-verified every
//! time they are read, so a corrupted or tampered cache is detected (LW012).

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::error::{CoreError, Result};
use crate::integrity::{to_hex, Algorithm, Integrity};
use crate::lockfile::LockedPackage;
use crate::registry::Packument;

#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    /// `impl Into<PathBuf>` lets callers pass a `&str`, `String`, `&Path` or
    /// `PathBuf` without converting first.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Cache { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn tarball_path(&self, key: &str) -> PathBuf {
        self.root.join("tarballs").join(format!("{key}.tgz"))
    }

    /// Read a cached tarball. `Ok(None)` means "not cached".
    pub fn read_tarball(&self, key: &str) -> Result<Option<Vec<u8>>> {
        read_optional(&self.tarball_path(key))
    }

    pub fn write_tarball(&self, key: &str, data: &[u8]) -> Result<PathBuf> {
        let path = self.tarball_path(key);
        write_atomic(&path, data)?;
        Ok(path)
    }

    /// `@scope/name` becomes `@scope%2fname.json`, the same escaping the npm
    /// registry uses in URLs, so names map to unique, valid file names.
    pub fn packument_path(&self, name: &str) -> PathBuf {
        self.root
            .join("packuments")
            .join(format!("{}.json", name.replace('/', "%2f")))
    }

    /// Read cached metadata. A corrupt file is treated as a cache miss.
    pub fn read_packument(&self, name: &str) -> Result<Option<Packument>> {
        let Some(bytes) = read_optional(&self.packument_path(name))? else {
            return Ok(None);
        };
        match serde_json::from_slice(&bytes) {
            Ok(p) => Ok(Some(p)),
            Err(err) => {
                tracing::warn!(package = name, %err, "ignoring corrupt cached metadata");
                Ok(None)
            }
        }
    }

    pub fn write_packument(&self, packument: &Packument) -> Result<()> {
        let path = self.packument_path(&packument.name);
        let json = serde_json::to_vec(packument)
            .map_err(|e| CoreError::Metadata(format!("cannot serialise metadata: {e}")))?;
        write_atomic(&path, &json)
    }
}

/// The cache key for a package's tarball: its integrity hash in hex, or a
/// hash of the URL when the lockfile has no integrity.
pub fn tarball_key(pkg: &LockedPackage, url: &str) -> Result<String> {
    match pkg.integrity.as_deref() {
        Some(sri) => Ok(Integrity::parse(sri)?.cache_key()),
        None => Ok(format!(
            "url-{}",
            to_hex(&Algorithm::Sha256.digest(url.as_bytes()))
        )),
    }
}

/// Read a file, mapping "not found" to `Ok(None)`.
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(CoreError::io(path, err)),
    }
}

/// Write to a temporary file in the same directory, then rename it into
/// place. A rename is atomic on the same filesystem, so a crash or a
/// concurrent reader never sees a half-written file.
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| CoreError::io(path, std::io::Error::other("path has no parent")))?;
    fs::create_dir_all(dir).map_err(|e| CoreError::io(dir, e))?;
    let mut builder = tempfile::Builder::new();
    // Temporary files are private (0600) by default. Cached tarballs and
    // metadata are public data; make them readable like normal files so a
    // cache can be shared or mounted into a container.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o644));
    }
    let mut tmp = builder
        .tempfile_in(dir)
        .map_err(|e| CoreError::io(dir, e))?;
    tmp.write_all(data).map_err(|e| CoreError::io(path, e))?;
    tmp.persist(path)
        .map_err(|e| CoreError::io(path, e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tarball_round_trip_and_miss() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::new(dir.path());
        assert_eq!(cache.read_tarball("sha512-00").expect("read"), None);
        cache.write_tarball("sha512-00", b"data").expect("write");
        assert_eq!(
            cache.read_tarball("sha512-00").expect("read"),
            Some(b"data".to_vec())
        );
    }

    #[test]
    fn packument_names_are_escaped_and_corrupt_files_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::new(dir.path());
        let p = Packument {
            name: "@scope/pkg".into(),
            ..Packument::default()
        };
        cache.write_packument(&p).expect("write");
        assert!(dir.path().join("packuments/@scope%2fpkg.json").exists());
        assert_eq!(
            cache.read_packument("@scope/pkg").expect("read"),
            Some(p.clone())
        );

        fs::write(cache.packument_path("@scope/pkg"), "{not json").expect("write");
        assert_eq!(cache.read_packument("@scope/pkg").expect("read"), None);
    }

    #[cfg(unix)]
    #[test]
    fn cached_files_are_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = Cache::new(dir.path())
            .write_tarball("k", b"x")
            .expect("write");
        let mode = fs::metadata(path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn key_uses_integrity_or_url_hash() {
        let mut pkg = LockedPackage {
            name: "a".into(),
            version: "1.0.0".into(),
            resolved: None,
            integrity: Some(Integrity::of(Algorithm::Sha512, b"t").to_sri()),
        };
        assert!(tarball_key(&pkg, "u").expect("key").starts_with("sha512-"));
        pkg.integrity = None;
        assert!(tarball_key(&pkg, "u").expect("key").starts_with("url-"));
    }
}

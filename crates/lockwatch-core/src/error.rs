//! Error type for the core library.
//!
//! `thiserror` generates the `std::error::Error` and `Display` impls from the
//! `#[error("...")]` attributes, so each variant documents its own message.
//! The CLI wraps these in `anyhow::Error`, which is fine for an application
//! but too loose for a library whose callers may want to `match` on a variant.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// The lockfile could not be read as JSON at all.
    #[error("lockfile is not valid JSON: {0}")]
    LockfileJson(serde_json::Error),

    /// The lockfile is JSON but not a format we support (for example v1).
    #[error("unsupported lockfile: {0}")]
    UnsupportedLockfile(String),

    /// A filesystem operation failed. We keep the path because a bare
    /// `io::Error` ("No such file or directory") does not say which file.
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A request failed before we got an HTTP status (DNS, TLS, timeout...).
    #[error("network error fetching {url}: {message}")]
    Network { url: String, message: String },

    /// The server answered with a non-success status code.
    #[error("HTTP {status} fetching {url}")]
    HttpStatus { url: String, status: u16 },

    /// The response was larger than we are willing to download.
    #[error("response from {url} is larger than the {limit} byte limit")]
    TooLarge { url: String, limit: u64 },

    /// `--offline` was given and the item is not in the cache.
    #[error("not in cache (offline mode): {0}")]
    OfflineCacheMiss(String),

    /// A `resolved` URL we refuse to fetch (wrong scheme or host).
    #[error("refusing to fetch {url}: {reason}")]
    DisallowedUrl { url: String, reason: String },

    /// The `integrity` string from the lockfile could not be parsed.
    #[error("invalid integrity string {0:?}")]
    InvalidIntegrity(String),

    /// The tarball is not a valid gzip-compressed tar archive.
    #[error("invalid package archive: {0}")]
    InvalidArchive(String),

    /// `scan-package` was given something that is not `name@version`.
    #[error("invalid package spec {0:?}: expected <name>@<version>")]
    InvalidSpec(String),

    /// The registry metadata (packument) was missing or malformed.
    #[error("registry metadata error: {0}")]
    Metadata(String),
}

impl CoreError {
    /// Small helper so call sites can write
    /// `fs::read(&p).map_err(|e| CoreError::io(&p, e))?`.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        CoreError::Io {
            path: path.into(),
            source,
        }
    }
}

/// Shorthand used throughout the crate: `Result<T>` means
/// `std::result::Result<T, CoreError>`.
pub type Result<T> = std::result::Result<T, CoreError>;

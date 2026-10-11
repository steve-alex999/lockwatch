//! Subresource Integrity (SRI) strings, as used in `package-lock.json`.
//!
//! An SRI string is `<algorithm>-<base64 digest>`, for example
//! `sha512-9u2o...==`. It can hold several space-separated hashes; we verify
//! the strongest one we support. npm writes `sha512` today and `sha1` for very
//! old packages.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _; // brings the `.encode()` / `.decode()` methods into scope
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{CoreError, Result};

/// Supported hash algorithms, weakest first. Deriving `PartialOrd`/`Ord`
/// orders the variants by declaration order, so `max()` picks the strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    fn from_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "sha1" => Some(Algorithm::Sha1),
            "sha256" => Some(Algorithm::Sha256),
            "sha384" => Some(Algorithm::Sha384),
            "sha512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }

    pub fn prefix(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
        }
    }

    fn digest_len(self) -> usize {
        match self {
            Algorithm::Sha1 => 20,
            Algorithm::Sha256 => 32,
            Algorithm::Sha384 => 48,
            Algorithm::Sha512 => 64,
        }
    }

    /// Hash `data` with this algorithm.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        // Each hasher type implements the `Digest` trait, so `X::digest(data)`
        // works the same way for all of them.
        match self {
            Algorithm::Sha1 => Sha1::digest(data).to_vec(),
            Algorithm::Sha256 => Sha256::digest(data).to_vec(),
            Algorithm::Sha384 => Sha384::digest(data).to_vec(),
            Algorithm::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// One parsed hash: which algorithm, and the raw digest bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    pub algorithm: Algorithm,
    pub digest: Vec<u8>,
}

impl Integrity {
    /// Parse an SRI string and keep its strongest supported hash.
    pub fn parse(sri: &str) -> Result<Self> {
        let mut best: Option<Integrity> = None;
        for token in sri.split_whitespace() {
            // "sha512-AAAA==?opt" -> ("sha512", "AAAA==?opt")
            let Some((prefix, rest)) = token.split_once('-') else {
                continue;
            };
            let Some(algorithm) = Algorithm::from_prefix(prefix) else {
                continue;
            };
            // SRI allows options after '?'; npm never writes them, but ignore them.
            let b64 = rest.split('?').next().unwrap_or_default();
            let Ok(digest) = BASE64.decode(b64) else {
                continue;
            };
            if digest.len() != algorithm.digest_len() {
                continue;
            }
            let candidate = Integrity { algorithm, digest };
            // Keep the candidate if we have nothing yet or it is stronger.
            if best
                .as_ref()
                .is_none_or(|b| candidate.algorithm > b.algorithm)
            {
                best = Some(candidate);
            }
        }
        best.ok_or_else(|| CoreError::InvalidIntegrity(sri.to_string()))
    }

    /// Compute the integrity of `data` with `algorithm`.
    pub fn of(algorithm: Algorithm, data: &[u8]) -> Self {
        Integrity {
            algorithm,
            digest: algorithm.digest(data),
        }
    }

    /// Does `data` hash to this value?
    pub fn matches(&self, data: &[u8]) -> bool {
        self.algorithm.digest(data) == self.digest
    }

    /// Back to SRI form, `sha512-<base64>`.
    pub fn to_sri(&self) -> String {
        format!(
            "{}-{}",
            self.algorithm.prefix(),
            BASE64.encode(&self.digest)
        )
    }

    /// A file-name-safe key for the cache: `sha512-<hex>`.
    /// Base64 contains `/`, which cannot appear in a file name, so use hex.
    pub fn cache_key(&self) -> String {
        format!("{}-{}", self.algorithm.prefix(), to_hex(&self.digest))
    }
}

/// Bytes to lowercase hex, two characters per byte.
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String cannot fail, so ignoring the Result is fine.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Turn an old-style hex `shasum` (from registry metadata) into an SRI string.
pub fn sri_from_sha1_hex(hex: &str) -> Option<String> {
    if hex.len() != 40 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..20)
        .map(|i| {
            hex.get(i * 2..i * 2 + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect();
    bytes.map(|b| format!("sha1-{}", BASE64.encode(b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_sha512_and_sha1() {
        let data = b"hello lockwatch";
        for alg in [Algorithm::Sha1, Algorithm::Sha512] {
            let sri = Integrity::of(alg, data).to_sri();
            let parsed = Integrity::parse(&sri).expect("round trip");
            assert!(parsed.matches(data));
            assert!(!parsed.matches(b"tampered"));
        }
    }

    #[test]
    fn known_sha1_vector() {
        // sha1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let sri = sri_from_sha1_hex("a9993e364706816aba3e25717850c26c9cd0d89d").expect("hex");
        assert!(Integrity::parse(&sri).expect("valid").matches(b"abc"));
        assert_eq!(sri_from_sha1_hex("zz"), None);
    }

    #[test]
    fn picks_strongest_of_several_hashes() {
        let data = b"x";
        let sri = format!(
            "{} {}",
            Integrity::of(Algorithm::Sha1, data).to_sri(),
            Integrity::of(Algorithm::Sha512, data).to_sri()
        );
        assert_eq!(
            Integrity::parse(&sri).expect("valid").algorithm,
            Algorithm::Sha512
        );
    }

    #[test]
    fn rejects_invalid_strings() {
        for bad in ["", "md5-abc", "sha512-not*base64", "sha512-AAAA", "nodash"] {
            assert!(Integrity::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cache_key_is_hex() {
        let key = Integrity::of(Algorithm::Sha256, b"").cache_key();
        assert_eq!(
            key,
            "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}

//! Safe extraction of npm package tarballs (`.tgz`).
//!
//! A tarball is attacker-controlled input, so extraction is a security
//! boundary. This module:
//! - rejects absolute paths and `..` components (path traversal, "zip slip"),
//! - skips symlinks, hardlinks and device files instead of creating them,
//! - stops at 50 MB of unpacked data or 10,000 entries (decompression bombs),
//! - writes files larger than 5 MB only as a record (path, size, first bytes),
//!   because they are too big to analyse.
//!
//! npm puts every file under a top-level folder (normally `package/`) and
//! strips it when installing; we strip it too, so `package/index.js` becomes
//! `index.js`.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Component, Path};

use flate2::read::GzDecoder;
use tar::{Archive, EntryType};

use crate::error::{CoreError, Result};

/// How many leading bytes of every file we keep for magic-number checks.
pub const HEAD_BYTES: u64 = 512;

#[derive(Debug, Clone, Copy)]
pub struct ExtractLimits {
    /// Total unpacked bytes per package.
    pub max_total_bytes: u64,
    /// Number of archive entries per package.
    pub max_entries: usize,
    /// Files larger than this are recorded but not written or analysed.
    pub max_file_bytes: u64,
}

impl Default for ExtractLimits {
    fn default() -> Self {
        ExtractLimits {
            max_total_bytes: 50 * 1024 * 1024,
            max_entries: 10_000,
            max_file_bytes: 5 * 1024 * 1024,
        }
    }
}

/// One regular file from the archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedFile {
    /// Path inside the package, `/`-separated, without the `package/` prefix.
    pub path: String,
    pub size: u64,
    /// First bytes of the file (up to [`HEAD_BYTES`]), for magic numbers.
    pub head: Vec<u8>,
    /// False when the file was over the size limit and not written to disk.
    pub written: bool,
}

#[derive(Debug, Default)]
pub struct Extraction {
    /// Files sorted by path.
    pub files: Vec<ExtractedFile>,
    /// Human-readable notes about anything skipped (shown in the report).
    pub warnings: Vec<String>,
}

/// Unpack `tgz` into `dest`, which should be an empty temporary directory.
pub fn extract_tarball(tgz: &[u8], dest: &Path, limits: &ExtractLimits) -> Result<Extraction> {
    let invalid = |e: std::io::Error| CoreError::InvalidArchive(e.to_string());
    // GzDecoder decompresses lazily as tar reads from it, so we never hold
    // the whole unpacked archive in memory.
    let mut archive = Archive::new(GzDecoder::new(tgz));
    let entries = archive.entries().map_err(invalid)?;

    // Keyed by path: if an archive lists the same path twice, the later
    // entry wins, as it would on disk.
    let mut files: BTreeMap<String, ExtractedFile> = BTreeMap::new();
    let mut warnings = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut entry_count: usize = 0;

    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            // A broken first entry means this is not a tarball at all.
            Err(e) if entry_count == 0 => return Err(invalid(e)),
            Err(e) => {
                warnings.push(format!(
                    "archive is truncated or corrupt ({e}); later files not analysed"
                ));
                break;
            }
        };
        entry_count += 1;
        if entry_count > limits.max_entries {
            warnings.push(format!(
                "archive has more than {} entries; later files not analysed",
                limits.max_entries
            ));
            break;
        }

        // Count the size before reading, so we never decompress past the
        // budget (even data we only skip over has to be decompressed).
        let size = entry.header().size().unwrap_or(0);
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > limits.max_total_bytes {
            warnings.push(format!(
                "unpacked size exceeds {} MB; later files not analysed",
                limits.max_total_bytes / (1024 * 1024)
            ));
            break;
        }

        let raw_path = match entry.path() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(_) => {
                warnings.push("skipped entry with an unreadable path".into());
                continue;
            }
        };
        match entry.header().entry_type() {
            EntryType::Regular | EntryType::Continuous => {}
            EntryType::Directory => continue,
            EntryType::Symlink => {
                warnings.push(format!("skipped symlink {raw_path}"));
                continue;
            }
            EntryType::Link => {
                warnings.push(format!("skipped hardlink {raw_path}"));
                continue;
            }
            other => {
                warnings.push(format!("skipped special entry {raw_path} ({other:?})"));
                continue;
            }
        }

        let Some(rel) = safe_relative_path(Path::new(&raw_path)) else {
            warnings.push(format!("skipped unsafe path {raw_path:?}"));
            continue;
        };

        if size > limits.max_file_bytes {
            // Keep only the first bytes so LW011 can still spot binaries.
            let mut head = Vec::new();
            (&mut entry)
                .take(HEAD_BYTES)
                .read_to_end(&mut head)
                .map_err(invalid)?;
            warnings.push(format!(
                "{rel} is {size} bytes, over the {} MB per-file limit; not analysed",
                limits.max_file_bytes / (1024 * 1024)
            ));
            files.insert(
                rel.clone(),
                ExtractedFile {
                    path: rel,
                    size,
                    head,
                    written: false,
                },
            );
            continue;
        }

        // `size` is at most max_file_bytes here, so this bounded read is small.
        let mut data = Vec::new();
        (&mut entry)
            .take(limits.max_file_bytes)
            .read_to_end(&mut data)
            .map_err(invalid)?;

        let target = dest.join(&rel);
        if let Err(e) = write_file(&target, &data) {
            // For example a file and a directory with the same name.
            warnings.push(format!("could not write {rel}: {e}"));
            continue;
        }
        let head_len = data.len().min(HEAD_BYTES as usize);
        files.insert(
            rel.clone(),
            ExtractedFile {
                path: rel,
                size: data.len() as u64,
                head: data[..head_len].to_vec(),
                written: true,
            },
        );
    }

    Ok(Extraction {
        files: files.into_values().collect(),
        warnings,
    })
}

fn write_file(target: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(target, data)
}

/// Turn an archive path into a safe relative path, or `None` if it must be
/// rejected.
///
/// Rejected: absolute paths, `..` anywhere, non-UTF-8 names, and entries at
/// the top level (npm strips the first component, so they would not be
/// installed). `./` components are ignored.
pub fn safe_relative_path(path: &Path) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    // Drop the "package/" folder.
    if parts.len() < 2 {
        return None;
    }
    Some(parts[1..].join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::build_tgz;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    /// Build a tarball whose header names are written raw, bypassing the tar
    /// crate's own path checks, so we can create hostile archives.
    fn hostile_tgz(entries: &[(&str, EntryType, &[u8], Option<&str>)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (name, kind, data, link) in entries {
            let mut header = tar::Header::new_gnu();
            let name_field = &mut header.as_old_mut().name;
            name_field[..name.len()].copy_from_slice(name.as_bytes());
            header.set_entry_type(*kind);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            if let Some(target) = link {
                let link_field = &mut header.as_old_mut().linkname;
                link_field[..target.len()].copy_from_slice(target.as_bytes());
            }
            header.set_cksum();
            builder.append(&header, *data).expect("append");
        }
        builder.into_inner().expect("tar").finish().expect("gzip")
    }

    #[test]
    fn extracts_and_strips_package_prefix() {
        let tgz = build_tgz(&[
            ("package/package.json", br#"{"name":"x"}"#.as_slice()),
            ("package/lib/index.js", b"module.exports = 1;"),
        ]);
        let dir = tempfile::tempdir().expect("tempdir");
        let out = extract_tarball(&tgz, dir.path(), &ExtractLimits::default()).expect("extract");
        let paths: Vec<&str> = out.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["lib/index.js", "package.json"]);
        assert!(out.warnings.is_empty());
        assert_eq!(
            fs::read_to_string(dir.path().join("lib/index.js")).expect("read"),
            "module.exports = 1;"
        );
    }

    #[test]
    fn rejects_path_traversal_and_absolute_paths() {
        let outer = tempfile::tempdir().expect("tempdir");
        let dest = outer.path().join("dest");
        fs::create_dir(&dest).expect("mkdir");
        let tgz = hostile_tgz(&[
            ("package/../../escaped.txt", EntryType::Regular, b"x", None),
            (
                "package/a/../../../escaped2.txt",
                EntryType::Regular,
                b"x",
                None,
            ),
            (
                "/tmp/lockwatch-absolute.txt",
                EntryType::Regular,
                b"x",
                None,
            ),
            ("package/ok.js", EntryType::Regular, b"ok", None),
        ]);
        let out = extract_tarball(&tgz, &dest, &ExtractLimits::default()).expect("extract");
        assert_eq!(out.files.len(), 1);
        assert_eq!(out.files[0].path, "ok.js");
        assert_eq!(out.warnings.len(), 3, "{:?}", out.warnings);
        assert!(!outer.path().join("escaped.txt").exists());
        assert!(!outer.path().join("escaped2.txt").exists());
        assert!(!Path::new("/tmp/lockwatch-absolute.txt").exists());
    }

    #[test]
    fn skips_symlinks_and_hardlinks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tgz = hostile_tgz(&[
            ("package/link", EntryType::Symlink, b"", Some("/etc/passwd")),
            ("package/hard", EntryType::Link, b"", Some("/etc/passwd")),
            ("package/index.js", EntryType::Regular, b"1", None),
        ]);
        let out = extract_tarball(&tgz, dir.path(), &ExtractLimits::default()).expect("extract");
        assert_eq!(out.files.len(), 1);
        assert!(fs::symlink_metadata(dir.path().join("link")).is_err());
        assert!(fs::symlink_metadata(dir.path().join("hard")).is_err());
        assert!(out.warnings.iter().any(|w| w.contains("symlink")));
        assert!(out.warnings.iter().any(|w| w.contains("hardlink")));
    }

    #[test]
    fn records_but_does_not_write_oversized_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let big = vec![b'a'; 2_000];
        let tgz = build_tgz(&[
            ("package/big.bin", big.as_slice()),
            ("package/small.js", b"1"),
        ]);
        let limits = ExtractLimits {
            max_file_bytes: 1_000,
            ..ExtractLimits::default()
        };
        let out = extract_tarball(&tgz, dir.path(), &limits).expect("extract");
        let big_entry = &out.files[0];
        assert_eq!(big_entry.path, "big.bin");
        assert!(!big_entry.written);
        assert_eq!(big_entry.size, 2_000);
        assert_eq!(big_entry.head.len(), HEAD_BYTES as usize);
        assert!(!dir.path().join("big.bin").exists());
        assert!(dir.path().join("small.js").exists());
        assert!(out.warnings[0].contains("per-file limit"));
    }

    #[test]
    fn stops_at_total_size_and_entry_limits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let chunk = vec![b'a'; 600];
        let tgz = build_tgz(&[
            ("package/1.js", chunk.as_slice()),
            ("package/2.js", chunk.as_slice()),
            ("package/3.js", chunk.as_slice()),
        ]);
        let limits = ExtractLimits {
            max_total_bytes: 1_000,
            ..ExtractLimits::default()
        };
        let out = extract_tarball(&tgz, dir.path(), &limits).expect("extract");
        assert_eq!(out.files.len(), 1);
        assert!(out.warnings[0].contains("unpacked size"));

        let limits = ExtractLimits {
            max_entries: 2,
            ..ExtractLimits::default()
        };
        let out = extract_tarball(&tgz, dir.path(), &limits).expect("extract");
        assert_eq!(out.files.len(), 2);
        assert!(out.warnings[0].contains("more than 2 entries"));
    }

    #[test]
    fn rejects_non_gzip_input() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = extract_tarball(
            b"definitely not gzip",
            dir.path(),
            &ExtractLimits::default(),
        )
        .expect_err("invalid");
        assert!(matches!(err, CoreError::InvalidArchive(_)));
    }

    #[test]
    fn safe_relative_path_cases() {
        let p = |s: &str| safe_relative_path(Path::new(s));
        assert_eq!(p("package/a/b.js").as_deref(), Some("a/b.js"));
        assert_eq!(p("./package/./a.js").as_deref(), Some("a.js"));
        assert_eq!(p("package"), None);
        assert_eq!(p("package/../x"), None);
        assert_eq!(p("/abs/x"), None);
    }
}

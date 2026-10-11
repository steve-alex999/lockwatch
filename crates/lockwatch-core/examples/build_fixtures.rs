//! Builds the test fixtures from the readable sources in fixtures/packages.
//!
//!     cargo run -p lockwatch-core --example build_fixtures
//!
//! For every fixture directory it:
//! 1. packs the files into an npm-style tarball (`package/...`) with fixed
//!    timestamps and permissions, so the output is byte-for-byte
//!    reproducible,
//! 2. stores it in fixtures/cache/tarballs under its integrity hash, exactly
//!    where `lockwatch --cache-dir fixtures/cache --offline` looks for it,
//! 3. writes trimmed registry metadata to fixtures/cache/packuments,
//! 4. writes the lockfiles in fixtures/lockfiles.
//!
//! Special files in a fixture directory (not packed):
//! - `_generate.json`: `{ "path": "elf" | "pe" | "macho" }` creates small
//!   fake binaries (magic bytes + a note), so no real executable is stored.
//! - `_registry.json`: custom version history for the metadata rules.
//! - `_lockfile.json`: `{ "tamper": true }` gives the package a wrong
//!   integrity in every lockfile (rule LW012).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use flate2::{Compression, GzBuilder};
use lockwatch_core::cache::Cache;
use lockwatch_core::integrity::{Algorithm, Integrity};
use lockwatch_core::registry::{Packument, VersionInfo};
use serde_json::{json, Value};

type BoxError = Box<dyn std::error::Error>;

/// npm's own fixed mtime for packed files (1985-10-26T08:15:00Z).
const NPM_MTIME: u64 = 499_162_500;
const DEFAULT_TIME: &str = "2025-01-01T00:00:00Z";
const DEFAULT_PUBLISHER: &str = "fixture-author";

struct Fixture {
    name: String,
    version: String,
    /// The integrity written to lockfiles (wrong on purpose if tampered).
    lock_integrity: String,
}

fn main() -> Result<(), BoxError> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixtures = root.join("fixtures");
    let cache_dir = fixtures.join("cache");
    if cache_dir.exists() {
        fs::remove_dir_all(&cache_dir)?;
    }
    let cache = Cache::new(&cache_dir);

    let mut sets: BTreeMap<&str, Vec<Fixture>> = BTreeMap::new();
    for set in ["malicious", "benign"] {
        let mut list = Vec::new();
        let mut dirs: Vec<PathBuf> = fs::read_dir(fixtures.join("packages").join(set))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for dir in dirs {
            list.push(build_one(&dir, &cache)?);
        }
        sets.insert(set, list);
    }

    let lockfiles = fixtures.join("lockfiles");
    fs::create_dir_all(&lockfiles)?;
    let all: Vec<&Fixture> = sets.values().flatten().collect();
    let by_name = |n: &str| -> Result<&Fixture, BoxError> {
        all.iter()
            .copied()
            .find(|f| f.name == n)
            .ok_or_else(|| format!("no fixture named {n}").into())
    };

    for (set, list) in &sets {
        let refs: Vec<&Fixture> = list.iter().collect();
        write_lockfile(&lockfiles.join(format!("{set}.json")), set, &refs, false, 3)?;
    }

    // mixed.json: at least one package per rule, some benign packages and
    // entries that are skipped (link, file:, git).
    let mixed: Vec<&Fixture> = [
        "lwfx-curl-pipe-sh",
        "lwfx-cp-in-helper",
        "lwfx-steal-env-token",
        "lwfx-obf-entropy",
        "expresss",
        "lwfx-fresh-release",
        "lwfx-new-maintainer",
        "lwfx-hidden-elf",
        "lwfx-tampered",
        "lwfx-ok-node-gyp",
        "lwfx-ok-env-config",
        "lwfx-ok-http-client",
    ]
    .iter()
    .map(|n| by_name(n))
    .collect::<Result<_, _>>()?;
    write_lockfile(&lockfiles.join("mixed.json"), "mixed", &mixed, true, 3)?;

    let small: Vec<&Fixture> = ["lwfx-ok-env-config", "lwfx-ok-http-client", "lwfx-net-ip"]
        .iter()
        .map(|n| by_name(n))
        .collect::<Result<_, _>>()?;
    write_lockfile(&lockfiles.join("small.json"), "small", &small, false, 3)?;
    write_lockfile(
        &lockfiles.join("v2-small.json"),
        "v2-small",
        &small,
        false,
        2,
    )?;

    write_large_lockfile(&lockfiles.join("large.json"), &all)?;
    println!("built {} fixtures into {}", all.len(), cache_dir.display());
    Ok(())
}

fn build_one(dir: &Path, cache: &Cache) -> Result<Fixture, BoxError> {
    let manifest: Value = serde_json::from_slice(&fs::read(dir.join("package.json"))?)?;
    let name = manifest["name"]
        .as_str()
        .ok_or("fixture without a name")?
        .to_string();
    let version = manifest["version"]
        .as_str()
        .ok_or("fixture without a version")?
        .to_string();

    // Collect files (sorted, relative, '/'-separated), skipping `_*.json`.
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    collect_files(dir, dir, &mut files)?;
    if let Ok(text) = fs::read(dir.join("_generate.json")) {
        let spec: BTreeMap<String, String> = serde_json::from_slice(&text)?;
        for (path, kind) in spec {
            files.push((path, fake_binary(&kind)?));
        }
    }
    files.sort();
    let tarball = pack(&files)?;
    let real = Integrity::of(Algorithm::Sha512, &tarball);

    let tamper = fs::read(dir.join("_lockfile.json"))
        .ok()
        .and_then(|t| serde_json::from_slice::<Value>(&t).ok())
        .is_some_and(|v| v["tamper"] == json!(true));
    let lock_integrity = if tamper {
        // A valid SRI string for different bytes. The real tarball is stored
        // under this key, as if the cache or a mirror had been tampered with.
        Integrity::of(Algorithm::Sha512, b"lockwatch fixture: tampered").to_sri()
    } else {
        real.to_sri()
    };
    cache.write_tarball(&Integrity::parse(&lock_integrity)?.cache_key(), &tarball)?;

    // Registry metadata.
    let mut packument = Packument {
        name: name.clone(),
        ..Packument::default()
    };
    let history: Vec<(String, String, String)> = match fs::read(dir.join("_registry.json")) {
        Ok(text) => {
            let v: Value = serde_json::from_slice(&text)?;
            v["versions"]
                .as_array()
                .ok_or("_registry.json needs a versions array")?
                .iter()
                .map(|e| {
                    let s = |k: &str| e[k].as_str().unwrap_or_default().to_string();
                    (s("version"), s("publisher"), s("time"))
                })
                .collect()
        }
        Err(_) => vec![(
            version.clone(),
            DEFAULT_PUBLISHER.into(),
            DEFAULT_TIME.into(),
        )],
    };
    for (v, publisher, time) in &history {
        let is_current = *v == version;
        packument.versions.insert(
            v.clone(),
            VersionInfo {
                publisher: Some(publisher.clone()),
                tarball: is_current.then(|| registry_url(&name, &version)),
                integrity: is_current.then(|| lock_integrity.clone()),
            },
        );
        packument.time.insert(v.clone(), time.clone());
    }
    if let Some((_, _, first)) = history.first() {
        packument.time.insert("created".into(), first.clone());
    }
    cache.write_packument(&packument)?;

    Ok(Fixture {
        name,
        version,

        lock_integrity,
    })
}

fn collect_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), BoxError> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(root, &path, out)?;
            continue;
        }
        let rel = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        if dir == root && rel.starts_with('_') && rel.ends_with(".json") {
            continue;
        }
        out.push((rel, fs::read(&path)?));
    }
    Ok(())
}

/// Small files with the magic bytes of a binary format plus a note. They
/// are not executables.
fn fake_binary(kind: &str) -> Result<Vec<u8>, BoxError> {
    let note = b"lockwatch fixture: magic bytes only, not a real executable\n";
    let mut data = match kind {
        "elf" => {
            let mut d = vec![0u8; 64];
            d[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\x00");
            d
        }
        "macho" => {
            let mut d = vec![0u8; 64];
            d[..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
            d
        }
        "pe" => {
            let mut d = vec![0u8; 0x80];
            d[..2].copy_from_slice(b"MZ");
            d[0x3C] = 0x40;
            d[0x40..0x44].copy_from_slice(b"PE\0\0");
            d
        }
        other => return Err(format!("unknown fake binary kind {other}").into()),
    };
    data.extend_from_slice(note);
    Ok(data)
}

/// Deterministic npm-style tarball.
fn pack(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, BoxError> {
    // GzBuilder with no file name and mtime 0 keeps the gzip header fixed.
    let gz = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::best());
    let mut builder = tar::Builder::new(gz);
    for (path, data) in files {
        let mut header = tar::Header::new_ustar();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(NPM_MTIME);
        header.set_uid(0);
        header.set_gid(0);
        header.set_entry_type(tar::EntryType::Regular);
        builder.append_data(&mut header, format!("package/{path}"), data.as_slice())?;
    }
    Ok(builder.into_inner()?.finish()?)
}

fn registry_url(name: &str, version: &str) -> String {
    let base = name.rsplit('/').next().unwrap_or(name);
    format!("https://registry.npmjs.org/{name}/-/{base}-{version}.tgz")
}

fn entry(f: &Fixture) -> Value {
    json!({
        "version": f.version,
        "resolved": registry_url(&f.name, &f.version),
        "integrity": f.lock_integrity,
    })
}

fn write_lockfile(
    path: &Path,
    set: &str,
    fixtures: &[&Fixture],
    with_skipped: bool,
    lockfile_version: u32,
) -> Result<(), BoxError> {
    let mut packages = serde_json::Map::new();
    let deps: serde_json::Map<String, Value> = fixtures
        .iter()
        .map(|f| (f.name.clone(), json!(f.version)))
        .collect();
    packages.insert(
        String::new(),
        json!({ "name": format!("lockwatch-fixtures-{set}"), "version": "1.0.0", "dependencies": deps }),
    );
    for f in fixtures {
        packages.insert(format!("node_modules/{}", f.name), entry(f));
    }
    if with_skipped {
        packages.insert(
            "node_modules/local-lib".into(),
            json!({ "resolved": "packages/local-lib", "link": true }),
        );
        packages.insert(
            "packages/local-lib".into(),
            json!({ "name": "local-lib", "version": "0.1.0" }),
        );
        packages.insert(
            "node_modules/file-dep".into(),
            json!({ "version": "1.0.0", "resolved": "file:../file-dep" }),
        );
        packages.insert(
            "node_modules/git-dep".into(),
            json!({ "version": "1.0.0", "resolved": "git+https://example.invalid/git-dep.git#0123abc" }),
        );
    }
    let mut lock = json!({
        "name": format!("lockwatch-fixtures-{set}"),
        "version": "1.0.0",
        "lockfileVersion": lockfile_version,
        "requires": true,
        "packages": packages,
    });
    if lockfile_version == 2 {
        // v2 also carries the old v1-style tree; lockwatch ignores it.
        lock["dependencies"] = json!({});
    }
    fs::write(path, serde_json::to_string_pretty(&lock)? + "\n")?;
    Ok(())
}

/// More than 200 entries (for the API's job mode): every fixture installed
/// at the top level and nested under four other fixtures. They deduplicate
/// to the same tarballs.
fn write_large_lockfile(path: &Path, fixtures: &[&Fixture]) -> Result<(), BoxError> {
    let mut packages = serde_json::Map::new();
    packages.insert(
        String::new(),
        json!({ "name": "lockwatch-fixtures-large", "version": "1.0.0" }),
    );
    for (i, f) in fixtures.iter().enumerate() {
        packages.insert(format!("node_modules/{}", f.name), entry(f));
        for k in 1..=4 {
            let parent = fixtures[(i + k) % fixtures.len()];
            packages.insert(
                format!("node_modules/{}/node_modules/{}", parent.name, f.name),
                entry(f),
            );
        }
    }
    let lock = json!({
        "name": "lockwatch-fixtures-large",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": packages,
    });
    fs::write(path, serde_json::to_string_pretty(&lock)? + "\n")?;
    Ok(())
}

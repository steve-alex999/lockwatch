//! LW011: the package ships executable or binary files it does not explain.
//!
//! Native addons (`.node`) and prebuilt executables are normal for packages
//! that declare a native build (gypfile, node-gyp, prebuild-install,
//! platform-specific `os`/`cpu`, ...). A binary in a package that declares
//! none of that is unusual, and binaries cannot be reviewed like source.

use super::{Finding, Rule, Severity};
use crate::context::PackageContext;

pub struct UnexpectedBinary;

/// Identify a binary format from the first bytes of a file.
pub fn binary_kind(path: &str, head: &[u8]) -> Option<&'static str> {
    const MACHO: [[u8; 4]; 4] = [
        [0xFE, 0xED, 0xFA, 0xCE],
        [0xFE, 0xED, 0xFA, 0xCF],
        [0xCE, 0xFA, 0xED, 0xFE],
        [0xCF, 0xFA, 0xED, 0xFE],
    ];
    if head.starts_with(b"\x7fELF") {
        return Some("ELF executable");
    }
    if MACHO.iter().any(|m| head.starts_with(m)) {
        return Some("Mach-O executable");
    }
    if head.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        return Some("Mach-O universal binary");
    }
    if head.starts_with(b"MZ") {
        // A real PE file has "PE\0\0" at the offset stored at 0x3C. Text that
        // just starts with "MZ" does not.
        let pe_offset = head
            .get(0x3C..0x40)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
        let has_pe_signature = pe_offset
            .and_then(|o| head.get(o..o + 4))
            .is_some_and(|sig| sig == b"PE\0\0");
        let windows_ext = [".exe", ".dll"].iter().any(|e| path.ends_with(e));
        if has_pe_signature || windows_ext {
            return Some("Windows PE executable");
        }
    }
    let lower = path.to_ascii_lowercase();
    [
        (".node", "Node.js native addon"),
        (".exe", "Windows executable"),
        (".dll", "Windows library"),
        (".so", "shared library"),
        (".dylib", "macOS library"),
    ]
    .iter()
    .find(|(ext, _)| lower.ends_with(ext))
    .map(|(_, kind)| *kind)
}

impl Rule for UnexpectedBinary {
    fn id(&self) -> &'static str {
        "LW011"
    }
    fn name(&self) -> &'static str {
        "Unexpected binary"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn description(&self) -> &'static str {
        "ELF, Mach-O or PE files, or .node/.exe/.dll/.so/.dylib files, in a package whose \
         manifest does not declare a native build"
    }

    fn check(&self, ctx: &PackageContext) -> Vec<Finding> {
        if ctx.manifest.declares_native_build() {
            return Vec::new();
        }
        ctx.files
            .iter()
            .filter_map(|f| binary_kind(&f.path, &f.head).map(|kind| (f, kind)))
            .map(|(f, kind)| {
                self.finding(
                    ctx,
                    Some(&f.path),
                    None,
                    &format!("{} ({kind}, {} bytes)", f.path, f.size),
                    format!(
                        "The package ships {} {kind} but its package.json declares no native build.",
                        if kind.starts_with(['E', 'a', 'e', 'i', 'o', 'u']) { "an" } else { "a" }
                    ),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PackageContext;

    fn ctx(files: &[(&str, &[u8])]) -> PackageContext {
        PackageContext::from_files("p", "1.0.0", files, None, 0)
    }

    #[test]
    fn elf_and_pe_files_without_native_build() {
        let mut pe = vec![0u8; 0x80];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3C] = 0x40;
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        let c = ctx(&[
            ("package.json", br#"{"name":"p"}"#),
            ("bin/helper", b"\x7fELF\x02\x01\x01rest"),
            ("tools/run.dat", &pe),
        ]);
        let f = UnexpectedBinary.check(&c);
        assert_eq!(f.len(), 2);
        assert!(f[0].evidence.contains("ELF executable"));
        assert!(f[1].evidence.contains("Windows PE executable"));
    }

    #[test]
    fn native_addon_extension() {
        let c = ctx(&[("package.json", b"{}"), ("build/addon.node", b"\0\0\0\0")]);
        assert_eq!(UnexpectedBinary.check(&c).len(), 1);
    }

    #[test]
    fn declared_native_builds_and_text_starting_with_mz_are_fine() {
        let c = ctx(&[
            ("package.json", br#"{"gypfile": true}"#),
            ("build/Release/addon.node", b"\x7fELF"),
        ]);
        assert!(UnexpectedBinary.check(&c).is_empty());
        let c = ctx(&[("package.json", b"{}"), ("README.md", b"MZ is a postcode")]);
        assert!(UnexpectedBinary.check(&c).is_empty());
    }
}

//! LW007: obfuscated code.
//!
//! Four independent signals, each reported separately:
//! - a string literal over 1,000 characters with entropy above 5.0 bits per
//!   character (an encoded or encrypted payload),
//! - more than 30% of the file made of `\xNN` / `\uNNNN` escapes,
//! - a line over 5,000 characters in a file not named `*.min.js`,
//! - javascript-obfuscator's `_0x1a2b` identifiers, densely used.
//!
//! All thresholds are heuristics; see docs/RULES.md for known false positives.

use super::{Finding, Rule, Severity};
use crate::context::PackageContext;

pub struct Obfuscation;

pub const ENTROPY_THRESHOLD: f64 = 5.0;
pub const ESCAPE_RATIO_THRESHOLD: f64 = 0.30;
/// Files smaller than this are too short for the escape ratio to mean much.
pub const ESCAPE_MIN_FILE_BYTES: usize = 200;
pub const LONG_LINE_CHARS: usize = 5_000;
/// `_0x` identifiers: at least this many, and at least this many per KB.
pub const OBFUSCATOR_MIN_COUNT: usize = 10;
pub const OBFUSCATOR_MIN_PER_KB: f64 = 2.0;

fn is_minified_name(path: &str) -> bool {
    [".min.js", ".min.cjs", ".min.mjs"]
        .iter()
        .any(|ext| path.ends_with(ext))
}

impl Rule for Obfuscation {
    fn id(&self) -> &'static str {
        "LW007"
    }
    fn name(&self) -> &'static str {
        "Obfuscation"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn description(&self) -> &'static str {
        "a >1,000 character string with entropy >5.0 bits/char, >30% hex/unicode escapes, \
         a >5,000 character line outside *.min.js, or dense _0x identifiers"
    }

    fn check(&self, ctx: &PackageContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (path, facts) in &ctx.js {
            let file = Some(path.as_str());
            if let Some(s) = facts
                .long_strings
                .iter()
                .find(|s| s.entropy > ENTROPY_THRESHOLD)
            {
                findings.push(self.finding(
                    ctx,
                    file,
                    Some(s.hit.line),
                    &s.hit.evidence,
                    format!(
                        "A {}-character string literal has {:.2} bits/char of entropy, typical of \
                         an encoded or encrypted payload.",
                        s.length, s.entropy
                    ),
                ));
            }

            let ob = &facts.obfuscation;
            if ob.size >= ESCAPE_MIN_FILE_BYTES && ob.escape_ratio > ESCAPE_RATIO_THRESHOLD {
                if let Some(hit) = &ob.first_escape {
                    findings.push(self.finding(
                        ctx,
                        file,
                        Some(hit.line),
                        &hit.evidence,
                        format!(
                            "{:.0}% of the file is \\x or \\u escape sequences.",
                            ob.escape_ratio * 100.0
                        ),
                    ));
                }
            }

            if ob.longest_line_len > LONG_LINE_CHARS && !is_minified_name(path) {
                if let Some(hit) = &ob.longest_line {
                    findings.push(self.finding(
                        ctx,
                        file,
                        Some(hit.line),
                        &hit.evidence,
                        format!(
                            "Line {} is {} characters long in a file not named *.min.js.",
                            hit.line, ob.longest_line_len
                        ),
                    ));
                }
            }

            let per_kb = if ob.size == 0 {
                0.0
            } else {
                ob.obfuscator_identifiers as f64 * 1000.0 / ob.size as f64
            };
            if ob.obfuscator_identifiers >= OBFUSCATOR_MIN_COUNT && per_kb >= OBFUSCATOR_MIN_PER_KB
            {
                if let Some(hit) = &ob.first_obfuscator_identifier {
                    findings.push(self.finding(
                        ctx,
                        file,
                        Some(hit.line),
                        &hit.evidence,
                        format!(
                            "{} _0x-style identifiers ({per_kb:.1} per KB), the signature of \
                             javascript-obfuscator.",
                            ob.obfuscator_identifiers
                        ),
                    ));
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_helpers::ctx;

    /// Deterministic pseudo-random base64-ish text (high entropy).
    fn noise(len: usize) -> String {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut x: u32 = 12345;
        (0..len)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                alphabet[((x >> 16) % 64) as usize] as char
            })
            .collect()
    }

    #[test]
    fn high_entropy_string_and_escapes() {
        let payload = format!("const p = '{}';", noise(2_000));
        let escaped = format!("var s = \"{}\";", "\\x41\\x42\\x43".repeat(100));
        let c = ctx("p", &[("a.js", &payload), ("b.js", &escaped)]);
        let f = Obfuscation.check(&c);
        let explanations: Vec<&str> = f.iter().map(|x| x.explanation.as_str()).collect();
        assert_eq!(f.len(), 2, "{explanations:?}");
        assert!(explanations[0].contains("bits/char"));
        assert!(explanations[1].contains("escape sequences"));
    }

    #[test]
    fn long_lines_and_obfuscator_identifiers() {
        let long_line = format!("var a = [{}];", "1,".repeat(3_000));
        let obfuscated = (0..20)
            .map(|i| format!("var _0x{:04x}=_0x1a2b[{i}];", 0x1000 + i))
            .collect::<String>();
        let c = ctx(
            "p",
            &[("dist/bundle.js", &long_line), ("o.js", &obfuscated)],
        );
        let f = Obfuscation.check(&c);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f[0].explanation.contains("characters long"));
        assert!(f[1].explanation.contains("_0x-style"));
    }

    #[test]
    fn minified_files_and_normal_code_are_fine() {
        let long_line = format!("var a = [{}];", "1,".repeat(3_000));
        let english = format!("const msg = '{}';", "the quick brown fox ".repeat(100));
        let c = ctx(
            "p",
            &[("dist/app.min.js", &long_line), ("index.js", &english)],
        );
        assert!(Obfuscation.check(&c).is_empty());
    }
}

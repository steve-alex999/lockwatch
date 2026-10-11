//! Text helpers: line numbers, evidence snippets, entropy, host extraction
//! and the obfuscation measurements used by LW007.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

use super::{Hit, ObfuscationFacts, MAX_EVIDENCE_CHARS};

/// Maps byte offsets to line numbers. Built once per file; lookups are a
/// binary search over the offsets where lines start.
pub struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    pub fn new(source: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(source.match_indices('\n').map(|(i, _)| i + 1));
        LineIndex { starts }
    }

    /// 1-based line number containing byte `offset`.
    pub fn line_of(&self, offset: usize) -> u32 {
        // `partition_point` returns how many line starts are <= offset.
        let line = self.starts.partition_point(|&start| start <= offset);
        u32::try_from(line).unwrap_or(u32::MAX)
    }

    /// Byte range `[start, end)` of the line containing `offset`, without
    /// the newline.
    fn line_bounds(&self, source: &str, offset: usize) -> (usize, usize) {
        let idx = self
            .starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        let start = self.starts.get(idx).copied().unwrap_or(0);
        let end = source[start..]
            .find('\n')
            .map_or(source.len(), |rel| start + rel);
        (start, end)
    }

    /// The source line around `offset`, trimmed and cut to at most
    /// [`MAX_EVIDENCE_CHARS`]. On long (minified) lines, the excerpt is a
    /// window centred on the match rather than the start of the line.
    pub fn snippet(&self, source: &str, offset: usize) -> String {
        let offset = offset.min(source.len());
        let (start, end) = self.line_bounds(source, offset);
        let line = source.get(start..end).unwrap_or_default();
        if line.chars().count() <= MAX_EVIDENCE_CHARS {
            return truncate_chars(line.trim(), MAX_EVIDENCE_CHARS);
        }
        // Window: 60 bytes before the match, rest after, on char boundaries.
        let rel = offset - start;
        let mut from = rel.saturating_sub(60);
        while !line.is_char_boundary(from) {
            from -= 1;
        }
        let window = &line[from..];
        let body = truncate_chars(window.trim(), MAX_EVIDENCE_CHARS - 2);
        if from > 0 {
            format!("…{body}")
        } else {
            body
        }
    }
}

/// Cut `s` to at most `max` characters, ending in `…` if anything was cut.
pub fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Shannon entropy in bits per character: how unpredictable the next
/// character is. English text is about 4.2, base64 at most 6.0, and random
/// bytes approach 8.
pub fn shannon_entropy(s: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    let mut total = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// A regex that is compiled the first time it is used, then shared by all
/// threads. `OnceLock` is a thread-safe "set once" cell.
///
/// Compilation can fail only if the pattern itself is wrong, which is a
/// programming error. Instead of panicking (the spec bans `unwrap`/`expect`
/// outside tests), a broken pattern simply matches nothing, and the test
/// `all_patterns_compile` makes sure that never ships.
pub struct LazyRegex {
    pattern: &'static str,
    cell: OnceLock<Option<Regex>>,
}

impl LazyRegex {
    /// `const fn` so it can initialise a `static`.
    pub const fn new(pattern: &'static str) -> Self {
        LazyRegex {
            pattern,
            cell: OnceLock::new(),
        }
    }

    pub fn get(&self) -> Option<&Regex> {
        self.cell
            .get_or_init(|| Regex::new(self.pattern).ok())
            .as_ref()
    }

    pub fn is_match(&self, haystack: &str) -> bool {
        self.get().is_some_and(|re| re.is_match(haystack))
    }

    /// All matches. The `'h` lifetime ties each `Match` to the searched
    /// text, which it borrows from.
    pub fn find_iter<'s, 'h>(
        &'s self,
        haystack: &'h str,
    ) -> impl Iterator<Item = regex::Match<'h>> + use<'s, 'h> {
        self.get()
            .into_iter()
            .flat_map(move |re| re.find_iter(haystack))
    }

    pub fn captures_iter<'s, 'h>(
        &'s self,
        haystack: &'h str,
    ) -> impl Iterator<Item = regex::Captures<'h>> + use<'s, 'h> {
        self.get()
            .into_iter()
            .flat_map(move |re| re.captures_iter(haystack))
    }

    pub fn captures<'h>(&self, haystack: &'h str) -> Option<regex::Captures<'h>> {
        self.get().and_then(|re| re.captures(haystack))
    }

    #[cfg(test)]
    pub fn compiles(&self) -> bool {
        Regex::new(self.pattern).is_ok()
    }
}

static URL_HOST: LazyRegex =
    LazyRegex::new(r"(?i)\b(?:https?|wss?|ftp)://([a-z0-9.\-]+|\[[0-9a-f:]+\])");
static IPV4: LazyRegex =
    LazyRegex::new(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d{1,5})?$");
static ESCAPE: LazyRegex =
    LazyRegex::new(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\}");
static OBFUSCATOR_IDENT: LazyRegex = LazyRegex::new(r"\b_0x[0-9a-fA-F]{4,}\b");

/// Is `s` a dotted IPv4 address (optionally with `:port`)?
pub fn is_ipv4(s: &str) -> bool {
    IPV4.captures(s).is_some_and(|caps| {
        (1..=4).all(|i| {
            caps.get(i)
                .is_some_and(|m| m.as_str().parse::<u8>().is_ok())
        })
    })
}

/// Hosts named by URLs inside a string, plus the string itself if it is a
/// bare IP address. Loopback and empty hosts are ignored.
pub fn hosts_in_string(s: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for caps in URL_HOST.captures_iter(s) {
        if let Some(m) = caps.get(1) {
            let host = m.as_str().trim_end_matches('.').to_ascii_lowercase();
            if host.is_empty() || host == "localhost" || host.starts_with("127.") {
                continue;
            }
            let is_ip = is_ipv4(&host) || host.starts_with('[');
            out.push((host, is_ip));
        }
    }
    if out.is_empty() && is_ipv4(s.trim()) && !s.trim().starts_with("127.") {
        out.push((s.trim().to_string(), true));
    }
    out
}

/// Share of the file's characters that are `\xNN` / `\uNNNN` escapes.
pub fn escape_ratio(source: &str) -> f64 {
    if source.is_empty() {
        return 0.0;
    }
    let escaped: usize = ESCAPE.find_iter(source).map(|m| m.len()).sum();
    escaped as f64 / source.len() as f64
}

/// The longest line: (1-based line number, length in bytes, start offset).
pub fn longest_line(source: &str) -> (u32, usize, usize) {
    let mut best = (1u32, 0usize, 0usize);
    let mut offset = 0usize;
    for (i, line) in source.split('\n').enumerate() {
        if line.len() > best.1 {
            best = (u32::try_from(i + 1).unwrap_or(u32::MAX), line.len(), offset);
        }
        offset += line.len() + 1;
    }
    best
}

/// Count of `_0x1a2b`-style identifiers, the signature of
/// javascript-obfuscator output, and the byte offset of the first one.
pub fn obfuscator_identifiers(source: &str) -> (usize, Option<usize>) {
    let mut first = None;
    let mut count = 0;
    for m in OBFUSCATOR_IDENT.find_iter(source) {
        if first.is_none() {
            first = Some(m.start());
        }
        count += 1;
    }
    (count, first)
}

/// Compute all LW007 measurements for one file.
pub fn measure_obfuscation(source: &str) -> ObfuscationFacts {
    let lines = LineIndex::new(source);
    let hit_at = |offset: usize, detail: String| Hit {
        line: lines.line_of(offset),
        evidence: lines.snippet(source, offset),
        detail,
    };
    let (line_no, line_len, line_start) = longest_line(source);
    let (ident_count, first_ident) = obfuscator_identifiers(source);
    ObfuscationFacts {
        size: source.len(),
        escape_ratio: escape_ratio(source),
        first_escape: ESCAPE
            .find_iter(source)
            .next()
            .map(|m| hit_at(m.start(), "escape sequence".into())),
        longest_line: (line_len > 0).then(|| Hit {
            line: line_no,
            evidence: lines.snippet(source, line_start),
            detail: format!("{line_len} characters"),
        }),
        longest_line_len: line_len,
        obfuscator_identifiers: ident_count,
        first_obfuscator_identifier: first_ident
            .map(|offset| hit_at(offset, "_0x identifier".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile() {
        for re in [&URL_HOST, &IPV4, &ESCAPE, &OBFUSCATOR_IDENT] {
            assert!(re.compiles(), "{}", re.pattern);
        }
    }

    #[test]
    fn line_numbers_and_snippets() {
        let src = "a\n  const x = 1;  \nlast";
        let idx = LineIndex::new(src);
        assert_eq!(idx.line_of(0), 1);
        assert_eq!(idx.line_of(4), 2);
        assert_eq!(idx.line_of(src.len() - 1), 3);
        assert_eq!(idx.snippet(src, 5), "const x = 1;");

        let long = format!("{}MATCH{}", "x".repeat(500), "y".repeat(500));
        let idx = LineIndex::new(&long);
        let snip = idx.snippet(&long, 500);
        assert!(snip.contains("MATCH"));
        assert!(snip.chars().count() <= MAX_EVIDENCE_CHARS);
    }

    #[test]
    fn entropy_values() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
    }

    #[test]
    fn hosts_and_ips() {
        assert_eq!(
            hosts_in_string("http://203.0.113.5/p"),
            vec![("203.0.113.5".to_string(), true)]
        );
        assert_eq!(
            hosts_in_string("see https://Example.INVALID/x and wss://c2.example.invalid:8443"),
            vec![
                ("example.invalid".to_string(), false),
                ("c2.example.invalid".to_string(), false)
            ]
        );
        assert_eq!(
            hosts_in_string("203.0.113.9"),
            vec![("203.0.113.9".to_string(), true)]
        );
        assert!(hosts_in_string("http://localhost:3000").is_empty());
        assert!(hosts_in_string("1.2.3").is_empty());
        assert!(!is_ipv4("999.1.1.1"));
    }

    #[test]
    fn obfuscation_measurements() {
        assert!(escape_ratio(r"\x41\x42\x43") > 0.99);
        assert_eq!(escape_ratio("plain"), 0.0);
        assert_eq!(longest_line("a\nbbb\ncc"), (2, 3, 2));
        let (n, first) = obfuscator_identifiers("var _0x1a2b=1; _0x1a2b(); _0xzz;");
        assert_eq!((n, first), (2, Some(4)));
    }
}

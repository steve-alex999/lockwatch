//! Static analysis helpers shared by the rules.
//!
//! The rules do not walk syntax trees themselves. Instead, each JavaScript
//! file is analysed once ([`js::analyze_js`]) into a plain [`JsFacts`]
//! struct ("this file calls child_process.exec on line 4", "it reads
//! process.env.NPM_TOKEN on line 9", ...), and each rule filters those facts.
//! That keeps the rules short and lets them run in parallel: the facts are
//! ordinary owned data (`Send + Sync`), while oxc's syntax tree lives in a
//! single-threaded memory arena.

pub mod fallback;
pub mod js;
pub mod shell;
pub mod text;

/// Maximum length of an evidence snippet, in characters (from the spec).
pub const MAX_EVIDENCE_CHARS: usize = 200;

/// One place in a file where something interesting was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// 1-based line number.
    pub line: u32,
    /// A short excerpt of the source around the match.
    pub evidence: String,
    /// What matched, for example `child_process.execSync` or `NPM_TOKEN`.
    pub detail: String,
}

/// A hard-coded network destination found in a string literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHit {
    pub hit: Hit,
    pub host: String,
    pub is_ip: bool,
}

/// A string literal longer than 1,000 characters.
#[derive(Debug, Clone, PartialEq)]
pub struct LongString {
    pub hit: Hit,
    pub length: usize,
    /// Shannon entropy in bits per character.
    pub entropy: f64,
}

/// Everything the rules want to know about one JavaScript file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct JsFacts {
    /// `false` when the parser failed and the regex fallback was used.
    pub parsed: bool,
    /// Calls such as `child_process.exec(...)` (detail = function name).
    pub child_process_calls: Vec<Hit>,
    /// `require('child_process')` / `import ... from 'child_process'`.
    pub child_process_imports: Vec<Hit>,
    /// Network modules imported, and `fetch()` calls (detail = module).
    pub network: Vec<Hit>,
    /// Hard-coded IP addresses and host names in string literals.
    pub hosts: Vec<HostHit>,
    /// Reads of secret-looking environment variables (detail = name).
    pub secret_env_reads: Vec<Hit>,
    /// String literals naming credential files such as `.npmrc`.
    pub credential_paths: Vec<Hit>,
    /// The file calls a file-reading function (`readFileSync`, ...).
    pub reads_files: bool,
    /// `eval`, `new Function`, `vm.runIn*`, `require(<computed>)`.
    pub dynamic_code: Vec<Hit>,
    pub long_strings: Vec<LongString>,
    /// Relative module paths this file requires or imports (`./lib/x`).
    pub local_requires: Vec<String>,
    /// Measurements for the obfuscation rule (LW007).
    pub obfuscation: ObfuscationFacts,
}

/// Raw-text measurements used by LW007. Computed for every JavaScript file,
/// parsed or not.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ObfuscationFacts {
    /// File size in bytes.
    pub size: usize,
    /// Share of the file made of `\xNN` / `\uNNNN` escapes (0.0 to 1.0).
    pub escape_ratio: f64,
    /// Where the first escape sequence is.
    pub first_escape: Option<Hit>,
    /// The longest line, its length in bytes in `detail`.
    pub longest_line: Option<Hit>,
    pub longest_line_len: usize,
    /// Number of `_0x1a2b`-style identifiers, and where the first one is.
    pub obfuscator_identifiers: usize,
    pub first_obfuscator_identifier: Option<Hit>,
}

/// Node's built-in network modules plus common HTTP client packages.
pub const NETWORK_MODULES: [&str; 14] = [
    "http",
    "https",
    "http2",
    "net",
    "tls",
    "dns",
    "dgram",
    "axios",
    "node-fetch",
    "got",
    "request",
    "undici",
    "needle",
    "superagent",
];

/// child_process functions that start a program.
pub const CHILD_PROCESS_FUNCTIONS: [&str; 7] = [
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "spawn",
    "spawnSync",
    "fork",
];

/// Environment variable names that look like secrets (rule LW005).
/// Matched case-insensitively.
pub fn is_secret_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    matches!(upper.as_str(), "NPM_TOKEN" | "GITHUB_TOKEN" | "GH_TOKEN")
        || upper.starts_with("AWS_")
        || upper.contains("SECRET")
        || upper.contains("KEY")
}

/// Does a string name a credential file (rule LW005)? Covers both whole
/// paths (`~/.aws/credentials`) and the pieces passed to `path.join`
/// (`'.ssh'`, `'.aws'`).
pub fn is_credential_path(s: &str) -> bool {
    let s = s.replace('\\', "/");
    s.contains(".npmrc")
        || s.contains(".git-credentials")
        || s.contains(".aws/credentials")
        || s.contains(".ssh/")
        || s == ".ssh"
        || s == ".aws"
        || s.ends_with("/.ssh")
}

/// Strip the `node:` prefix so `node:child_process` == `child_process`.
pub fn normalize_module(name: &str) -> &str {
    name.strip_prefix("node:").unwrap_or(name)
}

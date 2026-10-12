//! The scan report: the JSON structure (see docs/report.schema.json) and the
//! human-readable table.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::rules::{Finding, Severity};
use crate::score::RiskLevel;

pub const TOOL_NAME: &str = "lockwatch";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub tool: String,
    pub version: String,
    /// RFC 3339 UTC time of the scan.
    pub scanned_at: String,
    /// The lockfile name, or `name@version` for `scan-package`.
    pub lockfile: String,
    pub summary: Summary,
    /// Every scanned package, highest risk first.
    pub packages: Vec<PackageReport>,
    /// Packages that were not scanned, with the reason.
    pub skipped: Vec<SkippedPackage>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub packages_total: usize,
    pub packages_scanned: usize,
    pub packages_skipped: usize,
    pub findings: SeverityCounts,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn add(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageReport {
    pub name: String,
    pub version: String,
    pub risk_score: u32,
    pub risk_level: RiskLevel,
    pub findings: Vec<Finding>,
    /// Notes such as "file X over the size limit, not analysed".
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedPackage {
    pub name: String,
    pub version: Option<String>,
    pub reason: String,
    /// True when the package could not be scanned because of an error (for
    /// example a download failure), false when it was skipped on purpose
    /// (local folder, git dependency).
    pub error: bool,
}

impl Report {
    /// Is there a finding at or above `threshold`?
    pub fn has_findings_at_or_above(&self, threshold: Severity) -> bool {
        self.packages
            .iter()
            .flat_map(|p| &p.findings)
            .any(|f| f.severity >= threshold)
    }

    /// Were some packages not scanned because of errors?
    pub fn is_incomplete(&self) -> bool {
        self.skipped.iter().any(|s| s.error)
    }

    /// Human-readable output: one row per package with findings, sorted by
    /// score, then the details, the skipped list and the summary.
    pub fn to_table(&self) -> String {
        let mut out = String::new();
        // `writeln!` into a String cannot fail; `let _ =` discards the Ok(()).
        let scanned = self.summary.packages_scanned;
        let _ = writeln!(
            out,
            "{} {}: {scanned} package{} from {} scanned in {:.1} s\n",
            self.tool,
            self.version,
            if scanned == 1 { "" } else { "s" },
            self.lockfile,
            self.summary.duration_ms as f64 / 1000.0
        );

        let flagged: Vec<&PackageReport> = self
            .packages
            .iter()
            .filter(|p| !p.findings.is_empty())
            .collect();
        if flagged.is_empty() {
            out.push_str("No findings.\n");
        } else {
            let rows: Vec<[String; 4]> = flagged
                .iter()
                .map(|p| {
                    let mut ids: Vec<&str> =
                        p.findings.iter().map(|f| f.rule_id.as_str()).collect();
                    ids.dedup();
                    [
                        format!("{}@{}", p.name, p.version),
                        p.risk_level.as_str().to_string(),
                        p.risk_score.to_string(),
                        ids.join(", "),
                    ]
                })
                .collect();
            let header = ["PACKAGE", "LEVEL", "SCORE", "RULES"].map(String::from);
            let widths: Vec<usize> = (0..4)
                .map(|i| {
                    rows.iter()
                        .chain(std::iter::once(&header))
                        .map(|r| r[i].chars().count())
                        .max()
                        .unwrap_or(0)
                })
                .collect();
            for row in std::iter::once(&header).chain(rows.iter()) {
                let _ = writeln!(
                    out,
                    "{:<w0$}  {:<w1$}  {:>w2$}  {}",
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    w0 = widths[0],
                    w1 = widths[1],
                    w2 = widths[2]
                );
            }
            let clean = self.packages.len() - flagged.len();
            if clean > 0 {
                let _ = writeln!(out, "({clean} packages with no findings not shown)");
            }

            out.push_str("\nFindings\n");
            for p in &flagged {
                let _ = writeln!(
                    out,
                    "\n  {}@{} ({}, score {})",
                    p.name,
                    p.version,
                    p.risk_level.as_str(),
                    p.risk_score
                );
                for f in &p.findings {
                    let location = match (&f.file, f.line) {
                        (Some(file), Some(line)) => format!(" {file}:{line}"),
                        (Some(file), None) => format!(" {file}"),
                        _ => String::new(),
                    };
                    let _ = writeln!(
                        out,
                        "    [{}] {}{}",
                        f.severity.as_str(),
                        f.rule_id,
                        location
                    );
                    let _ = writeln!(out, "        {}", f.evidence);
                    let _ = writeln!(out, "        {}", f.explanation);
                }
                for w in &p.warnings {
                    let _ = writeln!(out, "    note: {w}");
                }
            }
        }

        if !self.skipped.is_empty() {
            let _ = writeln!(out, "\nSkipped ({})", self.skipped.len());
            for s in &self.skipped {
                let version = s
                    .version
                    .as_deref()
                    .map(|v| format!("@{v}"))
                    .unwrap_or_default();
                let _ = writeln!(out, "  {}{}: {}", s.name, version, s.reason);
            }
        }

        let c = &self.summary.findings;
        let _ = writeln!(
            out,
            "\nFindings: critical {} | high {} | medium {} | low {} | info {}",
            c.critical, c.high, c.medium, c.low, c.info
        );
        if self.is_incomplete() {
            out.push_str("WARNING: some packages could not be scanned (see Skipped).\n");
        }
        out
    }
}

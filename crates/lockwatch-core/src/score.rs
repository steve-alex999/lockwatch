//! Risk score per package, from 0 to 100.
//!
//! All weights and thresholds live here (and are documented in
//! docs/RULES.md):
//! - each rule that fired adds the weight of its most severe finding:
//!   critical 60, high 30, medium 12, low 3, info 0,
//! - plus 15 if LW004 (install-time network) and LW005 (credential access)
//!   fired in the same file,
//! - capped at 100.
//!
//! Levels: 0-9 none, 10-29 low, 30-59 medium, 60-79 high, 80+ critical.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::rules::{Finding, Severity};

pub const WEIGHT_CRITICAL: u32 = 60;
pub const WEIGHT_HIGH: u32 = 30;
pub const WEIGHT_MEDIUM: u32 = 12;
pub const WEIGHT_LOW: u32 = 3;
pub const WEIGHT_INFO: u32 = 0;
/// Extra points when network access and credential access share a file.
pub const EXFILTRATION_BONUS: u32 = 15;
pub const MAX_SCORE: u32 = 100;

/// Lowest score of each level.
pub const LEVEL_LOW: u32 = 10;
pub const LEVEL_MEDIUM: u32 = 30;
pub const LEVEL_HIGH: u32 = 60;
pub const LEVEL_CRITICAL: u32 = 80;

pub fn severity_weight(severity: Severity) -> u32 {
    match severity {
        Severity::Critical => WEIGHT_CRITICAL,
        Severity::High => WEIGHT_HIGH,
        Severity::Medium => WEIGHT_MEDIUM,
        Severity::Low => WEIGHT_LOW,
        Severity::Info => WEIGHT_INFO,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::None => "none",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

pub fn risk_level(score: u32) -> RiskLevel {
    match score {
        s if s >= LEVEL_CRITICAL => RiskLevel::Critical,
        s if s >= LEVEL_HIGH => RiskLevel::High,
        s if s >= LEVEL_MEDIUM => RiskLevel::Medium,
        s if s >= LEVEL_LOW => RiskLevel::Low,
        _ => RiskLevel::None,
    }
}

/// Score a package's findings. Several findings from the same rule count
/// once (at their highest severity), so a file with 40 `eval` calls does not
/// outscore a credential stealer.
pub fn risk_score(findings: &[Finding]) -> u32 {
    let mut worst_per_rule: BTreeMap<&str, Severity> = BTreeMap::new();
    for f in findings {
        let entry = worst_per_rule
            .entry(f.rule_id.as_str())
            .or_insert(f.severity);
        *entry = (*entry).max(f.severity);
    }
    let mut score: u32 = worst_per_rule.values().map(|s| severity_weight(*s)).sum();

    let files_with = |rule: &str| -> BTreeSet<&str> {
        findings
            .iter()
            .filter(|f| f.rule_id == rule)
            .filter_map(|f| f.file.as_deref())
            .collect()
    };
    if !files_with("LW004").is_disjoint(&files_with("LW005")) {
        score += EXFILTRATION_BONUS;
    }
    score.min(MAX_SCORE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(rule: &str, severity: Severity, file: &str) -> Finding {
        Finding {
            rule_id: rule.into(),
            severity,
            package: "p".into(),
            version: "1".into(),
            file: Some(file.into()),
            line: None,
            evidence: String::new(),
            explanation: String::new(),
        }
    }

    #[test]
    fn same_rule_counts_once_at_its_worst() {
        let findings = vec![
            f("LW006", Severity::Medium, "a.js"),
            f("LW006", Severity::Medium, "b.js"),
            f("LW001", Severity::Info, "package.json"),
            f("LW001", Severity::Low, "package.json"),
        ];
        assert_eq!(risk_score(&findings), WEIGHT_MEDIUM + WEIGHT_LOW);
        assert_eq!(risk_level(15), RiskLevel::Low);
    }

    #[test]
    fn exfiltration_bonus_and_cap() {
        let findings = vec![
            f("LW004", Severity::High, "i.js"),
            f("LW005", Severity::Critical, "i.js"),
        ];
        assert_eq!(risk_score(&findings), MAX_SCORE); // 30 + 60 + 15 = 105
        let apart = vec![
            f("LW004", Severity::High, "i.js"),
            f("LW005", Severity::High, "other.js"),
        ];
        assert_eq!(risk_score(&apart), 60);
        assert_eq!(risk_level(60), RiskLevel::High);
    }

    #[test]
    fn level_boundaries() {
        let cases = [
            (0, RiskLevel::None),
            (9, RiskLevel::None),
            (10, RiskLevel::Low),
            (29, RiskLevel::Low),
            (30, RiskLevel::Medium),
            (59, RiskLevel::Medium),
            (60, RiskLevel::High),
            (79, RiskLevel::High),
            (80, RiskLevel::Critical),
            (100, RiskLevel::Critical),
        ];
        for (score, level) in cases {
            assert_eq!(risk_level(score), level, "{score}");
        }
    }
}

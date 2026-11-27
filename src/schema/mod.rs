pub mod catalog;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;
use std::str::FromStr;

pub const SCHEMA_VERSION: &str = "1.0";
pub const TOOL_NAME: &str = "raksa-hostguard";
pub const LAYER_HOST: &str = "host-hardening";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 1,
            Severity::Low => 2,
            Severity::Medium => 3,
            Severity::High => 4,
            Severity::Critical => 5,
        }
    }

    pub fn meets_threshold(self, threshold: Option<Severity>) -> bool {
        match threshold {
            Some(limit) => self.rank() >= limit.rank(),
            None => false,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "info" => Ok(Severity::Info),
            other => Err(format!(
                "invalid severity {:?}: expected critical, high, medium, low, or info",
                other
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub module: String,
    pub layer: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub evidence: Map<String, Value>,
    pub remediation: String,
    pub mitre_d3fend: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Summary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureScore {
    pub score: u8,
    pub grade: String,
}

pub fn compute_posture(summary: &Summary) -> PostureScore {
    let deduction = summary
        .critical
        .saturating_mul(25)
        .saturating_add(summary.high.saturating_mul(15))
        .saturating_add(summary.medium.saturating_mul(8))
        .saturating_add(summary.low.saturating_mul(3))
        .saturating_add(summary.info);
    let score = 100usize.saturating_sub(deduction) as u8;
    let grade = match score {
        95..=100 => "A+",
        90..=94 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    };
    PostureScore {
        score,
        grade: grade.to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub tool: String,
    pub layer: String,
    pub generated_at: DateTime<Utc>,
    pub posture: PostureScore,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(findings: Vec<Finding>, generated_at: DateTime<Utc>) -> Self {
        let mut summary = Summary {
            total: findings.len(),
            ..Summary::default()
        };
        for f in &findings {
            match f.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }
        let posture = compute_posture(&summary);

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            tool: TOOL_NAME.to_string(),
            layer: LAYER_HOST.to_string(),
            generated_at,
            posture,
            summary,
            findings,
        }
    }

    pub fn has_threshold_breach(&self, threshold: Option<Severity>) -> bool {
        let Some(limit) = threshold else {
            return false;
        };
        self.findings.iter().any(|f| f.severity >= limit)
    }
}

pub fn sanitize_id_part(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_severities_and_ranks() {
        assert_eq!("CRITICAL".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!(" high ".parse::<Severity>().unwrap(), Severity::High);
        assert_eq!("Medium".parse::<Severity>().unwrap(), Severity::Medium);
        assert_eq!("low".parse::<Severity>().unwrap(), Severity::Low);
        assert_eq!("info".parse::<Severity>().unwrap(), Severity::Info);
        assert!("extreme".parse::<Severity>().is_err());

        assert!(Severity::Critical.meets_threshold(Some(Severity::High)));
        assert!(!Severity::Medium.meets_threshold(Some(Severity::High)));
        assert!(!Severity::Critical.meets_threshold(None));
    }

    #[test]
    fn builds_report_summary_and_threshold_breach() {
        let now = Utc::now();
        let empty = Report::new(Vec::new(), now);
        assert_eq!(empty.summary.total, 0);
        assert!(!empty.has_threshold_breach(Some(Severity::Info)));

        let mk = |sev: Severity| Finding {
            id: "id".to_string(),
            rule_id: "HOST-001".to_string(),
            module: "fim".to_string(),
            layer: LAYER_HOST.to_string(),
            severity: sev,
            title: "t".to_string(),
            description: "d".to_string(),
            target: "file:///etc/passwd".to_string(),
            evidence: Map::new(),
            remediation: "r".to_string(),
            mitre_d3fend: "D3-FIM".to_string(),
            timestamp: now,
        };

        let rep = Report::new(
            vec![
                mk(Severity::Critical),
                mk(Severity::High),
                mk(Severity::Medium),
                mk(Severity::Low),
                mk(Severity::Info),
            ],
            now,
        );
        assert_eq!(rep.summary.total, 5);
        assert_eq!(rep.summary.critical, 1);
        assert_eq!(rep.summary.high, 1);
        assert_eq!(rep.summary.medium, 1);
        assert_eq!(rep.summary.low, 1);
        assert_eq!(rep.summary.info, 1);
        assert_eq!(rep.posture.score, 48);
        assert_eq!(rep.posture.grade, "F");
        assert!(rep.has_threshold_breach(Some(Severity::High)));

        assert_eq!(empty.posture.score, 100);
        assert_eq!(empty.posture.grade, "A+");
    }
}

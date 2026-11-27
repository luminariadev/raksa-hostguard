use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::audit::MAX_CONFIG_BYTES;
use crate::schema::{Finding, Severity, SCHEMA_VERSION, TOOL_NAME};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default)]
    pub suppressions: Vec<Suppression>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    pub rule_id: String,
    #[serde(default)]
    pub target_contains: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub expires_on: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingBaseline {
    pub schema_version: String,
    pub tool: String,
    pub generated_at: DateTime<Utc>,
    #[serde(default)]
    pub fingerprints: Vec<String>,
}

pub fn discover_policy_in_dir(dir: &Path) -> Option<PathBuf> {
    let base = if dir.is_file() {
        dir.parent().unwrap_or_else(|| Path::new("."))
    } else {
        dir
    };
    for name in [".hostguard.yml", ".hostguard.yaml"] {
        let candidate = base.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn finding_fingerprint(finding: &Finding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.rule_id.as_bytes());
    hasher.update(b"|");
    hasher.update(finding.module.as_bytes());
    hasher.update(b"|");
    hasher.update(finding.target.as_bytes());
    hasher.update(b"|");
    hasher.update(finding.title.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

pub fn write_finding_baseline(path: &Path, findings: &[Finding]) -> Result<usize, String> {
    let mut unique = BTreeSet::new();
    for f in findings {
        unique.insert(finding_fingerprint(f));
    }
    let fingerprints: Vec<String> = unique.into_iter().collect();
    let count = fingerprints.len();

    let baseline = FindingBaseline {
        schema_version: SCHEMA_VERSION.to_string(),
        tool: TOOL_NAME.to_string(),
        generated_at: Utc::now(),
        fingerprints,
    };

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create baseline directory {:?}: {e}", parent))?;
    }
    let encoded = serde_json::to_string_pretty(&baseline)
        .map_err(|e| format!("failed to encode finding baseline: {e}"))?;
    fs::write(path, format!("{encoded}\n"))
        .map_err(|e| format!("failed to write finding baseline {:?}: {e}", path))?;
    Ok(count)
}

pub fn load_finding_baseline(path: &Path) -> Result<FindingBaseline, String> {
    let mut file =
        File::open(path).map_err(|e| format!("failed to open baseline file {:?}: {e}", path))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("failed to stat baseline file {:?}: {e}", path))?;
    if meta.len() > MAX_CONFIG_BYTES as u64 {
        return Err(format!(
            "baseline file {:?} exceeds {} byte limit",
            path, MAX_CONFIG_BYTES
        ));
    }

    let mut buf = Vec::with_capacity(meta.len() as usize);
    (&mut file)
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("failed to read baseline file {:?}: {e}", path))?;
    if buf.len() > MAX_CONFIG_BYTES {
        return Err(format!(
            "baseline file {:?} exceeds {} byte limit",
            path, MAX_CONFIG_BYTES
        ));
    }

    let text = String::from_utf8(buf)
        .map_err(|e| format!("baseline file {:?} is not valid UTF-8: {e}", path))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("failed to parse finding baseline {:?}: {e}", path))
}

pub fn apply_finding_baseline(
    findings: Vec<Finding>,
    baseline: &FindingBaseline,
) -> (Vec<Finding>, usize) {
    let known: BTreeSet<&str> = baseline.fingerprints.iter().map(String::as_str).collect();
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed = 0usize;
    for finding in findings {
        let fp = finding_fingerprint(&finding);
        if known.contains(fp.as_str()) {
            suppressed += 1;
        } else {
            kept.push(finding);
        }
    }
    (kept, suppressed)
}

pub fn load_policy(path: &Path) -> Result<Policy, String> {
    let mut file =
        File::open(path).map_err(|e| format!("failed to open policy file {:?}: {e}", path))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("failed to stat policy file {:?}: {e}", path))?;
    if meta.len() > MAX_CONFIG_BYTES as u64 {
        return Err(format!(
            "policy file {:?} exceeds {} byte limit",
            path, MAX_CONFIG_BYTES
        ));
    }

    let mut buf = Vec::with_capacity(meta.len() as usize);
    (&mut file)
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("failed to read policy file {:?}: {e}", path))?;
    if buf.len() > MAX_CONFIG_BYTES {
        return Err(format!(
            "policy file {:?} exceeds {} byte limit",
            path, MAX_CONFIG_BYTES
        ));
    }

    let text = String::from_utf8(buf)
        .map_err(|e| format!("policy file {:?} is not valid UTF-8: {e}", path))?;
    let policy: Policy = serde_yaml_ng::from_str(&text)
        .map_err(|e| format!("failed to parse YAML/JSON policy {:?}: {e}", path))?;

    for (idx, sup) in policy.suppressions.iter().enumerate() {
        if sup.rule_id.trim().is_empty() {
            return Err(format!("suppression #{idx} has an empty rule_id"));
        }
        if sup.reason.trim().is_empty() {
            return Err(format!(
                "suppression #{idx} ({}) must declare a non-empty audit reason",
                sup.rule_id
            ));
        }
        if let Some(exp) = &sup.expires_on {
            NaiveDate::parse_from_str(exp.trim(), "%Y-%m-%d").map_err(|_| {
                format!(
                    "suppression #{idx} ({}) has invalid expires_on date {:?} (expected YYYY-MM-DD)",
                    sup.rule_id, exp
                )
            })?;
        }
    }

    Ok(policy)
}

pub fn apply_policy(
    findings: Vec<Finding>,
    policy: &Policy,
    today: NaiveDate,
) -> (Vec<Finding>, usize) {
    let mut kept = Vec::with_capacity(findings.len());
    let mut filtered_count = 0usize;

    for finding in findings {
        if let Some(min_sev) = policy.min_severity {
            if finding.severity < min_sev {
                filtered_count += 1;
                continue;
            }
        }

        let is_suppressed = policy.suppressions.iter().any(|sup| {
            if !sup.rule_id.trim().eq_ignore_ascii_case(&finding.rule_id) {
                return false;
            }
            if let Some(substr) = &sup.target_contains {
                let s = substr.trim();
                if !s.is_empty() && !finding.target.contains(s) {
                    return false;
                }
            }
            match &sup.expires_on {
                None => true,
                Some(exp) => match NaiveDate::parse_from_str(exp.trim(), "%Y-%m-%d") {
                    Ok(exp_date) => exp_date >= today,
                    Err(_) => false,
                },
            }
        });

        if is_suppressed {
            filtered_count += 1;
        } else {
            kept.push(finding);
        }
    }

    (kept, filtered_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::LAYER_HOST;
    use chrono::Utc;
    use serde_json::Map;
    use tempfile::tempdir;

    fn mk_finding(rule_id: &str, severity: Severity, target: &str) -> Finding {
        Finding {
            id: format!("id-{rule_id}"),
            rule_id: rule_id.to_string(),
            module: "test".to_string(),
            layer: LAYER_HOST.to_string(),
            severity,
            title: "Test".to_string(),
            description: "Desc".to_string(),
            target: target.to_string(),
            evidence: Map::new(),
            remediation: "Fix".to_string(),
            mitre_d3fend: "D3-FIM".to_string(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn suppresses_active_and_ignores_expired_rules() {
        let today = NaiveDate::from_ymd_opt(2026, 11, 26).unwrap();
        let policy = Policy {
            min_severity: None,
            suppressions: vec![
                Suppression {
                    rule_id: "HOST-204".to_string(),
                    target_contains: Some("legacy.Dockerfile".to_string()),
                    reason: "Pinned in next sprint".to_string(),
                    expires_on: Some("2026-12-31".to_string()),
                },
                Suppression {
                    rule_id: "HOST-104".to_string(),
                    target_contains: None,
                    reason: "Expired exception".to_string(),
                    expires_on: Some("2026-01-01".to_string()),
                },
            ],
        };

        let findings = vec![
            mk_finding("HOST-204", Severity::Medium, "file://legacy.Dockerfile"),
            mk_finding("HOST-204", Severity::Medium, "file://prod.Dockerfile"),
            mk_finding("HOST-104", Severity::Medium, "file://sshd_config"),
        ];

        let (kept, suppressed) = apply_policy(findings, &policy, today);
        assert_eq!(suppressed, 1);
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].target, "file://prod.Dockerfile");
        assert_eq!(kept[1].rule_id, "HOST-104");
    }

    #[test]
    fn enforces_min_severity_and_validates_policy_dates() {
        let today = NaiveDate::from_ymd_opt(2026, 11, 26).unwrap();
        let policy = Policy {
            min_severity: Some(Severity::High),
            suppressions: vec![],
        };

        let findings = vec![
            mk_finding("HOST-204", Severity::Medium, "file://Dockerfile"),
            mk_finding("HOST-201", Severity::High, "file://Dockerfile"),
            mk_finding("HOST-001", Severity::Critical, "file:///etc/passwd"),
        ];
        let (kept, filtered) = apply_policy(findings, &policy, today);
        assert_eq!(filtered, 1);
        assert_eq!(kept.len(), 2);

        let dir = tempdir().unwrap();
        let bad_path = dir.path().join("bad-policy.yml");
        std::fs::write(
            &bad_path,
            "suppressions:\n  - rule_id: HOST-204\n    reason: test\n    expires_on: 2026/12/31\n",
        )
        .unwrap();
        assert!(load_policy(&bad_path).is_err());

        let good_path = dir.path().join("good-policy.yml");
        std::fs::write(
            &good_path,
            "min_severity: medium\nsuppressions:\n  - rule_id: HOST-204\n    reason: base digest tracked upstream\n    expires_on: 2027-06-01\n",
        )
        .unwrap();
        let loaded = load_policy(&good_path).expect("valid policy");
        assert_eq!(loaded.min_severity, Some(Severity::Medium));
        assert_eq!(loaded.suppressions.len(), 1);
    }

    #[test]
    fn finding_baseline_roundtrip_and_policy_autodiscovery() {
        let dir = tempdir().unwrap();
        assert!(discover_policy_in_dir(dir.path()).is_none());

        let hidden = dir.path().join(".hostguard.yml");
        std::fs::write(&hidden, "min_severity: low\n").unwrap();
        assert_eq!(discover_policy_in_dir(dir.path()), Some(hidden));

        let f1 = mk_finding(
            "HOST-305",
            Severity::High,
            "file:///etc/systemd/system/app.service",
        );
        let f2 = mk_finding("HOST-306", Severity::High, "file:///etc/crontab");
        let base_path = dir.path().join("baselines/hostguard-baseline.json");

        let count = write_finding_baseline(&base_path, &[f1.clone(), f1.clone()]).unwrap();
        assert_eq!(count, 1);

        let loaded = load_finding_baseline(&base_path).unwrap();
        let (kept, suppressed) = apply_finding_baseline(vec![f1, f2.clone()], &loaded);
        assert_eq!(suppressed, 1);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].rule_id, "HOST-306");
    }
}

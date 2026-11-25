pub mod hash;

use crate::schema::{sanitize_id_part, Finding, Severity, LAYER_HOST, SCHEMA_VERSION, TOOL_NAME};
use chrono::{DateTime, Utc};
use hash::{hash_file_streaming, FimError, DEFAULT_MAX_FILE_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;

const MODULE_FIM: &str = "fim";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub sha256: String,
    pub size: u64,
    pub mode: String,
    pub modified_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub schema_version: String,
    pub tool: String,
    pub created_at: DateTime<Utc>,
    pub root_paths: Vec<String>,
    pub max_file_bytes: u64,
    #[serde(default)]
    pub excludes: Vec<String>,
    pub entries: BTreeMap<String, FileEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct SnapshotStats {
    pub files_hashed: usize,
    pub files_skipped_oversize: usize,
    pub files_skipped_error: usize,
}

pub fn create_snapshot(
    roots: &[PathBuf],
    excludes: &[String],
    max_file_bytes: u64,
) -> Result<(BaselineSnapshot, SnapshotStats), FimError> {
    if roots.is_empty() {
        return Err(FimError::InvalidInput(
            "at least one --path must be provided".to_string(),
        ));
    }

    let limit = if max_file_bytes == 0 {
        DEFAULT_MAX_FILE_BYTES
    } else {
        max_file_bytes
    };

    let mut normalized_roots = Vec::with_capacity(roots.len());
    let mut entries = BTreeMap::new();
    let mut stats = SnapshotStats::default();

    for root in roots {
        if !root.exists() {
            return Err(FimError::InvalidInput(format!(
                "monitored path {:?} does not exist",
                root
            )));
        }
        let canon = fs::canonicalize(root).unwrap_or_else(|_| root.clone());
        normalized_roots.push(normalize_path(&canon));

        for walk_item in WalkDir::new(&canon).follow_links(false) {
            let entry = match walk_item {
                Ok(e) => e,
                Err(_) => {
                    stats.files_skipped_error += 1;
                    continue;
                }
            };
            if entry.path_is_symlink() || !entry.file_type().is_file() {
                continue;
            }
            let path_key = normalize_path(entry.path());
            if is_excluded(&path_key, excludes) {
                continue;
            }

            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => {
                    stats.files_skipped_error += 1;
                    continue;
                }
            };

            match hash_file_streaming(entry.path(), limit) {
                Ok((sha256, size)) => {
                    stats.files_hashed += 1;
                    entries.insert(
                        path_key,
                        FileEntry {
                            sha256,
                            size,
                            mode: format_permissions(&meta),
                            modified_unix: modified_unix(&meta),
                        },
                    );
                }
                Err(FimError::TooLarge { .. }) => {
                    stats.files_skipped_oversize += 1;
                }
                Err(_) => {
                    stats.files_skipped_error += 1;
                }
            }
        }
    }

    let snapshot = BaselineSnapshot {
        schema_version: SCHEMA_VERSION.to_string(),
        tool: TOOL_NAME.to_string(),
        created_at: Utc::now(),
        root_paths: normalized_roots,
        max_file_bytes: limit,
        excludes: excludes.to_vec(),
        entries,
    };

    Ok((snapshot, stats))
}

pub fn save_snapshot(path: &Path, snapshot: &BaselineSnapshot) -> Result<(), FimError> {
    let json = serde_json::to_string_pretty(snapshot)?;
    fs::write(path, json)?;
    Ok(())
}

pub fn load_snapshot(path: &Path) -> Result<BaselineSnapshot, FimError> {
    let raw = fs::read_to_string(path)?;
    let snap: BaselineSnapshot = serde_json::from_str(&raw)?;
    Ok(snap)
}

pub fn verify_snapshot(snapshot: &BaselineSnapshot) -> Result<Vec<Finding>, FimError> {
    let now = Utc::now();
    let mut findings = Vec::new();
    let mut seen_paths = BTreeSet::new();
    let limit = if snapshot.max_file_bytes == 0 {
        DEFAULT_MAX_FILE_BYTES
    } else {
        snapshot.max_file_bytes
    };

    for (path_key, expected) in &snapshot.entries {
        seen_paths.insert(path_key.clone());
        let p = Path::new(path_key);
        let Ok(meta) = fs::symlink_metadata(p) else {
            let mut ev = Map::new();
            ev.insert("expected_sha256".to_string(), json!(expected.sha256));
            ev.insert("expected_size".to_string(), json!(expected.size));
            findings.push(Finding {
                id: format!("host-002-{}", sanitize_id_part(path_key)),
                rule_id: "HOST-002".to_string(),
                module: MODULE_FIM.to_string(),
                layer: LAYER_HOST.to_string(),
                severity: Severity::High,
                title: "Monitored file deleted".to_string(),
                description: format!("Baseline file {path_key} is missing from disk."),
                target: format!("file://{path_key}"),
                evidence: ev,
                remediation: format!(
                    "Verify whether removal of {path_key} was authorized; restore from trusted backup or re-baseline if intentional."
                ),
                mitre_d3fend: "D3-FIM".to_string(),
                timestamp: now,
            });
            continue;
        };

        if meta.file_type().is_symlink() || !meta.is_file() {
            let mut ev = Map::new();
            ev.insert("expected_type".to_string(), json!("regular_file"));
            ev.insert(
                "observed_symlink".to_string(),
                json!(meta.file_type().is_symlink()),
            );
            findings.push(Finding {
                id: format!("host-001-type-{}", sanitize_id_part(path_key)),
                rule_id: "HOST-001".to_string(),
                module: MODULE_FIM.to_string(),
                layer: LAYER_HOST.to_string(),
                severity: Severity::Critical,
                title: "Monitored file replaced with non-regular file".to_string(),
                description: format!(
                    "Baseline regular file {path_key} was replaced by a symlink or directory."
                ),
                target: format!("file://{path_key}"),
                evidence: ev,
                remediation: format!("Inspect {path_key} immediately for unauthorized tampering."),
                mitre_d3fend: "D3-FIM".to_string(),
                timestamp: now,
            });
            continue;
        }

        match hash_file_streaming(p, limit) {
            Ok((actual_sha, actual_size)) => {
                if actual_sha != expected.sha256 {
                    let mut ev = Map::new();
                    ev.insert("expected_sha256".to_string(), json!(expected.sha256));
                    ev.insert("actual_sha256".to_string(), json!(actual_sha));
                    ev.insert("expected_size".to_string(), json!(expected.size));
                    ev.insert("actual_size".to_string(), json!(actual_size));
                    findings.push(Finding {
                        id: format!("host-001-{}", sanitize_id_part(path_key)),
                        rule_id: "HOST-001".to_string(),
                        module: MODULE_FIM.to_string(),
                        layer: LAYER_HOST.to_string(),
                        severity: Severity::Critical,
                        title: "Monitored file content modified".to_string(),
                        description: format!(
                            "SHA-256 mismatch on {path_key}: expected {}..., observed {}...",
                            short_hash(&expected.sha256),
                            short_hash(&actual_sha)
                        ),
                        target: format!("file://{path_key}"),
                        evidence: ev,
                        remediation: format!(
                            "Inspect recent changes to {path_key}; restore from a verified artifact if unauthorized."
                        ),
                        mitre_d3fend: "D3-FIM".to_string(),
                        timestamp: now,
                    });
                }
            }
            Err(FimError::TooLarge { size, limit, .. }) => {
                let mut ev = Map::new();
                ev.insert("expected_sha256".to_string(), json!(expected.sha256));
                ev.insert("actual_size".to_string(), json!(size));
                ev.insert("max_file_bytes".to_string(), json!(limit));
                findings.push(Finding {
                    id: format!("host-001-size-{}", sanitize_id_part(path_key)),
                    rule_id: "HOST-001".to_string(),
                    module: MODULE_FIM.to_string(),
                    layer: LAYER_HOST.to_string(),
                    severity: Severity::Critical,
                    title: "Monitored file content modified".to_string(),
                    description: format!(
                        "File {path_key} grew to {size} bytes, exceeding baseline cap {limit}."
                    ),
                    target: format!("file://{path_key}"),
                    evidence: ev,
                    remediation: format!(
                        "Inspect {path_key} for unexpected growth or log injection."
                    ),
                    mitre_d3fend: "D3-FIM".to_string(),
                    timestamp: now,
                });
            }
            Err(_) => {}
        }

        let actual_mode = format_permissions(&meta);
        if actual_mode != expected.mode {
            let mut ev = Map::new();
            ev.insert("expected_mode".to_string(), json!(expected.mode));
            ev.insert("actual_mode".to_string(), json!(actual_mode));
            findings.push(Finding {
                id: format!("host-004-{}", sanitize_id_part(path_key)),
                rule_id: "HOST-004".to_string(),
                module: MODULE_FIM.to_string(),
                layer: LAYER_HOST.to_string(),
                severity: Severity::High,
                title: "Monitored file permissions changed".to_string(),
                description: format!(
                    "Permissions on {path_key} drifted from {} to {}.",
                    expected.mode, actual_mode
                ),
                target: format!("file://{path_key}"),
                evidence: ev,
                remediation: format!(
                    "Restore permissions on {path_key} to {} and check who modified metadata.",
                    expected.mode
                ),
                mitre_d3fend: "D3-FIM".to_string(),
                timestamp: now,
            });
        }
    }

    // Detect unexpected newly created files inside monitored roots.
    for root_str in &snapshot.root_paths {
        let root_path = Path::new(root_str);
        if !root_path.exists() {
            continue;
        }
        for walk_item in WalkDir::new(root_path).follow_links(false) {
            let Ok(entry) = walk_item else {
                continue;
            };
            if entry.path_is_symlink() || !entry.file_type().is_file() {
                continue;
            }
            let path_key = normalize_path(entry.path());
            if seen_paths.contains(&path_key) || is_excluded(&path_key, &snapshot.excludes) {
                continue;
            }
            seen_paths.insert(path_key.clone());

            let meta = entry.metadata().ok();
            let mut ev = Map::new();
            if let Some(m) = &meta {
                ev.insert("size".to_string(), json!(m.len()));
                ev.insert("mode".to_string(), json!(format_permissions(m)));
            }
            findings.push(Finding {
                id: format!("host-003-{}", sanitize_id_part(&path_key)),
                rule_id: "HOST-003".to_string(),
                module: MODULE_FIM.to_string(),
                layer: LAYER_HOST.to_string(),
                severity: Severity::Medium,
                title: "Unexpected file added in monitored directory".to_string(),
                description: format!(
                    "New file {path_key} appeared in monitored root after baseline snapshot."
                ),
                target: format!("file://{path_key}"),
                evidence: ev,
                remediation: format!(
                    "Verify origin of {path_key}; remove unauthorized artifacts or update baseline."
                ),
                mitre_d3fend: "D3-FIM".to_string(),
                timestamp: now,
            });
        }
    }

    Ok(findings)
}

pub fn normalize_path(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    if let Some(stripped) = raw.strip_prefix("//?/") {
        stripped.to_string()
    } else {
        raw
    }
}

fn is_excluded(path_key: &str, patterns: &[String]) -> bool {
    let file_name = path_key.rsplit('/').next().unwrap_or(path_key);
    for pat in patterns {
        let p = pat.trim().replace('\\', "/");
        if p.is_empty() {
            continue;
        }
        if let Some(suffix) = p.strip_prefix('*') {
            if path_key.ends_with(suffix) || file_name.ends_with(suffix) {
                return true;
            }
        } else if let Some(prefix) = p.strip_suffix('*') {
            if file_name.starts_with(prefix) || path_key.starts_with(prefix) {
                return true;
            }
        } else if path_key.contains(&p) {
            return true;
        }
    }
    false
}

#[cfg(unix)]
fn format_permissions(meta: &fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;
    format!("{:04o}", meta.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn format_permissions(meta: &fs::Metadata) -> String {
    if meta.permissions().readonly() {
        "readonly".to_string()
    } else {
        "writable".to_string()
    }
}

fn modified_unix(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

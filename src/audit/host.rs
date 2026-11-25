use crate::audit::read_bounded_text;
use crate::schema::{sanitize_id_part, Finding, Severity, LAYER_HOST};
use chrono::Utc;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const MODULE_HOST: &str = "host-auditor";

pub fn audit_sysctl_path(path: &Path) -> io::Result<Vec<Finding>> {
    if path.is_dir() {
        let mut conf_files: Vec<PathBuf> = WalkDir::new(path)
            .max_depth(2)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_type().is_file()
                    && e.path()
                        .extension()
                        .and_then(|s| s.to_str())
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("conf"))
            })
            .map(|e| e.into_path())
            .collect();
        conf_files.sort();

        let mut merged = HashMap::new();
        for file in conf_files {
            let content = read_bounded_text(&file)?;
            let label = file.to_string_lossy().replace('\\', "/");
            parse_sysctl_into(&content, &label, &mut merged);
        }
        return Ok(evaluate_sysctl(&merged));
    }

    let content = read_bounded_text(path)?;
    let label = path.to_string_lossy().replace('\\', "/");
    Ok(audit_sysctl_content(&content, &label))
}

pub fn audit_sysctl_content(content: &str, source_label: &str) -> Vec<Finding> {
    let mut settings = HashMap::new();
    parse_sysctl_into(content, source_label, &mut settings);
    evaluate_sysctl(&settings)
}

fn parse_sysctl_into(
    content: &str,
    source_label: &str,
    out: &mut HashMap<String, (usize, String, String)>,
) {
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let cleaned = line
            .split('#')
            .next()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let Some((raw_k, raw_v)) = cleaned.split_once('=') else {
            continue;
        };
        let key = raw_k.trim().to_ascii_lowercase();
        let val = raw_v.trim().to_string();
        if !key.is_empty() && !val.is_empty() {
            out.insert(key, (line_no, val, source_label.to_string()));
        }
    }
}

fn evaluate_sysctl(settings: &HashMap<String, (usize, String, String)>) -> Vec<Finding> {
    let now = Utc::now();
    let mut findings = Vec::new();

    // Sort keys deterministically for consistent output ordering.
    let ordered: BTreeMap<&String, &(usize, String, String)> = settings.iter().collect();

    for (key, (line_no, val, source)) in ordered {
        let trimmed = val.trim();
        let target = format!("file://{source}");

        match key.as_str() {
            "net.ipv4.ip_forward" => {
                if trimmed != "0" {
                    findings.push(host_finding(
                        "HOST-301",
                        Severity::High,
                        "Insecure kernel network sysctl parameter",
                        format!(
                            "Sysctl {key} is set to '{trimmed}' (expected 0) on line {line_no} in {source}."
                        ),
                        &target,
                        json!({ "parameter": key, "observed": trimmed, "expected": "0", "line": line_no, "cis_ref": "CIS Linux 3.1.1" }),
                        "Set net.ipv4.ip_forward = 0 unless this host acts as a dedicated router/container bridge.",
                        "D3-CH",
                        &format!("sysctl-l{line_no}-{}", sanitize_id_part(key)),
                        now,
                    ));
                }
            }
            "net.ipv4.conf.all.accept_redirects"
            | "net.ipv4.conf.default.accept_redirects"
            | "net.ipv4.conf.all.accept_source_route"
            | "net.ipv4.conf.all.send_redirects" => {
                if trimmed != "0" {
                    findings.push(host_finding(
                        "HOST-301",
                        Severity::High,
                        "Insecure kernel network sysctl parameter",
                        format!(
                            "Sysctl {key} is set to '{trimmed}' (expected 0) on line {line_no} in {source}."
                        ),
                        &target,
                        json!({ "parameter": key, "observed": trimmed, "expected": "0", "line": line_no, "cis_ref": "CIS Linux 3.2" }),
                        &format!("Set {key} = 0 to reject forged ICMP redirects or source-routed packets."),
                        "D3-CH",
                        &format!("sysctl-l{line_no}-{}", sanitize_id_part(key)),
                        now,
                    ));
                }
            }
            "net.ipv4.tcp_syncookies" => {
                if trimmed != "1" {
                    findings.push(host_finding(
                        "HOST-301",
                        Severity::High,
                        "Insecure kernel network sysctl parameter",
                        format!(
                            "Sysctl {key} is set to '{trimmed}' (expected 1) on line {line_no} in {source}."
                        ),
                        &target,
                        json!({ "parameter": key, "observed": trimmed, "expected": "1", "line": line_no, "cis_ref": "CIS Linux 3.3.8" }),
                        "Set net.ipv4.tcp_syncookies = 1 to harden against SYN flood exhaustion.",
                        "D3-CH",
                        &format!("sysctl-l{line_no}-{}", sanitize_id_part(key)),
                        now,
                    ));
                }
            }
            "net.ipv4.conf.all.rp_filter" => {
                if trimmed == "0" {
                    findings.push(host_finding(
                        "HOST-301",
                        Severity::High,
                        "Insecure kernel network sysctl parameter",
                        format!(
                            "Sysctl {key} is set to 0 (expected 1 or 2) on line {line_no} in {source}."
                        ),
                        &target,
                        json!({ "parameter": key, "observed": trimmed, "expected": "1", "line": line_no, "cis_ref": "CIS Linux 3.3.7" }),
                        "Set net.ipv4.conf.all.rp_filter = 1 to enforce strict reverse-path filtering.",
                        "D3-CH",
                        &format!("sysctl-l{line_no}-{}", sanitize_id_part(key)),
                        now,
                    ));
                }
            }
            "kernel.randomize_va_space" => {
                if trimmed != "2" {
                    findings.push(host_finding(
                        "HOST-302",
                        Severity::High,
                        "Weak kernel memory or process protection sysctl parameter",
                        format!(
                            "Sysctl {key} is set to '{trimmed}' (expected 2 for full ASLR) on line {line_no} in {source}."
                        ),
                        &target,
                        json!({ "parameter": key, "observed": trimmed, "expected": "2", "line": line_no, "cis_ref": "CIS Linux 1.5.2" }),
                        "Set kernel.randomize_va_space = 2 to enforce full Address Space Layout Randomization.",
                        "D3-CH",
                        &format!("sysctl-l{line_no}-{}", sanitize_id_part(key)),
                        now,
                    ));
                }
            }
            "kernel.yama.ptrace_scope" | "kernel.kptr_restrict" | "kernel.dmesg_restrict" => {
                if trimmed == "0" {
                    findings.push(host_finding(
                        "HOST-302",
                        Severity::High,
                        "Weak kernel memory or process protection sysctl parameter",
                        format!(
                            "Sysctl {key} is set to 0 (unrestricted) on line {line_no} in {source}."
                        ),
                        &target,
                        json!({ "parameter": key, "observed": trimmed, "expected": ">= 1", "line": line_no, "cis_ref": "CIS Linux 1.5.1" }),
                        &format!("Set {key} = 1 (or 2 for strict isolation) in /etc/sysctl.d/."),
                        "D3-CH",
                        &format!("sysctl-l{line_no}-{}", sanitize_id_part(key)),
                        now,
                    ));
                }
            }
            "fs.suid_dumpable" if trimmed != "0" => {
                findings.push(host_finding(
                    "HOST-302",
                    Severity::High,
                    "Weak kernel memory or process protection sysctl parameter",
                    format!(
                        "Sysctl {key} is set to '{trimmed}' (expected 0) on line {line_no} in {source}."
                    ),
                    &target,
                    json!({ "parameter": key, "observed": trimmed, "expected": "0", "line": line_no, "cis_ref": "CIS Linux 1.5.1" }),
                    "Set fs.suid_dumpable = 0 to prevent privileged binaries from writing core dumps containing secrets.",
                    "D3-CH",
                    &format!("sysctl-l{line_no}-{}", sanitize_id_part(key)),
                    now,
                ));
            }
            _ => {}
        }
    }

    findings
}

pub fn audit_sudoers_path(path: &Path) -> io::Result<Vec<Finding>> {
    if path.is_dir() {
        let mut files: Vec<PathBuf> = WalkDir::new(path)
            .max_depth(2)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| {
                let name = e.file_name().to_string_lossy();
                e.file_type().is_file()
                    && !name.ends_with('~')
                    && !name.eq_ignore_ascii_case("README")
                    && !name.contains('.')
            })
            .map(|e| e.into_path())
            .collect();
        files.sort();

        let mut all = Vec::new();
        for f in files {
            let content = read_bounded_text(&f)?;
            let label = f.to_string_lossy().replace('\\', "/");
            all.extend(audit_sudoers_content(&content, &label));
        }
        return Ok(all);
    }

    let content = read_bounded_text(path)?;
    let label = path.to_string_lossy().replace('\\', "/");
    Ok(audit_sudoers_content(&content, &label))
}

pub fn audit_sudoers_content(content: &str, source_label: &str) -> Vec<Finding> {
    let now = Utc::now();
    let mut findings = Vec::new();
    let target = format!("file://{source_label}");

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cleaned = line.split('#').next().unwrap_or("").trim();
        if cleaned.is_empty() {
            continue;
        }
        let upper = cleaned.to_ascii_uppercase();

        if upper.starts_with("DEFAULTS") && upper.contains("!AUTHENTICATE") {
            findings.push(host_finding(
                "HOST-304",
                Severity::High,
                "Unrestricted passwordless sudoers rule",
                format!(
                    "Sudoers line {line_no} in {source_label} disables password authentication globally via !authenticate."
                ),
                &target,
                json!({ "line": line_no, "directive": "Defaults !authenticate", "cis_ref": "CIS Linux 5.3.4" }),
                "Remove !authenticate from sudoers Defaults to require authentication for privilege escalation.",
                "D3-SUC",
                &format!("sudoers-l{line_no}-auth"),
                now,
            ));
            continue;
        }

        if let Some((_, rhs)) = upper.split_once("NOPASSWD:") {
            let cmd_part = rhs.trim();
            if cmd_part == "ALL"
                || cmd_part.split_whitespace().any(|tok| tok == "ALL")
                || cmd_part.contains('*')
            {
                findings.push(host_finding(
                    "HOST-304",
                    Severity::High,
                    "Unrestricted passwordless sudoers rule",
                    format!(
                        "Sudoers line {line_no} in {source_label} grants unconstrained passwordless privilege (NOPASSWD ALL or wildcard)."
                    ),
                    &target,
                    json!({ "line": line_no, "pattern": "NOPASSWD", "cis_ref": "CIS Linux 5.3.4" }),
                    "Require password authentication or restrict NOPASSWD rules to exact immutable command paths with no wildcards.",
                    "D3-SUC",
                    &format!("sudoers-l{line_no}-nopasswd"),
                    now,
                ));
            }
        }
    }

    findings
}

pub fn audit_host_permissions_path(path: &Path) -> io::Result<Vec<Finding>> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("permissions target {:?} does not exist", path),
        ));
    }

    #[cfg(unix)]
    {
        use crate::fim::normalize_path;
        use std::os::unix::fs::PermissionsExt;

        let mut collected = Vec::new();
        for entry in WalkDir::new(path)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file() {
                if let Ok(meta) = entry.metadata() {
                    let mode = meta.permissions().mode() & 0o7777;
                    collected.push((normalize_path(entry.path()), mode));
                }
            }
        }
        Ok(audit_permissions_entries(&collected))
    }

    #[cfg(not(unix))]
    {
        let _ = std::fs::metadata(path)?;
        Ok(Vec::new())
    }
}

pub fn audit_permissions_entries(entries: &[(String, u32)]) -> Vec<Finding> {
    let now = Utc::now();
    let mut findings = Vec::new();

    for (raw_path, mode) in entries {
        let norm = raw_path.replace('\\', "/");
        let file_name = norm
            .rsplit('/')
            .next()
            .unwrap_or(&norm)
            .to_ascii_lowercase();
        let mut reasons: Vec<&'static str> = Vec::new();

        if mode & 0o002 != 0 {
            reasons.push("world-writable");
        }
        if mode & 0o6000 != 0 {
            reasons.push("suid-or-sgid-set");
        }
        if is_sensitive_perm_file(&file_name) && (mode & 0o077 != 0) {
            reasons.push("sensitive-file-group-or-world-accessible");
        }

        if !reasons.is_empty() {
            let mode_str = format!("{:04o}", mode & 0o7777);
            findings.push(host_finding(
                "HOST-303",
                Severity::Critical,
                "Overly permissive file mode, world-writable file, or unauthorized SUID/SGID",
                format!(
                    "File '{norm}' has insecure permissions {mode_str} ({}).",
                    reasons.join(", ")
                ),
                &format!("file://{norm}"),
                json!({
                    "mode": mode_str,
                    "reasons": reasons,
                    "cis_ref": "CIS Linux 6.1.2-6.1.9"
                }),
                &format!("Restrict file permissions on '{norm}' (e.g., chmod 0600 or 0640 and remove SUID/world-write bits)."),
                "D3-LPM",
                &format!("perm-{}", sanitize_id_part(&norm)),
                now,
            ));
        }
    }

    findings
}

fn is_sensitive_perm_file(file_name: &str) -> bool {
    matches!(
        file_name,
        "shadow"
            | "shadow-"
            | "gshadow"
            | "gshadow-"
            | "sudoers"
            | "id_rsa"
            | "id_ed25519"
            | "id_ecdsa"
            | "id_dsa"
            | "authorized_keys"
    ) || file_name.ends_with(".key")
        || file_name.ends_with(".pem")
}

#[allow(clippy::too_many_arguments)]
fn host_finding(
    rule_id: &str,
    severity: Severity,
    title: &str,
    description: String,
    target: &str,
    evidence_val: serde_json::Value,
    remediation: &str,
    mitre_d3fend: &str,
    id_suffix: &str,
    timestamp: chrono::DateTime<Utc>,
) -> Finding {
    let evidence = evidence_val.as_object().cloned().unwrap_or_default();
    Finding {
        id: format!("{}-{}", rule_id.to_ascii_lowercase(), id_suffix),
        rule_id: rule_id.to_string(),
        module: MODULE_HOST.to_string(),
        layer: LAYER_HOST.to_string(),
        severity,
        title: title.to_string(),
        description,
        target: target.to_string(),
        evidence,
        remediation: remediation.to_string(),
        mitre_d3fend: mitre_d3fend.to_string(),
        timestamp,
    }
}

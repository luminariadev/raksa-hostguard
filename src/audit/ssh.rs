use crate::audit::read_bounded_text;
use crate::schema::{sanitize_id_part, Finding, Severity, LAYER_HOST};
use chrono::Utc;
use serde_json::{json, Map};
use std::collections::HashMap;
use std::io;
use std::path::Path;

const MODULE_SSH: &str = "ssh-auditor";

#[derive(Debug, Clone)]
struct Directive {
    line: usize,
    value: String,
}

pub fn audit_sshd_file(path: &Path) -> io::Result<Vec<Finding>> {
    let content = read_bounded_text(path)?;
    let label = path.to_string_lossy().replace('\\', "/");
    Ok(audit_sshd_config(&content, &label))
}

pub fn audit_sshd_config(content: &str, source_label: &str) -> Vec<Finding> {
    let now = Utc::now();
    let directives = parse_global_directives(content);
    let mut findings = Vec::new();
    let target = format!("file://{source_label}");

    if let Some(dir) = directives.get("permitrootlogin") {
        if dir.value.eq_ignore_ascii_case("yes") {
            findings.push(ssh_finding(
                "HOST-101",
                Severity::High,
                "SSH root login enabled",
                format!(
                    "PermitRootLogin is set to '{}' on line {} in {}.",
                    dir.value, dir.line, source_label
                ),
                &target,
                "PermitRootLogin",
                &dir.value,
                dir.line,
                "Set 'PermitRootLogin no' (or 'prohibit-password' if strictly required) and reload sshd.",
                "CIS 5.2.8",
                now,
            ));
        }
    }

    if let Some(dir) = directives.get("passwordauthentication") {
        if dir.value.eq_ignore_ascii_case("yes") {
            findings.push(ssh_finding(
                "HOST-102",
                Severity::High,
                "SSH password authentication enabled",
                format!(
                    "PasswordAuthentication is set to '{}' on line {} in {}.",
                    dir.value, dir.line, source_label
                ),
                &target,
                "PasswordAuthentication",
                &dir.value,
                dir.line,
                "Set 'PasswordAuthentication no' and require SSH public-key or certificate authentication.",
                "CIS 5.2.12",
                now,
            ));
        }
    }

    if let Some(dir) = directives.get("permitemptypasswords") {
        if dir.value.eq_ignore_ascii_case("yes") {
            findings.push(ssh_finding(
                "HOST-103",
                Severity::Critical,
                "SSH empty passwords permitted",
                format!(
                    "PermitEmptyPasswords is set to '{}' on line {} in {}.",
                    dir.value, dir.line, source_label
                ),
                &target,
                "PermitEmptyPasswords",
                &dir.value,
                dir.line,
                "Set 'PermitEmptyPasswords no' immediately and reload sshd.",
                "CIS 5.2.9",
                now,
            ));
        }
    }

    if let Some(dir) = directives.get("x11forwarding") {
        if dir.value.eq_ignore_ascii_case("yes") {
            findings.push(ssh_finding(
                "HOST-104",
                Severity::Medium,
                "SSH X11 forwarding enabled",
                format!(
                    "X11Forwarding is set to '{}' on line {} in {}.",
                    dir.value, dir.line, source_label
                ),
                &target,
                "X11Forwarding",
                &dir.value,
                dir.line,
                "Set 'X11Forwarding no' unless interactive graphical forwarding is explicitly required.",
                "CIS 5.2.6",
                now,
            ));
        }
    }

    if let Some(dir) = directives.get("maxauthtries") {
        if let Ok(tries) = dir.value.parse::<u32>() {
            if tries > 4 {
                findings.push(ssh_finding(
                    "HOST-104",
                    Severity::Medium,
                    "SSH MaxAuthTries exceeds CIS threshold",
                    format!(
                        "MaxAuthTries is set to {} (recommended <= 4) on line {} in {}.",
                        tries, dir.line, source_label
                    ),
                    &target,
                    "MaxAuthTries",
                    &dir.value,
                    dir.line,
                    "Set 'MaxAuthTries 4' or lower to restrict password/key brute-force attempts per connection.",
                    "CIS 5.2.7",
                    now,
                ));
            }
        }
    }

    if let Some(dir) = directives.get("protocol") {
        let allows_v1 = dir.value.split(',').any(|p| p.trim() == "1");
        if allows_v1 {
            findings.push(ssh_finding(
                "HOST-104",
                Severity::Medium,
                "Legacy SSH Protocol 1 permitted",
                format!(
                    "Protocol '{}' enables legacy SSH v1 on line {} in {}.",
                    dir.value, dir.line, source_label
                ),
                &target,
                "Protocol",
                &dir.value,
                dir.line,
                "Set 'Protocol 2' or remove legacy SSHv1 directives.",
                "CIS 5.2.4",
                now,
            ));
        }
    }

    findings
}

// OpenSSH evaluates the first matching global directive prior to any `Match` block.
fn parse_global_directives(content: &str) -> HashMap<String, Directive> {
    let mut map = HashMap::new();
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

        let mut parts = cleaned.splitn(2, |c: char| c.is_whitespace() || c == '=');
        let key = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let value = parts
            .next()
            .unwrap_or("")
            .trim()
            .trim_start_matches('=')
            .trim()
            .to_string();

        if key.is_empty() || value.is_empty() {
            continue;
        }
        if key == "match" {
            break;
        }
        map.entry(key).or_insert(Directive {
            line: line_no,
            value,
        });
    }
    map
}

#[allow(clippy::too_many_arguments)]
fn ssh_finding(
    rule_id: &str,
    severity: Severity,
    title: &str,
    description: String,
    target: &str,
    directive: &str,
    observed: &str,
    line: usize,
    remediation: &str,
    cis_ref: &str,
    timestamp: chrono::DateTime<Utc>,
) -> Finding {
    let mut ev = Map::new();
    ev.insert("directive".to_string(), json!(directive));
    ev.insert("observed_value".to_string(), json!(observed));
    ev.insert("line".to_string(), json!(line));
    ev.insert("cis_ref".to_string(), json!(cis_ref));

    Finding {
        id: format!(
            "{}-{}-l{}",
            rule_id.to_ascii_lowercase(),
            sanitize_id_part(directive),
            line
        ),
        rule_id: rule_id.to_string(),
        module: MODULE_SSH.to_string(),
        layer: LAYER_HOST.to_string(),
        severity,
        title: title.to_string(),
        description,
        target: target.to_string(),
        evidence: ev,
        remediation: remediation.to_string(),
        mitre_d3fend: "D3-SUC".to_string(),
        timestamp,
    }
}

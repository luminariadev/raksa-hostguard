use crate::audit::read_bounded_text;
use crate::schema::{sanitize_id_part, Finding, Severity, LAYER_HOST};
use chrono::Utc;
use serde_json::{json, Map};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MODULE_SSH: &str = "ssh-auditor";
const MAX_INCLUDE_DEPTH: usize = 2;

#[derive(Debug, Clone)]
struct Directive {
    line: usize,
    value: String,
    source: String,
}

pub fn audit_sshd_file(path: &Path) -> io::Result<Vec<Finding>> {
    let label = path.to_string_lossy().replace('\\', "/");
    let mut directives = HashMap::new();
    let mut visited = HashSet::new();
    collect_sshd_file(path, 0, &mut visited, &mut directives)?;
    Ok(evaluate_sshd_directives(&directives, &label))
}

pub fn audit_sshd_config(content: &str, source_label: &str) -> Vec<Finding> {
    let mut directives = HashMap::new();
    parse_directives_into(content, source_label, &mut directives);
    evaluate_sshd_directives(&directives, source_label)
}

fn collect_sshd_file(
    path: &Path,
    depth: usize,
    visited: &mut HashSet<PathBuf>,
    directives: &mut HashMap<String, Directive>,
) -> io::Result<()> {
    let canon = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(canon) {
        return Ok(());
    }

    let content = read_bounded_text(path)?;
    let label = path.to_string_lossy().replace('\\', "/");
    let include_patterns = parse_directives_into(&content, &label, directives);

    if depth < MAX_INCLUDE_DEPTH {
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        for pattern in include_patterns {
            for inc_path in resolve_include_paths(base_dir, &pattern) {
                if inc_path.is_file() {
                    let _ = collect_sshd_file(&inc_path, depth + 1, visited, directives);
                }
            }
        }
    }

    Ok(())
}

fn resolve_include_paths(base_dir: &Path, raw_pattern: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for token in raw_pattern.split_whitespace() {
        let pat = token.trim_matches('"').trim_matches('\'');
        if pat.is_empty() {
            continue;
        }
        let joined = if Path::new(pat).is_absolute() {
            PathBuf::from(pat)
        } else {
            base_dir.join(pat)
        };

        if let Some(name) = joined.file_name().and_then(|n| n.to_str()) {
            if name.contains('*') {
                let parent = joined.parent().unwrap_or(base_dir);
                let (prefix, suffix) = name.split_once('*').unwrap_or(("", ""));
                if let Ok(entries) = fs::read_dir(parent) {
                    let mut matched: Vec<PathBuf> = entries
                        .flatten()
                        .map(|e| e.path())
                        .filter(|p| {
                            p.is_file()
                                && p.file_name()
                                    .and_then(|n| n.to_str())
                                    .map(|s| s.starts_with(prefix) && s.ends_with(suffix))
                                    .unwrap_or(false)
                        })
                        .collect();
                    matched.sort();
                    out.extend(matched);
                }
                continue;
            }
        }

        if joined.exists() {
            out.push(joined);
        }
    }
    out
}

// OpenSSH evaluates the first matching global directive prior to any `Match` block.
fn parse_directives_into(
    content: &str,
    source_label: &str,
    map: &mut HashMap<String, Directive>,
) -> Vec<String> {
    let mut includes = Vec::new();
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
        if key == "include" {
            includes.push(value);
            continue;
        }
        map.entry(key).or_insert(Directive {
            line: line_no,
            value,
            source: source_label.to_string(),
        });
    }
    includes
}

fn evaluate_sshd_directives(
    directives: &HashMap<String, Directive>,
    _fallback_label: &str,
) -> Vec<Finding> {
    let now = Utc::now();
    let mut findings = Vec::new();

    if let Some(dir) = directives.get("permitrootlogin") {
        if dir.value.eq_ignore_ascii_case("yes") {
            findings.push(ssh_finding(
                "HOST-101",
                Severity::High,
                "SSH root login enabled",
                format!(
                    "PermitRootLogin is set to '{}' on line {} in {}.",
                    dir.value, dir.line, dir.source
                ),
                dir,
                "PermitRootLogin",
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
                    dir.value, dir.line, dir.source
                ),
                dir,
                "PasswordAuthentication",
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
                    dir.value, dir.line, dir.source
                ),
                dir,
                "PermitEmptyPasswords",
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
                    dir.value, dir.line, dir.source
                ),
                dir,
                "X11Forwarding",
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
                        tries, dir.line, dir.source
                    ),
                    dir,
                    "MaxAuthTries",
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
                    dir.value, dir.line, dir.source
                ),
                dir,
                "Protocol",
                "Set 'Protocol 2' or remove legacy SSHv1 directives.",
                "CIS 5.2.4",
                now,
            ));
        }
    }

    if let Some(dir) = directives.get("ciphers") {
        let weak: Vec<&str> = dir
            .value
            .split(',')
            .map(str::trim)
            .filter(|tok| is_weak_cipher(tok))
            .collect();
        if !weak.is_empty() {
            findings.push(ssh_finding(
                "HOST-105",
                Severity::High,
                "Weak SSH ciphers configured",
                format!(
                    "Ciphers permits deprecated algorithms ({}) on line {} in {}.",
                    weak.join(", "),
                    dir.line,
                    dir.source
                ),
                dir,
                "Ciphers",
                "Restrict Ciphers to AEAD/CTR algorithms such as chacha20-poly1305@openssh.com and aes256-gcm@openssh.com.",
                "CIS 5.2.13",
                now,
            ));
        }
    }

    if let Some(dir) = directives.get("macs") {
        let weak: Vec<&str> = dir
            .value
            .split(',')
            .map(str::trim)
            .filter(|tok| is_weak_mac(tok))
            .collect();
        if !weak.is_empty() {
            findings.push(ssh_finding(
                "HOST-105",
                Severity::High,
                "Weak SSH MAC algorithms configured",
                format!(
                    "MACs permits weak integrity algorithms ({}) on line {} in {}.",
                    weak.join(", "),
                    dir.line,
                    dir.source
                ),
                dir,
                "MACs",
                "Use strong SHA-2 / UMAC-128 ETM MACs such as hmac-sha2-512-etm@openssh.com and hmac-sha2-256-etm@openssh.com.",
                "CIS 5.2.14",
                now,
            ));
        }
    }

    if let Some(dir) = directives.get("kexalgorithms") {
        let weak: Vec<&str> = dir
            .value
            .split(',')
            .map(str::trim)
            .filter(|tok| is_weak_kex(tok))
            .collect();
        if !weak.is_empty() {
            findings.push(ssh_finding(
                "HOST-105",
                Severity::High,
                "Weak SSH key exchange algorithms configured",
                format!(
                    "KexAlgorithms permits legacy SHA-1 key exchange ({}) on line {} in {}.",
                    weak.join(", "),
                    dir.line,
                    dir.source
                ),
                dir,
                "KexAlgorithms",
                "Use modern key exchange algorithms such as curve25519-sha256 or ecdh-sha2-nistp521.",
                "CIS 5.2.15",
                now,
            ));
        }
    }

    if let Some(dir) = directives.get("allowagentforwarding") {
        if dir.value.eq_ignore_ascii_case("yes") {
            findings.push(ssh_finding(
                "HOST-106",
                Severity::Medium,
                "SSH agent forwarding enabled",
                format!(
                    "AllowAgentForwarding is enabled on line {} in {}.",
                    dir.line, dir.source
                ),
                dir,
                "AllowAgentForwarding",
                "Set 'AllowAgentForwarding no' to reduce lateral SSH agent hijacking risk.",
                "CIS 5.2.17",
                now,
            ));
        }
    }

    if let Some(dir) = directives.get("allowtcpforwarding") {
        if dir.value.eq_ignore_ascii_case("yes") {
            findings.push(ssh_finding(
                "HOST-106",
                Severity::Medium,
                "SSH TCP forwarding enabled",
                format!(
                    "AllowTcpForwarding is enabled on line {} in {}.",
                    dir.line, dir.source
                ),
                dir,
                "AllowTcpForwarding",
                "Set 'AllowTcpForwarding no' unless explicit bastion tunneling is required.",
                "CIS 5.2.18",
                now,
            ));
        }
    }

    if let Some(dir) = directives.get("permituserenvironment") {
        if dir.value.eq_ignore_ascii_case("yes") {
            findings.push(ssh_finding(
                "HOST-106",
                Severity::Medium,
                "SSH PermitUserEnvironment enabled",
                format!(
                    "PermitUserEnvironment is set to '{}' on line {} in {}.",
                    dir.value, dir.line, dir.source
                ),
                dir,
                "PermitUserEnvironment",
                "Set 'PermitUserEnvironment no' to prevent users from altering daemon environment variables.",
                "CIS 5.2.16",
                now,
            ));
        }
    }

    if let Some(dir) = directives.get("clientaliveinterval") {
        if let Ok(interval) = dir.value.parse::<u32>() {
            if interval == 0 || interval > 300 {
                findings.push(ssh_finding(
                    "HOST-106",
                    Severity::Medium,
                    "Weak SSH ClientAliveInterval idle timeout",
                    format!(
                        "ClientAliveInterval is {}s (recommended 1..=300) on line {} in {}.",
                        interval, dir.line, dir.source
                    ),
                    dir,
                    "ClientAliveInterval",
                    "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 2' or tighter.",
                    "CIS 5.2.19",
                    now,
                ));
            }
        }
    }

    findings
}

fn is_weak_cipher(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.ends_with("-cbc")
        || lower == "3des-cbc"
        || lower == "blowfish-cbc"
        || lower == "cast128-cbc"
        || lower.starts_with("arcfour")
}

fn is_weak_mac(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.starts_with("hmac-md5")
        || lower.starts_with("hmac-sha1")
        || lower.starts_with("umac-64")
        || lower.starts_with("hmac-ripemd160")
}

fn is_weak_kex(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "diffie-hellman-group1-sha1"
            | "diffie-hellman-group14-sha1"
            | "diffie-hellman-group-exchange-sha1"
    )
}

#[allow(clippy::too_many_arguments)]
fn ssh_finding(
    rule_id: &str,
    severity: Severity,
    title: &str,
    description: String,
    dir: &Directive,
    directive_name: &str,
    remediation: &str,
    cis_ref: &str,
    timestamp: chrono::DateTime<Utc>,
) -> Finding {
    let mut ev = Map::new();
    ev.insert("directive".to_string(), json!(directive_name));
    ev.insert("observed_value".to_string(), json!(dir.value));
    ev.insert("line".to_string(), json!(dir.line));
    ev.insert("cis_ref".to_string(), json!(cis_ref));

    Finding {
        id: format!(
            "{}-{}-l{}",
            rule_id.to_ascii_lowercase(),
            sanitize_id_part(directive_name),
            dir.line
        ),
        rule_id: rule_id.to_string(),
        module: MODULE_SSH.to_string(),
        layer: LAYER_HOST.to_string(),
        severity,
        title: title.to_string(),
        description,
        target: format!("file://{}", dir.source),
        evidence: ev,
        remediation: remediation.to_string(),
        mitre_d3fend: "D3-SUC".to_string(),
        timestamp,
    }
}

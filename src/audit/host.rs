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

#[derive(Debug, Default)]
struct SystemdUnitState {
    target_label: String,
    user: Option<String>,
    dynamic_user: bool,
    no_new_privileges: Option<bool>,
    protect_system: Option<String>,
    protect_home: Option<String>,
    exec_starts: Vec<(usize, String)>,
}

pub fn audit_systemd_path(path: &Path) -> io::Result<Vec<Finding>> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("systemd target {:?} does not exist", path),
        ));
    }
    if path.is_file() {
        let content = read_bounded_text(path)?;
        let label = path.to_string_lossy().replace('\\', "/");
        return Ok(audit_systemd_content(&content, &label));
    }

    let mut units: BTreeMap<String, SystemdUnitState> = BTreeMap::new();
    let mut service_files: Vec<PathBuf> = Vec::new();
    let mut dropins: Vec<PathBuf> = Vec::new();

    for entry in WalkDir::new(path)
        .max_depth(3)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let name = p
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let parent_name = p
            .parent()
            .and_then(|d| d.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if name.ends_with(".service") {
            service_files.push(p.to_path_buf());
        } else if parent_name.ends_with(".service.d") && name.ends_with(".conf") {
            dropins.push(p.to_path_buf());
        }
    }
    service_files.sort();
    dropins.sort();

    for sf in service_files {
        let unit_key = sf
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let label = sf.to_string_lossy().replace('\\', "/");
        let content = read_bounded_text(&sf)?;
        let state = units.entry(unit_key).or_default();
        if state.target_label.is_empty() {
            state.target_label = label;
        }
        parse_systemd_into(&content, state);
    }

    for df in dropins {
        let unit_dir = df
            .parent()
            .and_then(|d| d.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let unit_key = unit_dir.strip_suffix(".d").unwrap_or(&unit_dir).to_string();
        let label = df.to_string_lossy().replace('\\', "/");
        let content = read_bounded_text(&df)?;
        let state = units.entry(unit_key).or_default();
        if state.target_label.is_empty() {
            state.target_label = label;
        }
        parse_systemd_into(&content, state);
    }

    let now = Utc::now();
    let mut findings = Vec::new();
    for state in units.values() {
        evaluate_systemd_state(state, now, &mut findings);
    }
    Ok(findings)
}

pub fn audit_systemd_content(content: &str, source_label: &str) -> Vec<Finding> {
    let mut state = SystemdUnitState {
        target_label: source_label.to_string(),
        ..SystemdUnitState::default()
    };
    parse_systemd_into(content, &mut state);
    let mut findings = Vec::new();
    evaluate_systemd_state(&state, Utc::now(), &mut findings);
    findings
}

fn parse_systemd_into(content: &str, state: &mut SystemdUnitState) {
    let mut current_section = String::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            continue;
        }
        if current_section != "service" {
            continue;
        }
        let Some((raw_k, raw_v)) = trimmed.split_once('=') else {
            continue;
        };
        let key = raw_k.trim().to_ascii_lowercase();
        let val = raw_v.trim().to_string();
        match key.as_str() {
            "user" => state.user = Some(val),
            "dynamicuser" => {
                state.dynamic_user =
                    matches!(val.to_ascii_lowercase().as_str(), "yes" | "true" | "1");
            }
            "nonewprivileges" => {
                state.no_new_privileges = Some(matches!(
                    val.to_ascii_lowercase().as_str(),
                    "yes" | "true" | "1"
                ));
            }
            "protectsystem" => state.protect_system = Some(val.to_ascii_lowercase()),
            "protecthome" => state.protect_home = Some(val.to_ascii_lowercase()),
            "execstart" | "execstartpre" | "execstartpost" if !val.is_empty() => {
                state.exec_starts.push((line_no, val));
            }
            _ => {}
        }
    }
}

fn evaluate_systemd_state(
    state: &SystemdUnitState,
    now: chrono::DateTime<Utc>,
    findings: &mut Vec<Finding>,
) {
    let label = &state.target_label;
    let target = format!("file://{label}");

    for (line_no, cmd) in &state.exec_starts {
        let lower = cmd.to_ascii_lowercase();
        if contains_temp_exec(&lower) || has_remote_shell_pipe(&lower) {
            findings.push(host_finding(
                "HOST-305",
                Severity::Critical,
                "Weak systemd service hardening or unsafe ExecStart target",
                format!(
                    "systemd unit {label} line {line_no} runs ExecStart from an untrusted temporary path or remote pipe: '{cmd}'."
                ),
                &target,
                json!({ "line": line_no, "exec": cmd, "cis_ref": "CIS Linux 5.x" }),
                "Execute only immutable binaries installed under /usr/bin, /usr/sbin, or /opt with root-owned write permissions.",
                "D3-CH",
                &format!("systemd-exec-{line_no}-{}", sanitize_id_part(label)),
                now,
            ));
        }
    }

    let runs_as_root = match state.user.as_deref().map(str::trim) {
        Some(u) if !u.is_empty() => u == "0" || u.eq_ignore_ascii_case("root"),
        _ => !state.dynamic_user,
    };
    if runs_as_root {
        findings.push(host_finding(
            "HOST-305",
            Severity::High,
            "Weak systemd service hardening or unsafe ExecStart target",
            format!(
                "systemd unit {label} runs as root (User={}).",
                state.user.as_deref().unwrap_or("<unset>")
            ),
            &target,
            json!({ "setting": "User", "observed": state.user, "cis_ref": "CIS Linux 5.x" }),
            "Configure a dedicated non-root User= (or DynamicUser=yes) in the [Service] section.",
            "D3-CH",
            &format!("systemd-user-{}", sanitize_id_part(label)),
            now,
        ));
    }

    if state.no_new_privileges != Some(true) {
        findings.push(host_finding(
            "HOST-305",
            Severity::High,
            "Weak systemd service hardening or unsafe ExecStart target",
            format!("systemd unit {label} omits NoNewPrivileges=yes."),
            &target,
            json!({ "setting": "NoNewPrivileges", "observed": state.no_new_privileges, "cis_ref": "CIS Linux 5.x" }),
            "Add NoNewPrivileges=yes under [Service] to block setuid/capability privilege elevation.",
            "D3-CH",
            &format!("systemd-nnp-{}", sanitize_id_part(label)),
            now,
        ));
    }

    let sys_hard = state
        .protect_system
        .as_deref()
        .is_some_and(|v| matches!(v, "strict" | "full" | "yes" | "true"));
    if !sys_hard {
        findings.push(host_finding(
            "HOST-305",
            Severity::Medium,
            "Weak systemd service hardening or unsafe ExecStart target",
            format!(
                "systemd unit {label} sets ProtectSystem={} (expected strict or full).",
                state.protect_system.as_deref().unwrap_or("<unset>")
            ),
            &target,
            json!({ "setting": "ProtectSystem", "observed": state.protect_system, "cis_ref": "CIS Linux 5.x" }),
            "Set ProtectSystem=strict (with narrow ReadWritePaths= if needed) under [Service].",
            "D3-CH",
            &format!("systemd-protsys-{}", sanitize_id_part(label)),
            now,
        ));
    }

    let home_hard = state
        .protect_home
        .as_deref()
        .is_some_and(|v| matches!(v, "yes" | "true" | "read-only" | "tmpfs"));
    if !home_hard {
        findings.push(host_finding(
            "HOST-305",
            Severity::Medium,
            "Weak systemd service hardening or unsafe ExecStart target",
            format!(
                "systemd unit {label} sets ProtectHome={} (expected yes or read-only).",
                state.protect_home.as_deref().unwrap_or("<unset>")
            ),
            &target,
            json!({ "setting": "ProtectHome", "observed": state.protect_home, "cis_ref": "CIS Linux 5.x" }),
            "Set ProtectHome=yes under [Service] to isolate /home and /root directories.",
            "D3-CH",
            &format!("systemd-prothome-{}", sanitize_id_part(label)),
            now,
        ));
    }
}

pub fn audit_persistence_path(path: &Path) -> io::Result<Vec<Finding>> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("persistence target {:?} does not exist", path),
        ));
    }
    if path.is_file() {
        let content = read_bounded_text(path)?;
        let label = path.to_string_lossy().replace('\\', "/");
        return Ok(audit_persistence_content(&content, &label));
    }

    let mut files: Vec<PathBuf> = WalkDir::new(path)
        .max_depth(2)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();
    files.sort();

    let mut all = Vec::new();
    for f in files {
        let content = read_bounded_text(&f)?;
        let label = f.to_string_lossy().replace('\\', "/");
        all.extend(audit_persistence_content(&content, &label));
    }
    Ok(all)
}

pub fn audit_persistence_content(content: &str, source_label: &str) -> Vec<Finding> {
    let now = Utc::now();
    let target = format!("file://{source_label}");
    let mut findings = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();

        if has_remote_shell_pipe(&lower) {
            findings.push(host_finding(
                "HOST-306",
                Severity::Critical,
                "Suspicious cron, anacron, at, or shell profile persistence hook",
                format!("Persistence line {line_no} in {source_label} fetches and executes a remote script directly."),
                &target,
                json!({ "line": line_no, "pattern": "remote_fetch_pipe", "cis_ref": "CIS Linux 5.1" }),
                "Remove remote download-and-execute hooks; deploy checksum-verified immutable packages instead.",
                "D3-SPP",
                &format!("persist-l{line_no}-remote-{}", sanitize_id_part(source_label)),
                now,
            ));
            continue;
        }

        if has_base64_shell_pipe(&lower) {
            findings.push(host_finding(
                "HOST-306",
                Severity::Critical,
                "Suspicious cron, anacron, at, or shell profile persistence hook",
                format!("Persistence line {line_no} in {source_label} decodes obfuscated base64 input directly into a shell."),
                &target,
                json!({ "line": line_no, "pattern": "base64_shell_pipe", "cis_ref": "CIS Linux 5.1" }),
                "Remove obfuscated scheduled or shell startup commands and inspect host integrity baselines.",
                "D3-SPP",
                &format!("persist-l{line_no}-b64-{}", sanitize_id_part(source_label)),
                now,
            ));
            continue;
        }

        if contains_temp_exec(&lower) {
            findings.push(host_finding(
                "HOST-306",
                Severity::High,
                "Suspicious cron, anacron, at, or shell profile persistence hook",
                format!("Persistence line {line_no} in {source_label} references execution from a temporary writable directory."),
                &target,
                json!({ "line": line_no, "pattern": "temp_dir_exec", "cis_ref": "CIS Linux 5.1" }),
                "Never execute cron or profile commands from /tmp, /var/tmp, or /dev/shm.",
                "D3-SPP",
                &format!("persist-l{line_no}-tmp-{}", sanitize_id_part(source_label)),
                now,
            ));
        }

        if lower.contains("ld_preload=") || has_unsafe_path_hijack(trimmed) {
            findings.push(host_finding(
                "HOST-306",
                Severity::High,
                "Suspicious cron, anacron, at, or shell profile persistence hook",
                format!("Persistence line {line_no} in {source_label} injects LD_PRELOAD or unsafe relative PATH segments."),
                &target,
                json!({ "line": line_no, "pattern": "env_hijack", "cis_ref": "CIS Linux 5.1" }),
                "Remove LD_PRELOAD hooks and relative '.' or trailing ':' PATH entries from cron and shell init files.",
                "D3-SPP",
                &format!("persist-l{line_no}-env-{}", sanitize_id_part(source_label)),
                now,
            ));
        }
    }

    findings
}

pub fn audit_auth_policy_path(path: &Path) -> io::Result<Vec<Finding>> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("auth policy target {:?} does not exist", path),
        ));
    }
    if path.is_file() {
        let content = read_bounded_text(path)?;
        let label = path.to_string_lossy().replace('\\', "/");
        return Ok(audit_auth_policy_content(&content, &label));
    }

    let mut files: Vec<PathBuf> = WalkDir::new(path)
        .max_depth(2)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();
    files.sort();

    let mut all = Vec::new();
    for f in files {
        let content = read_bounded_text(&f)?;
        let label = f.to_string_lossy().replace('\\', "/");
        all.extend(audit_auth_policy_content(&content, &label));
    }
    Ok(all)
}

pub fn audit_auth_policy_content(content: &str, source_label: &str) -> Vec<Finding> {
    let lower_label = source_label.to_ascii_lowercase();
    let is_pam = lower_label.contains("pam")
        || lower_label.contains("common-auth")
        || lower_label.contains("system-auth")
        || content.lines().any(|l| {
            l.contains("pam_unix.so")
                || l.contains("pam_permit.so")
                || l.contains("pam_faillock.so")
        });

    if is_pam {
        audit_pam_content(content, source_label)
    } else {
        audit_login_defs_content(content, source_label)
    }
}

fn audit_login_defs_content(content: &str, source_label: &str) -> Vec<Finding> {
    let now = Utc::now();
    let target = format!("file://{source_label}");
    let mut findings = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let cleaned = raw_line.split('#').next().unwrap_or("").trim();
        if cleaned.is_empty() {
            continue;
        }
        let mut parts = cleaned.split_whitespace();
        let key = parts.next().unwrap_or("").to_ascii_uppercase();
        let val = parts.next().unwrap_or("").trim();
        if val.is_empty() {
            continue;
        }

        match key.as_str() {
            "PASS_MAX_DAYS" => {
                if let Ok(days) = val.parse::<u32>() {
                    if days > 365 {
                        findings.push(host_finding(
                            "HOST-307",
                            Severity::Medium,
                            "Weak PAM authentication/lockout or login.defs password policy",
                            format!("login.defs line {line_no} sets PASS_MAX_DAYS={days} (expected <= 365)."),
                            &target,
                            json!({ "line": line_no, "key": "PASS_MAX_DAYS", "observed": days, "cis_ref": "CIS Linux 5.4.1.1" }),
                            "Set PASS_MAX_DAYS 365 (or stricter, e.g. 90-180) in /etc/login.defs.",
                            "D3-SUC",
                            &format!("auth-maxdays-l{line_no}"),
                            now,
                        ));
                    }
                }
            }
            "PASS_MIN_LEN" => {
                if let Ok(len) = val.parse::<u32>() {
                    if len < 12 {
                        findings.push(host_finding(
                            "HOST-307",
                            Severity::Medium,
                            "Weak PAM authentication/lockout or login.defs password policy",
                            format!("login.defs line {line_no} sets PASS_MIN_LEN={len} (expected >= 12)."),
                            &target,
                            json!({ "line": line_no, "key": "PASS_MIN_LEN", "observed": len, "cis_ref": "CIS Linux 5.4.1" }),
                            "Enforce minimum password length >= 12 via PAM pam_pwquality and PASS_MIN_LEN.",
                            "D3-SUC",
                            &format!("auth-minlen-l{line_no}"),
                            now,
                        ));
                    }
                }
            }
            "PASS_WARN_AGE" => {
                if let Ok(days) = val.parse::<u32>() {
                    if days < 7 {
                        findings.push(host_finding(
                            "HOST-307",
                            Severity::Low,
                            "Weak PAM authentication/lockout or login.defs password policy",
                            format!("login.defs line {line_no} sets PASS_WARN_AGE={days} (expected >= 7)."),
                            &target,
                            json!({ "line": line_no, "key": "PASS_WARN_AGE", "observed": days, "cis_ref": "CIS Linux 5.4.1.3" }),
                            "Set PASS_WARN_AGE 7 or higher in /etc/login.defs.",
                            "D3-SUC",
                            &format!("auth-warnage-l{line_no}"),
                            now,
                        ));
                    }
                }
            }
            "UMASK" => {
                if let Ok(mode) = u32::from_str_radix(val, 8) {
                    if mode & 0o027 != 0o027 && mode != 0o077 {
                        findings.push(host_finding(
                            "HOST-307",
                            Severity::High,
                            "Weak PAM authentication/lockout or login.defs password policy",
                            format!("login.defs line {line_no} sets permissive default UMASK {val} (expected 027 or 077)."),
                            &target,
                            json!({ "line": line_no, "key": "UMASK", "observed": val, "cis_ref": "CIS Linux 5.4.4" }),
                            "Set UMASK 027 (or 077) in /etc/login.defs.",
                            "D3-SUC",
                            &format!("auth-umask-l{line_no}"),
                            now,
                        ));
                    }
                }
            }
            "ENCRYPT_METHOD" => {
                let u = val.to_ascii_uppercase();
                if matches!(u.as_str(), "DES" | "MD5" | "BIGCRYPT") {
                    findings.push(host_finding(
                        "HOST-307",
                        Severity::High,
                        "Weak PAM authentication/lockout or login.defs password policy",
                        format!("login.defs line {line_no} uses weak ENCRYPT_METHOD {val}."),
                        &target,
                        json!({ "line": line_no, "key": "ENCRYPT_METHOD", "observed": val, "cis_ref": "CIS Linux 5.4.1" }),
                        "Set ENCRYPT_METHOD YESCRYPT or SHA512 in /etc/login.defs.",
                        "D3-SUC",
                        &format!("auth-hash-l{line_no}"),
                        now,
                    ));
                }
            }
            _ => {}
        }
    }

    findings
}

fn audit_pam_content(content: &str, source_label: &str) -> Vec<Finding> {
    let now = Utc::now();
    let target = format!("file://{source_label}");
    let mut findings = Vec::new();
    let mut has_auth_rules = false;
    let mut has_lockout = false;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let cleaned = raw_line.split('#').next().unwrap_or("").trim();
        if cleaned.is_empty() {
            continue;
        }
        let lower = cleaned.to_ascii_lowercase();
        let mut cols = lower.split_whitespace();
        let module_type = cols.next().unwrap_or("");
        if module_type == "auth" {
            has_auth_rules = true;
        }

        if lower.contains("pam_unix.so") && lower.split_whitespace().any(|t| t == "nullok") {
            findings.push(host_finding(
                "HOST-307",
                Severity::Critical,
                "Weak PAM authentication/lockout or login.defs password policy",
                format!("PAM line {line_no} in {source_label} allows empty passwords via nullok."),
                &target,
                json!({ "line": line_no, "option": "nullok", "cis_ref": "CIS Linux 5.3.2" }),
                "Remove nullok from pam_unix.so rules.",
                "D3-SUC",
                &format!("pam-nullok-l{line_no}"),
                now,
            ));
        }

        if (module_type == "auth" || module_type == "account") && lower.contains("pam_permit.so") {
            findings.push(host_finding(
                "HOST-307",
                Severity::Critical,
                "Weak PAM authentication/lockout or login.defs password policy",
                format!("PAM line {line_no} in {source_label} unconditionally grants access via pam_permit.so."),
                &target,
                json!({ "line": line_no, "module": "pam_permit.so", "cis_ref": "CIS Linux 5.3.2" }),
                "Remove pam_permit.so from auth/account PAM stacks.",
                "D3-SUC",
                &format!("pam-permit-l{line_no}"),
                now,
            ));
        }

        if lower.contains("pam_faillock.so") || lower.contains("pam_tally2.so") {
            has_lockout = true;
        }
    }

    if has_auth_rules && !has_lockout {
        findings.push(host_finding(
            "HOST-307",
            Severity::High,
            "Weak PAM authentication/lockout or login.defs password policy",
            format!("PAM auth stack in {source_label} omits account lockout protection (pam_faillock.so)."),
            &target,
            json!({ "missing": "pam_faillock.so", "cis_ref": "CIS Linux 5.3.2" }),
            "Enable pam_faillock.so in PAM auth/account configuration to rate-limit failed logins.",
            "D3-SUC",
            &format!("pam-lockout-{}", sanitize_id_part(source_label)),
            now,
        ));
    }

    findings
}

pub fn audit_kernel_audit_path(path: &Path) -> io::Result<Vec<Finding>> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("kernel/audit target {:?} does not exist", path),
        ));
    }
    if path.is_file() {
        let content = read_bounded_text(path)?;
        let label = path.to_string_lossy().replace('\\', "/");
        return Ok(audit_kernel_audit_content(&content, &label));
    }

    let mut modprobe_texts = Vec::new();
    let mut modprobe_label = None;
    let mut findings = Vec::new();
    let mut files: Vec<PathBuf> = WalkDir::new(path)
        .max_depth(2)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();
    files.sort();

    for f in files {
        let content = read_bounded_text(&f)?;
        let label = f.to_string_lossy().replace('\\', "/");
        if is_modprobe_file(&label, &content) {
            if modprobe_label.is_none() {
                modprobe_label = Some(path.to_string_lossy().replace('\\', "/"));
            }
            modprobe_texts.push(content);
        } else {
            findings.extend(audit_kernel_audit_content(&content, &label));
        }
    }

    if let Some(lbl) = modprobe_label {
        let combined = modprobe_texts.join("\n");
        findings.extend(audit_modprobe_content(&combined, &lbl));
    }
    Ok(findings)
}

pub fn audit_kernel_audit_content(content: &str, source_label: &str) -> Vec<Finding> {
    if is_modprobe_file(source_label, content) {
        audit_modprobe_content(content, source_label)
    } else if is_auditd_conf(source_label, content) {
        audit_auditd_conf_content(content, source_label)
    } else {
        audit_audit_rules_content(content, source_label)
    }
}

fn is_modprobe_file(label: &str, content: &str) -> bool {
    let low = label.to_ascii_lowercase();
    low.contains("modprobe")
        || content.lines().any(|l| {
            let t = l.trim().to_ascii_lowercase();
            t.starts_with("blacklist ") || (t.starts_with("install ") && t.contains("/bin/"))
        })
}

fn is_auditd_conf(label: &str, content: &str) -> bool {
    let low = label.to_ascii_lowercase();
    low.ends_with("auditd.conf")
        || content
            .lines()
            .any(|l| l.to_ascii_lowercase().contains("max_log_file_action"))
}

fn audit_modprobe_content(content: &str, source_label: &str) -> Vec<Finding> {
    const CORE_DISABLED_MODULES: &[&str] = &["cramfs", "dccp", "sctp"];
    let mut disabled = BTreeMap::<String, bool>::new();
    for raw_line in content.lines() {
        let cleaned = raw_line.split('#').next().unwrap_or("").trim();
        let lower = cleaned.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("blacklist ") {
            if let Some(mod_name) = rest.split_whitespace().next() {
                disabled.insert(mod_name.to_string(), true);
            }
        } else if let Some(rest) = lower.strip_prefix("install ") {
            let mut toks = rest.split_whitespace();
            if let Some(mod_name) = toks.next() {
                if rest.contains("/bin/true") || rest.contains("/bin/false") {
                    disabled.insert(mod_name.to_string(), true);
                }
            }
        }
    }

    let missing: Vec<&str> = CORE_DISABLED_MODULES
        .iter()
        .copied()
        .filter(|m| !disabled.contains_key(*m))
        .collect();
    if missing.is_empty() {
        return Vec::new();
    }

    vec![host_finding(
        "HOST-308",
        Severity::Medium,
        "Missing kernel module blacklist or weak auditd logging policy",
        format!(
            "modprobe configuration {source_label} does not disable legacy kernel modules: {}.",
            missing.join(", ")
        ),
        &format!("file://{source_label}"),
        json!({ "missing_blacklists": missing, "cis_ref": "CIS Linux 1.1.1 / 3.4" }),
        "Add 'install <module> /bin/false' and 'blacklist <module>' entries under /etc/modprobe.d/.",
        "D3-CH",
        &format!("modprobe-{}", sanitize_id_part(source_label)),
        Utc::now(),
    )]
}

fn audit_auditd_conf_content(content: &str, source_label: &str) -> Vec<Finding> {
    let now = Utc::now();
    let target = format!("file://{source_label}");
    let mut findings = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let cleaned = raw_line.split('#').next().unwrap_or("").trim();
        let Some((raw_k, raw_v)) = cleaned.split_once('=') else {
            continue;
        };
        let key = raw_k.trim().to_ascii_lowercase();
        let val = raw_v.trim().to_ascii_lowercase();
        if matches!(
            key.as_str(),
            "max_log_file_action" | "space_left_action" | "admin_space_left_action"
        ) && matches!(val.as_str(), "ignore" | "suspend")
        {
            findings.push(host_finding(
                "HOST-308",
                Severity::High,
                "Missing kernel module blacklist or weak auditd logging policy",
                format!("auditd.conf line {line_no} sets {key} = {val}, risking silent audit log loss."),
                &target,
                json!({ "line": line_no, "key": key, "observed": val, "cis_ref": "CIS Linux 4.1.2" }),
                "Configure max_log_file_action = keep_logs and alert/halt policies for space_left_action.",
                "D3-CH",
                &format!("auditd-{key}-l{line_no}"),
                now,
            ));
        }
    }

    findings
}

fn audit_audit_rules_content(content: &str, source_label: &str) -> Vec<Finding> {
    let now = Utc::now();
    let target = format!("file://{source_label}");
    let mut findings = Vec::new();
    let mut has_immutable = false;
    let mut has_identity_watch = false;

    for raw_line in content.lines() {
        let cleaned = raw_line.split('#').next().unwrap_or("").trim();
        if cleaned.is_empty() {
            continue;
        }
        let lower = cleaned.to_ascii_lowercase();
        if lower == "-e 2" || lower.starts_with("-e 2 ") {
            has_immutable = true;
        }
        if lower.contains("-w /etc/passwd")
            || (lower.contains("-w /etc/") && lower.contains("shadow"))
            || lower.contains("-w /etc/sudoers")
        {
            has_identity_watch = true;
        }
    }

    if !has_identity_watch {
        findings.push(host_finding(
            "HOST-308",
            Severity::High,
            "Missing kernel module blacklist or weak auditd logging policy",
            format!("audit.rules {source_label} omits identity/privilege file watches (/etc/passwd, shadow, sudoers)."),
            &target,
            json!({ "missing": "identity_watch", "cis_ref": "CIS Linux 4.1.3" }),
            "Add -w /etc/passwd -p wa -k identity and /etc/sudoers watch rules.",
            "D3-CH",
            &format!("auditrules-id-{}", sanitize_id_part(source_label)),
            now,
        ));
    }

    if !has_immutable {
        findings.push(host_finding(
            "HOST-308",
            Severity::Medium,
            "Missing kernel module blacklist or weak auditd logging policy",
            format!("audit.rules {source_label} omits '-e 2' immutable configuration lock."),
            &target,
            json!({ "missing": "-e 2", "cis_ref": "CIS Linux 4.1.17" }),
            "Append '-e 2' at the end of /etc/audit/rules.d/ so audit configuration requires reboot to alter.",
            "D3-CH",
            &format!("auditrules-imm-{}", sanitize_id_part(source_label)),
            now,
        ));
    }

    findings
}

fn contains_temp_exec(lower: &str) -> bool {
    lower.contains("/tmp/") || lower.contains("/var/tmp/") || lower.contains("/dev/shm/")
}

fn has_remote_shell_pipe(lower: &str) -> bool {
    (lower.contains("curl ") || lower.contains("wget "))
        && lower.contains('|')
        && lower.split('|').skip(1).any(|rhs| {
            let cmd = rhs.split_whitespace().next().unwrap_or("");
            matches!(
                cmd,
                "sh" | "bash" | "dash" | "zsh" | "python" | "python3" | "/bin/sh" | "/bin/bash"
            )
        })
}

fn has_base64_shell_pipe(lower: &str) -> bool {
    lower.contains("base64")
        && (lower.contains(" -d") || lower.contains("--decode"))
        && lower.contains('|')
        && lower.split('|').skip(1).any(|rhs| {
            let cmd = rhs.split_whitespace().next().unwrap_or("");
            matches!(
                cmd,
                "sh" | "bash" | "dash" | "zsh" | "/bin/sh" | "/bin/bash"
            )
        })
}

fn has_unsafe_path_hijack(trimmed: &str) -> bool {
    let Some((_, rhs)) = trimmed.split_once("PATH=") else {
        return false;
    };
    let val = rhs
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches('"')
        .trim_matches('\'');
    val.ends_with(':') || val.starts_with(':') || val.split(':').any(|seg| seg == ".")
}

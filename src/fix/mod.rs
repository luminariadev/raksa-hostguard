use crate::audit::read_bounded_text;
use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use serde_yaml_ng::{Mapping, Value as YamlValue};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FixKind {
    #[default]
    Auto,
    Ssh,
    Sysctl,
    Dockerfile,
    Compose,
    Systemd,
    Daemon,
}

impl FixKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FixKind::Auto => "auto",
            FixKind::Ssh => "ssh",
            FixKind::Sysctl => "sysctl",
            FixKind::Dockerfile => "dockerfile",
            FixKind::Compose => "compose",
            FixKind::Systemd => "systemd",
            FixKind::Daemon => "daemon",
        }
    }
}

impl FromStr for FixKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(FixKind::Auto),
            "ssh" => Ok(FixKind::Ssh),
            "sysctl" => Ok(FixKind::Sysctl),
            "dockerfile" => Ok(FixKind::Dockerfile),
            "compose" | "docker-compose" => Ok(FixKind::Compose),
            "systemd" => Ok(FixKind::Systemd),
            "daemon" | "daemon.json" => Ok(FixKind::Daemon),
            other => Err(format!(
                "invalid fix kind {:?}: expected auto, ssh, sysctl, dockerfile, compose, systemd, or daemon",
                other
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FixPatch {
    pub target: String,
    pub kind: String,
    pub rules_addressed: Vec<String>,
    pub unified_diff: String,
    pub summary: String,
}

pub fn generate_fix_preview_path(path: &Path, kind: FixKind) -> io::Result<Vec<FixPatch>> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("fix-preview target {:?} does not exist", path),
        ));
    }

    if path.is_file() {
        let content = read_bounded_text(path)?;
        let label = path.to_string_lossy().replace('\\', "/");
        let resolved = match kind {
            FixKind::Auto => {
                detect_kind_from_path(path).unwrap_or_else(|| detect_kind_from_content(&content))
            }
            k => k,
        };
        let patch = generate_fix_preview_content(&content, &label, resolved)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        return Ok(patch.into_iter().collect());
    }

    let mut files: Vec<(PathBuf, FixKind)> = Vec::new();
    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_ignored_dir(e.path()))
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let detected = match kind {
            FixKind::Auto => detect_kind_from_path(entry.path()),
            k => Some(k),
        };
        if let Some(fk) = detected {
            files.push((entry.into_path(), fk));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut patches = Vec::new();
    for (p, fk) in files {
        let content = read_bounded_text(&p)?;
        let label = p.to_string_lossy().replace('\\', "/");
        if let Some(patch) = generate_fix_preview_content(&content, &label, fk)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        {
            patches.push(patch);
        }
    }
    Ok(patches)
}

pub fn generate_fix_preview_content(
    content: &str,
    source_label: &str,
    kind: FixKind,
) -> Result<Option<FixPatch>, String> {
    let resolved = match kind {
        FixKind::Auto => detect_kind_from_content(content),
        k => k,
    };

    let (patched, rules) = match resolved {
        FixKind::Ssh => transform_ssh(content),
        FixKind::Sysctl => transform_sysctl(content),
        FixKind::Dockerfile => transform_dockerfile(content),
        FixKind::Compose => transform_compose(content)?,
        FixKind::Systemd => transform_systemd(content),
        FixKind::Daemon => transform_daemon_json(content)?,
        FixKind::Auto => unreachable!(),
    };

    if patched == content || rules.is_empty() {
        return Ok(None);
    }

    let unified_diff = build_unified_diff(source_label, content, &patched);
    if unified_diff.is_empty() {
        return Ok(None);
    }

    let summary = format!(
        "Preview patch for {} ({}) addressing {}",
        source_label,
        resolved.as_str(),
        rules.join(", ")
    );

    Ok(Some(FixPatch {
        target: source_label.to_string(),
        kind: resolved.as_str().to_string(),
        rules_addressed: rules,
        unified_diff,
        summary,
    }))
}

fn is_ignored_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    matches!(name, ".git" | "target" | "node_modules" | "vendor")
}

fn detect_kind_from_path(path: &Path) -> Option<FixKind> {
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if fname == "sshd_config" || (fname.starts_with("sshd_") && fname.ends_with(".conf")) {
        Some(FixKind::Ssh)
    } else if fname.contains("sysctl") && fname.ends_with(".conf") {
        Some(FixKind::Sysctl)
    } else if fname == "dockerfile"
        || fname.starts_with("dockerfile.")
        || fname.ends_with(".dockerfile")
    {
        Some(FixKind::Dockerfile)
    } else if fname.contains("compose") && (fname.ends_with(".yml") || fname.ends_with(".yaml")) {
        Some(FixKind::Compose)
    } else if fname.ends_with(".service") {
        Some(FixKind::Systemd)
    } else if fname == "daemon.json"
        || fname.ends_with(".daemon.json")
        || (fname.starts_with("daemon.") && fname.ends_with(".json"))
    {
        Some(FixKind::Daemon)
    } else {
        None
    }
}

fn detect_kind_from_content(content: &str) -> FixKind {
    let trimmed = content.trim_start();
    if trimmed.starts_with('{') {
        return FixKind::Daemon;
    }
    if content.contains("[Service]") {
        return FixKind::Systemd;
    }
    if content
        .lines()
        .any(|l| l.trim_start().starts_with("services:"))
    {
        return FixKind::Compose;
    }
    if content
        .lines()
        .any(|l| l.trim_start().to_ascii_uppercase().starts_with("FROM "))
    {
        return FixKind::Dockerfile;
    }
    if content.lines().any(|l| {
        let t = l.trim().to_ascii_lowercase();
        t.contains("net.ipv4.") || t.contains("kernel.") || t.contains("fs.suid_dumpable")
    }) {
        return FixKind::Sysctl;
    }
    FixKind::Ssh
}

fn transform_ssh(content: &str) -> (String, Vec<String>) {
    let mut out_lines = Vec::new();
    let mut rules = BTreeSet::new();

    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out_lines.push(raw.to_string());
            continue;
        }
        let cleaned = trimmed.split('#').next().unwrap_or("").trim();
        let mut parts = cleaned.splitn(2, |c: char| c.is_whitespace() || c == '=');
        let key = parts.next().unwrap_or("").trim();
        let key_low = key.to_ascii_lowercase();
        let val = parts
            .next()
            .unwrap_or("")
            .trim()
            .trim_start_matches('=')
            .trim();

        let replacement = match key_low.as_str() {
            "permitrootlogin" if val.eq_ignore_ascii_case("yes") => {
                rules.insert("HOST-101".to_string());
                Some("PermitRootLogin no".to_string())
            }
            "passwordauthentication" if val.eq_ignore_ascii_case("yes") => {
                rules.insert("HOST-102".to_string());
                Some("PasswordAuthentication no".to_string())
            }
            "permitemptypasswords" if val.eq_ignore_ascii_case("yes") => {
                rules.insert("HOST-103".to_string());
                Some("PermitEmptyPasswords no".to_string())
            }
            "x11forwarding" if val.eq_ignore_ascii_case("yes") => {
                rules.insert("HOST-104".to_string());
                Some("X11Forwarding no".to_string())
            }
            "maxauthtries" if val.parse::<u32>().is_ok_and(|n| n > 4) => {
                rules.insert("HOST-104".to_string());
                Some("MaxAuthTries 4".to_string())
            }
            "allowagentforwarding" if val.eq_ignore_ascii_case("yes") => {
                rules.insert("HOST-106".to_string());
                Some("AllowAgentForwarding no".to_string())
            }
            "allowtcpforwarding" if val.eq_ignore_ascii_case("yes") => {
                rules.insert("HOST-106".to_string());
                Some("AllowTcpForwarding no".to_string())
            }
            "permituserenvironment" if val.eq_ignore_ascii_case("yes") => {
                rules.insert("HOST-106".to_string());
                Some("PermitUserEnvironment no".to_string())
            }
            _ => None,
        };

        out_lines.push(replacement.unwrap_or_else(|| raw.to_string()));
    }

    let mut joined = out_lines.join("\n");
    if content.ends_with('\n') && !joined.ends_with('\n') {
        joined.push('\n');
    }
    (joined, rules.into_iter().collect())
}

fn transform_sysctl(content: &str) -> (String, Vec<String>) {
    let mut out_lines = Vec::new();
    let mut rules = BTreeSet::new();

    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            out_lines.push(raw.to_string());
            continue;
        }
        let cleaned = trimmed
            .split('#')
            .next()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let Some((raw_k, raw_v)) = cleaned.split_once('=') else {
            out_lines.push(raw.to_string());
            continue;
        };
        let key_orig = raw_k.trim();
        let key = key_orig.to_ascii_lowercase();
        let val = raw_v.trim();

        let replacement = match key.as_str() {
            "net.ipv4.ip_forward"
            | "net.ipv4.conf.all.accept_redirects"
            | "net.ipv4.conf.default.accept_redirects"
            | "net.ipv4.conf.all.accept_source_route"
            | "net.ipv4.conf.all.send_redirects"
                if val != "0" =>
            {
                rules.insert("HOST-301".to_string());
                Some(format!("{key_orig} = 0"))
            }
            "net.ipv4.tcp_syncookies" if val != "1" => {
                rules.insert("HOST-301".to_string());
                Some(format!("{key_orig} = 1"))
            }
            "net.ipv4.conf.all.rp_filter" if val == "0" => {
                rules.insert("HOST-301".to_string());
                Some(format!("{key_orig} = 1"))
            }
            "kernel.randomize_va_space" if val != "2" => {
                rules.insert("HOST-302".to_string());
                Some(format!("{key_orig} = 2"))
            }
            "kernel.yama.ptrace_scope" | "kernel.kptr_restrict" | "kernel.dmesg_restrict"
                if val == "0" =>
            {
                rules.insert("HOST-302".to_string());
                Some(format!("{key_orig} = 1"))
            }
            "fs.suid_dumpable" if val != "0" => {
                rules.insert("HOST-302".to_string());
                Some(format!("{key_orig} = 0"))
            }
            _ => None,
        };

        out_lines.push(replacement.unwrap_or_else(|| raw.to_string()));
    }

    let mut joined = out_lines.join("\n");
    if content.ends_with('\n') && !joined.ends_with('\n') {
        joined.push('\n');
    }
    (joined, rules.into_iter().collect())
}

fn transform_dockerfile(content: &str) -> (String, Vec<String>) {
    let mut lines: Vec<String> = content.lines().map(ToString::to_string).collect();
    let mut last_from_idx = None;
    let mut last_user_after_from: Option<(usize, String)> = None;
    let mut last_runtime_idx = None;

    for (idx, line) in lines.iter().enumerate() {
        let up = line.trim_start().to_ascii_uppercase();
        if up.starts_with("FROM ") {
            last_from_idx = Some(idx);
            last_user_after_from = None;
            last_runtime_idx = None;
        } else if last_from_idx.is_some() && up.starts_with("USER ") {
            let tok = line.trim_start()[5..].trim().to_string();
            last_user_after_from = Some((idx, tok));
        } else if last_from_idx.is_some()
            && (up.starts_with("CMD ") || up.starts_with("ENTRYPOINT "))
        {
            last_runtime_idx = Some(idx);
        }
    }

    let mut rules = Vec::new();
    let needs_nonroot = last_from_idx.is_some()
        && match &last_user_after_from {
            None => true,
            Some((_, u)) => {
                let primary = u.split(':').next().unwrap_or(u).trim();
                primary == "0" || primary.eq_ignore_ascii_case("root")
            }
        };

    if needs_nonroot {
        rules.push("HOST-201".to_string());
        if let Some((u_idx, _)) = last_user_after_from {
            lines[u_idx] = "USER nonroot:nonroot".to_string();
        } else if let Some(rt_idx) = last_runtime_idx {
            lines.insert(rt_idx, "USER nonroot:nonroot".to_string());
        } else {
            lines.push("USER nonroot:nonroot".to_string());
        }
    }

    let mut joined = lines.join("\n");
    if content.ends_with('\n') && !joined.ends_with('\n') {
        joined.push('\n');
    }
    (joined, rules)
}

fn transform_compose(content: &str) -> Result<(String, Vec<String>), String> {
    let mut doc: YamlValue = serde_yaml_ng::from_str(content)
        .map_err(|e| format!("parse compose YAML for fix-preview: {e}"))?;
    let mut rules = BTreeSet::new();

    if let Some(root) = doc.as_mapping_mut() {
        if let Some(YamlValue::Mapping(services)) =
            root.get_mut(YamlValue::String("services".to_string()))
        {
            for (_, svc_val) in services.iter_mut() {
                let Some(svc) = svc_val.as_mapping_mut() else {
                    continue;
                };
                harden_compose_service(svc, &mut rules);
            }
        }
    }

    if rules.is_empty() {
        return Ok((content.to_string(), Vec::new()));
    }

    let rendered = serde_yaml_ng::to_string(&doc)
        .map_err(|e| format!("serialize patched compose YAML: {e}"))?;
    Ok((rendered, rules.into_iter().collect()))
}

fn harden_compose_service(svc: &mut Mapping, rules: &mut BTreeSet<String>) {
    if let Some(YamlValue::String(u)) = svc.get(YamlValue::String("user".to_string())) {
        let primary = u.split(':').next().unwrap_or(u).trim();
        if primary == "0" || primary.eq_ignore_ascii_case("root") {
            svc.insert(
                YamlValue::String("user".to_string()),
                YamlValue::String("1000:1000".to_string()),
            );
            rules.insert("HOST-201".to_string());
        }
    }

    if svc
        .get(YamlValue::String("privileged".to_string()))
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        svc.insert(
            YamlValue::String("privileged".to_string()),
            YamlValue::Bool(false),
        );
        rules.insert("HOST-202".to_string());
    }

    let sec_key = YamlValue::String("security_opt".to_string());
    let has_nnp = svc
        .get(&sec_key)
        .and_then(|v| v.as_sequence())
        .is_some_and(|seq| {
            seq.iter().any(|item| {
                item.as_str().is_some_and(|s| {
                    let l = s.trim().to_ascii_lowercase();
                    l == "no-new-privileges"
                        || l == "no-new-privileges:true"
                        || l == "no-new-privileges=true"
                })
            })
        });
    if !has_nnp {
        let entry = svc
            .entry(sec_key)
            .or_insert_with(|| YamlValue::Sequence(Vec::new()));
        if let YamlValue::Sequence(seq) = entry {
            seq.push(YamlValue::String("no-new-privileges:true".to_string()));
            rules.insert("HOST-207".to_string());
        }
    }

    let cap_key = YamlValue::String("cap_drop".to_string());
    let has_cap_drop_all = svc
        .get(&cap_key)
        .and_then(|v| v.as_sequence())
        .is_some_and(|seq| {
            seq.iter().any(|item| {
                item.as_str()
                    .is_some_and(|s| s.trim().eq_ignore_ascii_case("ALL"))
            })
        });
    if !has_cap_drop_all {
        let entry = svc
            .entry(cap_key)
            .or_insert_with(|| YamlValue::Sequence(Vec::new()));
        if let YamlValue::Sequence(seq) = entry {
            seq.push(YamlValue::String("ALL".to_string()));
            rules.insert("HOST-208".to_string());
        }
    }
}

fn transform_systemd(content: &str) -> (String, Vec<String>) {
    let mut lines: Vec<String> = content.lines().map(ToString::to_string).collect();
    let mut rules = BTreeSet::new();
    let mut in_service = false;
    let mut service_end_idx = None;
    let mut has_user = false;
    let mut has_dynamic_user = false;
    let mut has_nnp = false;
    let mut has_protsys = false;
    let mut has_prothome = false;

    for (idx, raw) in lines.iter_mut().enumerate() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if in_service && service_end_idx.is_none() {
                service_end_idx = Some(idx);
            }
            in_service = trimmed[1..trimmed.len() - 1]
                .trim()
                .eq_ignore_ascii_case("service");
            continue;
        }
        if !in_service {
            continue;
        }
        let Some((raw_k, raw_v)) = trimmed.split_once('=') else {
            continue;
        };
        let key = raw_k.trim().to_ascii_lowercase();
        let val = raw_v.trim();
        let low = val.to_ascii_lowercase();
        match key.as_str() {
            "user" => {
                has_user = true;
                if val == "0" || val.eq_ignore_ascii_case("root") {
                    *raw = "User=nonroot".to_string();
                    rules.insert("HOST-305".to_string());
                }
            }
            "dynamicuser" if matches!(low.as_str(), "yes" | "true" | "1") => {
                has_dynamic_user = true;
            }
            "nonewprivileges" => {
                has_nnp = true;
                if !matches!(low.as_str(), "yes" | "true" | "1") {
                    *raw = "NoNewPrivileges=yes".to_string();
                    rules.insert("HOST-305".to_string());
                }
            }
            "protectsystem" => {
                has_protsys = true;
                if !matches!(low.as_str(), "strict" | "full" | "yes" | "true") {
                    *raw = "ProtectSystem=strict".to_string();
                    rules.insert("HOST-305".to_string());
                }
            }
            "protecthome" => {
                has_prothome = true;
                if !matches!(low.as_str(), "yes" | "true" | "read-only" | "tmpfs") {
                    *raw = "ProtectHome=yes".to_string();
                    rules.insert("HOST-305".to_string());
                }
            }
            _ => {}
        }
    }

    let mut additions = Vec::new();
    if !has_user && !has_dynamic_user {
        additions.push("User=nonroot".to_string());
        rules.insert("HOST-305".to_string());
    }
    if !has_nnp {
        additions.push("NoNewPrivileges=yes".to_string());
        rules.insert("HOST-305".to_string());
    }
    if !has_protsys {
        additions.push("ProtectSystem=strict".to_string());
        rules.insert("HOST-305".to_string());
    }
    if !has_prothome {
        additions.push("ProtectHome=yes".to_string());
        rules.insert("HOST-305".to_string());
    }

    if !additions.is_empty() {
        if let Some(insert_at) = service_end_idx {
            for (offset, line) in additions.into_iter().enumerate() {
                lines.insert(insert_at + offset, line);
            }
        } else {
            lines.extend(additions);
        }
    }

    let mut joined = lines.join("\n");
    if content.ends_with('\n') && !joined.ends_with('\n') {
        joined.push('\n');
    }
    (joined, rules.into_iter().collect())
}

fn transform_daemon_json(content: &str) -> Result<(String, Vec<String>), String> {
    let mut val: JsonValue = serde_json::from_str(content)
        .map_err(|e| format!("parse daemon JSON for fix-preview: {e}"))?;
    let Some(obj) = val.as_object_mut() else {
        return Err("daemon JSON must be an object".to_string());
    };
    let mut rules = BTreeSet::new();

    let has_tcp = obj
        .get("hosts")
        .and_then(|v| v.as_array())
        .is_some_and(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .any(|s| s.trim().to_ascii_lowercase().starts_with("tcp://"))
        });
    if has_tcp && obj.get("tlsverify").and_then(|v| v.as_bool()) != Some(true) {
        obj.insert("tlsverify".to_string(), json!(true));
        rules.insert("HOST-210".to_string());
    }
    if obj.get("icc").and_then(|v| v.as_bool()) != Some(false) {
        obj.insert("icc".to_string(), json!(false));
        rules.insert("HOST-210".to_string());
    }
    if obj.get("no-new-privileges").and_then(|v| v.as_bool()) != Some(true) {
        obj.insert("no-new-privileges".to_string(), json!(true));
        rules.insert("HOST-210".to_string());
    }
    if !obj
        .get("userns-remap")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty())
    {
        obj.insert("userns-remap".to_string(), json!("default"));
        rules.insert("HOST-210".to_string());
    }
    if obj.get("live-restore").and_then(|v| v.as_bool()) != Some(true) {
        obj.insert("live-restore".to_string(), json!(true));
        rules.insert("HOST-210".to_string());
    }

    if rules.is_empty() {
        return Ok((content.to_string(), Vec::new()));
    }
    let mut rendered = serde_json::to_string_pretty(&val)
        .map_err(|e| format!("serialize patched daemon JSON: {e}"))?;
    rendered.push('\n');
    Ok((rendered, rules.into_iter().collect()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DiffOp {
    Context(usize),
    Remove(usize),
    Add(usize),
}

fn build_unified_diff(label: &str, old_text: &str, new_text: &str) -> String {
    let a: Vec<&str> = old_text.lines().collect();
    let b: Vec<&str> = new_text.lines().collect();
    if a == b {
        return String::new();
    }

    let n = a.len();
    let m = b.len();

    let mut out = String::new();
    out.push_str(&format!("--- a/{label}\n+++ b/{label}\n"));
    out.push_str(&format!("@@ -1,{} +1,{} @@\n", n, m));

    if n.saturating_mul(m) > 2_000_000 {
        for line in &a {
            out.push('-');
            out.push_str(line);
            out.push('\n');
        }
        for line in &b {
            out.push('+');
            out.push_str(line);
            out.push('\n');
        }
        return out;
    }

    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    let mut ops = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push(DiffOp::Context(i));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            ops.push(DiffOp::Remove(i));
            i += 1;
        } else {
            ops.push(DiffOp::Add(j));
            j += 1;
        }
    }
    while i < n {
        ops.push(DiffOp::Remove(i));
        i += 1;
    }
    while j < m {
        ops.push(DiffOp::Add(j));
        j += 1;
    }

    for op in ops {
        match op {
            DiffOp::Context(idx) => {
                out.push(' ');
                out.push_str(a[idx]);
                out.push('\n');
            }
            DiffOp::Remove(idx) => {
                out.push('-');
                out.push_str(a[idx]);
                out.push('\n');
            }
            DiffOp::Add(idx) => {
                out.push('+');
                out.push_str(b[idx]);
                out.push('\n');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{docker, host, ssh};

    #[test]
    fn fix_preview_returns_none_for_hardened_and_valid_diffs_for_insecure() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));

        // Hardened inputs produce no diff
        assert!(generate_fix_preview_path(
            &manifest.join("testdata/sshd_hardened.conf"),
            FixKind::Ssh
        )
        .unwrap()
        .is_empty());
        assert!(generate_fix_preview_path(
            &manifest.join("testdata/sysctl_hardened.conf"),
            FixKind::Sysctl
        )
        .unwrap()
        .is_empty());
        assert!(generate_fix_preview_path(
            &manifest.join("testdata/app.hardened.service"),
            FixKind::Systemd
        )
        .unwrap()
        .is_empty());
        assert!(generate_fix_preview_path(
            &manifest.join("testdata/daemon.hardened.json"),
            FixKind::Daemon
        )
        .unwrap()
        .is_empty());

        // Insecure SSH -> patched text clears SSH findings
        let raw_ssh =
            std::fs::read_to_string(manifest.join("testdata/sshd_insecure.conf")).unwrap();
        let ssh_patch = generate_fix_preview_content(&raw_ssh, "sshd_insecure.conf", FixKind::Ssh)
            .unwrap()
            .expect("ssh patch");
        assert!(ssh_patch.unified_diff.contains("+PermitRootLogin no"));
        let (patched_ssh, _) = transform_ssh(&raw_ssh);
        assert!(ssh::audit_sshd_config(&patched_ssh, "patched").is_empty());

        // Insecure Sysctl -> patched text clears sysctl findings
        let raw_sys =
            std::fs::read_to_string(manifest.join("testdata/sysctl_insecure.conf")).unwrap();
        let sys_patch =
            generate_fix_preview_content(&raw_sys, "sysctl_insecure.conf", FixKind::Sysctl)
                .unwrap()
                .expect("sysctl patch");
        assert!(sys_patch.unified_diff.contains("= 2"));
        let (patched_sys, _) = transform_sysctl(&raw_sys);
        assert!(host::audit_sysctl_content(&patched_sys, "patched").is_empty());

        // Insecure Dockerfiles, Compose, Systemd, Daemon
        let df_patch = generate_fix_preview_path(
            &manifest.join("testdata/Dockerfile.insecure"),
            FixKind::Dockerfile,
        )
        .unwrap();
        assert_eq!(df_patch.len(), 1);
        assert!(df_patch[0].unified_diff.contains("+USER nonroot:nonroot"));

        let raw_comp =
            std::fs::read_to_string(manifest.join("testdata/docker-compose.insecure.yml")).unwrap();
        let comp_patch = generate_fix_preview_content(
            &raw_comp,
            "docker-compose.insecure.yml",
            FixKind::Compose,
        )
        .unwrap()
        .expect("compose patch");
        assert!(comp_patch.unified_diff.contains("no-new-privileges:true"));
        assert!(comp_patch.rules_addressed.iter().any(|r| r == "HOST-202"));

        let sysd_patch = generate_fix_preview_path(
            &manifest.join("testdata/app.insecure.service"),
            FixKind::Systemd,
        )
        .unwrap();
        assert_eq!(sysd_patch.len(), 1);
        assert!(sysd_patch[0].unified_diff.contains("+ProtectHome=yes"));

        let raw_dm =
            std::fs::read_to_string(manifest.join("testdata/daemon.insecure.json")).unwrap();
        let dm_patch =
            generate_fix_preview_content(&raw_dm, "daemon.insecure.json", FixKind::Daemon)
                .unwrap()
                .expect("daemon patch");
        assert!(dm_patch.unified_diff.contains("\"icc\": false"));
        let (patched_dm, _) = transform_daemon_json(&raw_dm).unwrap();
        assert!(docker::audit_daemon_json(&patched_dm, "patched")
            .unwrap()
            .is_empty());
    }
}

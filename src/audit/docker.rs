use crate::audit::read_bounded_text;
use crate::schema::{sanitize_id_part, Finding, Severity, LAYER_HOST};
use chrono::Utc;
use serde_json::{json, Map, Value as JsonValue};
use serde_yaml_ng::Value;
use std::collections::HashSet;
use std::io;
use std::path::Path;
use walkdir::WalkDir;

const MODULE_DOCKER: &str = "docker-auditor";

#[derive(Debug, Clone)]
struct StageState {
    start_line: usize,
    image: String,
    last_user: Option<String>,
}

pub fn audit_docker_path(path: &Path) -> io::Result<Vec<Finding>> {
    if path.is_file() {
        return audit_single_docker_file(path);
    }
    if !path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("docker audit path {:?} does not exist", path),
        ));
    }

    let mut all_findings = Vec::new();
    for entry in WalkDir::new(path).follow_links(false) {
        let Ok(e) = entry else {
            continue;
        };
        if e.path_is_symlink() || !e.file_type().is_file() {
            continue;
        }
        let norm = e.path().to_string_lossy().replace('\\', "/");
        if norm.contains("/.git/") || norm.contains("/target/") || norm.contains("/node_modules/") {
            continue;
        }
        if is_docker_manifest(e.path()) {
            all_findings.extend(audit_single_docker_file(e.path())?);
        }
    }
    Ok(all_findings)
}

fn audit_single_docker_file(path: &Path) -> io::Result<Vec<Finding>> {
    let content = read_bounded_text(path)?;
    let label = path.to_string_lossy().replace('\\', "/");
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if fname.ends_with(".yml") || fname.ends_with(".yaml") {
        audit_compose(&content, &label).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    } else {
        Ok(audit_dockerfile(&content, &label))
    }
}

fn is_docker_manifest(path: &Path) -> bool {
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    fname == "dockerfile"
        || fname.starts_with("dockerfile.")
        || fname.ends_with(".dockerfile")
        || (fname.contains("compose") && (fname.ends_with(".yml") || fname.ends_with(".yaml")))
}

pub fn audit_dockerfile(content: &str, source_label: &str) -> Vec<Finding> {
    let now = Utc::now();
    let target = format!("file://{source_label}");
    let statements = join_dockerfile_continuations(content);

    let mut findings = Vec::new();
    let mut stages: Vec<StageState> = Vec::new();
    let mut stage_aliases: HashSet<String> = HashSet::new();

    for (line_no, stmt) in statements {
        let mut parts = stmt.splitn(2, char::is_whitespace);
        let instr = parts.next().unwrap_or("").trim().to_ascii_uppercase();
        let rest = parts.next().unwrap_or("").trim();

        match instr.as_str() {
            "FROM" => {
                let (image, alias) = parse_from_clause(rest);
                if !image.is_empty() {
                    let lower_img = image.to_ascii_lowercase();
                    if lower_img != "scratch"
                        && !stage_aliases.contains(&lower_img)
                        && is_unpinned_image(&image)
                    {
                        let mut ev = Map::new();
                        ev.insert("image".to_string(), json!(image));
                        ev.insert("line".to_string(), json!(line_no));
                        ev.insert("cis_ref".to_string(), json!("CIS Docker 4.7"));
                        findings.push(docker_finding(
                            "HOST-204",
                            Severity::Medium,
                            "Unpinned or :latest container image tag",
                            format!(
                                "Dockerfile stage image '{}' on line {} lacks an immutable tag or SHA-256 digest.",
                                image, line_no
                            ),
                            &target,
                            ev,
                            "Pin the base image to an explicit version tag or @sha256 digest.",
                            "D3-SPP",
                            &format!("l{line_no}-img"),
                            now,
                        ));
                    }
                    stages.push(StageState {
                        start_line: line_no,
                        image: image.clone(),
                        last_user: None,
                    });
                }
                if let Some(a) = alias {
                    stage_aliases.insert(a.to_ascii_lowercase());
                }
            }
            "USER" => {
                if let Some(stage) = stages.last_mut() {
                    let user_token = rest.split_whitespace().next().unwrap_or("").trim();
                    if !user_token.is_empty() {
                        stage.last_user = Some(user_token.to_string());
                    }
                }
            }
            "ENV" | "ARG" => {
                for (key, val) in parse_env_or_arg_pairs(rest) {
                    if is_secret_key(&key) && is_literal_secret_value(&val) {
                        let mut ev = Map::new();
                        ev.insert("instruction".to_string(), json!(instr));
                        ev.insert("variable_key".to_string(), json!(key));
                        ev.insert("line".to_string(), json!(line_no));
                        ev.insert("cis_ref".to_string(), json!("CIS Docker 4.10"));
                        findings.push(docker_finding(
                            "HOST-205",
                            Severity::High,
                            "Hardcoded secret literal in container environment",
                            format!(
                                "Dockerfile {} sets a literal value for sensitive key '{}' on line {} (value redacted).",
                                instr, key, line_no
                            ),
                            &target,
                            ev,
                            "Remove literal secrets from Dockerfile; pass credentials at runtime via secret mounts or CI secrets.",
                            "D3-SM",
                            &format!("l{line_no}-{}", sanitize_id_part(&key)),
                            now,
                        ));
                    }
                }
            }
            "ADD" => {
                let lower = rest.to_ascii_lowercase();
                if lower.contains("http://") || lower.contains("https://") {
                    let mut ev = Map::new();
                    ev.insert("line".to_string(), json!(line_no));
                    ev.insert("instruction".to_string(), json!("ADD"));
                    ev.insert("cis_ref".to_string(), json!("CIS Docker 4.9"));
                    findings.push(docker_finding(
                        "HOST-206",
                        Severity::Medium,
                        "Unverified remote artifact fetch in Dockerfile",
                        format!(
                            "Dockerfile uses remote ADD URL on line {} without checksum verification.",
                            line_no
                        ),
                        &target,
                        ev,
                        "Prefer COPY from a verified build stage or download with explicit SHA-256 verification.",
                        "D3-SPP",
                        &format!("l{line_no}-add"),
                        now,
                    ));
                }
            }
            "RUN" => {
                if has_pipe_to_shell(rest) {
                    let mut ev = Map::new();
                    ev.insert("line".to_string(), json!(line_no));
                    ev.insert("instruction".to_string(), json!("RUN"));
                    ev.insert("cis_ref".to_string(), json!("CIS Docker 4.9"));
                    findings.push(docker_finding(
                        "HOST-206",
                        Severity::Medium,
                        "Unverified remote artifact fetch in Dockerfile",
                        format!(
                            "Dockerfile pipes curl/wget output directly into a shell on line {}.",
                            line_no
                        ),
                        &target,
                        ev,
                        "Download remote scripts first, verify SHA-256 checksums, and avoid piping directly to sh/bash.",
                        "D3-SPP",
                        &format!("l{line_no}-run"),
                        now,
                    ));
                }
            }
            _ => {}
        }
    }

    if let Some(final_stage) = stages.last() {
        let runs_as_root = match &final_stage.last_user {
            None => true,
            Some(user) => is_root_user(user),
        };
        if runs_as_root {
            let mut ev = Map::new();
            ev.insert("final_stage_image".to_string(), json!(final_stage.image));
            ev.insert(
                "final_stage_line".to_string(),
                json!(final_stage.start_line),
            );
            ev.insert(
                "configured_user".to_string(),
                json!(final_stage.last_user.as_deref().unwrap_or("<none>")),
            );
            ev.insert("cis_ref".to_string(), json!("CIS Docker 4.1"));
            findings.push(docker_finding(
                "HOST-201",
                Severity::High,
                "Container configured to run as root",
                format!(
                    "Final Dockerfile stage ({}) runs as root (configured USER: {}).",
                    final_stage.image,
                    final_stage.last_user.as_deref().unwrap_or("none")
                ),
                &target,
                ev,
                "Add a dedicated non-root USER instruction (e.g., USER nonroot or UID >= 1000) in the final stage.",
                "D3-LPM",
                "final-user",
                now,
            ));
        }
    }

    findings
}

pub fn audit_compose(content: &str, source_label: &str) -> Result<Vec<Finding>, String> {
    let doc: Value = serde_yaml_ng::from_str(content)
        .map_err(|e| format!("parse compose YAML {:?}: {e}", source_label))?;

    let now = Utc::now();
    let mut findings = Vec::new();

    let Some(services) = doc.get("services").and_then(|v| v.as_mapping()) else {
        return Ok(findings);
    };

    for (svc_key, svc_val) in services {
        let Some(svc_name) = svc_key.as_str() else {
            continue;
        };
        let Some(svc) = svc_val.as_mapping() else {
            continue;
        };
        let svc_target = format!("compose://{source_label}#services.{svc_name}");

        if let Some(user_val) = mapping_str(svc, "user") {
            if is_root_user(&user_val) {
                let mut ev = Map::new();
                ev.insert("service".to_string(), json!(svc_name));
                ev.insert("user".to_string(), json!(user_val));
                ev.insert("cis_ref".to_string(), json!("CIS Docker 4.1"));
                findings.push(docker_finding(
                    "HOST-201",
                    Severity::High,
                    "Container configured to run as root",
                    format!("Compose service '{svc_name}' explicitly configures root user '{user_val}'."),
                    &svc_target,
                    ev,
                    "Run the service under an explicit non-root UID/GID.",
                    "D3-LPM",
                    &format!("{svc_name}-user"),
                    now,
                ));
            }
        }

        let is_privileged = svc
            .get(Value::String("privileged".to_string()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if is_privileged {
            let mut ev = Map::new();
            ev.insert("service".to_string(), json!(svc_name));
            ev.insert("privileged".to_string(), json!(true));
            ev.insert("cis_ref".to_string(), json!("CIS Docker 5.4"));
            findings.push(docker_finding(
                "HOST-202",
                Severity::Critical,
                "Privileged container or Docker socket mount",
                format!("Compose service '{svc_name}' runs with privileged: true."),
                &svc_target,
                ev,
                "Remove privileged: true and grant only minimal required Linux capabilities.",
                "D3-LPM",
                &format!("{svc_name}-priv"),
                now,
            ));
        }

        if let Some(vols) = svc
            .get(Value::String("volumes".to_string()))
            .and_then(|v| v.as_sequence())
        {
            for vol in vols {
                let vol_str = match vol {
                    Value::String(s) => s.as_str(),
                    Value::Mapping(m) => m
                        .get(Value::String("source".to_string()))
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    _ => "",
                };
                if vol_str.contains("docker.sock") {
                    let mut ev = Map::new();
                    ev.insert("service".to_string(), json!(svc_name));
                    ev.insert("volume".to_string(), json!(vol_str));
                    ev.insert("cis_ref".to_string(), json!("CIS Docker 5.31"));
                    findings.push(docker_finding(
                        "HOST-202",
                        Severity::Critical,
                        "Privileged container or Docker socket mount",
                        format!(
                            "Compose service '{svc_name}' mounts Docker daemon socket ({vol_str}), granting root-equivalent host control."
                        ),
                        &svc_target,
                        ev,
                        "Remove the docker.sock bind mount or isolate access behind a restricted socket proxy.",
                        "D3-LPM",
                        &format!("{svc_name}-sock"),
                        now,
                    ));
                }
            }
        }

        if let Some(net_mode) = mapping_str(svc, "network_mode") {
            if net_mode.eq_ignore_ascii_case("host") {
                let mut ev = Map::new();
                ev.insert("service".to_string(), json!(svc_name));
                ev.insert("network_mode".to_string(), json!(net_mode));
                ev.insert("cis_ref".to_string(), json!("CIS Docker 5.9"));
                findings.push(docker_finding(
                    "HOST-203",
                    Severity::High,
                    "Host namespace sharing or dangerous Linux capabilities",
                    format!("Compose service '{svc_name}' shares the host network namespace."),
                    &svc_target,
                    ev,
                    "Use an isolated bridge network and publish only required ports.",
                    "D3-NI",
                    &format!("{svc_name}-nethost"),
                    now,
                ));
            }
        }

        if let Some(pid_mode) = mapping_str(svc, "pid") {
            if pid_mode.eq_ignore_ascii_case("host") {
                let mut ev = Map::new();
                ev.insert("service".to_string(), json!(svc_name));
                ev.insert("pid".to_string(), json!(pid_mode));
                ev.insert("cis_ref".to_string(), json!("CIS Docker 5.15"));
                findings.push(docker_finding(
                    "HOST-203",
                    Severity::High,
                    "Host namespace sharing or dangerous Linux capabilities",
                    format!("Compose service '{svc_name}' shares the host PID namespace."),
                    &svc_target,
                    ev,
                    "Remove pid: host unless host process tracing is strictly required.",
                    "D3-NI",
                    &format!("{svc_name}-pidhost"),
                    now,
                ));
            }
        }

        if let Some(caps) = svc
            .get(Value::String("cap_add".to_string()))
            .and_then(|v| v.as_sequence())
        {
            for cap in caps {
                if let Some(cap_name) = cap.as_str() {
                    let upper = cap_name.trim().to_ascii_uppercase();
                    if upper == "SYS_ADMIN" || upper == "ALL" || upper == "CAP_SYS_ADMIN" {
                        let mut ev = Map::new();
                        ev.insert("service".to_string(), json!(svc_name));
                        ev.insert("capability".to_string(), json!(upper));
                        ev.insert("cis_ref".to_string(), json!("CIS Docker 5.3"));
                        findings.push(docker_finding(
                            "HOST-203",
                            Severity::High,
                            "Host namespace sharing or dangerous Linux capabilities",
                            format!("Compose service '{svc_name}' adds dangerous Linux capability {upper}."),
                            &svc_target,
                            ev,
                            "Drop ALL capabilities by default and avoid granting SYS_ADMIN or ALL.",
                            "D3-NI",
                            &format!("{svc_name}-cap-{}", sanitize_id_part(&upper)),
                            now,
                        ));
                    }
                }
            }
        }

        if let Some(img) = mapping_str(svc, "image") {
            if is_unpinned_image(&img) {
                let mut ev = Map::new();
                ev.insert("service".to_string(), json!(svc_name));
                ev.insert("image".to_string(), json!(img));
                ev.insert("cis_ref".to_string(), json!("CIS Docker 4.7"));
                findings.push(docker_finding(
                    "HOST-204",
                    Severity::Medium,
                    "Unpinned or :latest container image tag",
                    format!("Compose service '{svc_name}' uses unpinned image '{img}'."),
                    &svc_target,
                    ev,
                    "Pin service images to an explicit release tag or @sha256 digest.",
                    "D3-SPP",
                    &format!("{svc_name}-img"),
                    now,
                ));
            }
        }

        if let Some(env_val) = svc.get(Value::String("environment".to_string())) {
            for (k, v) in extract_compose_env(env_val) {
                if is_secret_key(&k) && is_literal_secret_value(&v) {
                    let mut ev = Map::new();
                    ev.insert("service".to_string(), json!(svc_name));
                    ev.insert("variable_key".to_string(), json!(k));
                    ev.insert("cis_ref".to_string(), json!("CIS Docker 4.10"));
                    findings.push(docker_finding(
                        "HOST-205",
                        Severity::High,
                        "Hardcoded secret literal in container environment",
                        format!(
                            "Compose service '{svc_name}' sets a hardcoded credential literal for '{k}' (value redacted)."
                        ),
                        &svc_target,
                        ev,
                        "Replace literal credentials with ${ENV_VAR} interpolation or Compose secrets.",
                        "D3-SM",
                        &format!("{svc_name}-env-{}", sanitize_id_part(&k)),
                        now,
                    ));
                }
            }
        }
    }

    Ok(findings)
}

fn join_dockerfile_continuations(content: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut start_line = 0usize;

    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim();
        if current.is_empty() && (trimmed.is_empty() || trimmed.starts_with('#')) {
            continue;
        }
        if current.is_empty() {
            start_line = line_no;
        }
        if let Some(prefix) = trimmed.strip_suffix('\\') {
            current.push_str(prefix.trim_end());
            current.push(' ');
        } else {
            current.push_str(trimmed);
            out.push((start_line, std::mem::take(&mut current)));
        }
    }
    if !current.trim().is_empty() {
        out.push((start_line, current));
    }
    out
}

fn parse_from_clause(rest: &str) -> (String, Option<String>) {
    let tokens: Vec<&str> = rest
        .split_whitespace()
        .filter(|t| !t.starts_with("--"))
        .collect();
    if tokens.is_empty() {
        return (String::new(), None);
    }
    let image = tokens[0].to_string();
    let alias = if tokens.len() >= 3 && tokens[1].eq_ignore_ascii_case("AS") {
        Some(tokens[2].to_string())
    } else {
        None
    };
    (image, alias)
}

fn is_unpinned_image(image: &str) -> bool {
    if image.contains("@sha256:") {
        return false;
    }
    let last_segment = image.rsplit('/').next().unwrap_or(image);
    match last_segment.split_once(':') {
        None => true,
        Some((_, tag)) => tag.is_empty() || tag.eq_ignore_ascii_case("latest"),
    }
}

fn is_root_user(user: &str) -> bool {
    let primary = user.split(':').next().unwrap_or(user).trim();
    primary == "0" || primary.eq_ignore_ascii_case("root")
}

fn parse_env_or_arg_pairs(rest: &str) -> Vec<(String, String)> {
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.contains('=') {
        let mut pairs = Vec::new();
        for tok in trimmed.split_whitespace() {
            if let Some((k, v)) = tok.split_once('=') {
                pairs.push((k.trim().to_string(), unquote(v.trim())));
            }
        }
        return pairs;
    }
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let key = parts.next().unwrap_or("").trim().to_string();
    let val = unquote(parts.next().unwrap_or("").trim());
    if key.is_empty() {
        Vec::new()
    } else {
        vec![(key, val)]
    }
}

fn extract_compose_env(val: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    match val {
        Value::Mapping(m) => {
            for (k, v) in m {
                let Some(key) = k.as_str() else {
                    continue;
                };
                let val_str = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => String::new(),
                };
                out.push((key.to_string(), val_str));
            }
        }
        Value::Sequence(seq) => {
            for item in seq {
                if let Some(s) = item.as_str() {
                    if let Some((k, v)) = s.split_once('=') {
                        out.push((k.trim().to_string(), unquote(v.trim())));
                    }
                }
            }
        }
        _ => {}
    }
    out
}

fn is_secret_key(key: &str) -> bool {
    let u = key.to_ascii_uppercase();
    u.contains("PASSWORD")
        || u.contains("PASSWD")
        || u.contains("SECRET")
        || u.contains("API_KEY")
        || u.contains("APIKEY")
        || u.contains("ACCESS_KEY")
        || u.contains("PRIVATE_KEY")
        || u.ends_with("_TOKEN")
        || u == "TOKEN"
}

fn is_literal_secret_value(val: &str) -> bool {
    let v = val.trim();
    !v.is_empty() && !v.starts_with('$')
}

fn has_pipe_to_shell(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    let has_fetcher = lower.contains("curl ") || lower.contains("wget ");
    if !has_fetcher || !lower.contains('|') {
        return false;
    }
    lower.split('|').skip(1).any(|rhs| {
        let first = rhs.split_whitespace().next().unwrap_or("");
        matches!(
            first,
            "sh" | "bash" | "ash" | "zsh" | "/bin/sh" | "/bin/bash"
        )
    })
}

fn mapping_str(m: &serde_yaml_ng::Mapping, key: &str) -> Option<String> {
    m.get(Value::String(key.to_string())).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn unquote(s: &str) -> String {
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[allow(clippy::too_many_arguments)]
fn docker_finding(
    rule_id: &str,
    severity: Severity,
    title: &str,
    description: String,
    target: &str,
    evidence: Map<String, JsonValue>,
    remediation: &str,
    mitre_d3fend: &str,
    id_suffix: &str,
    timestamp: chrono::DateTime<Utc>,
) -> Finding {
    Finding {
        id: format!("{}-{}", rule_id.to_ascii_lowercase(), id_suffix),
        rule_id: rule_id.to_string(),
        module: MODULE_DOCKER.to_string(),
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

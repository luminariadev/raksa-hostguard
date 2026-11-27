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

    if is_daemon_json_name(&fname) {
        audit_daemon_json(&content, &label)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    } else if is_podman_conf_name(&fname) {
        Ok(audit_podman_conf(&content, &label))
    } else if fname.ends_with(".yml") || fname.ends_with(".yaml") {
        audit_compose(&content, &label).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    } else {
        Ok(audit_dockerfile(&content, &label))
    }
}

fn is_daemon_json_name(lower_name: &str) -> bool {
    lower_name == "daemon.json"
        || lower_name.ends_with(".daemon.json")
        || (lower_name.starts_with("daemon.") && lower_name.ends_with(".json"))
}

fn is_podman_conf_name(lower_name: &str) -> bool {
    lower_name == "containers.conf" || lower_name.ends_with(".containers.conf")
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
        || is_daemon_json_name(&fname)
        || is_podman_conf_name(&fname)
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
            "RUN" if has_pipe_to_shell(rest) => {
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
                } else if let Some(sensitive_src) = sensitive_host_bind_source(vol) {
                    let mut ev = Map::new();
                    ev.insert("service".to_string(), json!(svc_name));
                    ev.insert("host_source".to_string(), json!(sensitive_src));
                    ev.insert("cis_ref".to_string(), json!("CIS Docker 5.5"));
                    findings.push(docker_finding(
                        "HOST-208",
                        Severity::Medium,
                        "Compose service omits cap_drop ALL or binds sensitive host path",
                        format!(
                            "Compose service '{svc_name}' bind-mounts sensitive host path '{sensitive_src}'."
                        ),
                        &svc_target,
                        ev,
                        "Avoid mounting sensitive host OS directories into containers; use scoped data volumes instead.",
                        "D3-NI",
                        &format!("{svc_name}-vol-{}", sanitize_id_part(&sensitive_src)),
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

        let sec_opts: Vec<String> = svc
            .get(Value::String("security_opt".to_string()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|item| item.as_str().map(|s| s.trim().to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let has_no_new_privs = sec_opts.iter().any(|opt| {
            let low = opt.to_ascii_lowercase();
            low == "no-new-privileges"
                || low == "no-new-privileges:true"
                || low == "no-new-privileges=true"
        });
        if !has_no_new_privs {
            let mut ev = Map::new();
            ev.insert("service".to_string(), json!(svc_name));
            ev.insert("missing".to_string(), json!("no-new-privileges:true"));
            ev.insert("cis_ref".to_string(), json!("CIS Docker 5.25"));
            findings.push(docker_finding(
                "HOST-207",
                Severity::Medium,
                "Compose service missing no-new-privileges hardening",
                format!(
                    "Compose service '{svc_name}' does not set security_opt: [no-new-privileges:true]."
                ),
                &svc_target,
                ev,
                "Add security_opt: ['no-new-privileges:true'] to block privilege escalation via setuid binaries.",
                "D3-LPM",
                &format!("{svc_name}-nonewpriv"),
                now,
            ));
        }

        for opt in &sec_opts {
            let low = opt.to_ascii_lowercase();
            if low.contains("seccomp:unconfined")
                || low.contains("seccomp=unconfined")
                || low.contains("apparmor:unconfined")
                || low.contains("apparmor=unconfined")
            {
                let mut ev = Map::new();
                ev.insert("service".to_string(), json!(svc_name));
                ev.insert("security_opt".to_string(), json!(opt));
                ev.insert("cis_ref".to_string(), json!("CIS Docker 5.1 / 5.21"));
                findings.push(docker_finding(
                    "HOST-209",
                    Severity::High,
                    "Container disables Seccomp/AppArmor or exposes sensitive port publicly",
                    format!("Compose service '{svc_name}' disables kernel sandboxing via '{opt}'."),
                    &svc_target,
                    ev,
                    "Remove unconfined seccomp/apparmor overrides and enforce default or custom restrictive profiles.",
                    "D3-NI",
                    &format!("{svc_name}-unconfined"),
                    now,
                ));
            }
        }

        let has_cap_drop_all = svc
            .get(Value::String("cap_drop".to_string()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter().any(|item| {
                    item.as_str()
                        .map(|s| s.trim().eq_ignore_ascii_case("ALL"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        if !has_cap_drop_all {
            let mut ev = Map::new();
            ev.insert("service".to_string(), json!(svc_name));
            ev.insert("missing".to_string(), json!("cap_drop: [ALL]"));
            ev.insert("cis_ref".to_string(), json!("CIS Docker 5.3"));
            findings.push(docker_finding(
                "HOST-208",
                Severity::Medium,
                "Compose service omits cap_drop ALL or binds sensitive host path",
                format!("Compose service '{svc_name}' does not drop ALL Linux capabilities."),
                &svc_target,
                ev,
                "Add cap_drop: [ALL] and re-add only strictly required non-privileged capabilities.",
                "D3-NI",
                &format!("{svc_name}-capdrop"),
                now,
            ));
        }

        if let Some(ports) = svc
            .get(Value::String("ports".to_string()))
            .and_then(|v| v.as_sequence())
        {
            for port_val in ports {
                if let Some((bind_desc, host_port)) = detect_exposed_sensitive_port(port_val) {
                    let mut ev = Map::new();
                    ev.insert("service".to_string(), json!(svc_name));
                    ev.insert("published_port".to_string(), json!(host_port));
                    ev.insert("binding".to_string(), json!(bind_desc));
                    ev.insert("cis_ref".to_string(), json!("CIS Docker 5.13"));
                    findings.push(docker_finding(
                        "HOST-209",
                        Severity::High,
                        "Container disables Seccomp/AppArmor or exposes sensitive port publicly",
                        format!(
                            "Compose service '{svc_name}' publishes sensitive port {host_port} on wildcard interface ({bind_desc})."
                        ),
                        &svc_target,
                        ev,
                        "Bind internal admin/datastore ports to 127.0.0.1 (e.g., 127.0.0.1:6379:6379) or keep them inside private container networks.",
                        "D3-NI",
                        &format!("{svc_name}-port-{host_port}"),
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

fn sensitive_host_bind_source(vol: &Value) -> Option<String> {
    let raw_src = match vol {
        Value::String(s) => s.split(':').next().unwrap_or("").trim().to_string(),
        Value::Mapping(m) => {
            if let Some(kind) = mapping_str(m, "type") {
                if !kind.eq_ignore_ascii_case("bind") {
                    return None;
                }
            }
            mapping_str(m, "source").unwrap_or_default()
        }
        _ => String::new(),
    };
    let clean = raw_src.trim();
    if !clean.starts_with('/') {
        return None;
    }
    let normalized = if clean == "/" {
        "/"
    } else {
        clean.trim_end_matches('/')
    };
    const SENSITIVE_PREFIXES: &[&str] = &["/etc", "/proc", "/sys", "/boot", "/root"];
    if normalized == "/"
        || SENSITIVE_PREFIXES
            .iter()
            .any(|p| normalized == *p || normalized.starts_with(&format!("{p}/")))
    {
        Some(clean.to_string())
    } else {
        None
    }
}

fn is_sensitive_port(port: u16) -> bool {
    matches!(port, 22 | 2375 | 2376 | 3306 | 5432 | 6379 | 27017)
}

fn is_loopback_host(host: &str) -> bool {
    let h = host
        .trim()
        .trim_matches('[')
        .trim_matches(']')
        .to_ascii_lowercase();
    h == "127.0.0.1" || h == "localhost" || h == "::1"
}

fn detect_exposed_sensitive_port(val: &Value) -> Option<(String, u16)> {
    match val {
        Value::String(raw) => {
            let trimmed = raw.trim();
            let without_proto = trimmed.split('/').next().unwrap_or(trimmed);
            let (host_opt, port_str) = if let Some(rest) = without_proto.strip_prefix('[') {
                if let Some((ip, tail)) = rest.split_once("]:") {
                    let hp = tail.split(':').next().unwrap_or("");
                    (Some(ip), hp)
                } else {
                    (None, "")
                }
            } else {
                let parts: Vec<&str> = without_proto.split(':').collect();
                match parts.len() {
                    1 => (None, parts[0]),
                    2 => (None, parts[0]),
                    3 => (Some(parts[0]), parts[1]),
                    _ => (None, ""),
                }
            };

            if host_opt.is_some_and(is_loopback_host) {
                return None;
            }
            let port_num = port_str
                .split('-')
                .next()
                .unwrap_or("")
                .parse::<u16>()
                .ok()?;
            if is_sensitive_port(port_num) {
                Some((trimmed.to_string(), port_num))
            } else {
                None
            }
        }
        Value::Mapping(m) => {
            let host_ip = mapping_str(m, "host_ip").unwrap_or_else(|| "0.0.0.0".to_string());
            if is_loopback_host(&host_ip) {
                return None;
            }
            let published = mapping_str(m, "published")?;
            let port_num = published.parse::<u16>().ok()?;
            if is_sensitive_port(port_num) {
                Some((format!("{host_ip}:{published}"), port_num))
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn audit_daemon_json(content: &str, source_label: &str) -> Result<Vec<Finding>, String> {
    let val: JsonValue = serde_json::from_str(content)
        .map_err(|e| format!("parse daemon JSON {:?}: {e}", source_label))?;
    let Some(obj) = val.as_object() else {
        return Err(format!(
            "daemon JSON {:?} must be a JSON object",
            source_label
        ));
    };

    let now = Utc::now();
    let target = format!("file://{source_label}");
    let mut findings = Vec::new();

    let tlsverify = obj
        .get("tlsverify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if let Some(hosts) = obj.get("hosts").and_then(|v| v.as_array()) {
        for h in hosts {
            if let Some(host_str) = h.as_str() {
                if host_str.trim().to_ascii_lowercase().starts_with("tcp://") && !tlsverify {
                    let mut ev = Map::new();
                    ev.insert("host".to_string(), json!(host_str));
                    ev.insert("tlsverify".to_string(), json!(tlsverify));
                    ev.insert("cis_ref".to_string(), json!("CIS Docker 2.16"));
                    findings.push(docker_finding(
                        "HOST-210",
                        Severity::Critical,
                        "Insecure container runtime daemon configuration",
                        format!(
                            "Docker daemon in {source_label} binds TCP socket '{host_str}' without tlsverify: true."
                        ),
                        &target,
                        ev,
                        "Use unix:// sockets only or enable mutual TLS with tlsverify: true, tlscacert, tlscert, and tlskey.",
                        "D3-CH",
                        "daemon-tcp-notls",
                        now,
                    ));
                }
            }
        }
    }

    if obj.get("icc").and_then(|v| v.as_bool()) != Some(false) {
        let mut ev = Map::new();
        ev.insert("setting".to_string(), json!("icc"));
        ev.insert(
            "observed".to_string(),
            obj.get("icc").cloned().unwrap_or(JsonValue::Null),
        );
        ev.insert("cis_ref".to_string(), json!("CIS Docker 2.1"));
        findings.push(docker_finding(
            "HOST-210",
            Severity::High,
            "Insecure container runtime daemon configuration",
            format!(
                "Docker daemon in {source_label} allows unrestricted inter-container communication (expected \"icc\": false)."
            ),
            &target,
            ev,
            "Set \"icc\": false in daemon.json and use explicit user-defined bridge networks.",
            "D3-CH",
            "daemon-icc",
            now,
        ));
    }

    if obj.get("no-new-privileges").and_then(|v| v.as_bool()) != Some(true) {
        let mut ev = Map::new();
        ev.insert("setting".to_string(), json!("no-new-privileges"));
        ev.insert("cis_ref".to_string(), json!("CIS Docker 2.15"));
        findings.push(docker_finding(
            "HOST-210",
            Severity::High,
            "Insecure container runtime daemon configuration",
            format!(
                "Docker daemon in {source_label} does not enforce \"no-new-privileges\": true."
            ),
            &target,
            ev,
            "Set \"no-new-privileges\": true in daemon.json to block setuid escalation across containers.",
            "D3-CH",
            "daemon-nonewpriv",
            now,
        ));
    }

    let has_userns = obj
        .get("userns-remap")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty());
    if !has_userns {
        let mut ev = Map::new();
        ev.insert("setting".to_string(), json!("userns-remap"));
        ev.insert("cis_ref".to_string(), json!("CIS Docker 2.8"));
        findings.push(docker_finding(
            "HOST-210",
            Severity::Medium,
            "Insecure container runtime daemon configuration",
            format!(
                "Docker daemon in {source_label} omits \"userns-remap\" user namespace isolation."
            ),
            &target,
            ev,
            "Configure \"userns-remap\": \"default\" in daemon.json.",
            "D3-CH",
            "daemon-userns",
            now,
        ));
    }

    if obj.get("live-restore").and_then(|v| v.as_bool()) != Some(true) {
        let mut ev = Map::new();
        ev.insert("setting".to_string(), json!("live-restore"));
        ev.insert("cis_ref".to_string(), json!("CIS Docker 2.14"));
        findings.push(docker_finding(
            "HOST-210",
            Severity::Low,
            "Insecure container runtime daemon configuration",
            format!("Docker daemon in {source_label} does not enable \"live-restore\": true."),
            &target,
            ev,
            "Set \"live-restore\": true in daemon.json to preserve running containers during daemon upgrades.",
            "D3-CH",
            "daemon-liverestore",
            now,
        ));
    }

    Ok(findings)
}

pub fn audit_podman_conf(content: &str, source_label: &str) -> Vec<Finding> {
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
        let val = unquote(raw_v.trim()).to_ascii_lowercase();

        match key.as_str() {
            "privileged" if val == "true" => {
                let mut ev = Map::new();
                ev.insert("line".to_string(), json!(line_no));
                ev.insert("setting".to_string(), json!("privileged = true"));
                findings.push(docker_finding(
                    "HOST-210",
                    Severity::Critical,
                    "Insecure container runtime daemon configuration",
                    format!(
                        "Podman containers.conf line {line_no} enables default privileged = true."
                    ),
                    &target,
                    ev,
                    "Set privileged = false in containers.conf.",
                    "D3-CH",
                    &format!("podman-l{line_no}-priv"),
                    now,
                ));
            }
            "netns" if val == "host" => {
                let mut ev = Map::new();
                ev.insert("line".to_string(), json!(line_no));
                ev.insert("setting".to_string(), json!("netns = \"host\""));
                findings.push(docker_finding(
                    "HOST-210",
                    Severity::High,
                    "Insecure container runtime daemon configuration",
                    format!("Podman containers.conf line {line_no} sets default netns = \"host\"."),
                    &target,
                    ev,
                    "Remove netns = \"host\" or default to bridge/pasta network isolation.",
                    "D3-CH",
                    &format!("podman-l{line_no}-netns"),
                    now,
                ));
            }
            "no_new_privileges" if val == "false" => {
                let mut ev = Map::new();
                ev.insert("line".to_string(), json!(line_no));
                ev.insert("setting".to_string(), json!("no_new_privileges = false"));
                findings.push(docker_finding(
                    "HOST-210",
                    Severity::High,
                    "Insecure container runtime daemon configuration",
                    format!(
                        "Podman containers.conf line {line_no} sets no_new_privileges = false."
                    ),
                    &target,
                    ev,
                    "Set no_new_privileges = true in containers.conf.",
                    "D3-CH",
                    &format!("podman-l{line_no}-nnp"),
                    now,
                ));
            }
            _ => {}
        }
    }

    findings
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

use crate::audit::audit_workspace;
use crate::audit::docker::{audit_compose, audit_docker_path, audit_dockerfile};
use crate::audit::host::{
    audit_host_permissions_path, audit_sudoers_content, audit_sudoers_path, audit_sysctl_content,
    audit_sysctl_path,
};
use crate::audit::ssh::{audit_sshd_config, audit_sshd_file};
use crate::audit::MAX_CONFIG_BYTES;
use crate::fim::hash::DEFAULT_MAX_FILE_BYTES;
use crate::fim::{
    create_snapshot_with_workers, default_worker_count, load_snapshot, save_snapshot,
    sign_snapshot, verify_snapshot_signed,
};
use crate::policy::{apply_policy, load_policy};
use crate::schema::catalog::rule_catalog;
use crate::schema::{Finding, Report};
use chrono::Utc;
use serde_json::{json, Map, Value};
use std::io::{self, BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
const MAX_RPC_LINE_BYTES: usize = 2 * 1024 * 1024;

pub fn serve_stdio() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let reader = stdin.lock();
    let writer = BufWriter::new(stdout.lock());
    serve_streams(reader, writer)
}

pub fn serve_streams<R: BufRead, W: Write>(mut reader: R, mut writer: W) -> io::Result<()> {
    while let Some(line) = read_bounded_line(&mut reader, MAX_RPC_LINE_BYTES)? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Value>(trimmed) {
            Ok(req) => handle_request(&req),
            Err(err) => Some(rpc_error(
                Value::Null,
                -32700,
                &format!("Parse error: {err}"),
            )),
        };

        if let Some(resp) = response {
            let encoded = serde_json::to_string(&resp)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            writer.write_all(encoded.as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }

    Ok(())
}

fn read_bounded_line<R: BufRead>(reader: &mut R, max_bytes: usize) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }

        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            if buf.len() + pos + 1 > max_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("JSON-RPC message exceeds {max_bytes} byte limit"),
                ));
            }
            buf.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            break;
        } else {
            if buf.len() + available.len() > max_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("JSON-RPC message exceeds {max_bytes} byte limit"),
                ));
            }
            buf.extend_from_slice(available);
            let consumed = available.len();
            reader.consume(consumed);
        }
    }

    String::from_utf8(buf)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn handle_request(req: &Value) -> Option<Value> {
    let Some(obj) = req.as_object() else {
        return Some(rpc_error(
            Value::Null,
            -32600,
            "Invalid Request: expected JSON object",
        ));
    };

    let id = obj.get("id").cloned();
    if obj.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return id
            .or(Some(Value::Null))
            .map(|req_id| rpc_error(req_id, -32600, "Invalid Request: jsonrpc must be '2.0'"));
    }

    let Some(method) = obj.get("method").and_then(|v| v.as_str()) else {
        return Some(rpc_error(
            id.unwrap_or(Value::Null),
            -32600,
            "Invalid Request: missing string method",
        ));
    };

    // Notifications omit id and do not receive a JSON-RPC response.
    let req_id = id?;

    let params = obj
        .get("params")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    match method {
        "initialize" => Some(rpc_result(
            req_id,
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {
                        "listChanged": false
                    }
                },
                "serverInfo": {
                    "name": crate::schema::TOOL_NAME,
                    "version": crate::VERSION
                }
            }),
        )),
        "ping" => Some(rpc_result(req_id, json!({}))),
        "tools/list" => Some(rpc_result(req_id, json!({ "tools": tool_definitions() }))),
        "tools/call" => Some(handle_tool_call(req_id, &params)),
        other => Some(rpc_error(
            req_id,
            -32601,
            &format!("Method not found: {other}"),
        )),
    }
}

fn handle_tool_call(req_id: Value, params: &Map<String, Value>) -> Value {
    let Some(tool_name) = params.get("name").and_then(|v| v.as_str()) else {
        return rpc_error(req_id, -32602, "Invalid params: missing tool 'name'");
    };
    let args = params
        .get("arguments")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    match tool_name {
        "hostguard_list_rules" => match serde_json::to_string_pretty(&rule_catalog()) {
            Ok(txt) => rpc_result(req_id, tool_ok(&txt)),
            Err(err) => rpc_result(req_id, tool_err(&format!("failed to encode rules: {err}"))),
        },
        "hostguard_fim_snapshot" => call_fim_snapshot(req_id, &args),
        "hostguard_fim_check" => call_fim_check(req_id, &args),
        "hostguard_audit_ssh" => call_audit_ssh(req_id, &args),
        "hostguard_audit_docker" => call_audit_docker(req_id, &args),
        "hostguard_audit_host" => call_audit_host(req_id, &args),
        "hostguard_audit_workspace" => call_audit_workspace(req_id, &args),
        unknown => rpc_error(req_id, -32602, &format!("Unknown tool: {unknown}")),
    }
}

fn call_fim_snapshot(req_id: Value, args: &Map<String, Value>) -> Value {
    let Some(paths_val) = args.get("paths").and_then(|v| v.as_array()) else {
        return rpc_error(
            req_id,
            -32602,
            "Invalid params: 'paths' must be a non-empty array of strings",
        );
    };

    let mut roots = Vec::with_capacity(paths_val.len());
    for item in paths_val {
        let Some(s) = item.as_str() else {
            return rpc_error(
                req_id,
                -32602,
                "Invalid params: every item in 'paths' must be a string",
            );
        };
        roots.push(PathBuf::from(s));
    }
    if roots.is_empty() {
        return rpc_error(
            req_id,
            -32602,
            "Invalid params: 'paths' array cannot be empty",
        );
    }

    let Some(baseline_out) = args.get("baseline_out").and_then(|v| v.as_str()) else {
        return rpc_error(
            req_id,
            -32602,
            "Invalid params: missing string 'baseline_out'",
        );
    };

    let mut excludes = Vec::new();
    if let Some(exc_val) = args.get("exclude") {
        let Some(arr) = exc_val.as_array() else {
            return rpc_error(
                req_id,
                -32602,
                "Invalid params: 'exclude' must be an array of strings",
            );
        };
        for item in arr {
            let Some(s) = item.as_str() else {
                return rpc_error(
                    req_id,
                    -32602,
                    "Invalid params: every item in 'exclude' must be a string",
                );
            };
            excludes.push(s.to_string());
        }
    }

    let max_file_bytes = match args.get("max_file_bytes") {
        None => DEFAULT_MAX_FILE_BYTES,
        Some(v) => match v.as_u64() {
            Some(n) => n,
            None => {
                return rpc_error(
                    req_id,
                    -32602,
                    "Invalid params: 'max_file_bytes' must be a non-negative integer",
                )
            }
        },
    };

    let workers = match parse_workers_arg(args) {
        Ok(w) => w,
        Err(msg) => return rpc_error(req_id, -32602, &msg),
    };

    let sign_key = match read_sign_key_env(args) {
        Ok(k) => k,
        Err(McpKeyError::InvalidParam(msg)) => return rpc_error(req_id, -32602, &msg),
        Err(McpKeyError::Runtime(msg)) => return rpc_result(req_id, tool_err(&msg)),
    };

    match create_snapshot_with_workers(&roots, &excludes, max_file_bytes, workers) {
        Ok((mut snapshot, stats)) => {
            if let Some(key) = &sign_key {
                if let Err(err) = sign_snapshot(&mut snapshot, key) {
                    return rpc_result(
                        req_id,
                        tool_err(&format!("failed to sign snapshot: {err}")),
                    );
                }
            }
            if let Err(err) = save_snapshot(Path::new(baseline_out), &snapshot) {
                return rpc_result(req_id, tool_err(&format!("failed to save snapshot: {err}")));
            }
            let total_bytes: u64 = snapshot.entries.values().map(|e| e.size).sum();
            let payload = json!({
                "status": "created",
                "baseline_out": baseline_out,
                "signed": sign_key.is_some(),
                "files_hashed": stats.files_hashed,
                "files_skipped_oversize": stats.files_skipped_oversize,
                "files_skipped_error": stats.files_skipped_error,
                "total_bytes": total_bytes,
                "created_at": snapshot.created_at
            });
            rpc_result(
                req_id,
                tool_ok(&serde_json::to_string_pretty(&payload).unwrap_or_default()),
            )
        }
        Err(err) => rpc_result(
            req_id,
            tool_err(&format!("failed to create FIM snapshot: {err}")),
        ),
    }
}

fn call_fim_check(req_id: Value, args: &Map<String, Value>) -> Value {
    let Some(baseline_path) = args.get("baseline_path").and_then(|v| v.as_str()) else {
        return rpc_error(
            req_id,
            -32602,
            "Invalid params: missing string 'baseline_path'",
        );
    };

    let workers = match parse_workers_arg(args) {
        Ok(w) => w,
        Err(msg) => return rpc_error(req_id, -32602, &msg),
    };

    let sign_key = match read_sign_key_env(args) {
        Ok(k) => k,
        Err(McpKeyError::InvalidParam(msg)) => return rpc_error(req_id, -32602, &msg),
        Err(McpKeyError::Runtime(msg)) => return rpc_result(req_id, tool_err(&msg)),
    };

    let snapshot = match load_snapshot(Path::new(baseline_path)) {
        Ok(s) => s,
        Err(err) => {
            return rpc_result(
                req_id,
                tool_err(&format!("failed to load baseline '{baseline_path}': {err}")),
            )
        }
    };

    match verify_snapshot_signed(&snapshot, sign_key.as_deref(), workers) {
        Ok(findings) => {
            let filtered = match maybe_apply_policy(findings, args) {
                Ok(f) => f,
                Err(McpKeyError::InvalidParam(msg)) => return rpc_error(req_id, -32602, &msg),
                Err(McpKeyError::Runtime(msg)) => return rpc_result(req_id, tool_err(&msg)),
            };
            let report = Report::new(filtered, Utc::now());
            rpc_result(
                req_id,
                tool_ok(&serde_json::to_string_pretty(&report).unwrap_or_default()),
            )
        }
        Err(err) => rpc_result(
            req_id,
            tool_err(&format!("failed to verify baseline: {err}")),
        ),
    }
}

fn call_audit_ssh(req_id: Value, args: &Map<String, Value>) -> Value {
    let path_opt = args.get("path").and_then(|v| v.as_str());
    let content_opt = args.get("content").and_then(|v| v.as_str());
    let label = args
        .get("source_label")
        .and_then(|v| v.as_str())
        .unwrap_or("inline:sshd_config");

    let findings = match (path_opt, content_opt) {
        (Some(p), None) => match audit_sshd_file(Path::new(p)) {
            Ok(f) => f,
            Err(err) => {
                return rpc_result(
                    req_id,
                    tool_err(&format!("failed to audit sshd file '{p}': {err}")),
                )
            }
        },
        (None, Some(c)) => {
            if c.len() > MAX_CONFIG_BYTES {
                return rpc_error(
                    req_id,
                    -32602,
                    &format!("Invalid params: 'content' exceeds {MAX_CONFIG_BYTES} byte limit"),
                );
            }
            audit_sshd_config(c, label)
        }
        _ => {
            return rpc_error(
                req_id,
                -32602,
                "Invalid params: provide exactly one of 'path' or 'content'",
            )
        }
    };

    let report = Report::new(findings, Utc::now());
    rpc_result(
        req_id,
        tool_ok(&serde_json::to_string_pretty(&report).unwrap_or_default()),
    )
}

fn call_audit_docker(req_id: Value, args: &Map<String, Value>) -> Value {
    let path_opt = args.get("path").and_then(|v| v.as_str());
    let content_opt = args.get("content").and_then(|v| v.as_str());
    let kind = args
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("dockerfile");
    let label = args
        .get("source_label")
        .and_then(|v| v.as_str())
        .unwrap_or("inline:docker");

    let findings = match (path_opt, content_opt) {
        (Some(p), None) => match audit_docker_path(Path::new(p)) {
            Ok(f) => f,
            Err(err) => {
                return rpc_result(
                    req_id,
                    tool_err(&format!("failed to audit docker path '{p}': {err}")),
                )
            }
        },
        (None, Some(c)) => {
            if c.len() > MAX_CONFIG_BYTES {
                return rpc_error(
                    req_id,
                    -32602,
                    &format!("Invalid params: 'content' exceeds {MAX_CONFIG_BYTES} byte limit"),
                );
            }
            match kind.trim().to_ascii_lowercase().as_str() {
                "dockerfile" => audit_dockerfile(c, label),
                "compose" | "docker-compose" => match audit_compose(c, label) {
                    Ok(f) => f,
                    Err(err) => {
                        return rpc_result(
                            req_id,
                            tool_err(&format!("invalid docker-compose YAML: {err}")),
                        )
                    }
                },
                other => {
                    return rpc_error(
                        req_id,
                        -32602,
                        &format!("Invalid params: unsupported kind '{other}' (expected dockerfile or compose)"),
                    )
                }
            }
        }
        _ => {
            return rpc_error(
                req_id,
                -32602,
                "Invalid params: provide exactly one of 'path' or 'content'",
            )
        }
    };

    let report = Report::new(findings, Utc::now());
    rpc_result(
        req_id,
        tool_ok(&serde_json::to_string_pretty(&report).unwrap_or_default()),
    )
}

enum McpKeyError {
    InvalidParam(String),
    Runtime(String),
}

fn parse_workers_arg(args: &Map<String, Value>) -> Result<usize, String> {
    match args.get("workers") {
        None => Ok(default_worker_count()),
        Some(v) => v
            .as_u64()
            .filter(|&n| n >= 1)
            .map(|n| n as usize)
            .ok_or_else(|| "Invalid params: 'workers' must be an integer >= 1".to_string()),
    }
}

fn read_sign_key_env(args: &Map<String, Value>) -> Result<Option<Vec<u8>>, McpKeyError> {
    let Some(val) = args.get("sign_key_env") else {
        return Ok(None);
    };
    let Some(var_name) = val.as_str().map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(McpKeyError::InvalidParam(
            "Invalid params: 'sign_key_env' must be a non-empty environment variable name"
                .to_string(),
        ));
    };
    let secret = std::env::var(var_name).map_err(|_| {
        McpKeyError::Runtime(format!(
            "signing key environment variable '{var_name}' is not set"
        ))
    })?;
    if secret.is_empty() {
        return Err(McpKeyError::Runtime(format!(
            "signing key environment variable '{var_name}' is empty"
        )));
    }
    Ok(Some(secret.into_bytes()))
}

fn maybe_apply_policy(
    findings: Vec<Finding>,
    args: &Map<String, Value>,
) -> Result<Vec<Finding>, McpKeyError> {
    let Some(val) = args.get("policy_path") else {
        return Ok(findings);
    };
    let Some(path_str) = val.as_str().map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(McpKeyError::InvalidParam(
            "Invalid params: 'policy_path' must be a non-empty string path".to_string(),
        ));
    };
    let policy = load_policy(Path::new(path_str)).map_err(McpKeyError::Runtime)?;
    Ok(apply_policy(findings, &policy, Utc::now().date_naive()).0)
}

fn call_audit_host(req_id: Value, args: &Map<String, Value>) -> Value {
    let Some(kind_raw) = args.get("kind").and_then(|v| v.as_str()) else {
        return rpc_error(
            req_id,
            -32602,
            "Invalid params: missing string 'kind' (sysctl, sudoers, or permissions)",
        );
    };
    let kind = kind_raw.trim().to_ascii_lowercase();
    let path_opt = args.get("path").and_then(|v| v.as_str());
    let content_opt = args.get("content").and_then(|v| v.as_str());
    let label = args
        .get("source_label")
        .and_then(|v| v.as_str())
        .unwrap_or("inline:host");

    let findings = match (kind.as_str(), path_opt, content_opt) {
        ("sysctl", Some(p), None) => match audit_sysctl_path(Path::new(p)) {
            Ok(f) => f,
            Err(err) => {
                return rpc_result(
                    req_id,
                    tool_err(&format!("failed to audit sysctl '{p}': {err}")),
                )
            }
        },
        ("sysctl", None, Some(c)) => {
            if c.len() > MAX_CONFIG_BYTES {
                return rpc_error(
                    req_id,
                    -32602,
                    &format!("Invalid params: 'content' exceeds {MAX_CONFIG_BYTES} byte limit"),
                );
            }
            audit_sysctl_content(c, label)
        }
        ("sudoers", Some(p), None) => match audit_sudoers_path(Path::new(p)) {
            Ok(f) => f,
            Err(err) => {
                return rpc_result(
                    req_id,
                    tool_err(&format!("failed to audit sudoers '{p}': {err}")),
                )
            }
        },
        ("sudoers", None, Some(c)) => {
            if c.len() > MAX_CONFIG_BYTES {
                return rpc_error(
                    req_id,
                    -32602,
                    &format!("Invalid params: 'content' exceeds {MAX_CONFIG_BYTES} byte limit"),
                );
            }
            audit_sudoers_content(c, label)
        }
        ("permissions", Some(p), None) => match audit_host_permissions_path(Path::new(p)) {
            Ok(f) => f,
            Err(err) => {
                return rpc_result(
                    req_id,
                    tool_err(&format!("failed to audit permissions '{p}': {err}")),
                )
            }
        },
        ("permissions", None, Some(_)) => {
            return rpc_error(
                req_id,
                -32602,
                "Invalid params: kind 'permissions' requires filesystem 'path', not inline 'content'",
            )
        }
        (other, Some(_), Some(_)) | (other, None, None) if matches!(other, "sysctl" | "sudoers" | "permissions") => {
            return rpc_error(
                req_id,
                -32602,
                "Invalid params: provide exactly one of 'path' or 'content'",
            )
        }
        (other, _, _) => {
            return rpc_error(
                req_id,
                -32602,
                &format!("Invalid params: unsupported host kind '{other}' (expected sysctl, sudoers, or permissions)"),
            )
        }
    };

    let filtered = match maybe_apply_policy(findings, args) {
        Ok(f) => f,
        Err(McpKeyError::InvalidParam(msg)) => return rpc_error(req_id, -32602, &msg),
        Err(McpKeyError::Runtime(msg)) => return rpc_result(req_id, tool_err(&msg)),
    };

    let report = Report::new(filtered, Utc::now());
    rpc_result(
        req_id,
        tool_ok(&serde_json::to_string_pretty(&report).unwrap_or_default()),
    )
}

fn call_audit_workspace(req_id: Value, args: &Map<String, Value>) -> Value {
    let Some(path_str) = args.get("path").and_then(|v| v.as_str()) else {
        return rpc_error(req_id, -32602, "Invalid params: missing string 'path'");
    };

    let findings = match audit_workspace(Path::new(path_str)) {
        Ok(f) => f,
        Err(err) => {
            return rpc_result(
                req_id,
                tool_err(&format!("failed to audit workspace '{path_str}': {err}")),
            )
        }
    };

    let filtered = match maybe_apply_policy(findings, args) {
        Ok(f) => f,
        Err(McpKeyError::InvalidParam(msg)) => return rpc_error(req_id, -32602, &msg),
        Err(McpKeyError::Runtime(msg)) => return rpc_result(req_id, tool_err(&msg)),
    };

    let report = Report::new(filtered, Utc::now());
    rpc_result(
        req_id,
        tool_ok(&serde_json::to_string_pretty(&report).unwrap_or_default()),
    )
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "hostguard_list_rules",
            "description": "List all 24 host hardening, FIM, SSH, Docker, and Linux CIS/MITRE D3FEND rules supported by raksa-hostguard.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        },
        {
            "name": "hostguard_fim_snapshot",
            "description": "Create a cryptographic SHA-256 baseline snapshot (optionally HMAC-SHA256 signed via env var) of host files or directories.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of file or directory paths to include in the baseline snapshot."
                    },
                    "baseline_out": {
                        "type": "string",
                        "description": "Output JSON file path where the snapshot structure will be written."
                    },
                    "exclude": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional filename or path substrings to exclude."
                    },
                    "max_file_bytes": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Optional max file size cap in bytes (default 50 MiB; 0 uses default)."
                    },
                    "sign_key_env": {
                        "type": "string",
                        "description": "Optional environment variable name holding the HMAC-SHA256 key to sign the snapshot."
                    },
                    "workers": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Optional parallel worker thread count."
                    }
                },
                "required": ["paths", "baseline_out"],
                "additionalProperties": false
            }
        },
        {
            "name": "hostguard_fim_check",
            "description": "Verify current filesystem state against a saved SHA-256 baseline snapshot (and optional HMAC-SHA256 signature) and report drift.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "baseline_path": {
                        "type": "string",
                        "description": "Path to a baseline JSON file created by hostguard_fim_snapshot."
                    },
                    "sign_key_env": {
                        "type": "string",
                        "description": "Optional environment variable name holding the HMAC-SHA256 verification key."
                    },
                    "workers": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Optional parallel worker thread count."
                    },
                    "policy_path": {
                        "type": "string",
                        "description": "Optional YAML/JSON suppression policy path."
                    }
                },
                "required": ["baseline_path"],
                "additionalProperties": false
            }
        },
        {
            "name": "hostguard_audit_ssh",
            "description": "Audit an OpenSSH sshd_config file (including drop-in Includes) or inline snippet against CIS Linux SSH rules (HOST-101 through HOST-106).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Filesystem path to sshd_config." },
                    "content": { "type": "string", "description": "Inline sshd_config text (max 1 MiB)." },
                    "source_label": { "type": "string", "description": "Optional label for inline findings." }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "hostguard_audit_docker",
            "description": "Audit a Dockerfile, docker-compose YAML file, directory tree, or inline container definition against CIS Docker rules (HOST-201 through HOST-209) with secret redaction.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File or directory path to audit." },
                    "content": { "type": "string", "description": "Inline Dockerfile or docker-compose YAML text (max 1 MiB)." },
                    "kind": { "type": "string", "enum": ["dockerfile", "compose"], "description": "Format when auditing inline content (default: dockerfile)." },
                    "source_label": { "type": "string", "description": "Optional label for inline findings." }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "hostguard_audit_host",
            "description": "Audit Linux sysctl configs, sudoers files, or host file permissions against CIS hardening rules (HOST-301 through HOST-304).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": ["sysctl", "sudoers", "permissions"],
                        "description": "Host audit domain to execute."
                    },
                    "path": { "type": "string", "description": "File or directory path on disk." },
                    "content": { "type": "string", "description": "Inline sysctl or sudoers config text (max 1 MiB)." },
                    "source_label": { "type": "string", "description": "Optional label for inline findings." },
                    "policy_path": { "type": "string", "description": "Optional YAML/JSON suppression policy path." }
                },
                "required": ["kind"],
                "additionalProperties": false
            }
        },
        {
            "name": "hostguard_audit_workspace",
            "description": "Recursively audit an entire repository or configuration directory across SSH, Docker/Compose, sysctl, and sudoers configs with optional policy suppression.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Workspace or directory path to scan." },
                    "policy_path": { "type": "string", "description": "Optional YAML/JSON suppression policy path." }
                },
                "required": ["path"],
                "additionalProperties": false
            }
        }
    ])
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn tool_ok(text: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": false
    })
}

fn tool_err(text: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": true
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Cursor;
    use tempfile::tempdir;

    fn run_rpc_session(lines: &[&str]) -> Vec<Value> {
        let input = format!("{}\n", lines.join("\n"));
        let mut output = Vec::new();
        serve_streams(Cursor::new(input.into_bytes()), &mut output).expect("serve_streams");
        let text = String::from_utf8(output).expect("utf8 rpc output");
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str::<Value>(l).expect("valid json response"))
            .collect()
    }

    #[test]
    fn mcp_lifecycle_list_rules_and_error_codes() {
        let responses = run_rpc_session(&[
            "not json",
            r#"{"jsonrpc":"1.0","id":0,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hostguard_list_rules","arguments":{}}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"unknown/method"}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"missing_tool"}}"#,
        ]);

        // Notification yields no response -> 7 responses total.
        assert_eq!(responses.len(), 7);
        assert_eq!(responses[0]["error"]["code"], -32700);
        assert_eq!(responses[1]["error"]["code"], -32600);
        assert_eq!(
            responses[2]["result"]["serverInfo"]["name"],
            "raksa-hostguard"
        );
        let tools = responses[3]["result"]["tools"]
            .as_array()
            .expect("tools array");
        assert_eq!(tools.len(), 7);

        let rules_text = responses[4]["result"]["content"][0]["text"]
            .as_str()
            .expect("rules text");
        let rules: Value = serde_json::from_str(rules_text).expect("rules json");
        assert_eq!(rules.as_array().expect("array").len(), 24);

        assert_eq!(responses[5]["error"]["code"], -32601);
        assert_eq!(responses[6]["error"]["code"], -32602);
    }

    #[test]
    fn mcp_inline_auditors_and_size_guard_work() {
        let oversized = "A".repeat(MAX_CONFIG_BYTES + 10);
        let big_req = json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "hostguard_audit_ssh",
                "arguments": { "content": oversized }
            }
        })
        .to_string();

        let ssh_req = json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "hostguard_audit_ssh",
                "arguments": { "content": "PermitRootLogin yes\n" }
            }
        })
        .to_string();

        let docker_req = json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "hostguard_audit_docker",
                "arguments": {
                    "kind": "compose",
                    "content": "services:\n  app:\n    image: nginx:latest\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    environment:\n      DB_PASSWORD: super_secret_value\n"
                }
            }
        })
        .to_string();

        let responses = run_rpc_session(&[&big_req, &ssh_req, &docker_req]);
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["error"]["code"], -32602);

        let ssh_report: Value = serde_json::from_str(
            responses[1]["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ssh_report["findings"][0]["rule_id"], "HOST-101");

        let docker_text = responses[2]["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(!docker_text.contains("super_secret_value"));
        let docker_report: Value = serde_json::from_str(docker_text).unwrap();
        assert_eq!(docker_report["summary"]["total"], 2);
    }

    #[test]
    fn mcp_fim_snapshot_and_check_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let watched = dir.path().join("etc");
        fs::create_dir_all(&watched).expect("create watched dir");
        let conf = watched.join("hosts");
        fs::write(&conf, "127.0.0.1 localhost\n").expect("write hosts");
        let baseline = dir.path().join("baseline.json");

        let snap_req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "hostguard_fim_snapshot",
                "arguments": {
                    "paths": [watched.to_string_lossy()],
                    "baseline_out": baseline.to_string_lossy()
                }
            }
        })
        .to_string();

        let clean_check = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "hostguard_fim_check",
                "arguments": {
                    "baseline_path": baseline.to_string_lossy()
                }
            }
        })
        .to_string();

        let first = run_rpc_session(&[&snap_req, &clean_check]);
        let clean_report: Value =
            serde_json::from_str(first[1]["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(clean_report["summary"]["total"], 0);

        fs::write(&conf, "127.0.0.1 evil.local\n").expect("tamper hosts");
        let second = run_rpc_session(&[&clean_check]);
        let tampered_report: Value =
            serde_json::from_str(second[0]["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(tampered_report["summary"]["critical"], 1);
        assert_eq!(tampered_report["findings"][0]["rule_id"], "HOST-001");
    }

    #[test]
    fn mcp_audit_host_and_workspace_with_policy() {
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("Dockerfile.insecure"),
            "FROM ubuntu:latest\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("sysctl.conf"),
            "net.ipv4.ip_forward = 1\nkernel.randomize_va_space = 0\n",
        )
        .unwrap();
        let policy_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/policy_suppress.yml");

        let sysctl_req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "hostguard_audit_host",
                "arguments": {
                    "kind": "sysctl",
                    "content": "net.ipv4.ip_forward = 1\nkernel.kptr_restrict = 0\n"
                }
            }
        })
        .to_string();

        let sudoers_req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "hostguard_audit_host",
                "arguments": {
                    "kind": "sudoers",
                    "content": "deploy ALL=(ALL) NOPASSWD: ALL\n"
                }
            }
        })
        .to_string();

        let ws_req = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "hostguard_audit_workspace",
                "arguments": {
                    "path": dir.path().to_string_lossy(),
                    "policy_path": policy_path.to_string_lossy()
                }
            }
        })
        .to_string();

        let bad_perms_req = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "hostguard_audit_host",
                "arguments": {
                    "kind": "permissions",
                    "content": "inline not supported"
                }
            }
        })
        .to_string();

        let responses = run_rpc_session(&[&sysctl_req, &sudoers_req, &ws_req, &bad_perms_req]);
        assert_eq!(responses.len(), 4);

        let sysctl_rep: Value = serde_json::from_str(
            responses[0]["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(sysctl_rep["summary"]["high"], 2);

        let sudo_rep: Value = serde_json::from_str(
            responses[1]["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(sudo_rep["findings"][0]["rule_id"], "HOST-304");

        let ws_rep: Value = serde_json::from_str(
            responses[2]["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let ws_rules: Vec<&str> = ws_rep["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["rule_id"].as_str().unwrap())
            .collect();
        // HOST-204 on Dockerfile.insecure was suppressed by testdata/policy_suppress.yml
        assert!(
            !ws_rules.contains(&"HOST-204"),
            "policy should suppress HOST-204"
        );
        assert!(ws_rules.contains(&"HOST-201"));
        assert!(ws_rules.contains(&"HOST-301"));

        assert_eq!(responses[3]["error"]["code"], -32602);
    }
}

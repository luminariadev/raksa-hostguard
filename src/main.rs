#![forbid(unsafe_code)]

use chrono::Utc;
use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand};
use raksa_hostguard::audit::audit_workspace;
use raksa_hostguard::audit::docker::audit_docker_path;
use raksa_hostguard::audit::host::{
    audit_host_permissions_path, audit_sudoers_path, audit_sysctl_path,
};
use raksa_hostguard::audit::ssh::audit_sshd_file;
use raksa_hostguard::fim::hash::DEFAULT_MAX_FILE_BYTES;
use raksa_hostguard::fim::{
    create_snapshot_with_workers, default_worker_count, load_snapshot, save_snapshot,
    sign_snapshot, verify_snapshot_signed, watch_snapshot, WatchConfig,
};
use raksa_hostguard::mcp::serve_stdio;
use raksa_hostguard::policy::{apply_policy, load_policy};
use raksa_hostguard::report::{write_report, OutputFormat};
use raksa_hostguard::schema::catalog::rule_catalog;
use raksa_hostguard::schema::{Finding, Report, Severity, LAYER_HOST, SCHEMA_VERSION, TOOL_NAME};
use serde_json::json;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "raksa-hostguard",
    version = raksa_hostguard::VERSION,
    about = "Defensive File Integrity Monitoring (FIM) and CIS Linux/SSH/Docker hardening auditor (Raksa Layer 2)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// File Integrity Monitoring (FIM) baseline creation, verification, and watch mode
    Fim {
        #[command(subcommand)]
        action: FimAction,
    },
    /// Audit OpenSSH sshd_config against CIS Linux hardening rules (HOST-101..106)
    AuditSsh(AuditSshArgs),
    /// Audit Dockerfiles and docker-compose files against CIS Docker rules (HOST-201..209)
    AuditDocker(AuditDockerArgs),
    /// Audit Linux host sysctl, sudoers, and file permissions against CIS rules (HOST-301..304)
    AuditHost(AuditHostArgs),
    /// Recursively audit a workspace across SSH, Docker, sysctl, and sudoers configs
    AuditWorkspace(AuditWorkspaceArgs),
    /// List all supported detection rules with CIS and MITRE D3FEND mappings
    Rules(RulesArgs),
    /// Start an MCP (Model Context Protocol) JSON-RPC 2.0 server over stdio
    Mcp,
    /// Print binary, Raksa Finding Schema, and layer version details
    Version,
}

#[derive(Subcommand, Debug)]
enum FimAction {
    /// Hash target files/directories into a deterministic JSON baseline snapshot
    Init(FimInitArgs),
    /// Verify disk state against a saved SHA-256 baseline snapshot
    Check(FimCheckArgs),
    /// Periodically monitor filesystem drift against a saved baseline snapshot
    Watch(FimWatchArgs),
}

#[derive(Args, Debug)]
struct FimInitArgs {
    /// File or directory path to monitor (repeatable)
    #[arg(long = "path", required = true)]
    paths: Vec<PathBuf>,
    /// Output baseline snapshot JSON path
    #[arg(long = "out", required = true)]
    out: PathBuf,
    /// Filename or path pattern to exclude from hashing (repeatable)
    #[arg(long = "exclude")]
    excludes: Vec<String>,
    /// Maximum single file size in bytes to hash (default 50 MiB)
    #[arg(long = "max-file-bytes", default_value_t = DEFAULT_MAX_FILE_BYTES)]
    max_file_bytes: u64,
    /// Environment variable holding the HMAC-SHA256 key used to sign the baseline
    #[arg(long = "sign-key-env")]
    sign_key_env: Option<String>,
    /// Number of parallel worker threads for SHA-256 hashing
    #[arg(long = "workers")]
    workers: Option<usize>,
    /// Output format: table or json
    #[arg(long = "format", default_value = "table")]
    format: String,
}

#[derive(Args, Debug)]
struct FimCheckArgs {
    /// Path to baseline snapshot JSON file
    #[arg(long = "baseline", required = true)]
    baseline: PathBuf,
    /// Environment variable holding the HMAC-SHA256 verification key
    #[arg(long = "sign-key-env")]
    sign_key_env: Option<String>,
    /// Number of parallel worker threads for verification
    #[arg(long = "workers")]
    workers: Option<usize>,
    /// Optional YAML/JSON policy suppression file
    #[arg(long = "policy")]
    policy: Option<PathBuf>,
    /// Report format: table, json, or sarif
    #[arg(long = "format", default_value = "table")]
    format: String,
    /// Exit with code 2 when any finding meets or exceeds this severity (critical|high|medium|low|info)
    #[arg(long = "fail-on")]
    fail_on: Option<Severity>,
    /// Write formatted report to this file instead of stdout
    #[arg(long = "output")]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct FimWatchArgs {
    /// Path to baseline snapshot JSON file
    #[arg(long = "baseline", required = true)]
    baseline: PathBuf,
    /// Polling interval in seconds between verification cycles
    #[arg(long = "interval-secs", default_value_t = 5)]
    interval_secs: u64,
    /// Stop automatically after M cycles (omit to watch indefinitely)
    #[arg(long = "max-cycles")]
    max_cycles: Option<usize>,
    /// Environment variable holding the HMAC-SHA256 verification key
    #[arg(long = "sign-key-env")]
    sign_key_env: Option<String>,
    /// Number of parallel worker threads for verification
    #[arg(long = "workers")]
    workers: Option<usize>,
    /// Optional YAML/JSON policy suppression file
    #[arg(long = "policy")]
    policy: Option<PathBuf>,
    /// Incremental output format: table or json
    #[arg(long = "format", default_value = "table")]
    format: String,
    /// Exit with code 2 if any watch cycle records a finding meeting this severity
    #[arg(long = "fail-on")]
    fail_on: Option<Severity>,
}

#[derive(Args, Debug)]
struct AuditSshArgs {
    /// Path to sshd_config file to audit
    #[arg(long = "path", default_value = "/etc/ssh/sshd_config")]
    path: PathBuf,
    /// Optional YAML/JSON policy suppression file
    #[arg(long = "policy")]
    policy: Option<PathBuf>,
    /// Report format: table, json, or sarif
    #[arg(long = "format", default_value = "table")]
    format: String,
    /// Exit with code 2 when any finding meets or exceeds this severity (critical|high|medium|low|info)
    #[arg(long = "fail-on")]
    fail_on: Option<Severity>,
    /// Write formatted report to this file instead of stdout
    #[arg(long = "output")]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct AuditDockerArgs {
    /// Path to Dockerfile, docker-compose file, or directory tree
    #[arg(long = "path", default_value = ".")]
    path: PathBuf,
    /// Optional YAML/JSON policy suppression file
    #[arg(long = "policy")]
    policy: Option<PathBuf>,
    /// Report format: table, json, or sarif
    #[arg(long = "format", default_value = "table")]
    format: String,
    /// Exit with code 2 when any finding meets or exceeds this severity (critical|high|medium|low|info)
    #[arg(long = "fail-on")]
    fail_on: Option<Severity>,
    /// Write formatted report to this file instead of stdout
    #[arg(long = "output")]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct AuditHostArgs {
    /// Path to sysctl.conf file or sysctl.d directory
    #[arg(long = "sysctl")]
    sysctl: Option<PathBuf>,
    /// Path to sudoers file or sudoers.d directory
    #[arg(long = "sudoers")]
    sudoers: Option<PathBuf>,
    /// Path to file or directory to inspect for unsafe permissions / SUID bits
    #[arg(long = "perms")]
    perms: Option<PathBuf>,
    /// Optional YAML/JSON policy suppression file
    #[arg(long = "policy")]
    policy: Option<PathBuf>,
    /// Report format: table, json, or sarif
    #[arg(long = "format", default_value = "table")]
    format: String,
    /// Exit with code 2 when any finding meets or exceeds this severity (critical|high|medium|low|info)
    #[arg(long = "fail-on")]
    fail_on: Option<Severity>,
    /// Write formatted report to this file instead of stdout
    #[arg(long = "output")]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct AuditWorkspaceArgs {
    /// Workspace or repository directory to scan across host & container configs
    #[arg(long = "path", default_value = ".")]
    path: PathBuf,
    /// Optional YAML/JSON policy suppression file
    #[arg(long = "policy")]
    policy: Option<PathBuf>,
    /// Report format: table, json, or sarif
    #[arg(long = "format", default_value = "table")]
    format: String,
    /// Exit with code 2 when any finding meets or exceeds this severity (critical|high|medium|low|info)
    #[arg(long = "fail-on")]
    fail_on: Option<Severity>,
    /// Write formatted report to this file instead of stdout
    #[arg(long = "output")]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct RulesArgs {
    /// Output format: table or json
    #[arg(long = "format", default_value = "table")]
    format: String,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(parsed) => parsed,
        Err(err) => {
            let kind = err.kind();
            let _ = err.print();
            return match kind {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ExitCode::SUCCESS,
                _ => ExitCode::from(1),
            };
        }
    };

    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Commands::Version => {
            println!(
                "{} v{} (schema {}, layer {})",
                TOOL_NAME,
                raksa_hostguard::VERSION,
                SCHEMA_VERSION,
                LAYER_HOST
            );
            Ok(ExitCode::SUCCESS)
        }
        Commands::Rules(args) => cmd_rules(args),
        Commands::Fim { action } => match action {
            FimAction::Init(args) => cmd_fim_init(args),
            FimAction::Check(args) => cmd_fim_check(args),
            FimAction::Watch(args) => cmd_fim_watch(args),
        },
        Commands::AuditSsh(args) => cmd_audit_ssh(args),
        Commands::AuditDocker(args) => cmd_audit_docker(args),
        Commands::AuditHost(args) => cmd_audit_host(args),
        Commands::AuditWorkspace(args) => cmd_audit_workspace(args),
        Commands::Mcp => {
            serve_stdio().map_err(|e| format!("mcp server failed: {e}"))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn cmd_rules(args: RulesArgs) -> Result<ExitCode, String> {
    let rules = rule_catalog();
    match args.format.trim().to_ascii_lowercase().as_str() {
        "json" => {
            let encoded = serde_json::to_string_pretty(&rules)
                .map_err(|e| format!("failed to serialize rules: {e}"))?;
            println!("{encoded}");
        }
        "table" => {
            println!(
                "RULE       SEVERITY  MODULE         CIS REF                 D3FEND     TITLE"
            );
            println!("{}", "-".repeat(100));
            for r in rules {
                println!(
                    "{:<10} {:<9} {:<14} {:<23} {:<10} {}",
                    r.rule_id,
                    r.default_severity.to_ascii_uppercase(),
                    r.module,
                    r.cis_ref,
                    r.mitre_d3fend,
                    r.title
                );
            }
        }
        other => {
            return Err(format!(
                "invalid format {:?}: expected table or json",
                other
            ))
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn resolve_workers(workers: Option<usize>) -> Result<usize, String> {
    match workers {
        None => Ok(default_worker_count()),
        Some(0) => Err("--workers must be >= 1".to_string()),
        Some(n) => Ok(n),
    }
}

fn resolve_sign_key(env_opt: Option<&str>) -> Result<Option<Vec<u8>>, String> {
    let Some(var_name) = env_opt.map(str::trim) else {
        return Ok(None);
    };
    if var_name.is_empty() {
        return Err("--sign-key-env must not be empty".to_string());
    }
    let val = std::env::var(var_name)
        .map_err(|_| format!("environment variable '{var_name}' for HMAC key is not set"))?;
    if val.is_empty() {
        return Err(format!(
            "environment variable '{var_name}' for HMAC key is empty"
        ));
    }
    Ok(Some(val.into_bytes()))
}

fn cmd_fim_init(args: FimInitArgs) -> Result<ExitCode, String> {
    let workers = resolve_workers(args.workers)?;
    let sign_key = resolve_sign_key(args.sign_key_env.as_deref())?;
    let (mut snapshot, stats) =
        create_snapshot_with_workers(&args.paths, &args.excludes, args.max_file_bytes, workers)
            .map_err(|e| format!("failed to create snapshot: {e}"))?;

    if let Some(key) = &sign_key {
        sign_snapshot(&mut snapshot, key).map_err(|e| format!("failed to sign snapshot: {e}"))?;
    }

    save_snapshot(&args.out, &snapshot)
        .map_err(|e| format!("failed to save snapshot to {:?}: {e}", args.out))?;

    let total_bytes: u64 = snapshot.entries.values().map(|e| e.size).sum();
    match args.format.trim().to_ascii_lowercase().as_str() {
        "json" => {
            let summary = json!({
                "status": "created",
                "tool": TOOL_NAME,
                "schema_version": SCHEMA_VERSION,
                "baseline_out": args.out.to_string_lossy(),
                "signed": sign_key.is_some(),
                "files_hashed": stats.files_hashed,
                "files_skipped_oversize": stats.files_skipped_oversize,
                "files_skipped_error": stats.files_skipped_error,
                "total_bytes": total_bytes,
                "created_at": snapshot.created_at
            });
            let encoded = serde_json::to_string_pretty(&summary)
                .map_err(|e| format!("failed to encode summary: {e}"))?;
            println!("{encoded}");
        }
        "table" => {
            println!(
                "FIM baseline created: {} (signed: {})",
                args.out.display(),
                sign_key.is_some()
            );
            println!(
                "  files hashed: {} | total bytes: {} | skipped oversize: {} | skipped unreadable: {}",
                stats.files_hashed,
                total_bytes,
                stats.files_skipped_oversize,
                stats.files_skipped_error
            );
        }
        other => {
            return Err(format!(
                "invalid format {:?}: expected table or json",
                other
            ))
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_fim_check(args: FimCheckArgs) -> Result<ExitCode, String> {
    let fmt: OutputFormat = args.format.parse()?;
    let workers = resolve_workers(args.workers)?;
    let sign_key = resolve_sign_key(args.sign_key_env.as_deref())?;
    let snapshot = load_snapshot(&args.baseline)
        .map_err(|e| format!("failed to load baseline {:?}: {e}", args.baseline))?;
    let findings = verify_snapshot_signed(&snapshot, sign_key.as_deref(), workers)
        .map_err(|e| format!("failed to verify baseline: {e}"))?;
    emit_report_and_exit(
        findings,
        fmt,
        args.output.as_deref(),
        args.policy.as_deref(),
        args.fail_on,
    )
}

fn cmd_fim_watch(args: FimWatchArgs) -> Result<ExitCode, String> {
    let fmt: OutputFormat = args.format.parse()?;
    if fmt == OutputFormat::Sarif {
        return Err("fim watch supports --format table or json (not sarif)".to_string());
    }
    let workers = resolve_workers(args.workers)?;
    let sign_key = resolve_sign_key(args.sign_key_env.as_deref())?;
    let policy = args.policy.as_deref().map(load_policy).transpose()?;
    let snapshot = load_snapshot(&args.baseline)
        .map_err(|e| format!("failed to load baseline {:?}: {e}", args.baseline))?;

    let cfg = WatchConfig {
        interval: Duration::from_secs(args.interval_secs),
        max_cycles: args.max_cycles,
        workers,
    };

    let mut breach = false;
    watch_snapshot(&snapshot, sign_key.as_deref(), &cfg, |_cycle, fresh| {
        let filtered = if let Some(pol) = &policy {
            apply_policy(fresh.to_vec(), pol, Utc::now().date_naive()).0
        } else {
            fresh.to_vec()
        };

        if !filtered.is_empty() {
            let report = Report::new(filtered, Utc::now());
            if report.has_threshold_breach(args.fail_on) {
                breach = true;
            }
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            if write_report(&mut handle, &report, fmt).is_err() || handle.flush().is_err() {
                return false;
            }
        }
        true
    })
    .map_err(|e| format!("fim watch failed: {e}"))?;

    if breach {
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn cmd_audit_ssh(args: AuditSshArgs) -> Result<ExitCode, String> {
    let fmt: OutputFormat = args.format.parse()?;
    let findings = audit_sshd_file(&args.path)
        .map_err(|e| format!("failed to audit sshd config {:?}: {e}", args.path))?;
    emit_report_and_exit(
        findings,
        fmt,
        args.output.as_deref(),
        args.policy.as_deref(),
        args.fail_on,
    )
}

fn cmd_audit_docker(args: AuditDockerArgs) -> Result<ExitCode, String> {
    let fmt: OutputFormat = args.format.parse()?;
    let findings = audit_docker_path(&args.path)
        .map_err(|e| format!("failed to audit docker path {:?}: {e}", args.path))?;
    emit_report_and_exit(
        findings,
        fmt,
        args.output.as_deref(),
        args.policy.as_deref(),
        args.fail_on,
    )
}

fn cmd_audit_host(args: AuditHostArgs) -> Result<ExitCode, String> {
    if args.sysctl.is_none() && args.sudoers.is_none() && args.perms.is_none() {
        return Err("at least one of --sysctl, --sudoers, or --perms must be provided".to_string());
    }
    let fmt: OutputFormat = args.format.parse()?;
    let mut findings = Vec::new();

    if let Some(p) = &args.sysctl {
        findings.extend(
            audit_sysctl_path(p).map_err(|e| format!("failed to audit sysctl {:?}: {e}", p))?,
        );
    }
    if let Some(p) = &args.sudoers {
        findings.extend(
            audit_sudoers_path(p).map_err(|e| format!("failed to audit sudoers {:?}: {e}", p))?,
        );
    }
    if let Some(p) = &args.perms {
        findings.extend(
            audit_host_permissions_path(p)
                .map_err(|e| format!("failed to audit permissions {:?}: {e}", p))?,
        );
    }

    emit_report_and_exit(
        findings,
        fmt,
        args.output.as_deref(),
        args.policy.as_deref(),
        args.fail_on,
    )
}

fn cmd_audit_workspace(args: AuditWorkspaceArgs) -> Result<ExitCode, String> {
    let fmt: OutputFormat = args.format.parse()?;
    let findings = audit_workspace(&args.path)
        .map_err(|e| format!("failed to audit workspace {:?}: {e}", args.path))?;
    emit_report_and_exit(
        findings,
        fmt,
        args.output.as_deref(),
        args.policy.as_deref(),
        args.fail_on,
    )
}

fn emit_report_and_exit(
    findings: Vec<Finding>,
    fmt: OutputFormat,
    output_path: Option<&Path>,
    policy_path: Option<&Path>,
    fail_on: Option<Severity>,
) -> Result<ExitCode, String> {
    let effective = if let Some(pol_path) = policy_path {
        let policy = load_policy(pol_path)?;
        apply_policy(findings, &policy, Utc::now().date_naive()).0
    } else {
        findings
    };

    let report = Report::new(effective, Utc::now());

    if let Some(path) = output_path {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create parent directory {:?}: {e}", parent))?;
        }
        let file = fs::File::create(path)
            .map_err(|e| format!("failed to create output file {:?}: {e}", path))?;
        write_report(io::BufWriter::new(file), &report, fmt)
            .map_err(|e| format!("failed to write report: {e}"))?;
    } else {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        write_report(&mut handle, &report, fmt)
            .map_err(|e| format!("failed to write stdout report: {e}"))?;
        handle
            .flush()
            .map_err(|e| format!("failed to flush stdout: {e}"))?;
    }

    if report.has_threshold_breach(fail_on) {
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

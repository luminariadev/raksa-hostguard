#![forbid(unsafe_code)]

use chrono::Utc;
use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand};
use raksa_hostguard::audit::docker::audit_docker_path;
use raksa_hostguard::audit::ssh::audit_sshd_file;
use raksa_hostguard::fim::hash::DEFAULT_MAX_FILE_BYTES;
use raksa_hostguard::fim::{create_snapshot, load_snapshot, save_snapshot, verify_snapshot};
use raksa_hostguard::mcp::serve_stdio;
use raksa_hostguard::report::{write_report, OutputFormat};
use raksa_hostguard::schema::catalog::rule_catalog;
use raksa_hostguard::schema::{Report, Severity, LAYER_HOST, SCHEMA_VERSION, TOOL_NAME};
use serde_json::json;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "raksa-hostguard",
    version = raksa_hostguard::VERSION,
    about = "Defensive File Integrity Monitoring (FIM) and CIS SSH/Docker hardening auditor (Raksa Layer 2)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// File Integrity Monitoring (FIM) baseline creation and drift verification
    Fim {
        #[command(subcommand)]
        action: FimAction,
    },
    /// Audit OpenSSH sshd_config against CIS Linux hardening rules (HOST-101..104)
    AuditSsh(AuditSshArgs),
    /// Audit Dockerfiles and docker-compose files against CIS Docker rules (HOST-201..206)
    AuditDocker(AuditDockerArgs),
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
    /// Output format: table or json
    #[arg(long = "format", default_value = "table")]
    format: String,
}

#[derive(Args, Debug)]
struct FimCheckArgs {
    /// Path to baseline snapshot JSON file
    #[arg(long = "baseline", required = true)]
    baseline: PathBuf,
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
struct AuditSshArgs {
    /// Path to sshd_config file to audit
    #[arg(long = "path", default_value = "/etc/ssh/sshd_config")]
    path: PathBuf,
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
        },
        Commands::AuditSsh(args) => cmd_audit_ssh(args),
        Commands::AuditDocker(args) => cmd_audit_docker(args),
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
            println!("RULE       SEVERITY  MODULE   CIS REF         D3FEND     TITLE");
            println!("{}", "-".repeat(92));
            for r in rules {
                println!(
                    "{:<10} {:<9} {:<8} {:<15} {:<10} {}",
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

fn cmd_fim_init(args: FimInitArgs) -> Result<ExitCode, String> {
    let (snapshot, stats) = create_snapshot(&args.paths, &args.excludes, args.max_file_bytes)
        .map_err(|e| format!("failed to create snapshot: {e}"))?;
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
            println!("FIM baseline created: {}", args.out.display());
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
    let snapshot = load_snapshot(&args.baseline)
        .map_err(|e| format!("failed to load baseline {:?}: {e}", args.baseline))?;
    let findings =
        verify_snapshot(&snapshot).map_err(|e| format!("failed to verify baseline: {e}"))?;
    emit_report_and_exit(findings, fmt, args.output.as_deref(), args.fail_on)
}

fn cmd_audit_ssh(args: AuditSshArgs) -> Result<ExitCode, String> {
    let fmt: OutputFormat = args.format.parse()?;
    let findings = audit_sshd_file(&args.path)
        .map_err(|e| format!("failed to audit sshd config {:?}: {e}", args.path))?;
    emit_report_and_exit(findings, fmt, args.output.as_deref(), args.fail_on)
}

fn cmd_audit_docker(args: AuditDockerArgs) -> Result<ExitCode, String> {
    let fmt: OutputFormat = args.format.parse()?;
    let findings = audit_docker_path(&args.path)
        .map_err(|e| format!("failed to audit docker path {:?}: {e}", args.path))?;
    emit_report_and_exit(findings, fmt, args.output.as_deref(), args.fail_on)
}

fn emit_report_and_exit(
    findings: Vec<raksa_hostguard::schema::Finding>,
    fmt: OutputFormat,
    output_path: Option<&Path>,
    fail_on: Option<Severity>,
) -> Result<ExitCode, String> {
    let report = Report::new(findings, Utc::now());

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

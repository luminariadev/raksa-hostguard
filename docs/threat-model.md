# raksa-hostguard Threat Model (`v0.3.0`)

## Defensive Scope

`raksa-hostguard` helps platform engineers, Blue Teams, and DevSecOps pipelines detect unauthorized host filesystem tampering, generate read-only configuration remediation diffs, and catch OS, SSH, systemd, persistence, PAM, kernel, and container drift before or during production operation.

### In Scope
- Creating parallel cryptographic (SHA-256) file integrity baselines with optional HMAC-SHA256 authenticity tags, verifying disk drift, and monitoring via event-driven `notify` (`fim watch --watch-mode events --siem-out`).
- Auditing `sshd_config` (including bounded `Include` drop-ins) for authentication, cipher/MAC/Kex, and forwarding exposures (`HOST-101`..`106`).
- Auditing `Dockerfile` (multi-stage aware), `docker-compose.yml`, Docker `daemon.json`, and Podman `containers.conf` against CIS Docker hardening guidelines (`HOST-201`..`210`).
- Auditing Linux `sysctl`, `sudoers`, host permissions / SUID bits, `systemd` units + `.service.d` drop-ins, cron/anacron/shell persistence, PAM/`login.defs`, and `modprobe.d`/`auditd` (`HOST-301`..`308`).
- Generating read-only unified hardening diffs (`fix-preview`), gating on deterministic SHA-256 baselines (`--baseline`), and applying expiration-enforced suppression policies (`.hostguard.yml`).

### Out of Scope (Non-Goals)
- **Kernel-level inline blocking**: `raksa-hostguard` uses unprivileged OS filesystem notifications (`notify`) and periodic reconciliation without loading kernel modules, eBPF LSM hooks, or AppArmor/SELinux enforcers.
- **Automated disk mutation (`fix-preview`)**: Patch previews are strictly read-only on `stdout` or explicit `--output` artifacts so operators and Git review control all host modifications.
- **Encrypted secret vaulting**: `HOST-205` detects literal secret assignments and redacts secret values from reports so credentials never leak into CI logs, Markdown tables, NDJSON streams, or SARIF artifacts.

## Security Guarantees & Trust Boundaries

1. **Memory Safety (`#![forbid(unsafe_code)]`)**: All workspace crate code forbids `unsafe` Rust blocks, and `Cargo.toml` uses pure-Rust crates without C FFI (`notify 8.2` uses `macos_kqueue`, `inotify`, and `ReadDirectoryChangesW`).
2. **Symlink-Loop, Diff Memory, & Input Size Guards**:
   - Directory traversal sets `follow_links(false)` so cyclic symlinks cannot cause infinite loops or escape monitored roots.
   - OpenSSH `Include` resolution caps recursion depth at `2` and tracks visited canonical paths; systemd unit drop-in collection bounds traversal depth at `3`.
   - SHA-256 hashing streams files in 64 KiB chunks and enforces a configurable `max_file_bytes` cap (default `50 MiB`).
   - All static configuration parsers, baseline files, and inline MCP inputs enforce a strict `1 MiB` size cap (`2 MiB` MCP RPC line cap), and `fix-preview` LCS diffing bounds table allocation safely when `lines_old * lines_new > 2,000,000`.
3. **Baseline Anti-Tampering (`HOST-005` HMAC-SHA256)**:
   - When `--sign-key-env` (or MCP `sign_key_env`) is configured, `fim init` appends an RFC 2104 HMAC-SHA256 signature computed over the canonical snapshot payload, and `fim check` / `fim watch` verify it in constant time (`constant_time_eq`).
   - Key material is read exclusively from environment variables, never passed as CLI flags, MCP parameters, or written into snapshots.
4. **Fail-Closed Policy Suppressions**:
   - Suppressions require an explicit `reason`. Expired `expires_on` dates (`expires_on < today`) automatically stop suppressing findings.
5. **Secret Redaction & Output Safety**:
   - `HOST-205` reports only the variable key name and line/service target without printing secret literals.
   - `table` and `markdown` outputs pass untrusted paths and titles through `sanitize_terminal_text` (stripping ANSI CSI/OSC sequences, C0/C1 control codes, and escaping Markdown cell pipes).

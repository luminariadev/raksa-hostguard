# raksa-hostguard Threat Model

## Defensive Scope

`raksa-hostguard` helps platform engineers, Blue Teams, and DevSecOps pipelines detect unauthorized host filesystem tampering and catch OS, SSH, and container configuration drift before or during production operation.

### In Scope
- Creating parallel cryptographic (SHA-256) file integrity baselines with optional HMAC-SHA256 authenticity tags, verifying disk drift, and polling via `fim watch`.
- Auditing `sshd_config` (including bounded `Include` drop-ins) for authentication, cipher/MAC/Kex, and forwarding exposures.
- Auditing `Dockerfile` (multi-stage aware) and `docker-compose.yml` definitions against CIS Docker hardening guidelines.
- Auditing Linux `sysctl`, `sudoers`, and host file permissions / SUID bits via `audit-host` and `audit-workspace`.
- Auditing with expiration-enforced suppression policies (`.hostguard.yml`).

### Out of Scope (Non-Goals)
- **Kernel-level inline blocking**: `raksa-hostguard` does not install kernel modules, eBPF LSM hooks, or AppArmor/SELinux policies; `fim watch` performs periodic polling rather than blocking syscalls inline.
- **Live Docker daemon introspection**: `audit-docker` analyzes container build and compose manifests statically rather than attaching to `/var/run/docker.sock`.
- **Encrypted secret vaulting**: `HOST-205` detects literal secret assignments and redacts secret values from reports so credentials do not leak into CI logs or SARIF artifacts.

## Security Guarantees & Trust Boundaries

1. **Memory Safety (`#![forbid(unsafe_code)]`)**: All workspace crate code forbids `unsafe` Rust blocks, and `Cargo.toml` relies on pure Rust dependencies without C FFI.
2. **Symlink-Loop & Resource Exhaustion Guards**:
   - Directory traversal sets `follow_links(false)` so cyclic symlinks cannot cause infinite loops or escape monitored roots.
   - OpenSSH `Include` resolution caps recursion depth at 2 and tracks visited canonical paths to prevent cyclic includes.
   - SHA-256 hashing streams files in 64 KiB chunks and enforces a configurable `max_file_bytes` cap (default `50 MiB`).
   - All static configuration parsers (`policy`, `sshd_config`, `Dockerfile`, `docker-compose`, `sysctl`, `sudoers`) and inline MCP inputs enforce a strict `1 MiB` size cap.
3. **Baseline Anti-Tampering (`HOST-005` HMAC-SHA256)**:
   - When `--sign-key-env` (or MCP `sign_key_env`) is configured, `fim init` appends an RFC 2104 HMAC-SHA256 signature computed over the canonical snapshot payload, and `fim check` / `fim watch` verify it in constant time (`constant_time_eq`).
   - Key material is read exclusively from environment variables, never passed as CLI flag values, JSON MCP arguments, or stored in baselines.
4. **Fail-Closed Policy Suppressions**:
   - Suppressions require an explicit `reason`. Any suppression whose `expires_on` (`YYYY-MM-DD`) date has passed (`expires_on < today`) is automatically ignored so temporary risk acceptances cannot silently mask findings indefinitely.
5. **Secret Redaction & Terminal Safety**:
   - `HOST-205` reports only the variable key name and line/service target without printing secret literals.
   - `table` output strips ANSI CSI/OSC escape sequences and control characters before printing file paths or titles.

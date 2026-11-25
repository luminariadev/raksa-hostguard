# raksa-hostguard Threat Model

## Defensive Scope

`raksa-hostguard` helps platform engineers, Blue Teams, and DevSecOps pipelines detect unauthorized host filesystem changes and catch OS/container configuration drift before deployment.

### In Scope
- Creating cryptographic (SHA-256) file integrity baselines and verifying content, existence, and permission drift locally.
- Auditing `sshd_config` against CIS Linux hardening recommendations.
- Auditing `Dockerfile` (multi-stage aware) and `docker-compose.yml` definitions against CIS Docker hardening guidelines.

### Out of Scope (Non-Goals)
- **Kernel-level inline blocking**: `raksa-hostguard` does not install kernel modules, eBPF LSM hooks, or AppArmor/SELinux policies; it inspects and reports posture drift.
- **Live Docker daemon introspection**: `audit-docker` analyzes container build and compose manifests statically prior to or alongside deployment rather than attaching to `/var/run/docker.sock`.
- **Encrypted secret vaulting**: Finding reports redact secret values in `HOST-205` evidence so credentials are never echoed into CI logs or SARIF uploads.

## Security Guarantees & Trust Boundaries

1. **Memory Safety (`#![forbid(unsafe_code)]`)**: All workspace crate code forbids `unsafe` Rust blocks.
2. **Symlink-Loop & Resource Exhaustion Guards**:
   - Directory traversal sets `follow_links(false)` so cyclic symlinks cannot trigger infinite loops or escape monitored roots.
   - SHA-256 hashing streams files in 64 KiB chunks and enforces a configurable `max_file_bytes` cap (default `50 MiB`) so huge sparse files or logs do not exhaust memory.
   - Configuration parsers (`sshd_config`, `Dockerfile`, `docker-compose.yml`) enforce a `1 MiB` input cap.
3. **Baseline Integrity Assumption**:
   - File integrity verification (`fim check`) assumes the stored JSON baseline file is protected on read-only media, signed in CI, or stored off-host so a compromised local user cannot rewrite expected hashes alongside tampered binaries.
4. **Secret Redaction**:
   - `HOST-205` reports the variable key name and file/service target without printing the hardcoded literal secret value into stdout, JSON, or SARIF reports.

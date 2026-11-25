# raksa-hostguard

[![CI](https://github.com/luminariadev/raksa-hostguard/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa-hostguard/actions/workflows/ci.yml)
[![Release](https://github.com/luminariadev/raksa-hostguard/actions/workflows/release.yml/badge.svg)](https://github.com/luminariadev/raksa-hostguard/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)

Defensive host hardening, File Integrity Monitoring (FIM), and Linux/Docker CIS configuration auditor written in pure safe Rust (`#![forbid(unsafe_code)]`).

`raksa-hostguard` is **Layer 2 (`host-hardening`)** of the Raksa DevSecOps and Blue Team defense suite. It validates file integrity baselines, OpenSSH daemon settings, and container build/compose manifests offline, and outputs **Raksa Finding Schema v1** reports (`table`, `json`, `sarif` `2.1.0`) alongside a built-in `stdio` MCP server for automated security triage.

---

## Key Capabilities

- **Streaming SHA-256 FIM (`fim init` / `fim check`)**: Hashes directories and files in fixed 64 KiB streaming buffers with symlink loop safety (`walkdir` non-following), configurable `--exclude` filters, and a 50 MiB default single-file guard. Detects content modification (`HOST-001`), deletion (`HOST-002`), unexpected additions (`HOST-003`), and permission drift (`HOST-004`).
- **CIS OpenSSH Auditor (`audit-ssh`)**: Audits `sshd_config` directives (`PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `X11Forwarding`, `AllowAgentForwarding`, `AllowTcpForwarding`, `MaxAuthTries`) before reloading `sshd`.
- **Multi-Stage Dockerfile & Compose Auditor (`audit-docker`)**: Evaluates final-stage non-root execution (allowing privileged builder stages when the final image drops privileges), `privileged: true` and `docker.sock` mounts, `network_mode: host` / `pid: host` / `SYS_ADMIN` / `ALL`, unpinned or `:latest` tags, unverified remote `ADD` URLs or `curl|sh` pipes, and hardcoded credential literals.
- **Credential Redaction & Output Safety**: Secret-bearing environment/arg findings log only the variable name and line/service location (never plaintext secret values). Terminal `table` rendering strips ANSI/CSI/OSC escape sequences to protect operator consoles.
- **Native MCP Server (`raksa-hostguard mcp`)**: Exposes 5 defensive inspection tools over newline-delimited `stdio` JSON-RPC 2.0 with a strict 1 MiB inline content cap.

---

## Defensive Scope & Boundaries

`raksa-hostguard` focuses strictly on **static configuration auditing and snapshot-based file integrity verification**. Understanding these boundaries helps teams avoid blind spots:

- **Snapshot vs. Continuous Kernel Monitoring**: `fim check` compares disk state against a saved JSON baseline on demand (for cron, systemd timers, or CI verification). It does **not** install kernel modules, eBPF probes, or `fanotify` daemons for real-time process blocking.
- **Permission Granularity**: On POSIX/Linux targets, `HOST-004` records full octal permission modes (e.g., `0644`). On Windows NTFS hosts, Rust standard metadata exposes the read-only attribute rather than POSIX mode bits.
- **Static Config vs. Runtime Daemon Inspection**: `audit-ssh` and `audit-docker` inspect configuration files statically. They do not connect to live Docker sockets or probe remote SSH ports (network exposure auditing lives in [raksa-netguard](https://github.com/luminariadev/raksa-netguard)).
- **Heuristic Secret Detection**: `HOST-205` flags literal assignments to credential-named keys (ignoring `${VAR}` / `$VAR` interpolation), and is not a replacement for dedicated git history secret scanners.

---

## Architecture

```text
+-------------------------------------------------------------------------+
|                       CLI & stdio MCP Entrypoint                        |
|   fim init | fim check | audit-ssh | audit-docker | rules | mcp         |
+------+-------------------+--------------------+-------------------+-----+
       |                   |                    |                   |
       v                   v                    v                   v
+--------------+   +---------------+   +----------------+   +-------------+
| FIM Engine   |   | SSH Auditor   |   | Docker/Compose |   | Rule Catalog|
| 64 KiB SHA256|   | CIS 5.2.x     |   | CIS 4.x / 5.x  |   | 14 HOST-*   |
+------+-------+   +-------+-------+   +--------+-------+   +-------------+
       |                   |                    |
       +-------------------+--------------------+
                           |
                           v
       +---------------------------------------+
       |        Raksa Finding Schema v1        |
       |  Summary + Severity Gate (--fail-on)  |
       +-------------------+-------------------+
                           |
        +------------------+------------------+
        v                  v                  v
+---------------+  +---------------+  +---------------+
| Table Output  |  | JSON Schema 1 |  | SARIF 2.1.0   |
| ANSI-Sanitized|  | Automation    |  | GitHub SecOps |
+---------------+  +---------------+  +---------------+
```

See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md) for detailed design and security controls.

---

## Installation

### 1. Prebuilt Release Binaries

Download the archive for Linux (`x86_64-unknown-linux-musl`), Windows (`x86_64-pc-windows-msvc`), or macOS (`aarch64-apple-darwin`) along with `SHA256SUMS.txt` from [GitHub Releases](https://github.com/luminariadev/raksa-hostguard/releases).

### 2. Build from Source (Rust 1.80+)

```bash
git clone https://github.com/luminariadev/raksa-hostguard.git
cd raksa-hostguard
cargo install --path . --locked
```

### 3. Container Image (Distroless Non-Root)

```bash
docker build -t raksa-hostguard:v0.1.0 .
docker run --rm raksa-hostguard:v0.1.0 version
```

---

## Quickstart & Verified Examples

### Version & Rule Catalog

```bash
raksa-hostguard version
# raksa-hostguard v0.1.0 (schema 1.0, layer host-hardening)

raksa-hostguard rules
```

### Audit OpenSSH Configuration

```bash
raksa-hostguard audit-ssh --path testdata/sshd_insecure.conf --fail-on high
```

Verified output (`exit 2` because `--fail-on high` threshold is breached):

```text
raksa-hostguard v0.1.0 | layer: host-hardening | total: 5 (critical: 1, high: 2, medium: 2, low: 0, info: 0)
SEVERITY  RULE       MODULE          TARGET                               TITLE
----------------------------------------------------------------------------------------------------
HIGH      HOST-101   ssh-auditor     file://testdata/sshd_insecure.conf   SSH root login enabled
          fix: Set 'PermitRootLogin no' (or 'prohibit-password' if strictly required) and reload sshd.
HIGH      HOST-102   ssh-auditor     file://testdata/sshd_insecure.conf   SSH password authentication enabled
          fix: Set 'PasswordAuthentication no' and require SSH public-key or certificate authentication.
CRITICAL  HOST-103   ssh-auditor     file://testdata/sshd_insecure.conf   SSH empty passwords permitted
          fix: Set 'PermitEmptyPasswords no' immediately and reload sshd.
MEDIUM    HOST-104   ssh-auditor     file://testdata/sshd_insecure.conf   SSH X11 forwarding enabled
          fix: Set 'X11Forwarding no' unless interactive graphical forwarding is explicitly required.
MEDIUM    HOST-104   ssh-auditor     file://testdata/sshd_insecure.conf   SSH MaxAuthTries exceeds CIS threshold
          fix: Set 'MaxAuthTries 4' or lower to restrict password/key brute-force attempts per connection.
```

### Audit Dockerfiles & Compose Manifests (with Secret Redaction)

```bash
raksa-hostguard audit-docker --path testdata/Dockerfile.insecure --fail-on medium
```

Verified output (`exit 2`, literal passwords/tokens redacted):

```text
raksa-hostguard v0.1.0 | layer: host-hardening | total: 6 (critical: 0, high: 3, medium: 3, low: 0, info: 0)
SEVERITY  RULE       MODULE          TARGET                               TITLE
----------------------------------------------------------------------------------------------------
MEDIUM    HOST-204   docker-auditor  file://testdata/Dockerfile.insecure  Unpinned or :latest container image tag
          fix: Pin the base image to an explicit version tag or @sha256 digest.
HIGH      HOST-205   docker-auditor  file://testdata/Dockerfile.insecure  Hardcoded secret literal in container environment
          fix: Remove literal secrets from Dockerfile; pass credentials at runtime via secret mounts or CI secrets.
HIGH      HOST-205   docker-auditor  file://testdata/Dockerfile.insecure  Hardcoded secret literal in container environment
          fix: Remove literal secrets from Dockerfile; pass credentials at runtime via secret mounts or CI secrets.
MEDIUM    HOST-206   docker-auditor  file://testdata/Dockerfile.insecure  Unverified remote artifact fetch in Dockerfile
          fix: Prefer COPY from a verified build stage or download with explicit SHA-256 verification.
MEDIUM    HOST-206   docker-auditor  file://testdata/Dockerfile.insecure  Unverified remote artifact fetch in Dockerfile
          fix: Download remote scripts first, verify SHA-256 checksums, and avoid piping directly to sh/bash.
HIGH      HOST-201   docker-auditor  file://testdata/Dockerfile.insecure  Container configured to run as root
          fix: Add a dedicated non-root USER instruction (e.g., USER nonroot or UID >= 1000) in the final stage.
```

Running against the distroless image directly:

```bash
docker run --rm -v "$(pwd)/testdata:/testdata:ro" \
  raksa-hostguard:v0.1.0 audit-docker --path /testdata/Dockerfile.insecure --fail-on medium
```

### File Integrity Monitoring (FIM) Baseline & Verification

```bash
# 1. Create baseline snapshot
raksa-hostguard fim init --path /etc/ssh --out ssh-baseline.json

# 2. Verify filesystem state against baseline (exit 0 when clean, exit 2 on threshold breach)
raksa-hostguard fim check --baseline ssh-baseline.json --fail-on critical
```

Verified drift detection output when a monitored `hosts` file is altered:

```text
FIM baseline created: .../baseline.json
  files hashed: 1 | total bytes: 21 | skipped oversize: 0 | skipped unreadable: 0
raksa-hostguard v0.1.0 | layer: host-hardening | total: 1 (critical: 1, high: 0, medium: 0, low: 0, info: 0)
SEVERITY  RULE       MODULE          TARGET                               TITLE
----------------------------------------------------------------------------------------------------
CRITICAL  HOST-001   fim             file://.../etc/hosts                 Monitored file content modified
          fix: Inspect recent changes to .../etc/hosts; restore from a verified artifact if unauthorized.
```

---

## CI/CD SARIF Integration

Export findings in **SARIF 2.1.0** for GitHub Code Scanning alongside an automated severity gate (`exit 2` stops the pipeline cleanly on findings at or above `--fail-on`, while runtime errors return `exit 1`):

```yaml
- name: Run raksa-hostguard container audit
  run: |
    set +e
    raksa-hostguard audit-docker --path . --format sarif --output hostguard.sarif --fail-on high
    rc=$?
    set -e
    if [ "$rc" -eq 1 ]; then exit 1; fi

- name: Upload SARIF report
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: hostguard.sarif
```

---

## MCP Integration

`raksa-hostguard` implements a local Model Context Protocol (MCP) server over `stdio` JSON-RPC 2.0 so MCP-compatible clients and agents can audit host configs, run FIM checks, and inspect rule remediation directly.

```json
{
  "mcpServers": {
    "raksa-hostguard": {
      "command": "raksa-hostguard",
      "args": ["mcp"]
    }
  }
}
```

Available MCP tools:
- `hostguard_list_rules`: Return the full catalog of 14 `HOST-*` rules with CIS and MITRE D3FEND metadata.
- `hostguard_fim_snapshot`: Build and write a SHA-256 baseline JSON snapshot for specified host directories.
- `hostguard_fim_check`: Verify disk state against a saved baseline and return Raksa Schema v1 findings.
- `hostguard_audit_ssh`: Audit an `sshd_config` file path or inline text (max 1 MiB).
- `hostguard_audit_docker`: Audit a Dockerfile, Compose file, directory tree, or inline container config (max 1 MiB).

---

## Benchmarks

Measured with `cargo bench --locked` (release profile, Windows `x86_64`, 200 files totaling 16.00 MiB across 5 iterations for FIM, and 5,000 to 10,000 iterations for parsers):

| Benchmark | Workload | Elapsed | Throughput |
| :--- | :--- | :--- | :--- |
| `fim_create_snapshot` | 200 files (16.00 MiB) x 5 | 0.1372s | 7,290.8 files/s (583.26 MiB/s) |
| `fim_verify_snapshot` | 200 files (16.00 MiB) x 5 | 0.1483s | 6,741.1 files/s (539.29 MiB/s) |
| `audit_dockerfile` | 10,000 multi-stage parses | 0.0600s | 166,721.4 ops/s |
| `audit_compose` | 5,000 YAML compose parses | 0.0740s | 67,596.2 ops/s |

---

## Rule Catalog (CIS & MITRE D3FEND)

| Rule ID | Severity | Module | CIS Reference | MITRE D3FEND | Title |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `HOST-001` | Critical | `fim` | CIS Linux 6.1 | `D3-FIM` | Monitored file content modified |
| `HOST-002` | High | `fim` | CIS Linux 6.1 | `D3-FIM` | Monitored file deleted |
| `HOST-003` | Medium | `fim` | CIS Linux 6.1 | `D3-FIM` | Unexpected file added in monitored directory |
| `HOST-004` | High | `fim` | CIS Linux 6.1 | `D3-FIM` | Monitored file permissions changed |
| `HOST-101` | High | `ssh-auditor` | CIS Linux 5.2.8 | `D3-SUC` | SSH root login enabled |
| `HOST-102` | High | `ssh-auditor` | CIS Linux 5.2.12 | `D3-SUC` | SSH password authentication enabled |
| `HOST-103` | Critical | `ssh-auditor` | CIS Linux 5.2.9 | `D3-SUC` | SSH empty passwords permitted |
| `HOST-104` | Medium | `ssh-auditor` | CIS Linux 5.2.5-5.2.7 | `D3-SUC` | Weak SSH session hardening setting |
| `HOST-201` | High | `docker-auditor` | CIS Docker 4.1 | `D3-LPM` | Container configured to run as root |
| `HOST-202` | Critical | `docker-auditor` | CIS Docker 5.4 / 5.31 | `D3-LPM` | Privileged container or Docker socket mount |
| `HOST-203` | High | `docker-auditor` | CIS Docker 5.3 / 5.9 / 5.15 | `D3-NI` | Host namespace sharing or dangerous Linux capabilities |
| `HOST-204` | Medium | `docker-auditor` | CIS Docker 4.7 | `D3-SPP` | Unpinned or `:latest` container image tag |
| `HOST-205` | High | `docker-auditor` | CIS Docker 4.10 | `D3-SM` | Hardcoded secret literal in container environment |
| `HOST-206` | Medium | `docker-auditor` | CIS Docker 4.9 | `D3-SPP` | Unverified remote artifact fetch in Dockerfile |

---

## Raksa Security Suite

`raksa-hostguard` shares **Raksa Finding Schema v1** (`schema_version = "1.0"`) with the rest of the modular Raksa ecosystem:

- **Layer 1 (`network-defense`)**: [raksa-netguard](https://github.com/luminariadev/raksa-netguard) (Go) - Exposed port audit and real-time firewall/log anomaly detection.
- **Layer 2 (`host-hardening`)**: `raksa-hostguard` (Rust) - This repository.
- **Layer 3 (`web-defense`, planned)**: `raksa-webshield` (TypeScript + Go) - Anti-XSS middleware and HTTP security header auditor.
- **Layer 4 (`devsecops-ci`, planned)**: `raksa-pipeguard` (Go / Rust) - Secret scanning, SBOM audit, and IaC checks.
- **Layer 5 (`malware-ioc`, planned)**: `raksa-iocscan` (Python) - YARA, hash reputation, and entropy anomaly scanner.
- **Layer 6 (`observability-siem`, planned)**: `raksa-siem` (Python + Go) - Log normalizer, correlation engine, and alert router.

## License

Released under the [MIT License](LICENSE).

# raksa-hostguard

[![CI](https://github.com/luminariadev/raksa-hostguard/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa-hostguard/actions/workflows/ci.yml)
[![Release](https://github.com/luminariadev/raksa-hostguard/actions/workflows/release.yml/badge.svg)](https://github.com/luminariadev/raksa-hostguard/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)

Defensive host hardening, signed File Integrity Monitoring (FIM), and Linux/SSH/Docker CIS configuration auditor written in pure safe Rust (`#![forbid(unsafe_code)]`).

`raksa-hostguard` is **Layer 2 (`host-hardening`)** of the Raksa DevSecOps and Blue Team defense suite. It provides parallel SHA-256 integrity baselines with HMAC-SHA256 tamper protection, audits OpenSSH (`Include`-aware + weak crypto), Docker/Compose (`no-new-privileges`, `cap_drop`, Seccomp, public ports), and Linux host configs (`sysctl`, `sudoers`, SUID/permissions), outputs **Raksa Finding Schema v1** (`table`, `json`, `sarif` `2.1.0`), and runs a `stdio` JSON-RPC 2.0 MCP server with 7 tools.

---

## Key Capabilities

- **Parallel & HMAC-Signed FIM (`fim init` / `fim check` / `fim watch`)**: Multi-threaded streaming SHA-256 hashing (`std::thread::scope`, 64 KiB chunk buffers, symlink loop protection, 50 MiB file cap) with RFC 2104 HMAC-SHA256 baseline signing (`--sign-key-env`, detecting baseline tampering as `HOST-005`) and deduplicated polling watch mode (`fim watch`).
- **CIS OpenSSH Auditor (`audit-ssh`)**: Resolves `Include` drop-ins (depth <= 2 with cycle guard) and audits authentication directives (`HOST-101`..`HOST-104`), weak CBC/RC4/3DES/SHA-1/MD5 ciphers, MACs, and Kex (`HOST-105`), plus forwarding, `PermitUserEnvironment`, and `ClientAliveInterval` (`HOST-106`).
- **Multi-Stage Dockerfile & Compose Auditor (`audit-docker`)**: Checks final-stage non-root execution, `privileged: true` / `docker.sock`, host namespaces / `SYS_ADMIN`, unpinned/`:latest` images, secret literals (automatically redacted in reports), unverified `ADD`/`curl|sh`, `no-new-privileges:true` (`HOST-207`), `cap_drop: [ALL]` and sensitive host mounts (`HOST-208`), and unconfined Seccomp/AppArmor or public sensitive ports (`HOST-209`).
- **Linux Host CIS & Workspace Auditor (`audit-host` / `audit-workspace`)**: Audits `sysctl` network and kernel protections (`HOST-301`, `HOST-302`), unsafe file modes / world-writable / SUID/SGID (`HOST-303`), and `NOPASSWD ALL` / `!authenticate` sudoers rules (`HOST-304`), or scans an entire repo/host tree in one pass via `audit-workspace`.
- **Fail-Closed Suppression Policy (`--policy`)**: YAML/JSON policy files ([examples/hostguard-policy.yml](examples/hostguard-policy.yml)) support `min_severity`, `target_contains` scoping, mandatory audit reasons, and `expires_on` dates that automatically stop suppressing once expired.
- **Native MCP Server (`raksa-hostguard mcp`)**: Exposes 7 defensive inspection tools over newline-delimited `stdio` JSON-RPC 2.0 with 1 MiB inline payload caps.

---

## Defensive Scope & Boundaries

`raksa-hostguard` focuses on **static configuration auditing, baseline integrity verification, and periodic polling**. Understanding these boundaries prevents blind spots:

- **Periodic Watch vs. Kernel Inline Blocking**: `fim watch` verifies integrity periodically on a polling interval without loading kernel modules or eBPF probes. It detects tampering quickly but does not block syscalls inline.
- **Cross-Platform Permissions (`HOST-004` / `HOST-303`)**: On Linux/Unix targets, both octal permissions (`0600`, `4755`) and SUID/SGID/world-writable bits are checked. On Windows NTFS hosts, `audit-host --perms` skips Unix octal mode checks and `HOST-004` tracks read-only attribute changes.
- **Static Config vs. Live Network Exposure**: Static SSH/Docker/sysctl checks do not probe live TCP sockets (live network exposure detection belongs in Layer 1, [raksa-netguard](https://github.com/luminariadev/raksa-netguard)).

---

## Architecture

```text
+---------------------------------------------------------------------------------+
|                         CLI & stdio MCP Entrypoint                              |
|  fim init|check|watch | audit-ssh | audit-docker | audit-host | audit-workspace |
+--------+-----------------+----------------+---------------+---------------------+
         |                 |                |               |
         v                 v                v               v
+----------------+ +---------------+ +---------------+ +--------------------------+
| Parallel FIM   | | SSH Auditor   | | Docker/Compose| | Host Auditor             |
| + HMAC-SHA256  | | + Include/Kex | | + Cap/Seccomp | | sysctl + sudoers + perms |
+--------+-------+ +-------+-------+ +-------+-------+ +-------------+------------+
         |                 |                 |                       |
         +-----------------+--------+--------+-----------------------+
                                    |
                                    v
                     +------------------------------+
                     |  Policy Filter (--policy)    |
                     +--------------+---------------+
                                    |
                                    v
                     +------------------------------+
                     | Raksa Finding Schema v1      |
                     | Table | JSON | SARIF 2.1.0   |
                     +------------------------------+
```

See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md) for module details and trust boundaries.

---

## Installation

### 1. Prebuilt Release Binaries

Download archives for Linux (`x86_64-unknown-linux-musl`), Windows (`x86_64-pc-windows-msvc`), or macOS (`aarch64-apple-darwin`) and `SHA256SUMS.txt` from [GitHub Releases](https://github.com/luminariadev/raksa-hostguard/releases).

### 2. Build from Source (Rust 1.80+)

```bash
git clone https://github.com/luminariadev/raksa-hostguard.git
cd raksa-hostguard
cargo install --path . --locked
```

### 3. Container Image (Distroless Non-Root)

```bash
docker build -t raksa-hostguard:v0.2.0 .
docker run --rm raksa-hostguard:v0.2.0 version
```

---

## Quickstart & Verified Examples

### Version & Rule Catalog

```bash
raksa-hostguard version
# raksa-hostguard v0.2.0 (schema 1.0, layer host-hardening)

raksa-hostguard rules
```

### Audit Linux Host Kernel & Sudoers (`audit-host`)

```bash
raksa-hostguard audit-host \
  --sysctl testdata/sysctl_insecure.conf \
  --sudoers testdata/sudoers_insecure \
  --fail-on high
```

Verified output (`exit 2`):

```text
raksa-hostguard v0.2.0 | layer: host-hardening | total: 11 (critical: 0, high: 11, medium: 0, low: 0, info: 0)
SEVERITY  RULE       MODULE          TARGET                               TITLE
----------------------------------------------------------------------------------------------------
HIGH      HOST-302   host-auditor    file://testdata/sysctl_insecure.conf Weak kernel memory or process protection sysctl parameter
          fix: Set fs.suid_dumpable = 0 to prevent privileged binaries from writing core dumps containing secrets.
HIGH      HOST-302   host-auditor    file://testdata/sysctl_insecure.conf Weak kernel memory or process protection sysctl parameter
          fix: Set kernel.kptr_restrict = 1 (or 2 for strict isolation) in /etc/sysctl.d/.
HIGH      HOST-302   host-auditor    file://testdata/sysctl_insecure.conf Weak kernel memory or process protection sysctl parameter
          fix: Set kernel.randomize_va_space = 2 to enforce full Address Space Layout Randomization.
HIGH      HOST-301   host-auditor    file://testdata/sysctl_insecure.conf Insecure kernel network sysctl parameter
          fix: Set net.ipv4.ip_forward = 0 unless this host acts as a dedicated router/container bridge.
HIGH      HOST-304   host-auditor    file://testdata/sudoers_insecure     Unrestricted passwordless sudoers rule
          fix: Remove !authenticate from sudoers Defaults to require authentication for privilege escalation.
```

### Workspace Audit with Suppression Policy (`audit-workspace`)

```bash
raksa-hostguard audit-workspace \
  --path testdata \
  --policy testdata/policy_suppress.yml \
  --fail-on critical
```

Verified output (`exit 2`, `HOST-204` on `Dockerfile.insecure` suppressed by active policy):

```text
raksa-hostguard v0.2.0 | layer: host-hardening | total: 43 (critical: 3, high: 26, medium: 14, low: 0, info: 0)
```

### Audit OpenSSH & Docker (`audit-ssh` / `audit-docker`)

```bash
raksa-hostguard audit-ssh --path testdata/sshd_weak_crypto.conf --fail-on high
raksa-hostguard audit-docker --path testdata/docker-compose.unconfined.yml --fail-on high
```

Running directly inside the distroless Docker image:

```bash
docker run --rm -v "$(pwd)/testdata:/testdata:ro" \
  raksa-hostguard:v0.2.0 audit-host \
  --sysctl /testdata/sysctl_insecure.conf \
  --sudoers /testdata/sudoers_insecure \
  --fail-on high
```

### Signed & Parallel FIM (`fim init` / `fim check` / `fim watch`)

```bash
export RAKSA_FIM_KEY="replace-with-random-256-bit-secret"

# 1. Create a signed baseline using parallel worker threads
raksa-hostguard fim init --path /etc/ssh --out ssh-baseline.json --sign-key-env RAKSA_FIM_KEY

# 2. Verify integrity and baseline authenticity (exit 2 + HOST-005 if baseline was tampered)
raksa-hostguard fim check --baseline ssh-baseline.json --sign-key-env RAKSA_FIM_KEY --fail-on critical

# 3. Monitor continuously with deduplicated drift alerts
raksa-hostguard fim watch --baseline ssh-baseline.json --interval-secs 10 --sign-key-env RAKSA_FIM_KEY
```

Verified output when a signed baseline signature is modified (`HOST-005`, `exit 2`):

```text
FIM baseline created: .../signed.json (signed: true)
  files hashed: 1 | total bytes: 21 | skipped oversize: 0 | skipped unreadable: 0
raksa-hostguard v0.2.0 | layer: host-hardening | total: 1 (critical: 1, high: 0, medium: 0, low: 0, info: 0)
SEVERITY  RULE       MODULE          TARGET                               TITLE
----------------------------------------------------------------------------------------------------
CRITICAL  HOST-005   fim             baseline://snapshot                  FIM baseline HMAC-SHA256 signature invalid or missing
          fix: Re-verify the baseline against a trusted offline copy or regenerate it with 'fim init --sign-key-env ...'.
```

---

## CI/CD SARIF Integration

Export findings in **SARIF 2.1.0** for GitHub Code Scanning with `--policy` and `--fail-on` severity gating:

```yaml
- name: Run raksa-hostguard workspace audit
  run: |
    set +e
    raksa-hostguard audit-workspace --path . --policy .hostguard.yml --format sarif --output hostguard.sarif --fail-on high
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

`raksa-hostguard mcp` exposes 7 tools over `stdio` JSON-RPC 2.0 so MCP-compatible clients and agents can inspect workspaces, sysctl/sudoers configs, SSH/Docker manifests, and signed FIM baselines:

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
- `hostguard_list_rules`: Return all 24 `HOST-*` rules with CIS and MITRE D3FEND metadata.
- `hostguard_fim_snapshot`: Build a SHA-256 baseline JSON snapshot (optional `workers`, `sign_key_env`).
- `hostguard_fim_check`: Verify disk state and optional HMAC signature (optional `workers`, `sign_key_env`, `policy_path`).
- `hostguard_audit_ssh`: Audit `sshd_config` files (with `Include` resolution) or inline text (max 1 MiB).
- `hostguard_audit_docker`: Audit Dockerfiles, Compose files, directories, or inline container config (max 1 MiB).
- `hostguard_audit_host`: Audit `sysctl`, `sudoers`, or host `permissions` (with optional `policy_path`).
- `hostguard_audit_workspace`: Recursively audit a full workspace across SSH, Docker, sysctl, and sudoers (with optional `policy_path`).

---

## Benchmarks

Measured with `cargo bench --locked` (`v0.2.0` release profile, Windows `x86_64`, `workers=8`, 200 files totaling 16.00 MiB across 5 iterations for FIM, and 5,000 to 10,000 iterations for config auditors):

| Benchmark | Workload | Elapsed | Throughput |
| :--- | :--- | :--- | :--- |
| `fim_create_snapshot_1w` | 200 files (16.00 MiB) x 5, 1 worker | 0.1171s | 8,536.9 files/s (682.95 MiB/s) |
| `fim_create_snapshot_parallel` | 200 files (16.00 MiB) x 5, 8 workers | 0.0313s | 31,984.4 files/s (2,558.76 MiB/s) |
| `fim_verify_snapshot_parallel` | 200 files (16.00 MiB) x 5, 8 workers | 0.0370s | 27,037.1 files/s (2,162.97 MiB/s) |
| `audit_dockerfile` | 10,000 multi-stage parses | 0.0623s | 160,420.7 ops/s |
| `audit_compose` | 5,000 YAML compose parses | 0.0859s | 58,235.1 ops/s |
| `audit_sysctl` | 10,000 sysctl config parses | 0.0286s | 349,592.9 ops/s |

---

## Rule Catalog (24 CIS & MITRE D3FEND Rules)

| Rule ID | Severity | Module | CIS Reference | MITRE D3FEND | Title |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `HOST-001` | Critical | `fim` | CIS Linux 6.1 | `D3-FIM` | Monitored file content modified |
| `HOST-002` | High | `fim` | CIS Linux 6.1 | `D3-FIM` | Monitored file deleted |
| `HOST-003` | Medium | `fim` | CIS Linux 6.1 | `D3-FIM` | Unexpected file added in monitored directory |
| `HOST-004` | High | `fim` | CIS Linux 6.1 | `D3-FIM` | Monitored file permissions changed |
| `HOST-005` | Critical | `fim` | CIS Linux 6.1 | `D3-FIM` | FIM baseline HMAC-SHA256 signature invalid or missing |
| `HOST-101` | High | `ssh-auditor` | CIS Linux 5.2.8 | `D3-SUC` | SSH root login enabled |
| `HOST-102` | High | `ssh-auditor` | CIS Linux 5.2.12 | `D3-SUC` | SSH password authentication enabled |
| `HOST-103` | Critical | `ssh-auditor` | CIS Linux 5.2.9 | `D3-SUC` | SSH empty passwords permitted |
| `HOST-104` | Medium | `ssh-auditor` | CIS Linux 5.2.5-5.2.7 | `D3-SUC` | Weak SSH session hardening setting |
| `HOST-105` | High | `ssh-auditor` | CIS Linux 5.2.13-5.2.15 | `D3-SUC` | Weak or deprecated SSH cryptographic algorithms configured |
| `HOST-106` | Medium | `ssh-auditor` | CIS Linux 5.2.16-5.2.19 | `D3-SUC` | Weak SSH forwarding or idle session timeout policy |
| `HOST-201` | High | `docker-auditor` | CIS Docker 4.1 | `D3-LPM` | Container configured to run as root |
| `HOST-202` | Critical | `docker-auditor` | CIS Docker 5.4 / 5.31 | `D3-LPM` | Privileged container or Docker socket mount |
| `HOST-203` | High | `docker-auditor` | CIS Docker 5.3 / 5.9 / 5.15 | `D3-NI` | Host namespace sharing or dangerous Linux capabilities |
| `HOST-204` | Medium | `docker-auditor` | CIS Docker 4.7 | `D3-SPP` | Unpinned or `:latest` container image tag |
| `HOST-205` | High | `docker-auditor` | CIS Docker 4.10 | `D3-SM` | Hardcoded secret literal in container environment |
| `HOST-206` | Medium | `docker-auditor` | CIS Docker 4.9 | `D3-SPP` | Unverified remote artifact fetch in Dockerfile |
| `HOST-207` | Medium | `docker-auditor` | CIS Docker 5.12 / 5.25 | `D3-LPM` | Compose service missing no-new-privileges hardening |
| `HOST-208` | Medium | `docker-auditor` | CIS Docker 5.3 / 5.5 | `D3-NI` | Compose service omits cap_drop ALL or binds sensitive host path |
| `HOST-209` | High | `docker-auditor` | CIS Docker 5.1 / 5.13 / 5.21 | `D3-NI` | Container disables Seccomp/AppArmor or exposes sensitive port publicly |
| `HOST-301` | High | `host-auditor` | CIS Linux 3.1-3.3 | `D3-CH` | Insecure kernel network sysctl parameter |
| `HOST-302` | High | `host-auditor` | CIS Linux 1.5.1-1.5.2 | `D3-CH` | Weak kernel memory or process protection sysctl parameter |
| `HOST-303` | Critical | `host-auditor` | CIS Linux 6.1.2-6.1.9 | `D3-LPM` | Overly permissive file mode, world-writable file, or unauthorized SUID/SGID |
| `HOST-304` | High | `host-auditor` | CIS Linux 5.3.4 | `D3-SUC` | Unrestricted passwordless sudoers rule |

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

# raksa-hostguard

[![CI](https://github.com/luminariadev/raksa-hostguard/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa-hostguard/actions/workflows/ci.yml)
[![Release](https://github.com/luminariadev/raksa-hostguard/actions/workflows/release.yml/badge.svg)](https://github.com/luminariadev/raksa-hostguard/actions/workflows/release.yml)
[![GitHub Release](https://img.shields.io/github/v/release/luminariadev/raksa-hostguard)](https://github.com/luminariadev/raksa-hostguard/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-4c1.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![MCP](https://img.shields.io/badge/MCP-9%20tools-6f42c1.svg)](#mcp-integration)

Defensive host hardening, event-driven signed File Integrity Monitoring (FIM), and Linux/SSH/Docker CIS configuration auditor written in pure safe Rust (`#![forbid(unsafe_code)]`).

`raksa-hostguard` is **Layer 2 (`host-hardening`)** of the Raksa DevSecOps and Blue Team defense suite. In `v0.3.0`, it delivers parallel SHA-256 + HMAC-SHA256 integrity baselines with kernel event-driven `notify` watching (`--siem-out` Schema v1 NDJSON streaming), `29` CIS hardening rules across OpenSSH, Docker/Compose/`daemon.json`/Podman, `sysctl`, `sudoers`, permissions, `systemd`, persistence hooks, PAM/`login.defs`, and `modprobe.d`/`auditd`, read-only unified remediation diffs (`fix-preview`), `0-100 (A+..F)` posture scoring, deterministic `--baseline` suppression, `table|json|sarif|markdown|ndjson` output, and a 9-tool `stdio` JSON-RPC 2.0 MCP server.

---

## Key Capabilities (`v0.3.0`)

- **Event-Driven & HMAC-Signed FIM (`fim init` / `fim check` / `fim watch`)**: Multi-threaded streaming SHA-256 hashing (`std::thread::scope`, 64 KiB chunks, symlink loop protection, 50 MiB file cap) at `2,833.54 MiB/s` with RFC 2104 HMAC-SHA256 baseline signing (`--sign-key-env`, detecting baseline tampering as `HOST-005`). `fim watch --watch-mode auto|events|poll` uses OS kernel filesystem events (`inotify`/`ReadDirectoryChangesW`/`kqueue` via `notify`) with burst debouncing, periodic full-hash reconciliation, and `--siem-out` NDJSON telemetry streaming to Layer 6 (`raksa-siem`).
- **CIS OpenSSH Auditor (`audit-ssh`)**: Resolves `Include` drop-ins (`depth <= 2` with cycle guard) and audits authentication (`HOST-101`..`104`), weak CBC/RC4/3DES/SHA-1/MD5 crypto (`HOST-105`), forwarding, `PermitUserEnvironment`, and `ClientAliveInterval` (`HOST-106`).
- **Container & Runtime Daemon Auditor (`audit-docker`)**: Audits multi-stage Dockerfiles and Compose manifests (`HOST-201`..`209`) plus Docker `daemon.json` and Podman `containers.conf` (`HOST-210`: unauthenticated `tcp://` without `tlsverify`, `icc: false`, `no-new-privileges`, `userns-remap`, `live-restore`, Podman `privileged`/`netns=host`).
- **Expanded Linux Host & Workspace CIS Auditor (`audit-host` / `audit-workspace`)**: Audits `sysctl` (`HOST-301`, `HOST-302`), permissions/SUID/keys (`HOST-303`), `sudoers` (`HOST-304`), `systemd` `.service` units & `.service.d/*.conf` drop-ins (`HOST-305`), cron/anacron/persistence hooks (`HOST-306`), PAM & `login.defs` policies (`HOST-307`), and `modprobe.d` / `auditd.conf` / `audit.rules` (`HOST-308`), or scans an entire workspace with auto-discovered `.hostguard.yml` via `audit-workspace`.
- **Read-Only Remediation Diffs (`fix-preview`)**: Generates deterministic unified patches (`--format diff` or `json`) for SSH, sysctl, Dockerfile, Compose, systemd, and `daemon.json` without mutating host files on disk.
- **Suite Parity: Posture Scoring, `--baseline`, & PR Markdown/NDJSON**: Computes `0-100` (`A+..F`) posture scores, writes/applies SHA-256 `--baseline` finding fingerprints (`--findings-baseline` on `fim check`), validates fail-closed `.hostguard.yml` suppressions (`expires_on`), and outputs `table`, `json`, `sarif` `2.1.0`, `markdown`, or `ndjson`.
- **9-Tool Native MCP Server (`raksa-hostguard mcp`)**: Exposes `9` defensive tools over newline-delimited `stdio` JSON-RPC 2.0 with `1 MiB` inline config caps and `2 MiB` RPC frame caps.

---

## Defensive Scope & Boundaries

`raksa-hostguard` focuses on **static host/container configuration auditing, baseline integrity verification, and read-only remediation previews**:

- **Event Watch & Reconciliation vs. Kernel Syscall Blocking**: `fim watch --watch-mode events` receives OS filesystem notifications and falls back cleanly to periodic reconciliation sweeps (`--interval-secs`) without installing custom kernel modules or blocking syscalls inline.
- **Read-Only `fix-preview`**: Unified diffs show exact recommended hardening patches for review in Git PRs or operator approval without modifying `/etc/` or workspace configs automatically.
- **Cross-Platform Permissions (`HOST-004` / `HOST-303`)**: On Linux/Unix targets, both octal permissions (`0600`, `4755`) and SUID/SGID/world-writable bits are checked. On Windows NTFS hosts, `audit-host --perms` skips Unix octal mode checks and `HOST-004` tracks read-only attribute changes.
- **Static Config vs. Live Network Exposure**: Live port/socket and flow log auditing belongs in Layer 1 ([raksa-netguard](https://github.com/luminariadev/raksa-netguard)).

---

## Architecture

```text
+---------------------------------------------------------------------------------------------------+
|                                   CLI & 9-Tool stdio MCP Entrypoint                               |
|  fim init|check|watch | audit-ssh | audit-docker | audit-host | audit-workspace | fix-preview     |
+--------+---------------------+-------------------+---------------------+--------------------------+
         |                     |                   |                     |
         v                     v                   v                     v
+------------------+ +------------------+ +--------------------+ +----------------------------------+
| Parallel FIM     | | SSH Auditor      | | Docker & Daemon    | | Host Auditor                     |
| notify + HMAC    | | Include + Crypto | | Dockerfile/Compose | | sysctl/sudoers/perms/systemd/    |
| --siem-out       | |                  | | daemon.json/Podman | | persistence/PAM/modprobe/auditd  |
+--------+---------+ +--------+---------+ +---------+----------+ +----------------+-----------------+
         |                    |                     |                             |
         +--------------------+----------+----------+-----------------------------+
                                         |
                                         v
                      +--------------------------------------+
                      | Policy (.hostguard.yml) & Baselines  |
                      +------------------+-------------------+
                                         |
                                         v
                      +--------------------------------------+
                      | Raksa Schema v1 + Posture (0-100 A+) |
                      | Table | JSON | SARIF | MD | NDJSON   |
                      +--------------------------------------+
```

See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md) for module details and trust boundaries.

---

## Installation

### 1. Prebuilt Release Binaries

Download archives for Linux (`x86_64-unknown-linux-musl`), Windows (`x86_64-pc-windows-msvc`), or macOS (`aarch64-apple-darwin`) and `SHA256SUMS.txt` from [GitHub Releases](https://github.com/luminariadev/raksa-hostguard/releases).

### 2. Build from Source (Rust 1.88+)

```bash
git clone https://github.com/luminariadev/raksa-hostguard.git
cd raksa-hostguard
cargo install --path . --locked
```

### 3. Container Image (Distroless Non-Root)

```bash
docker build -t raksa-hostguard:v0.3.0 .
docker run --rm raksa-hostguard:v0.3.0 version
```

---

## Quickstart & Verified Examples

### Version & Rule Catalog

```bash
raksa-hostguard version
# raksa-hostguard v0.3.0 (schema 1.0, layer host-hardening)

raksa-hostguard rules
```

### Audit Host Hardening & Runtime Daemon (`audit-host` / `audit-docker`)

```bash
raksa-hostguard audit-host \
  --sysctl testdata/sysctl_insecure.conf \
  --sudoers testdata/sudoers_insecure \
  --systemd testdata/app.insecure.service \
  --persistence testdata/cron_insecure \
  --auth-policy testdata/login_insecure.defs \
  --kernel-audit testdata/audit_insecure.rules \
  --format markdown \
  --fail-on high

raksa-hostguard audit-docker --path testdata/daemon.insecure.json --format json --fail-on high
```

### Generate Read-Only Remediation Patches (`fix-preview`)

```bash
raksa-hostguard fix-preview \
  --path testdata/app.insecure.service \
  --kind systemd \
  --format diff
```

Verified diff preview output:

```diff
# testdata/app.insecure.service (HOST-305)
--- a/testdata/app.insecure.service
+++ b/testdata/app.insecure.service
@@ -1,10 +1,11 @@
 [Unit]
 Description=Insecure Unhardened Service

 [Service]
-User=root
-NoNewPrivileges=no
-ProtectSystem=no
+User=nonroot
+NoNewPrivileges=yes
+ProtectSystem=strict
 ExecStart=/var/tmp/stage-runner --daemon
+ProtectHome=yes
```

### Baseline Suppression & Workspace Audit (`--write-baseline` / `--baseline`)

```bash
# Snapshot acknowledged legacy findings, then gate CI only on new drift
raksa-hostguard audit-workspace --path testdata --write-baseline baselines/host.json --format json
raksa-hostguard audit-workspace --path testdata --baseline baselines/host.json --fail-on low
```

### Event-Driven Signed FIM with `raksa-siem` Streaming (`--watch-mode events --siem-out`)

```bash
export RAKSA_FIM_KEY="replace-with-random-256-bit-secret"

raksa-hostguard fim init --path /etc/ssh --out ssh-baseline.json --sign-key-env RAKSA_FIM_KEY
raksa-hostguard fim check --baseline ssh-baseline.json --sign-key-env RAKSA_FIM_KEY --fail-on critical

# Kernel-event notify watch with 250ms debounce and Schema v1 NDJSON streaming for raksa-siem
raksa-hostguard fim watch \
  --baseline ssh-baseline.json \
  --watch-mode events \
  --debounce-ms 250 \
  --interval-secs 30 \
  --siem-out /var/log/raksa/hostguard-events.ndjson \
  --sign-key-env RAKSA_FIM_KEY
```

---

## CI/CD SARIF & PR Markdown Integration

Export findings in **SARIF 2.1.0** or **Markdown** with `--policy`, `--baseline`, and `--fail-on` severity gating:

```yaml
- name: Run raksa-hostguard workspace audit
  run: |
    set +e
    raksa-hostguard audit-workspace --path . --format sarif --output hostguard.sarif --fail-on high
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

`raksa-hostguard mcp` exposes **9 tools** over `stdio` JSON-RPC 2.0 so MCP-compatible clients and triage agents can inspect hosts, configs, FIM baselines, and generated diff previews:

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

Available MCP tools (`9`):
- `hostguard_list_rules`: Return all 29 `HOST-*` rules with CIS and MITRE D3FEND metadata.
- `hostguard_fim_snapshot`: Build a SHA-256 baseline JSON snapshot (optional `workers`, `sign_key_env`).
- `hostguard_fim_check`: Verify disk state and optional HMAC signature (optional `workers`, `sign_key_env`, `policy_path`).
- `hostguard_audit_ssh`: Audit `sshd_config` files (with `Include` resolution) or inline text (max 1 MiB).
- `hostguard_audit_docker`: Audit Dockerfiles, Compose files, `daemon.json`, Podman `containers.conf`, directories, or inline content.
- `hostguard_audit_host`: Audit `sysctl`, `sudoers`, `permissions`, `systemd`, `persistence`, `auth`, or `kernel` targets (with optional `policy_path`).
- `hostguard_audit_workspace`: Recursively audit a full workspace across SSH, Docker/daemon, sysctl, sudoers, systemd, persistence, auth, and kernel configs.
- `hostguard_audit_systemd`: Dedicated audit of `systemd` `.service` units and `.service.d/*.conf` drop-ins (`HOST-305`).
- `hostguard_suggest_fix`: Generate read-only unified hardening patches for SSH, sysctl, Dockerfile, Compose, systemd, or `daemon.json`.

---

## Benchmarks (`v0.3.0`)

Measured with `cargo bench --locked` (`v0.3.0` release profile, Windows `x86_64`, `workers=8`, 200 files totaling 16.00 MiB across 5 iterations for FIM, and 5,000 to 10,000 iterations for config auditors), release binary size `4,942,811` bytes (`4.71 MiB`), and 51-frame warm MCP stdio burst `15.19 ms` (`0.304 ms/call`):

| Benchmark | Workload | Elapsed | Throughput |
| :--- | :--- | :--- | :--- |
| `fim_create_snapshot_1w` | 200 files (16.00 MiB) x 5, 1 worker | 0.1210s | 8,262.7 files/s (661.02 MiB/s) |
| `fim_create_snapshot_parallel` | 200 files (16.00 MiB) x 5, 8 workers | 0.0282s | 35,419.3 files/s (2,833.54 MiB/s) |
| `fim_verify_snapshot_parallel` | 200 files (16.00 MiB) x 5, 8 workers | 0.0367s | 27,216.4 files/s (2,177.32 MiB/s) |
| `audit_dockerfile` | 10,000 multi-stage parses | 0.0601s | 166,371.6 ops/s |
| `audit_compose` | 5,000 YAML compose parses | 0.0862s | 57,986.7 ops/s |
| `audit_sysctl` | 10,000 sysctl config parses | 0.0279s | 358,561.7 ops/s |
| `audit_systemd` | 10,000 systemd service unit parses | 0.0126s | 793,606.7 ops/s |
| `fix_preview` | 5,000 systemd diff generations | 0.0143s | 349,235.2 ops/s |

---

## Rule Catalog (29 CIS & MITRE D3FEND Rules)

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
| `HOST-210` | High | `docker-auditor` | CIS Docker 2.1-2.16 | `D3-CH` | Insecure container runtime daemon configuration |
| `HOST-301` | High | `host-auditor` | CIS Linux 3.1-3.3 | `D3-CH` | Insecure kernel network sysctl parameter |
| `HOST-302` | High | `host-auditor` | CIS Linux 1.5.1-1.5.2 | `D3-CH` | Weak kernel memory or process protection sysctl parameter |
| `HOST-303` | Critical | `host-auditor` | CIS Linux 6.1.2-6.1.9 | `D3-LPM` | Overly permissive file mode, world-writable file, or unauthorized SUID/SGID |
| `HOST-304` | High | `host-auditor` | CIS Linux 5.3.4 | `D3-SUC` | Unrestricted passwordless sudoers rule |
| `HOST-305` | High | `host-auditor` | CIS Linux 5.x | `D3-CH` | Weak systemd service hardening or unsafe ExecStart target |
| `HOST-306` | High | `host-auditor` | CIS Linux 5.1 | `D3-SPP` | Suspicious cron, anacron, at, or shell profile persistence hook |
| `HOST-307` | High | `host-auditor` | CIS Linux 5.3.2 / 5.4.1 | `D3-SUC` | Weak PAM authentication/lockout or login.defs password policy |
| `HOST-308` | Medium | `host-auditor` | CIS Linux 1.1.1 / 4.1 | `D3-CH` | Missing kernel module blacklist or weak auditd logging policy |

---

## Raksa Security Suite

`raksa-hostguard` shares **Raksa Finding Schema v1** (`schema_version = "1.0"`) across all six modular layers of the Raksa ecosystem:

- **Layer 1 (`network-defense`)**: [raksa-netguard](https://github.com/luminariadev/raksa-netguard) (Go) - Exposed port baseline auditor and real-time firewall/flow log anomaly detector.
- **Layer 2 (`host-hardening`)**: `raksa-hostguard` (Rust) - This repository.
- **Layer 3 (`web-defense`)**: [raksa-webshield](https://github.com/luminariadev/raksa-webshield) (TypeScript + Go) - Web/API security auditor, semantic SQLi/XSS WAF sidecar, TypeScript SDK, and MCP server.
- **Layer 4 (`devsecops`)**: [raksa-pipeguard](https://github.com/luminariadev/raksa-pipeguard) (Go) - Secret/diff scanner, CycloneDX & SPDX SBOMs, OSV/KEV/EPSS SCA, container tarball auditor, IaC/CI linters, and MCP server.
- **Layer 5 (`ioc-defense`)**: [raksa-iocscan](https://github.com/luminariadev/raksa-iocscan) (Python) - Zero-dep YARA, FastCDC fuzzy hash, PE Authenticode/Fat Mach-O triage, archive/doc scanner, watch daemon, and MCP server.
- **Layer 6 (`observability-siem`)**: [raksa-siem](https://github.com/luminariadev/raksa-siem) (Go + Python) - 13-format SIEM normalizer, Sigma YAML & sequence correlator, hash-chained ledger, mTLS collector, MCP server, and Python SDK.

## License

Released under the [MIT License](LICENSE).

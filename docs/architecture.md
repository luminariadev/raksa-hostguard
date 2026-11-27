# raksa-hostguard Architecture

`raksa-hostguard` is the Layer 2 (`host-hardening`) component of the Raksa security suite. Built with `#![forbid(unsafe_code)]` and pure-Rust crates without C/native `-sys` FFI dependencies, it inspects host filesystem integrity, generates read-only hardening patches, and audits Linux/SSH/Docker/systemd/PAM/kernel hardening configurations offline or over `stdio` MCP.

## Component Flow

```text
  [ Local Filesystem ]    [ sshd_config + Include ]    [ Docker / Daemon ]    [ sysctl / systemd / cron / PAM / auditd ]
           |                          |                         |                                    |
           v                          v                         v                                    v
  +------------------+      +-------------------+     +--------------------+      +------------------------------------+
  | fim (notify +    |      |   audit::ssh      |     |   audit::docker    |      |           audit::host              |
  | parallel HMAC)   |      |   (CIS 5.2.x)     |     |   (CIS 2.x/4/5.x)  |      | (CIS 1/3/4/5/6 + drop-ins)         |
  +--------+---------+      +---------+---------+     +---------+----------+      +-----------------+------------------+
           |                          |                         |                                   |
           +--------------------------+-------------------------+-----------------------------------+
                                      |
                                      v
                           +----------------------------------------+
                           | policy (.hostguard.yml) + baselines    |
                           +------------------+---------------------+
                                              |
                                              v
                           +----------------------------------------+
                           | schema::Report (v1 + Posture 0-100)    |
                           +------+--------+--------+--------+------+
                                  |        |        |        |
                                  v        v        v        v
                              [ Table ] [ JSON ] [ SARIF ] [ MD / NDJSON ]
                                              |
                                              v
                           +----------------------------------------+
                           | mcp::Server (9 tools) + fix::preview   |
                           +----------------------------------------+
```

## Module Responsibilities

- `src/main.rs`: CLI dispatcher (`fim init|check|watch`, `audit-ssh`, `audit-docker`, `audit-host`, `audit-workspace`, `fix-preview`, `rules`, `mcp`, `version`) using `clap` derive with standardized CI gate exit codes (`0` clean, `1` error, `2` threshold breach).
- `src/schema/`: Canonical Raksa Finding Schema v1 (`Report`, `PostureScore`, `Finding`, `Severity`, `Summary`) and built-in `rule_catalog()` (`29` `HOST-*` rules).
- `src/policy/`: YAML/JSON `.hostguard.yml` auto-discovery & suppression engine (`min_severity`, `rule_id`, `target_contains`, mandatory audit `reason`, fail-closed `expires_on`) plus deterministic SHA-256 `FindingBaseline` gating.
- `src/fim/`:
  - `hash.rs`: Bounded streaming SHA-256 hasher (64 KiB buffer, configurable max file size cap).
  - `sign.rs`: RFC 2104/4231 HMAC-SHA256 baseline signing and constant-time tag verification.
  - `mod.rs`: Symlink-safe traversal (`follow_links(false)`), `std::thread::scope` parallel hashing/verification (`HOST-001`..`HOST-005`), and event-driven `notify` watch + burst debounce + periodic reconciliation.
- `src/audit/`:
  - `ssh.rs`: OpenSSH `sshd_config` parser with bounded `Include` recursion and cipher/MAC/Kex/timeout audits (`HOST-101`..`HOST-106`).
  - `docker.rs`: Multi-stage `Dockerfile`, `docker-compose` YAML, Docker `daemon.json`, and Podman `containers.conf` auditor (`HOST-201`..`HOST-210`).
  - `host.rs`: Linux `sysctl`, `sudoers`, file permissions/SUID, `systemd` units + `.service.d` drop-ins, persistence hooks, PAM/`login.defs`, and `modprobe.d`/`auditd` auditors (`HOST-301`..`HOST-308`).
  - `mod.rs`: Shared bounded file reader (`1 MiB` cap) and recursive `audit_workspace` aggregator.
- `src/fix/`: Read-only deterministic hardening engine and bounded LCS unified diff builder (`FixKind`, `FixPatch`).
- `src/report/`: ANSI-sanitized `table` (with posture score), Schema v1 `json`, `sarif` `2.1.0`, GitHub PR `markdown`, and Schema v1 `ndjson` serializers.
- `src/mcp/`: Dependency-free `stdio` JSON-RPC 2.0 MCP server exposing `9` defensive `hostguard_*` tools.

## Rule, CIS & MITRE D3FEND Coverage (29 Rules)

| Rule ID | Module | Control | CIS Reference | MITRE D3FEND |
| :--- | :--- | :--- | :--- | :--- |
| `HOST-001` | `fim` | File content SHA-256 modified | CIS Linux 6.1 | `D3-FIM` |
| `HOST-002` | `fim` | Monitored baseline file deleted | CIS Linux 6.1 | `D3-FIM` |
| `HOST-003` | `fim` | Unexpected new file in monitored path | CIS Linux 6.1 | `D3-FIM` |
| `HOST-004` | `fim` | File permission or mode drift | CIS Linux 6.1 | `D3-FIM` |
| `HOST-005` | `fim` | Signed baseline HMAC-SHA256 invalid or missing | CIS Linux 6.1 | `D3-FIM` |
| `HOST-101` | `ssh-auditor` | SSH root login enabled (`PermitRootLogin yes`) | CIS Linux 5.2.8 | `D3-SUC` |
| `HOST-102` | `ssh-auditor` | SSH password authentication enabled | CIS Linux 5.2.12 | `D3-SUC` |
| `HOST-103` | `ssh-auditor` | SSH empty passwords permitted | CIS Linux 5.2.9 | `D3-SUC` |
| `HOST-104` | `ssh-auditor` | X11 forwarding, high `MaxAuthTries`, or Protocol 1 | CIS Linux 5.2.5-5.2.7 | `D3-SUC` |
| `HOST-105` | `ssh-auditor` | Weak SSH ciphers, MACs, or SHA-1 Kex algorithms | CIS Linux 5.2.13-5.2.15 | `D3-SUC` |
| `HOST-106` | `ssh-auditor` | Agent/TCP forwarding, env override, or idle timeout | CIS Linux 5.2.16-5.2.19 | `D3-SUC` |
| `HOST-201` | `docker-auditor` | Container runs as root / missing final `USER` | CIS Docker 4.1 | `D3-LPM` |
| `HOST-202` | `docker-auditor` | Privileged mode or Docker socket mounted | CIS Docker 5.4 / 5.31 | `D3-LPM` |
| `HOST-203` | `docker-auditor` | Host network/PID namespace or `SYS_ADMIN`/`ALL` cap | CIS Docker 5.3 / 5.9 / 5.15 | `D3-NI` |
| `HOST-204` | `docker-auditor` | Unpinned or `:latest` base/service image tag | CIS Docker 4.7 | `D3-SPP` |
| `HOST-205` | `docker-auditor` | Hardcoded secret literal in container `ENV`/`environment` | CIS Docker 4.10 | `D3-SM` |
| `HOST-206` | `docker-auditor` | Remote `ADD` URL or unverified pipe-to-shell `RUN` | CIS Docker 4.9 | `D3-SPP` |
| `HOST-207` | `docker-auditor` | Missing `no-new-privileges:true` in Compose `security_opt` | CIS Docker 5.12 / 5.25 | `D3-LPM` |
| `HOST-208` | `docker-auditor` | Missing `cap_drop: [ALL]` or sensitive host bind mount | CIS Docker 5.3 / 5.5 | `D3-NI` |
| `HOST-209` | `docker-auditor` | Unconfined Seccomp/AppArmor or wildcard sensitive port | CIS Docker 5.1 / 5.13 / 5.21 | `D3-NI` |
| `HOST-210` | `docker-auditor` | Docker `daemon.json` or Podman `containers.conf` drift | CIS Docker 2.1-2.16 | `D3-CH` |
| `HOST-301` | `host-auditor` | Insecure kernel network sysctl parameter | CIS Linux 3.1-3.3 | `D3-CH` |
| `HOST-302` | `host-auditor` | Weak ASLR, ptrace, kptr, dmesg, or `suid_dumpable` sysctl | CIS Linux 1.5.1-1.5.2 | `D3-CH` |
| `HOST-303` | `host-auditor` | World-writable, SUID/SGID, or open private key/credential mode | CIS Linux 6.1.2-6.1.9 | `D3-LPM` |
| `HOST-304` | `host-auditor` | Unrestricted `NOPASSWD ALL` or `Defaults !authenticate` | CIS Linux 5.3.4 | `D3-SUC` |
| `HOST-305` | `host-auditor` | Weak `systemd` sandboxing or untrusted `ExecStart` path | CIS Linux 5.x | `D3-CH` |
| `HOST-306` | `host-auditor` | Suspicious cron, anacron, `at`, or shell persistence hook | CIS Linux 5.1 | `D3-SPP` |
| `HOST-307` | `host-auditor` | Weak PAM (`nullok`/`pam_permit`/lockout) or `login.defs` | CIS Linux 5.3.2 / 5.4.1 | `D3-SUC` |
| `HOST-308` | `host-auditor` | Missing `modprobe.d` blacklists or weak `auditd` rules | CIS Linux 1.1.1 / 4.1 | `D3-CH` |

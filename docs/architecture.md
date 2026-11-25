# raksa-hostguard Architecture

`raksa-hostguard` is the Layer 2 (`host-hardening`) component of the Raksa security suite. Built with `#![forbid(unsafe_code)]` and zero C/native `-sys` dependencies, it inspects host filesystem integrity and Linux/SSH/Docker hardening configurations offline or over `stdio` MCP without kernel modules.

## Component Flow

```text
  [ Local Filesystem ]    [ sshd_config + Include ]    [ Dockerfile / Compose ]    [ sysctl / sudoers / perms ]
           |                          |                            |                            |
           v                          v                            v                            v
  +------------------+      +-------------------+       +-------------------+        +--------------------+
  | fim (Parallel +  |      |   audit::ssh      |       |  audit::docker    |        |    audit::host     |
  | HMAC-SHA256)     |      |   (CIS 5.2.x)     |       |  (CIS 4.x / 5.x)  |        |    (CIS 1/3/5/6)   |
  +--------+---------+      +---------+---------+       +---------+---------+        +----------+---------+
           |                          |                           |                             |
           +--------------------------+---------------------------+-----------------------------+
                                      |
                                      v
                           +---------------------+
                           |   policy::apply     | (.hostguard.yml + expires_on)
                           +----------+----------+
                                      |
                                      v
                           +---------------------+
                           | schema::Report (v1) | (Summary + --fail-on gate)
                           +----+-----+-----+----+
                                |     |     |
                      +---------+     |     +---------+
                      v               v               v
                +-----------+   +-----------+   +-----------+
                |   Table   |   |   JSON    |   | SARIF 2.1 |
                | ANSI-Safe |   | Schema v1 |   | Code Scan |
                +-----------+   +-----------+   +-----------+
                                      |
                                      v
                           +---------------------+
                           |    mcp::Server      | (7 tools over stdio JSON-RPC 2.0)
                           +---------------------+
```

## Module Responsibilities

- `src/main.rs`: CLI dispatcher (`fim init`, `fim check`, `fim watch`, `audit-ssh`, `audit-docker`, `audit-host`, `audit-workspace`, `rules`, `mcp`, `version`) using `clap` derive with standardized CI gate exit codes (`0` clean, `1` error, `2` threshold breach).
- `src/schema/`: Canonical Raksa Finding Schema v1 (`Report`, `Finding`, `Severity`, `Summary`) and built-in `rule_catalog()` (24 `HOST-*` rules).
- `src/policy/`: YAML/JSON policy suppression engine supporting `min_severity`, `rule_id`, `target_contains`, mandatory audit `reason`, and fail-closed `expires_on` enforcement.
- `src/fim/`:
  - `hash.rs`: Bounded streaming SHA-256 hasher (64 KiB buffer, configurable max file size cap).
  - `sign.rs`: RFC 2104/4231 HMAC-SHA256 baseline signing and constant-time tag verification.
  - `mod.rs`: Symlink-safe traversal (`follow_links(false)`), `std::thread::scope` parallel hashing/verification (`HOST-001`..`HOST-005`), and deduplicated `watch_snapshot` loop.
- `src/audit/`:
  - `ssh.rs`: OpenSSH `sshd_config` parser with bounded `Include` recursion and cipher/MAC/Kex/timeout audits (`HOST-101`..`HOST-106`).
  - `docker.rs`: Multi-stage `Dockerfile` and `docker-compose` YAML auditor (`HOST-201`..`HOST-209`).
  - `host.rs`: Linux `sysctl`, `sudoers`, and cross-platform octal permission / SUID / SGID auditor (`HOST-301`..`HOST-304`).
  - `mod.rs`: Shared bounded file reader (`1 MiB` cap) and recursive `audit_workspace` aggregator.
- `src/report/`: ANSI-sanitized tabular output, Raksa Finding Schema v1 JSON, and SARIF 2.1.0 serializer.
- `src/mcp/`: Dependency-free `stdio` JSON-RPC 2.0 MCP server exposing 7 defensive `hostguard_*` tools.

## Rule, CIS & MITRE D3FEND Coverage (24 Rules)

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
| `HOST-301` | `host-auditor` | Insecure kernel network sysctl parameter | CIS Linux 3.1-3.3 | `D3-CH` |
| `HOST-302` | `host-auditor` | Weak ASLR, ptrace, kptr, dmesg, or `suid_dumpable` sysctl | CIS Linux 1.5.1-1.5.2 | `D3-CH` |
| `HOST-303` | `host-auditor` | World-writable, SUID/SGID, or open private key/shadow mode | CIS Linux 6.1.2-6.1.9 | `D3-LPM` |
| `HOST-304` | `host-auditor` | Unrestricted `NOPASSWD ALL` or `Defaults !authenticate` | CIS Linux 5.3.4 | `D3-SUC` |

# raksa-hostguard Architecture

`raksa-hostguard` is the Layer 2 (Host & Container Hardening) component of the Raksa security suite. Built with `#![forbid(unsafe_code)]`, it inspects host filesystem integrity and static SSH/container configurations without kernel modules or invasive background daemons.

## Component Flow

```text
  [ Local Filesystem ]        [ sshd_config ]        [ Dockerfile / Compose ]
           |                         |                          |
           v                         v                          v
  +-----------------+       +-----------------+       +------------------+
  | fim::snapshot   |       |  audit::ssh     |       |  audit::docker   |
  | (Streaming      |       |  (CIS Linux)    |       |  (CIS Docker)    |
  |  SHA-256)       |       +-----------------+       +------------------+
  +-----------------+                |                          |
           |                         +------------+-------------+
           v                                      |
  +-----------------+                             |
  | fim::verify     |                             |
  +-----------------+                             |
           |                                      |
           +------------------+-------------------+
                              |
                              v
                   +--------------------+
                   | schema::Report (v1)|
                   +--------------------+
                     |        |        |
           +---------+        |        +------------+
           v                  v                     v
     +-----------+      +-----------+        +-------------+
     |   Table   |      |   JSON    |        |  SARIF 2.1  |
     +-----------+      +-----------+        +-------------+
                              |
                              v
                   +--------------------+
                   |    mcp::Server     | (stdio JSON-RPC 2.0)
                   +--------------------+
```

## Module Responsibilities

- `src/main.rs`: CLI dispatcher (`fim init`, `fim check`, `audit-ssh`, `audit-docker`, `rules`, `mcp`, `version`) using `clap` derive with standardized CI gate exit codes (`0` clean, `1` error, `2` threshold breach).
- `src/schema/`: Canonical Raksa Finding Schema v1 (`Report`, `Finding`, `Severity`, `Summary`) and built-in `rule_catalog()` (`HOST-001`..`HOST-206`).
- `src/fim/`:
  - `hash.rs`: Bounded streaming SHA-256 hasher (64 KiB buffer, configurable max file size cap).
  - `mod.rs`: Symlink-safe directory traversal (`follow_links(false)`), JSON baseline snapshot creation, and drift verification (`HOST-001`..`HOST-004`).
- `src/audit/`:
  - `ssh.rs`: OpenSSH `sshd_config` parser honoring first-match global directive semantics (`HOST-101`..`HOST-104`).
  - `docker.rs`: Multi-stage `Dockerfile` and YAML `docker-compose.yml` auditor (`HOST-201`..`HOST-206`).
- `src/report/`: ANSI-sanitized tabular output, Raksa Finding Schema v1 JSON, and SARIF 2.1.0 serializer.
- `src/mcp/`: Dependency-free stdio JSON-RPC 2.0 MCP server exposing `hostguard_*` tools for autonomous coding and security agents.

## Rule, CIS & MITRE D3FEND Coverage

| Rule ID | Module | Control | CIS Reference | MITRE D3FEND |
| :--- | :--- | :--- | :--- | :--- |
| `HOST-001` | `fim` | File content SHA-256 modified | CIS Linux 6.1 | `D3-FIM` |
| `HOST-002` | `fim` | Monitored baseline file deleted | CIS Linux 6.1 | `D3-FIM` |
| `HOST-003` | `fim` | Unexpected new file in monitored path | CIS Linux 6.1 | `D3-FIM` |
| `HOST-004` | `fim` | File permission or mode drift | CIS Linux 6.1 | `D3-FIM` |
| `HOST-101` | `ssh-auditor` | SSH root login enabled (`PermitRootLogin yes`) | CIS Linux 5.2.8 | `D3-SUC` |
| `HOST-102` | `ssh-auditor` | SSH password authentication enabled | CIS Linux 5.2.12 | `D3-SUC` |
| `HOST-103` | `ssh-auditor` | SSH empty passwords permitted | CIS Linux 5.2.9 | `D3-SUC` |
| `HOST-104` | `ssh-auditor` | SSH X11 forwarding, high `MaxAuthTries`, or Protocol 1 | CIS Linux 5.2.5-5.2.7 | `D3-SUC` |
| `HOST-201` | `docker-auditor` | Container runs as root / missing final `USER` | CIS Docker 4.1 | `D3-LPM` |
| `HOST-202` | `docker-auditor` | Privileged mode or Docker socket mounted | CIS Docker 5.4 / 5.31 | `D3-LPM` |
| `HOST-203` | `docker-auditor` | Host network/PID namespace or `SYS_ADMIN`/`ALL` cap | CIS Docker 5.3 / 5.9 / 5.15 | `D3-NI` |
| `HOST-204` | `docker-auditor` | Unpinned or `:latest` base/service image tag | CIS Docker 4.7 | `D3-SPP` |
| `HOST-205` | `docker-auditor` | Hardcoded secret literal in container `ENV`/`environment` | CIS Docker 4.10 | `D3-SM` |
| `HOST-206` | `docker-auditor` | Remote `ADD` URL or unverified pipe-to-shell `RUN` | CIS Docker 4.9 | `D3-SPP` |

# Changelog

All notable changes to `raksa-hostguard` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-26

### Added
- **Linux Host CIS Auditor (`audit-host` & `audit-workspace`)**: Audits kernel network sysctl hardening (`HOST-301`), memory/ptrace/dumpable protections (`HOST-302`), file permission/SUID/SGID/sensitive key exposures (`HOST-303`), and unrestricted `NOPASSWD` / `!authenticate` sudoers rules (`HOST-304`), plus recursive single-command `audit-workspace` triage across SSH, Docker, sysctl, and sudoers configs.
- **Enterprise Signed & Parallel FIM (`fim init`, `fim check`, `fim watch`)**: Added pure safe Rust RFC 2104/4231 HMAC-SHA256 baseline signing (`--sign-key-env`, detecting forged or unsigned baselines as `HOST-005`), multi-threaded hashing/verification workers (`--workers`), and deduplicated polling watch mode (`fim watch`).
- **Deeper SSH & Container Hardening Rules**: Added `Include` drop-in resolution (`<= 2` depth with cycle guard), weak SSH ciphers/MACs/Kex detection (`HOST-105`), forwarding/env/`ClientAliveInterval` checks (`HOST-106`), Compose `no-new-privileges` (`HOST-207`), `cap_drop: [ALL]` and sensitive host path mount guards (`HOST-208`), and unconfined Seccomp/AppArmor or wildcard sensitive port exposure detection (`HOST-209`).
- **Suppression Policy Engine (`--policy`)**: Added YAML/JSON `.hostguard.yml` suppression support with mandatory audit reasons, `target_contains` scoping, `min_severity` filtering, and fail-closed `expires_on` expiration dates (`examples/hostguard-policy.yml`).
- **MCP v0.2.0 Expansion**: Added `hostguard_audit_host` and `hostguard_audit_workspace` (7 total tools) plus optional `sign_key_env`, `workers`, and `policy_path` parameters on FIM/host tools.

## [0.1.0] - 2026-11-26

### Added
- Streaming SHA-256 File Integrity Monitoring (`fim init`, `fim check`) with bounded memory reads (64 KiB stream chunks), 50 MiB default single-file guard, exclusion filters, and drift classification (`HOST-001` through `HOST-004`).
- Hardened OpenSSH configuration auditor (`audit-ssh`) covering `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `X11Forwarding`, `AllowAgentForwarding`, `AllowTcpForwarding`, and `MaxAuthTries` (`HOST-101` through `HOST-104`).
- Multi-stage Dockerfile and `docker-compose` YAML auditor (`audit-docker`) covering final-stage non-root enforcement, `privileged: true` / `docker.sock` exposure, host namespace sharing / dangerous capabilities, unpinned `:latest` images, hardcoded credential redaction, and unverified remote fetch patterns (`HOST-201` through `HOST-206`).
- Unified Raksa Finding Schema v1 (`table` with ANSI/control-sequence sanitization, `json`, and SARIF `2.1.0` with sorted rule descriptors and line/service locations) plus CI severity gating (`--fail-on`, exit code `2`).
- Native `stdio` JSON-RPC 2.0 MCP server (`raksa-hostguard mcp`) exposing 5 defensive tools (`hostguard_list_rules`, `hostguard_fim_snapshot`, `hostguard_fim_check`, `hostguard_audit_ssh`, `hostguard_audit_docker`) with bounded 1 MiB inline payloads.
- Pure safe Rust codebase (`#![forbid(unsafe_code)]`), unit and CLI integration test suite (22 tests), throughput benchmarks (`cargo bench`), multi-stage distroless container (`gcr.io/distroless/static-debian12:nonroot`), and hardened CI + 3-OS release workflows.

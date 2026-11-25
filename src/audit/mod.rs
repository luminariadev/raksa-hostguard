pub mod docker;
pub mod host;
pub mod ssh;

use crate::schema::Finding;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use walkdir::WalkDir;

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024; // 1 MiB cap for static config parsing

pub(crate) fn read_bounded_text(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    if meta.len() > MAX_CONFIG_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "configuration file {:?} exceeds {} byte limit",
                path, MAX_CONFIG_BYTES
            ),
        ));
    }

    let mut buf = Vec::with_capacity(meta.len() as usize);
    let mut limited = (&mut file).take((MAX_CONFIG_BYTES + 1) as u64);
    limited.read_to_end(&mut buf)?;
    if buf.len() > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "configuration file {:?} exceeds {} byte limit",
                path, MAX_CONFIG_BYTES
            ),
        ));
    }
    String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn audit_workspace(root: &Path) -> io::Result<Vec<Finding>> {
    if !root.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("workspace path {:?} does not exist", root),
        ));
    }

    let mut files = Vec::new();
    let walker = WalkDir::new(root).follow_links(false).into_iter();
    for entry in walker.filter_entry(|e| !is_ignored_dir(e.path())) {
        let entry = entry?;
        if entry.file_type().is_file() {
            files.push(entry.into_path());
        }
    }
    files.sort();

    let mut findings = Vec::new();
    for path in files {
        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if is_docker_manifest(&fname) {
            findings.extend(docker::audit_docker_path(&path)?);
        } else if fname == "sshd_config" || (fname.starts_with("sshd_") && fname.ends_with(".conf"))
        {
            findings.extend(ssh::audit_sshd_file(&path)?);
        } else if fname.contains("sysctl") && fname.ends_with(".conf") {
            findings.extend(host::audit_sysctl_path(&path)?);
        } else if fname.starts_with("sudoers") {
            findings.extend(host::audit_sudoers_path(&path)?);
        }
    }

    Ok(findings)
}

fn is_ignored_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    matches!(name, ".git" | "target" | "node_modules" | "vendor")
}

fn is_docker_manifest(lower_name: &str) -> bool {
    lower_name == "dockerfile"
        || lower_name.starts_with("dockerfile.")
        || lower_name.ends_with(".dockerfile")
        || (lower_name.contains("compose")
            && (lower_name.ends_with(".yml") || lower_name.ends_with(".yaml")))
}

#[cfg(test)]
mod tests {
    use super::docker::{audit_compose, audit_docker_path, audit_dockerfile};
    use super::ssh::audit_sshd_file;
    use super::{audit_workspace, host};
    use std::collections::HashSet;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn ssh_fixtures_match_hardened_and_insecure_expectations() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let clean = audit_sshd_file(&root.join("testdata/sshd_hardened.conf"))
            .expect("hardened sshd fixture should parse");
        assert!(clean.is_empty(), "expected 0 findings, got {clean:?}");

        let insecure = audit_sshd_file(&root.join("testdata/sshd_insecure.conf"))
            .expect("insecure sshd fixture should parse");
        let rules: HashSet<&str> = insecure.iter().map(|f| f.rule_id.as_str()).collect();
        for expected in ["HOST-101", "HOST-102", "HOST-103", "HOST-104"] {
            assert!(rules.contains(expected), "missing expected rule {expected}");
        }
    }

    #[test]
    fn dockerfile_and_compose_fixtures_enforce_redaction_and_multistage_rules() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));

        let clean_df = audit_docker_path(&root.join("testdata/Dockerfile.hardened"))
            .expect("hardened Dockerfile should audit");
        assert!(
            clean_df.is_empty(),
            "expected 0 findings on hardened multi-stage Dockerfile, got {clean_df:?}"
        );

        let insecure_df = audit_docker_path(&root.join("testdata/Dockerfile.insecure"))
            .expect("insecure Dockerfile should audit");
        let df_rules: HashSet<&str> = insecure_df.iter().map(|f| f.rule_id.as_str()).collect();
        for expected in ["HOST-201", "HOST-204", "HOST-205", "HOST-206"] {
            assert!(
                df_rules.contains(expected),
                "missing {expected} in Dockerfile findings"
            );
        }
        let serialized_df =
            serde_json::to_string(&insecure_df).expect("serialize Dockerfile findings");
        assert!(!serialized_df.contains("super-secret-literal-password-999"));
        assert!(!serialized_df.contains("hardcoded_token_value_12345"));

        let clean_compose = audit_docker_path(&root.join("testdata/docker-compose.hardened.yml"))
            .expect("hardened compose should audit");
        assert!(
            clean_compose.is_empty(),
            "expected 0 findings on hardened compose fixture, got {clean_compose:?}"
        );

        let insecure_compose =
            audit_docker_path(&root.join("testdata/docker-compose.insecure.yml"))
                .expect("insecure compose should audit");
        let cmp_rules: HashSet<&str> = insecure_compose
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        for expected in ["HOST-201", "HOST-202", "HOST-203", "HOST-204", "HOST-205"] {
            assert!(
                cmp_rules.contains(expected),
                "missing {expected} in compose findings"
            );
        }
        let serialized_cmp =
            serde_json::to_string(&insecure_compose).expect("serialize compose findings");
        assert!(!serialized_cmp.contains("compose_literal_secret_abc"));
    }

    #[test]
    fn multistage_and_interpolation_edge_cases_avoid_false_positives() {
        let df = "FROM rust:1.86-alpine AS builder\nUSER root\nFROM alpine:3.21.3\nUSER appuser\n";
        let findings = audit_dockerfile(df, "inline.Dockerfile");
        assert!(
            findings.is_empty(),
            "builder root should not trigger HOST-201 when final stage is non-root: {findings:?}"
        );

        let compose = "services:\n  api:\n    image: myapp:1.2.0\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    environment:\n      SECRET_KEY: ${RUNTIME_SECRET}\n      TOKEN: $CI_TOKEN\n";
        let cmp_findings = audit_compose(compose, "inline-compose.yml").expect("valid yaml");
        assert!(
            cmp_findings.is_empty(),
            "env var interpolation should not trigger HOST-205: {cmp_findings:?}"
        );
    }

    #[test]
    fn ssh_weak_crypto_forwarding_and_include_rules_work() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let crypto = audit_sshd_file(&root.join("testdata/sshd_weak_crypto.conf"))
            .expect("weak crypto fixture");
        let rules: HashSet<&str> = crypto.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains("HOST-105"), "missing HOST-105: {crypto:?}");
        assert!(rules.contains("HOST-106"), "missing HOST-106: {crypto:?}");

        let clean = audit_sshd_file(&root.join("testdata/sshd_hardened.conf"))
            .expect("hardened sshd fixture");
        assert!(
            clean.is_empty(),
            "hardened sshd should stay clean: {clean:?}"
        );

        // Verify Include drop-in resolution.
        let dir = tempdir().unwrap();
        let dropins = dir.path().join("sshd_config.d");
        fs::create_dir_all(&dropins).unwrap();
        fs::write(dropins.join("10-weak.conf"), "AllowTcpForwarding yes\n").unwrap();
        let main_cfg = dir.path().join("sshd_config");
        fs::write(
            &main_cfg,
            "Include sshd_config.d/*.conf\nPermitRootLogin no\n",
        )
        .unwrap();

        let inc_findings = audit_sshd_file(&main_cfg).expect("audit include");
        assert!(
            inc_findings.iter().any(|f| f.rule_id == "HOST-106"),
            "Include drop-in directive should trigger HOST-106: {inc_findings:?}"
        );
    }

    #[test]
    fn compose_unconfined_seccomp_cap_drop_and_ports_trigger_v2_rules() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let findings = audit_docker_path(&root.join("testdata/docker-compose.unconfined.yml"))
            .expect("audit unconfined compose");
        let rules: HashSet<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        for expected in ["HOST-207", "HOST-208", "HOST-209"] {
            assert!(rules.contains(expected), "missing {expected}: {findings:?}");
        }

        let clean = audit_docker_path(&root.join("testdata/docker-compose.hardened.yml"))
            .expect("hardened compose");
        assert!(
            clean.is_empty(),
            "hardened compose should still yield 0 findings: {clean:?}"
        );
    }

    #[test]
    fn directory_scan_skips_vendor_and_build_dirs() {
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("Dockerfile"),
            "FROM alpine:3.21.3\nUSER app\n",
        )
        .expect("write root Dockerfile");

        for ignored in [".git", "target", "node_modules"] {
            let sub = dir.path().join(ignored);
            fs::create_dir_all(&sub).expect("create ignored subdir");
            fs::write(sub.join("Dockerfile"), "FROM ubuntu:latest\n")
                .expect("write ignored insecure Dockerfile");
        }

        let findings = audit_docker_path(dir.path()).expect("scan directory");
        assert!(
            findings.is_empty(),
            "ignored dirs should be skipped during scan: {findings:?}"
        );
    }

    #[test]
    fn sysctl_and_sudoers_fixtures_enforce_cis_hardening() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));

        let sys_clean = host::audit_sysctl_path(&root.join("testdata/sysctl_hardened.conf"))
            .expect("hardened sysctl");
        assert!(
            sys_clean.is_empty(),
            "hardened sysctl should produce 0 findings: {sys_clean:?}"
        );

        let sys_bad = host::audit_sysctl_path(&root.join("testdata/sysctl_insecure.conf"))
            .expect("insecure sysctl");
        let sys_rules: HashSet<&str> = sys_bad.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(sys_rules.contains("HOST-301"), "missing HOST-301");
        assert!(sys_rules.contains("HOST-302"), "missing HOST-302");

        let sudo_clean = host::audit_sudoers_path(&root.join("testdata/sudoers_hardened"))
            .expect("hardened sudoers");
        assert!(
            sudo_clean.is_empty(),
            "hardened sudoers should produce 0 findings: {sudo_clean:?}"
        );

        let sudo_bad = host::audit_sudoers_path(&root.join("testdata/sudoers_insecure"))
            .expect("insecure sudoers");
        assert!(
            sudo_bad.iter().any(|f| f.rule_id == "HOST-304"),
            "missing HOST-304: {sudo_bad:?}"
        );
    }

    #[test]
    fn host_permissions_detect_world_writable_suid_and_exposed_keys() {
        let entries = vec![
            ("/etc/app.conf".to_string(), 0o644),
            ("/home/deploy/.ssh/id_ed25519".to_string(), 0o600),
            ("/tmp/world_write.sh".to_string(), 0o777),
            ("/usr/local/bin/escalate".to_string(), 0o4755),
            ("/etc/shadow".to_string(), 0o644),
            ("/home/deploy/.ssh/id_rsa".to_string(), 0o644),
        ];
        let findings = host::audit_permissions_entries(&entries);
        assert_eq!(findings.len(), 4);
        assert!(findings.iter().all(|f| f.rule_id == "HOST-303"));
    }

    #[test]
    fn workspace_audit_aggregates_ssh_docker_sysctl_and_sudoers() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("Dockerfile"), "FROM ubuntu:latest\n").unwrap();
        fs::write(dir.path().join("sshd_config"), "PermitRootLogin yes\n").unwrap();
        fs::write(
            dir.path().join("99-sysctl.conf"),
            "kernel.randomize_va_space = 0\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("sudoers_custom"),
            "ops ALL=(ALL) NOPASSWD: ALL\n",
        )
        .unwrap();

        let vendor = dir.path().join("vendor");
        fs::create_dir_all(&vendor).unwrap();
        fs::write(vendor.join("sshd_config"), "PermitEmptyPasswords yes\n").unwrap();

        let findings = audit_workspace(dir.path()).expect("workspace scan");
        let rules: HashSet<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        for expected in ["HOST-101", "HOST-201", "HOST-204", "HOST-302", "HOST-304"] {
            assert!(rules.contains(expected), "missing {expected}: {findings:?}");
        }
        assert!(
            !rules.contains("HOST-103"),
            "vendor/ directory must be ignored: {findings:?}"
        );
    }
}

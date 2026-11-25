pub mod docker;
pub mod ssh;

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

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

#[cfg(test)]
mod tests {
    use super::docker::{audit_compose, audit_docker_path, audit_dockerfile};
    use super::ssh::audit_sshd_file;
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

        let compose = "services:\n  api:\n    image: myapp:1.2.0\n    environment:\n      SECRET_KEY: ${RUNTIME_SECRET}\n      TOKEN: $CI_TOKEN\n";
        let cmp_findings = audit_compose(compose, "inline-compose.yml").expect("valid yaml");
        assert!(
            cmp_findings.is_empty(),
            "env var interpolation should not trigger HOST-205: {cmp_findings:?}"
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
}

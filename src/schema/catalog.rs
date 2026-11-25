use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub module: &'static str,
    pub default_severity: &'static str,
    pub mitre_d3fend: &'static str,
    pub mitre_technique: &'static str,
    pub cis_ref: &'static str,
    pub description: &'static str,
}

pub fn rule_catalog() -> Vec<RuleInfo> {
    vec![
        RuleInfo {
            rule_id: "HOST-001",
            title: "Monitored file content modified",
            module: "fim",
            default_severity: "critical",
            mitre_d3fend: "D3-FIM",
            mitre_technique: "File Integrity Monitoring",
            cis_ref: "CIS Linux 6.1",
            description: "Cryptographic SHA-256 digest of a monitored file no longer matches the baseline snapshot.",
        },
        RuleInfo {
            rule_id: "HOST-002",
            title: "Monitored file deleted",
            module: "fim",
            default_severity: "high",
            mitre_d3fend: "D3-FIM",
            mitre_technique: "File Integrity Monitoring",
            cis_ref: "CIS Linux 6.1",
            description: "A file recorded in the integrity baseline snapshot is missing on disk.",
        },
        RuleInfo {
            rule_id: "HOST-003",
            title: "Unexpected file added in monitored directory",
            module: "fim",
            default_severity: "medium",
            mitre_d3fend: "D3-FIM",
            mitre_technique: "File Integrity Monitoring",
            cis_ref: "CIS Linux 6.1",
            description: "A new regular file appeared inside a monitored root after the baseline snapshot was created.",
        },
        RuleInfo {
            rule_id: "HOST-004",
            title: "Monitored file permissions changed",
            module: "fim",
            default_severity: "high",
            mitre_d3fend: "D3-FIM",
            mitre_technique: "File Integrity Monitoring",
            cis_ref: "CIS Linux 6.1",
            description: "File mode bits or read-only attribute changed relative to the baseline snapshot.",
        },
        RuleInfo {
            rule_id: "HOST-101",
            title: "SSH root login enabled",
            module: "ssh-auditor",
            default_severity: "high",
            mitre_d3fend: "D3-SUC",
            mitre_technique: "System User Configuration",
            cis_ref: "CIS Linux 5.2.8",
            description: "sshd_config allows PermitRootLogin yes instead of no or prohibit-password.",
        },
        RuleInfo {
            rule_id: "HOST-102",
            title: "SSH password authentication enabled",
            module: "ssh-auditor",
            default_severity: "high",
            mitre_d3fend: "D3-SUC",
            mitre_technique: "System User Configuration",
            cis_ref: "CIS Linux 5.2.12",
            description: "sshd_config enables interactive PasswordAuthentication instead of key-based auth.",
        },
        RuleInfo {
            rule_id: "HOST-103",
            title: "SSH empty passwords permitted",
            module: "ssh-auditor",
            default_severity: "critical",
            mitre_d3fend: "D3-SUC",
            mitre_technique: "System User Configuration",
            cis_ref: "CIS Linux 5.2.9",
            description: "sshd_config permits empty passwords via PermitEmptyPasswords yes.",
        },
        RuleInfo {
            rule_id: "HOST-104",
            title: "Weak SSH session hardening setting",
            module: "ssh-auditor",
            default_severity: "medium",
            mitre_d3fend: "D3-SUC",
            mitre_technique: "System User Configuration",
            cis_ref: "CIS Linux 5.2.5-5.2.7",
            description: "sshd_config enables X11Forwarding, sets MaxAuthTries above 4, or permits legacy Protocol 1.",
        },
        RuleInfo {
            rule_id: "HOST-201",
            title: "Container configured to run as root",
            module: "docker-auditor",
            default_severity: "high",
            mitre_d3fend: "D3-LPM",
            mitre_technique: "Local Privilege Management",
            cis_ref: "CIS Docker 4.1",
            description: "Final Dockerfile stage lacks a non-root USER instruction or compose service specifies user: root/0.",
        },
        RuleInfo {
            rule_id: "HOST-202",
            title: "Privileged container or Docker socket mount",
            module: "docker-auditor",
            default_severity: "critical",
            mitre_d3fend: "D3-LPM",
            mitre_technique: "Local Privilege Management",
            cis_ref: "CIS Docker 5.4 / 5.31",
            description: "Compose service sets privileged: true or mounts /var/run/docker.sock into the container.",
        },
        RuleInfo {
            rule_id: "HOST-203",
            title: "Host namespace sharing or dangerous Linux capabilities",
            module: "docker-auditor",
            default_severity: "high",
            mitre_d3fend: "D3-NI",
            mitre_technique: "Network Isolation",
            cis_ref: "CIS Docker 5.3 / 5.9 / 5.15",
            description: "Compose service shares network_mode: host, pid: host, or grants SYS_ADMIN / ALL capabilities.",
        },
        RuleInfo {
            rule_id: "HOST-204",
            title: "Unpinned or :latest container image tag",
            module: "docker-auditor",
            default_severity: "medium",
            mitre_d3fend: "D3-SPP",
            mitre_technique: "Software Package Pinning",
            cis_ref: "CIS Docker 4.7",
            description: "Base or service image omits an explicit immutable version tag or SHA-256 digest.",
        },
        RuleInfo {
            rule_id: "HOST-205",
            title: "Hardcoded secret literal in container environment",
            module: "docker-auditor",
            default_severity: "high",
            mitre_d3fend: "D3-SM",
            mitre_technique: "Secret Management",
            cis_ref: "CIS Docker 4.10",
            description: "Dockerfile ENV/ARG or compose environment defines a literal secret-like credential.",
        },
        RuleInfo {
            rule_id: "HOST-206",
            title: "Unverified remote artifact fetch in Dockerfile",
            module: "docker-auditor",
            default_severity: "medium",
            mitre_d3fend: "D3-SPP",
            mitre_technique: "Software Package Pinning",
            cis_ref: "CIS Docker 4.9",
            description: "Dockerfile uses remote ADD URL or pipes curl/wget directly to a shell without verification.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalog_contains_14_unique_rules() {
        let rules = rule_catalog();
        assert_eq!(rules.len(), 14);
        let mut seen = HashSet::new();
        for rule in rules {
            assert!(!rule.rule_id.is_empty());
            assert!(!rule.title.is_empty());
            assert!(!rule.mitre_d3fend.is_empty());
            assert!(seen.insert(rule.rule_id), "duplicate {}", rule.rule_id);
        }
    }
}

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_raksa-hostguard")
}

#[test]
fn cli_version_and_rules_work() {
    let ver = Command::new(bin_path())
        .arg("version")
        .output()
        .expect("run version");
    assert_eq!(ver.status.code(), Some(0));
    let ver_stdout = String::from_utf8_lossy(&ver.stdout);
    assert!(ver_stdout.contains("raksa-hostguard"));
    assert!(ver_stdout.contains("host-hardening"));

    let rules = Command::new(bin_path())
        .args(["rules", "--format", "json"])
        .output()
        .expect("run rules");
    assert_eq!(rules.status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&rules.stdout).expect("parse rules json");
    assert_eq!(parsed.as_array().expect("rules array").len(), 14);
}

#[test]
fn cli_fim_init_and_check_detect_tampering_exit_2() {
    let dir = tempdir().expect("tempdir");
    let watched = dir.path().join("watched");
    fs::create_dir_all(&watched).expect("create watched dir");
    let target_file = watched.join("app.conf");
    fs::write(&target_file, "listen=127.0.0.1\n").expect("write app.conf");
    let baseline = dir.path().join("baseline.json");

    let init = Command::new(bin_path())
        .args([
            "fim",
            "init",
            "--path",
            watched.to_str().unwrap(),
            "--out",
            baseline.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("run fim init");
    assert_eq!(init.status.code(), Some(0));
    let init_json: Value = serde_json::from_slice(&init.stdout).expect("parse init json");
    assert_eq!(init_json["files_hashed"], 1);

    let clean = Command::new(bin_path())
        .args([
            "fim",
            "check",
            "--baseline",
            baseline.to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("run clean fim check");
    assert_eq!(clean.status.code(), Some(0));

    fs::write(&target_file, "listen=0.0.0.0\n").expect("tamper app.conf");
    let tampered = Command::new(bin_path())
        .args([
            "fim",
            "check",
            "--baseline",
            baseline.to_str().unwrap(),
            "--format",
            "json",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("run tampered fim check");
    assert_eq!(tampered.status.code(), Some(2));
    let rep: Value = serde_json::from_slice(&tampered.stdout).expect("parse check json");
    assert_eq!(rep["summary"]["critical"], 1);
    assert_eq!(rep["findings"][0]["rule_id"], "HOST-001");
}

#[test]
fn cli_audit_ssh_hardened_and_insecure_sarif() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let hardened = manifest.join("testdata/sshd_hardened.conf");
    let insecure = manifest.join("testdata/sshd_insecure.conf");

    let ok = Command::new(bin_path())
        .args([
            "audit-ssh",
            "--path",
            hardened.to_str().unwrap(),
            "--fail-on",
            "low",
        ])
        .output()
        .expect("run audit-ssh hardened");
    assert_eq!(ok.status.code(), Some(0));

    let bad = Command::new(bin_path())
        .args([
            "audit-ssh",
            "--path",
            insecure.to_str().unwrap(),
            "--format",
            "sarif",
            "--fail-on",
            "high",
        ])
        .output()
        .expect("run audit-ssh insecure");
    assert_eq!(bad.status.code(), Some(2));
    let sarif: Value = serde_json::from_slice(&bad.stdout).expect("parse sarif");
    assert_eq!(sarif["version"], "2.1.0");
    assert!(!sarif["runs"][0]["results"]
        .as_array()
        .expect("results")
        .is_empty());
}

#[test]
fn cli_audit_docker_redacts_secrets_and_gates_severity() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let hardened_df = manifest.join("testdata/Dockerfile.hardened");
    let insecure_compose = manifest.join("testdata/docker-compose.insecure.yml");

    let ok = Command::new(bin_path())
        .args([
            "audit-docker",
            "--path",
            hardened_df.to_str().unwrap(),
            "--fail-on",
            "low",
        ])
        .output()
        .expect("run audit-docker hardened");
    assert_eq!(ok.status.code(), Some(0));

    let bad = Command::new(bin_path())
        .args([
            "audit-docker",
            "--path",
            insecure_compose.to_str().unwrap(),
            "--format",
            "json",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("run audit-docker insecure");
    assert_eq!(bad.status.code(), Some(2));
    let text = String::from_utf8_lossy(&bad.stdout);
    assert!(!text.contains("compose_literal_secret_abc"));
    let report: Value = serde_json::from_str(&text).expect("parse json report");
    assert!(report["summary"]["critical"].as_u64().unwrap() >= 2);
}

#[test]
fn cli_mcp_stdio_handshake_works() {
    let mut child = Command::new(bin_path())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn raksa-hostguard mcp");

    {
        let stdin = child.stdin.as_mut().expect("child stdin");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05"}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
        )
        .unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#).unwrap();
    }

    let output = child.wait_with_output().expect("wait mcp output");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let lines: Vec<Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid rpc response"))
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["result"]["serverInfo"]["name"], "raksa-hostguard");
    assert_eq!(lines[1]["result"]["tools"].as_array().unwrap().len(), 5);
}

#[test]
fn cli_runtime_and_arg_errors_return_exit_1() {
    let missing = Command::new(bin_path())
        .args(["audit-ssh", "--path", "does_not_exist_12345.conf"])
        .output()
        .expect("run missing path");
    assert_eq!(missing.status.code(), Some(1));

    let bad_flag = Command::new(bin_path())
        .args(["--unknown-flag"])
        .output()
        .expect("run bad flag");
    assert_eq!(bad_flag.status.code(), Some(1));
}

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
    assert_eq!(parsed.as_array().expect("rules array").len(), 29);
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
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"hostguard_audit_systemd","arguments":{{"content":"[Service]\nUser=root\nExecStart=/usr/bin/app\n"}}}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"hostguard_suggest_fix","arguments":{{"kind":"daemon","content":"{{\"icc\": true}}"}}}}}}"#
        )
        .unwrap();
    }

    let output = child.wait_with_output().expect("wait mcp output");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let lines: Vec<Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid rpc response"))
        .collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[0]["result"]["serverInfo"]["name"], "raksa-hostguard");
    assert_eq!(lines[1]["result"]["tools"].as_array().unwrap().len(), 9);
    let sys_text = lines[2]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(sys_text.contains("HOST-305"));
    let fix_text = lines[3]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(fix_text.contains("\\\"icc\\\": false"));
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

    let empty_host = Command::new(bin_path())
        .arg("audit-host")
        .output()
        .expect("run audit-host without targets");
    assert_eq!(empty_host.status.code(), Some(1));
}

#[test]
fn cli_signed_fim_tamper_and_watch_cycles_work() {
    let dir = tempdir().expect("tempdir");
    let watched = dir.path().join("etc");
    fs::create_dir_all(&watched).unwrap();
    let cfg = watched.join("daemon.conf");
    fs::write(&cfg, "secure=1\n").unwrap();
    let baseline = dir.path().join("signed-baseline.json");

    let init = Command::new(bin_path())
        .env("RAKSA_TEST_HMAC_KEY", "super-strong-signing-key")
        .args([
            "fim",
            "init",
            "--path",
            watched.to_str().unwrap(),
            "--out",
            baseline.to_str().unwrap(),
            "--sign-key-env",
            "RAKSA_TEST_HMAC_KEY",
            "--workers",
            "2",
            "--format",
            "json",
        ])
        .output()
        .expect("run signed fim init");
    assert_eq!(init.status.code(), Some(0));
    let init_json: Value = serde_json::from_slice(&init.stdout).unwrap();
    assert_eq!(init_json["signed"], true);

    let clean = Command::new(bin_path())
        .env("RAKSA_TEST_HMAC_KEY", "super-strong-signing-key")
        .args([
            "fim",
            "check",
            "--baseline",
            baseline.to_str().unwrap(),
            "--sign-key-env",
            "RAKSA_TEST_HMAC_KEY",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("clean signed fim check");
    assert_eq!(clean.status.code(), Some(0));

    // Tamper file contents cleanly first to exercise watch cycle breach
    fs::write(&cfg, "secure=0\n").unwrap();
    let watch = Command::new(bin_path())
        .env("RAKSA_TEST_HMAC_KEY", "super-strong-signing-key")
        .args([
            "fim",
            "watch",
            "--baseline",
            baseline.to_str().unwrap(),
            "--interval-secs",
            "0",
            "--max-cycles",
            "2",
            "--sign-key-env",
            "RAKSA_TEST_HMAC_KEY",
            "--format",
            "json",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("run fim watch");
    assert_eq!(watch.status.code(), Some(2));
    let watch_out = String::from_utf8_lossy(&watch.stdout);
    assert!(watch_out.contains("HOST-001"));

    // Now tamper baseline signature itself and expect HOST-005
    let raw_snap = fs::read_to_string(&baseline).unwrap();
    let mut snap_val: Value = serde_json::from_str(&raw_snap).unwrap();
    snap_val["signature_hmac_sha256"] = Value::String("0".repeat(64));
    fs::write(&baseline, serde_json::to_string_pretty(&snap_val).unwrap()).unwrap();

    let tampered = Command::new(bin_path())
        .env("RAKSA_TEST_HMAC_KEY", "super-strong-signing-key")
        .args([
            "fim",
            "check",
            "--baseline",
            baseline.to_str().unwrap(),
            "--sign-key-env",
            "RAKSA_TEST_HMAC_KEY",
            "--format",
            "json",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("check tampered signature");
    assert_eq!(tampered.status.code(), Some(2));
    let rep: Value = serde_json::from_slice(&tampered.stdout).unwrap();
    assert!(rep["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["rule_id"] == "HOST-005"));
}

#[test]
fn cli_audit_host_and_workspace_with_policy_work() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));

    let ok = Command::new(bin_path())
        .args([
            "audit-host",
            "--sysctl",
            manifest
                .join("testdata/sysctl_hardened.conf")
                .to_str()
                .unwrap(),
            "--sudoers",
            manifest.join("testdata/sudoers_hardened").to_str().unwrap(),
            "--fail-on",
            "low",
        ])
        .output()
        .expect("audit-host hardened");
    assert_eq!(ok.status.code(), Some(0));

    let bad = Command::new(bin_path())
        .args([
            "audit-host",
            "--sysctl",
            manifest
                .join("testdata/sysctl_insecure.conf")
                .to_str()
                .unwrap(),
            "--sudoers",
            manifest.join("testdata/sudoers_insecure").to_str().unwrap(),
            "--format",
            "json",
            "--fail-on",
            "high",
        ])
        .output()
        .expect("audit-host insecure");
    assert_eq!(bad.status.code(), Some(2));
    let host_rep: Value = serde_json::from_slice(&bad.stdout).unwrap();
    let host_rules: Vec<&str> = host_rep["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    assert!(host_rules.contains(&"HOST-301"));
    assert!(host_rules.contains(&"HOST-302"));
    assert!(host_rules.contains(&"HOST-304"));

    // Workspace audit with policy_suppress.yml suppresses HOST-204 on Dockerfile.insecure
    let ws = Command::new(bin_path())
        .args([
            "audit-workspace",
            "--path",
            manifest.join("testdata").to_str().unwrap(),
            "--policy",
            manifest
                .join("testdata/policy_suppress.yml")
                .to_str()
                .unwrap(),
            "--format",
            "json",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("audit-workspace");
    assert_eq!(ws.status.code(), Some(2));
    let ws_rep: Value = serde_json::from_slice(&ws.stdout).unwrap();
    let df_204_remaining = ws_rep["findings"].as_array().unwrap().iter().any(|f| {
        f["rule_id"] == "HOST-204"
            && f["target"]
                .as_str()
                .unwrap_or("")
                .contains("Dockerfile.insecure")
    });
    assert!(
        !df_204_remaining,
        "HOST-204 for Dockerfile.insecure should be suppressed by policy"
    );
}

#[test]
fn cli_v3_host_daemon_markdown_ndjson_baselines_fix_preview_and_siem_out() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = tempdir().expect("tempdir");

    // 1. Hardened v0.3.0 host & daemon checks pass with exit 0
    let ok_host = Command::new(bin_path())
        .args([
            "audit-host",
            "--systemd",
            manifest
                .join("testdata/app.hardened.service")
                .to_str()
                .unwrap(),
            "--persistence",
            manifest.join("testdata/cron_hardened").to_str().unwrap(),
            "--auth-policy",
            manifest
                .join("testdata/pam_hardened.conf")
                .to_str()
                .unwrap(),
            "--kernel-audit",
            manifest
                .join("testdata/modprobe_hardened.conf")
                .to_str()
                .unwrap(),
            "--fail-on",
            "low",
        ])
        .output()
        .unwrap();
    assert_eq!(ok_host.status.code(), Some(0));

    let ok_daemon = Command::new(bin_path())
        .args([
            "audit-docker",
            "--path",
            manifest
                .join("testdata/daemon.hardened.json")
                .to_str()
                .unwrap(),
            "--fail-on",
            "low",
        ])
        .output()
        .unwrap();
    assert_eq!(ok_daemon.status.code(), Some(0));

    // 2. Insecure v0.3.0 host & daemon checks emit HOST-210 and HOST-305..308 with Markdown + NDJSON + baseline gating
    let bad_daemon = Command::new(bin_path())
        .args([
            "audit-docker",
            "--path",
            manifest
                .join("testdata/daemon.insecure.json")
                .to_str()
                .unwrap(),
            "--format",
            "markdown",
            "--fail-on",
            "high",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_daemon.status.code(), Some(2));
    let md_txt = String::from_utf8_lossy(&bad_daemon.stdout);
    assert!(md_txt.contains("Posture Score"));
    assert!(md_txt.contains("HOST-210"));

    let baseline_file = dir.path().join("host-baseline.json");
    let bad_host = Command::new(bin_path())
        .args([
            "audit-host",
            "--systemd",
            manifest
                .join("testdata/app.insecure.service")
                .to_str()
                .unwrap(),
            "--persistence",
            manifest.join("testdata/cron_insecure").to_str().unwrap(),
            "--auth-policy",
            manifest
                .join("testdata/login_insecure.defs")
                .to_str()
                .unwrap(),
            "--kernel-audit",
            manifest
                .join("testdata/audit_insecure.rules")
                .to_str()
                .unwrap(),
            "--format",
            "ndjson",
            "--write-baseline",
            baseline_file.to_str().unwrap(),
            "--fail-on",
            "high",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_host.status.code(), Some(2));
    let ndjson_txt = String::from_utf8_lossy(&bad_host.stdout);
    let ndjson_lines: Vec<Value> = ndjson_txt
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid ndjson finding line"))
        .collect();
    assert!(ndjson_lines.iter().any(|v| v["rule_id"] == "HOST-305"));
    assert!(ndjson_lines.iter().any(|v| v["rule_id"] == "HOST-306"));
    assert!(ndjson_lines.iter().any(|v| v["rule_id"] == "HOST-307"));
    assert!(ndjson_lines.iter().any(|v| v["rule_id"] == "HOST-308"));

    let recheck = Command::new(bin_path())
        .args([
            "audit-host",
            "--systemd",
            manifest
                .join("testdata/app.insecure.service")
                .to_str()
                .unwrap(),
            "--persistence",
            manifest.join("testdata/cron_insecure").to_str().unwrap(),
            "--auth-policy",
            manifest
                .join("testdata/login_insecure.defs")
                .to_str()
                .unwrap(),
            "--kernel-audit",
            manifest
                .join("testdata/audit_insecure.rules")
                .to_str()
                .unwrap(),
            "--baseline",
            baseline_file.to_str().unwrap(),
            "--format",
            "json",
            "--fail-on",
            "low",
        ])
        .output()
        .unwrap();
    assert_eq!(recheck.status.code(), Some(0));
    let recheck_json: Value = serde_json::from_slice(&recheck.stdout).unwrap();
    assert_eq!(recheck_json["posture"]["score"], 100);
    assert_eq!(recheck_json["summary"]["total"], 0);

    // 3. fix-preview diff and json modes
    let fix_diff = Command::new(bin_path())
        .args([
            "fix-preview",
            "--path",
            manifest
                .join("testdata/app.insecure.service")
                .to_str()
                .unwrap(),
            "--kind",
            "systemd",
            "--format",
            "diff",
        ])
        .output()
        .unwrap();
    assert_eq!(fix_diff.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&fix_diff.stdout).contains("+User=nonroot"));

    let fix_json = Command::new(bin_path())
        .args([
            "fix-preview",
            "--path",
            manifest
                .join("testdata/daemon.insecure.json")
                .to_str()
                .unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(fix_json.status.code(), Some(0));
    let fj: Value = serde_json::from_slice(&fix_json.stdout).unwrap();
    assert_eq!(fj["count"], 1);

    // 4. Event-driven fim watch --siem-out emits Schema v1 NDJSON line
    let watched = dir.path().join("watched");
    fs::create_dir_all(&watched).unwrap();
    let target = watched.join("app.conf");
    fs::write(&target, "mode=secure\n").unwrap();
    let snap_path = dir.path().join("snap.json");
    let siem_out = dir.path().join("siem-events.ndjson");

    let init = Command::new(bin_path())
        .args([
            "fim",
            "init",
            "--path",
            watched.to_str().unwrap(),
            "--out",
            snap_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(init.status.code(), Some(0));

    // Mutate after init so Cycle 1 detects drift and writes NDJSON to --siem-out
    fs::write(&target, "mode=tampered\n").unwrap();
    let watch = Command::new(bin_path())
        .args([
            "fim",
            "watch",
            "--baseline",
            snap_path.to_str().unwrap(),
            "--watch-mode",
            "events",
            "--interval-secs",
            "0",
            "--debounce-ms",
            "30",
            "--max-cycles",
            "1",
            "--siem-out",
            siem_out.to_str().unwrap(),
            "--format",
            "ndjson",
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    assert_eq!(watch.status.code(), Some(2));
    let siem_raw = fs::read_to_string(&siem_out).unwrap();
    let first_ev: Value = serde_json::from_str(siem_raw.lines().next().unwrap()).unwrap();
    assert_eq!(first_ev["rule_id"], "HOST-001");
    assert_eq!(first_ev["layer"], "host-hardening");
}

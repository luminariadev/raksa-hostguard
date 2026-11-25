use crate::schema::catalog::{rule_catalog, RuleInfo};
use crate::schema::{Finding, Report, Severity};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::str::FromStr;

const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const REPO_URI: &str = "https://github.com/luminariadev/raksa-hostguard";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
    Sarif,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            other => Err(format!(
                "invalid output format {:?}: expected table, json, or sarif",
                other
            )),
        }
    }
}

pub fn write_report<W: Write>(
    mut writer: W,
    report: &Report,
    format: OutputFormat,
) -> io::Result<()> {
    let rendered = match format {
        OutputFormat::Table => format_table(report),
        OutputFormat::Json => {
            format_json(report).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        }
        OutputFormat::Sarif => {
            format_sarif(report).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        }
    };
    writer.write_all(rendered.as_bytes())
}

pub fn sanitize_terminal_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    chars.next();
                    for seq in chars.by_ref() {
                        if ('@'..='~').contains(&seq) {
                            break;
                        }
                    }
                    continue;
                } else if next == ']' {
                    chars.next();
                    while let Some(seq) = chars.next() {
                        if seq == '\x07' {
                            break;
                        }
                        if seq == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                    continue;
                }
            }
            continue;
        }

        if c.is_control() {
            if c == '\t' || c == '\n' || c == '\r' {
                out.push(' ');
            }
        } else {
            out.push(c);
        }
    }

    out.trim().to_string()
}

pub fn format_table(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} v{} | layer: {} | total: {} (critical: {}, high: {}, medium: {}, low: {}, info: {})\n",
        sanitize_terminal_text(&report.tool),
        crate::VERSION,
        sanitize_terminal_text(&report.layer),
        report.summary.total,
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.info
    ));

    if report.findings.is_empty() {
        out.push_str("No security findings detected.\n");
        return out;
    }

    out.push_str(&format!(
        "{:<9} {:<10} {:<15} {:<36} {}\n",
        "SEVERITY", "RULE", "MODULE", "TARGET", "TITLE"
    ));
    out.push_str(&"-".repeat(100));
    out.push('\n');

    for f in &report.findings {
        let sev = f.severity.as_str().to_ascii_uppercase();
        let rule = sanitize_terminal_text(&f.rule_id);
        let module = truncate_chars(&sanitize_terminal_text(&f.module), 15);
        let target = truncate_chars(&sanitize_terminal_text(&f.target), 36);
        let title = sanitize_terminal_text(&f.title);
        let remediation = sanitize_terminal_text(&f.remediation);

        out.push_str(&format!(
            "{:<9} {:<10} {:<15} {:<36} {}\n",
            sev, rule, module, target, title
        ));
        out.push_str(&format!("          fix: {}\n", remediation));
    }

    out
}

pub fn format_json(report: &Report) -> Result<String, serde_json::Error> {
    let mut text = serde_json::to_string_pretty(report)?;
    text.push('\n');
    Ok(text)
}

pub fn format_sarif(report: &Report) -> Result<String, serde_json::Error> {
    let catalog: HashMap<&'static str, RuleInfo> =
        rule_catalog().into_iter().map(|r| (r.rule_id, r)).collect();

    let mut rules_by_id: BTreeMap<String, Value> = BTreeMap::new();
    let mut results = Vec::with_capacity(report.findings.len());

    for f in &report.findings {
        rules_by_id.entry(f.rule_id.clone()).or_insert_with(|| {
            if let Some(info) = catalog.get(f.rule_id.as_str()) {
                json!({
                    "id": info.rule_id,
                    "name": info.title,
                    "shortDescription": { "text": info.title },
                    "fullDescription": { "text": info.description },
                    "helpUri": REPO_URI,
                    "properties": {
                        "cis_ref": info.cis_ref,
                        "mitre_d3fend": info.mitre_d3fend,
                        "mitre_technique": info.mitre_technique,
                        "default_severity": info.default_severity,
                        "module": info.module
                    }
                })
            } else {
                json!({
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": { "text": f.title },
                    "fullDescription": { "text": f.description },
                    "helpUri": REPO_URI,
                    "properties": {
                        "mitre_d3fend": f.mitre_d3fend,
                        "default_severity": f.severity.as_str(),
                        "module": f.module
                    }
                })
            }
        });

        results.push(finding_to_sarif_result(f));
    }

    let sarif_doc = json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool,
                        "version": crate::VERSION,
                        "informationUri": REPO_URI,
                        "rules": rules_by_id.into_values().collect::<Vec<Value>>()
                    }
                },
                "results": results
            }
        ]
    });

    let mut text = serde_json::to_string_pretty(&sarif_doc)?;
    text.push('\n');
    Ok(text)
}

fn finding_to_sarif_result(f: &Finding) -> Value {
    let level = match f.severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    };

    let (artifact_uri, logical_svc) = split_target_uri(&f.target);
    let mut phys = Map::new();
    phys.insert(
        "artifactLocation".to_string(),
        json!({ "uri": artifact_uri }),
    );

    if let Some(line) = f.evidence.get("line").and_then(|v| v.as_u64()) {
        if line >= 1 {
            phys.insert("region".to_string(), json!({ "startLine": line }));
        }
    }

    let mut location = Map::new();
    location.insert("physicalLocation".to_string(), Value::Object(phys));
    if let Some(svc) = logical_svc {
        location.insert(
            "logicalLocations".to_string(),
            json!([{ "name": svc, "kind": "service" }]),
        );
    }

    json!({
        "ruleId": f.rule_id,
        "level": level,
        "message": {
            "text": format!("{} Remediation: {}", f.description, f.remediation)
        },
        "locations": [Value::Object(location)],
        "partialFingerprints": {
            "raksaFindingId": f.id
        },
        "properties": {
            "severity": f.severity.as_str(),
            "module": f.module,
            "layer": f.layer,
            "mitre_d3fend": f.mitre_d3fend,
            "evidence": f.evidence
        }
    })
}

fn split_target_uri(target: &str) -> (String, Option<String>) {
    let without_scheme = target.strip_prefix("file://").unwrap_or(target);
    if let Some((path_part, frag)) = without_scheme.split_once('#') {
        let svc = frag.strip_prefix("service=").unwrap_or(frag).to_string();
        (path_part.replace('\\', "/"), Some(svc))
    } else {
        (without_scheme.replace('\\', "/"), None)
    }
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_string();
    }
    if max_chars <= 3 {
        return text.chars().take(max_chars).collect();
    }
    let mut shortened: String = text.chars().take(max_chars - 3).collect();
    shortened.push_str("...");
    shortened
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::LAYER_HOST;
    use chrono::Utc;

    fn sample_finding(rule_id: &str, sev: Severity, target: &str, line: Option<u64>) -> Finding {
        let mut evidence = Map::new();
        if let Some(l) = line {
            evidence.insert("line".to_string(), json!(l));
        }
        Finding {
            id: format!("id-{rule_id}-{}", line.unwrap_or(0)),
            rule_id: rule_id.to_string(),
            module: "docker-auditor".to_string(),
            layer: LAYER_HOST.to_string(),
            severity: sev,
            title: "Test finding".to_string(),
            description: "Found issue in config.".to_string(),
            target: target.to_string(),
            evidence,
            remediation: "Apply fix.".to_string(),
            mitre_d3fend: "D3-LPM".to_string(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn table_sanitizes_ansi_escape_sequences() {
        let mut malicious = sample_finding(
            "HOST-201",
            Severity::High,
            "file:///tmp/\x1b[31mevil\x1b[0m\r\npath",
            None,
        );
        malicious.title = "Title\x1b]0;pwn\x07Clean".to_string();
        let report = Report::new(vec![malicious], Utc::now());
        let rendered = format_table(&report);

        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains('\x07'));
        assert!(rendered.contains("HOST-201"));
        assert!(rendered.contains("TitleClean"));
    }

    #[test]
    fn json_emits_raksa_schema_v1() {
        let report = Report::new(
            vec![sample_finding(
                "HOST-101",
                Severity::High,
                "file:///etc/ssh/sshd_config",
                Some(12),
            )],
            Utc::now(),
        );
        let raw = format_json(&report).expect("serialize json");
        let parsed: Value = serde_json::from_str(&raw).expect("valid json");
        assert_eq!(parsed["schema_version"], "1.0");
        assert_eq!(parsed["tool"], "raksa-hostguard");
        assert_eq!(parsed["layer"], "host-hardening");
        assert_eq!(parsed["summary"]["total"], 1);
        assert_eq!(parsed["summary"]["high"], 1);
    }

    #[test]
    fn sarif_emits_valid_v210_with_deduped_sorted_rules_and_line_region() {
        let f1 = sample_finding(
            "HOST-204",
            Severity::Medium,
            "file://testdata/Dockerfile.insecure",
            Some(4),
        );
        let f2 = sample_finding(
            "HOST-204",
            Severity::Medium,
            "file://testdata/docker-compose.insecure.yml#service=web",
            None,
        );
        let f3 = sample_finding(
            "HOST-201",
            Severity::High,
            "file://testdata/Dockerfile.insecure",
            Some(1),
        );
        let report = Report::new(vec![f1, f2, f3], Utc::now());
        let raw = format_sarif(&report).expect("serialize sarif");
        let sarif: Value = serde_json::from_str(&raw).expect("valid sarif json");

        assert_eq!(sarif["version"], "2.1.0");
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], "HOST-201");
        assert_eq!(rules[1]["id"], "HOST-204");

        let results = sarif["runs"][0]["results"]
            .as_array()
            .expect("results array");
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["level"], "warning");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            4
        );
        assert_eq!(
            results[1]["locations"][0]["logicalLocations"][0]["name"],
            "web"
        );
        assert_eq!(results[2]["level"], "error");
    }
}

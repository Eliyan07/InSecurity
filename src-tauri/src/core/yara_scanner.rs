//! YARA-X scanning with compiled official rules.
use crate::core::utils::find_resource_path;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use yara_x::{Compiler, MetaValue, Rule, Rules, Scanner, SourceCode};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub severity: RuleSeverity,
    pub description: String,
    pub category: String,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone)]
struct RuleSource {
    category: String,
    source_path: String,
    content: String,
}

#[derive(Debug, Clone)]
struct RuleSourceInfo {
    category: String,
    #[allow(dead_code)]
    source_path: String,
}

pub struct YaraScanner {
    rules: Rules,
    rule_sources: HashMap<String, RuleSourceInfo>,
}

impl Default for YaraScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl YaraScanner {
    pub fn new() -> Self {
        let rule_sources = Self::load_rule_sources();
        Self::from_sources_with_audit(rule_sources, true)
    }

    fn from_sources_with_audit(rule_sources: Vec<RuleSource>, emit_audit: bool) -> Self {
        let (accepted_sources, mut rule_sources_by_name) =
            Self::validate_rule_sources(rule_sources, emit_audit);
        let rules = Self::compile_rule_sources(&accepted_sources, emit_audit);
        let compiled_rule_names: HashSet<String> = rules
            .iter()
            .map(|rule| rule.identifier().to_string())
            .collect();

        rule_sources_by_name.retain(|rule_name, _| compiled_rule_names.contains(rule_name));

        log::info!(
            "Initialized YARA-X scanner with {} compiled rules",
            compiled_rule_names.len()
        );

        Self {
            rules,
            rule_sources: rule_sources_by_name,
        }
    }

    #[cfg(test)]
    fn from_sources(rule_sources: Vec<RuleSource>) -> Self {
        Self::from_sources_with_audit(rule_sources, false)
    }

    fn load_rule_sources() -> Vec<RuleSource> {
        let mut rule_sources = Vec::new();

        for (category, candidates) in [
            (
                "strict",
                [
                    "resources/yara_rules/strict",
                    "src-tauri/resources/yara_rules/strict",
                    "../resources/yara_rules/strict",
                ],
            ),
            (
                "heuristic",
                [
                    "resources/yara_rules/heuristic",
                    "src-tauri/resources/yara_rules/heuristic",
                    "../resources/yara_rules/heuristic",
                ],
            ),
        ] {
            if let Some(dir) = find_resource_path(&candidates) {
                rule_sources.extend(Self::load_rule_sources_from_directory(&dir, category));
            } else {
                log::warn!(
                    "YARA-X rules directory not found for category: {}",
                    category
                );
            }
        }

        rule_sources
    }

    fn load_rule_sources_from_directory(dir: &Path, category: &str) -> Vec<RuleSource> {
        if !dir.exists() {
            log::warn!("YARA-X rules directory not found: {:?}", dir);
            return Vec::new();
        }

        let mut rule_paths: Vec<PathBuf> = match fs::read_dir(dir) {
            Ok(entries) => entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| Self::is_yara_rule_path(path))
                .collect(),
            Err(err) => {
                log::warn!("Failed to enumerate YARA-X rules in {:?}: {}", dir, err);
                return Vec::new();
            }
        };

        rule_paths.sort_by_key(|path| path.to_string_lossy().to_lowercase());

        let mut rule_sources = Vec::new();
        for path in rule_paths {
            let sig_path = path.with_extension("yar.sig");
            if !sig_path.exists() {
                if let Err(err) = crate::core::tamper_protection::sign_yara_rule(&path) {
                    log::warn!("Failed to auto-sign YARA rule {:?}: {}", path, err);
                }
            }

            match crate::core::tamper_protection::verify_yara_rule(&path) {
                Ok(true) => {}
                Ok(false) => {
                    log::error!(
                        "YARA rule signature INVALID - possible tampering: {:?}",
                        path
                    );
                    crate::core::tamper_protection::log_audit_event(
                        crate::core::tamper_protection::AuditEventType::YaraRuleRejected,
                        &format!("YARA rule tampered: {:?}", path),
                        path.to_str(),
                        None,
                    );
                    continue;
                }
                Err(err) => {
                    log::warn!("Could not verify YARA rule {:?}: {}", path, err);
                }
            }

            match fs::read_to_string(&path) {
                Ok(content) => rule_sources.push(RuleSource {
                    category: category.to_string(),
                    source_path: path.to_string_lossy().to_string(),
                    content,
                }),
                Err(err) => {
                    log::warn!("Failed to read YARA rule {:?}: {}", path, err);
                }
            }
        }

        rule_sources
    }

    fn validate_rule_sources(
        rule_sources: Vec<RuleSource>,
        emit_audit: bool,
    ) -> (Vec<RuleSource>, HashMap<String, RuleSourceInfo>) {
        let mut accepted_sources = Vec::new();
        let mut seen_rule_names = HashSet::new();
        let mut rule_sources_by_name = HashMap::new();

        for source in rule_sources {
            match Self::validate_rule_source(&source) {
                Ok(rule_names) => {
                    let duplicate_names: Vec<String> = rule_names
                        .iter()
                        .filter(|rule_name| seen_rule_names.contains(*rule_name))
                        .cloned()
                        .collect();

                    if !duplicate_names.is_empty() {
                        let details = format!(
                            "Duplicate YARA rule name(s) in {}: {}",
                            source.source_path,
                            duplicate_names.join(", ")
                        );
                        log::error!("{}", details);
                        Self::audit_compile_failure(&source, &details, emit_audit);
                        continue;
                    }

                    for rule_name in &rule_names {
                        seen_rule_names.insert(rule_name.clone());
                        rule_sources_by_name.insert(
                            rule_name.clone(),
                            RuleSourceInfo {
                                category: source.category.clone(),
                                source_path: source.source_path.clone(),
                            },
                        );
                    }

                    if emit_audit {
                        crate::core::tamper_protection::log_audit_event(
                            crate::core::tamper_protection::AuditEventType::YaraRuleLoaded,
                            &format!(
                                "Loaded {} YARA-X rule(s) from {}",
                                rule_names.len(),
                                source.source_path
                            ),
                            Some(source.source_path.as_str()),
                            None,
                        );
                    }

                    accepted_sources.push(source);
                }
                Err(details) => {
                    log::error!("{}", details);
                    Self::audit_compile_failure(&source, &details, emit_audit);
                }
            }
        }

        (accepted_sources, rule_sources_by_name)
    }

    fn validate_rule_source(source: &RuleSource) -> Result<Vec<String>, String> {
        let mut compiler = Compiler::new();
        compiler.relaxed_re_syntax(true);

        let source_code =
            SourceCode::from(source.content.as_str()).with_origin(source.source_path.as_str());

        if let Err(err) = compiler.add_source(source_code) {
            for warning in compiler.warnings() {
                log::warn!("YARA-X warning in {}: {}", source.source_path, warning);
            }

            let diagnostics = Self::format_compile_diagnostics(&compiler, &err.to_string());
            return Err(format!(
                "Failed to compile YARA-X rules from {}: {}",
                source.source_path, diagnostics
            ));
        }

        let rules = compiler.build();
        for warning in rules.warnings() {
            log::warn!("YARA-X warning in {}: {}", source.source_path, warning);
        }

        Ok(rules
            .iter()
            .map(|rule| rule.identifier().to_string())
            .collect())
    }

    fn compile_rule_sources(rule_sources: &[RuleSource], emit_audit: bool) -> Rules {
        let mut compiler = Compiler::new();
        compiler.relaxed_re_syntax(true);

        for source in rule_sources {
            let source_code =
                SourceCode::from(source.content.as_str()).with_origin(source.source_path.as_str());

            if let Err(err) = compiler.add_source(source_code) {
                let details = format!(
                    "Unexpected YARA-X compile failure after validation for {}: {}",
                    source.source_path,
                    Self::format_compile_diagnostics(&compiler, &err.to_string())
                );
                log::error!("{}", details);
                Self::audit_compile_failure(source, &details, emit_audit);
            }
        }

        compiler.build()
    }

    fn audit_compile_failure(source: &RuleSource, details: &str, emit_audit: bool) {
        if emit_audit {
            crate::core::tamper_protection::log_audit_event(
                crate::core::tamper_protection::AuditEventType::YaraRuleCompileFailed,
                details,
                Some(source.source_path.as_str()),
                None,
            );
        }
    }

    fn format_compile_diagnostics(compiler: &Compiler<'_>, primary_error: &str) -> String {
        let mut diagnostics = vec![primary_error.to_string()];

        for error in compiler.errors() {
            let rendered = error.to_string();
            if !diagnostics.iter().any(|existing| existing == &rendered) {
                diagnostics.push(rendered);
            }
        }

        diagnostics.join(" | ")
    }

    fn is_yara_rule_path(path: &Path) -> bool {
        matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some(ext) if ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara")
        )
    }

    fn rule_details(rule: &Rule<'_, '_>) -> (RuleSeverity, Option<String>) {
        let mut severity = RuleSeverity::Info;
        let mut description = None;

        for (ident, value) in rule.metadata() {
            match (ident, value) {
                ("severity", MetaValue::String(value)) => {
                    severity = Self::parse_severity(value);
                }
                ("description", MetaValue::String(value)) => {
                    description = Some(value.to_string());
                }
                ("description", MetaValue::Bytes(value)) => {
                    description = Some(String::from_utf8_lossy(value.as_ref()).into_owned());
                }
                _ => {}
            }
        }

        (severity, description)
    }

    fn parse_severity(value: &str) -> RuleSeverity {
        match value.to_lowercase().as_str() {
            "critical" => RuleSeverity::Critical,
            "high" => RuleSeverity::High,
            "medium" => RuleSeverity::Medium,
            "low" => RuleSeverity::Low,
            _ => RuleSeverity::Info,
        }
    }

    fn to_yara_match(&self, rule: Rule<'_, '_>) -> YaraMatch {
        let rule_name = rule.identifier().to_string();
        let (severity, description) = Self::rule_details(&rule);
        let offset = rule
            .patterns()
            .flat_map(|pattern| pattern.matches())
            .map(|matched| matched.range().start)
            .min();

        let source_info = self.rule_sources.get(&rule_name);

        YaraMatch {
            rule_name: rule_name.clone(),
            severity,
            description: description.unwrap_or(rule_name),
            category: source_info
                .map(|info| info.category.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            offset,
        }
    }

    pub fn scan(&self, content: &[u8]) -> Vec<YaraMatch> {
        let mut scanner = Scanner::new(&self.rules);

        match scanner.scan(content) {
            Ok(results) => results
                .matching_rules()
                .map(|rule| self.to_yara_match(rule))
                .collect(),
            Err(err) => {
                log::error!("YARA-X scan failed: {}", err);
                Vec::new()
            }
        }
    }
}

static YARA_SCANNER: Lazy<YaraScanner> = Lazy::new(YaraScanner::new);

pub fn scan_with_yara(content: &[u8]) -> Vec<YaraMatch> {
    YARA_SCANNER.scan(content)
}

pub fn get_rule_count() -> usize {
    YARA_SCANNER.rule_sources.len()
}

pub fn get_rules_by_severity(severity: RuleSeverity) -> Vec<String> {
    let mut rules: Vec<String> = YARA_SCANNER
        .rules
        .iter()
        .filter_map(|rule| {
            let (rule_severity, _) = YaraScanner::rule_details(&rule);
            (rule_severity == severity).then(|| rule.identifier().to_string())
        })
        .collect();

    rules.sort();
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(category: &str, source_path: &str, content: &str) -> RuleSource {
        RuleSource {
            category: category.to_string(),
            source_path: source_path.to_string(),
            content: content.to_string(),
        }
    }

    #[test]
    fn test_yara_match_serialization() {
        let yara_match = YaraMatch {
            rule_name: "TestRule".to_string(),
            severity: RuleSeverity::Critical,
            description: "Test description".to_string(),
            category: "strict".to_string(),
            offset: Some(100),
        };

        let json = serde_json::to_string(&yara_match).unwrap();
        assert!(json.contains("TestRule"));
        assert!(json.contains("Critical"));
        assert!(json.contains("100"));

        let deserialized: YaraMatch = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.rule_name, "TestRule");
        assert_eq!(deserialized.severity, RuleSeverity::Critical);
        assert_eq!(deserialized.category, "strict");
    }

    #[test]
    fn test_rules_loaded() {
        assert!(
            get_rule_count() > 0,
            "Expected YARA-X to load at least one bundled rule"
        );
    }

    #[test]
    fn test_eicar_at_zero_rule() {
        let scanner = YaraScanner::from_sources(vec![source(
            "strict",
            "eicar.yar",
            r#"
                rule EicarAtZero {
                    meta:
                        description = "EICAR test file"
                        severity = "high"
                    strings:
                        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                    condition:
                        $eicar at 0
                }
            "#,
        )]);

        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let prefixed =
            b"prefixX5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        let matches = scanner.scan(eicar);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "EicarAtZero");
        assert_eq!(matches[0].offset, Some(0));
        assert!(scanner.scan(prefixed).is_empty());
    }

    #[test]
    fn test_uint16_and_n_of_them_rule() {
        let scanner = YaraScanner::from_sources(vec![source(
            "strict",
            "pe_count.yar",
            r#"
                rule PeHeaderAndTwoStrings {
                    meta:
                        description = "PE header plus two strings"
                        severity = "critical"
                    strings:
                        $a = "alpha"
                        $b = "beta"
                        $c = "gamma"
                    condition:
                        uint16(0) == 0x5A4D and 2 of them
                }
            "#,
        )]);

        let matching = b"MZ....alpha....beta";
        let wrong_header = b"NZ....alpha....beta";

        let matches = scanner.scan(matching);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, RuleSeverity::Critical);
        assert!(scanner.scan(wrong_header).is_empty());
    }

    #[test]
    fn test_grouped_conditions_work() {
        let scanner = YaraScanner::from_sources(vec![source(
            "heuristic",
            "grouped.yar",
            r#"
                rule ProcessInjectionGrouped {
                    meta:
                        description = "Grouped any-of condition"
                        severity = "high"
                    strings:
                        $proc1 = "OpenProcess"
                        $proc2 = "CreateToolhelp32Snapshot"
                        $mem1 = "VirtualAllocEx"
                        $mem2 = "NtAllocateVirtualMemory"
                    condition:
                        any of ($proc*) and any of ($mem*)
                }
            "#,
        )]);

        let matching = b"...OpenProcess...VirtualAllocEx...";
        let partial = b"...OpenProcess only...";

        let matches = scanner.scan(matching);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].category, "heuristic");
        assert!(scanner.scan(partial).is_empty());
    }

    #[test]
    fn test_wide_ascii_nocase_string_matches() {
        let scanner = YaraScanner::from_sources(vec![source(
            "heuristic",
            "wide_ascii.yar",
            r#"
                rule WideAsciiNoCase {
                    meta:
                        description = "wide/ascii/nocase test"
                        severity = "medium"
                    strings:
                        $ps = "powershell" wide ascii nocase
                    condition:
                        $ps
                }
            "#,
        )]);

        let wide_mixed_case = [
            b'P', 0, b'o', 0, b'W', 0, b'e', 0, b'R', 0, b'S', 0, b'h', 0, b'E', 0, b'l', 0, b'L',
            0,
        ];

        let matches = scanner.scan(&wide_mixed_case);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, RuleSeverity::Medium);
    }

    #[test]
    fn test_compile_failure_skips_only_broken_source() {
        let scanner = YaraScanner::from_sources(vec![
            source(
                "strict",
                "good_rule.yar",
                r#"
                    rule GoodRule {
                        meta:
                            description = "Valid rule"
                            severity = "high"
                        strings:
                            $a = "GOOD"
                        condition:
                            $a
                    }
                "#,
            ),
            source(
                "strict",
                "broken_rule.yar",
                r#"
                    rule BrokenRule {
                        condition:
                    }
                "#,
            ),
        ]);

        let matches = scanner.scan(b"GOOD");
        assert_eq!(matches.len(), 1);
        assert_eq!(scanner.rule_sources.len(), 1);
        assert_eq!(scanner.rule_sources.keys().next().unwrap(), "GoodRule");
    }

    #[test]
    fn test_get_rules_by_severity_filters_bundled_rules() {
        let critical_rules = get_rules_by_severity(RuleSeverity::Critical);
        assert!(critical_rules.iter().all(|rule_name| !rule_name.is_empty()));
    }
}

// purple/src/correlation/rules/mod.rs
//!
//! Detection rules engine supporting:
//! - Custom rule definitions
//! - Sigma rule format support
//! - Rule matching and execution
//! - Rule management

use crate::correlation::models::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

/// Detection rules engine
#[derive(Debug, Clone)]
pub struct RulesEngine {
    rules: Arc<Mutex<Vec<DetectionRule>>>,
    sigma_rules: Arc<Mutex<Vec<SigmaRule>>>,
    compiled_rules: Arc<Mutex<HashMap<String, CompiledRule>>>,
    enabled: bool,
}

unsafe impl Send for RulesEngine {}
unsafe impl Sync for RulesEngine {}

impl Default for RulesEngine {
    fn default() -> Self {
        Self::new(true)
    }
}

impl RulesEngine {
    pub fn new(enabled: bool) -> Self {
        Self {
            rules: Arc::new(Mutex::new(Vec::new())),
            sigma_rules: Arc::new(Mutex::new(Vec::new())),
            compiled_rules: Arc::new(Mutex::new(HashMap::new())),
            enabled,
        }
    }

    /// Load rules from files
    pub fn load_rules_from_directory(&self, dir: PathBuf) -> Result<(), String> {
        if !dir.exists() {
            return Err(format!("Rules directory does not exist: {:?}", dir));
        }

        let mut loaded_count = 0;

        for entry in WalkDir::new(dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if let Some(ext) = entry.path().extension()
                && (ext == "yaml" || ext == "yml")
            {
                match self.load_rule_file(entry.path()) {
                    Ok(_) => loaded_count += 1,
                    Err(e) => {
                        log::warn!("Failed to load rule {}: {}", entry.path().display(), e)
                    }
                }
            }
        }

        log::info!("Loaded {} detection rules", loaded_count);
        Ok(())
    }

    /// Load a single rule file
    fn load_rule_file(&self, path: &Path) -> Result<(), String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read rule file: {}", e))?;

        // Try to parse as Sigma rule first
        if let Ok(sigma_rule) = serde_yaml::from_str::<SigmaRule>(&content) {
            let mut sigma_rules = self.sigma_rules.lock().unwrap_or_else(|e| e.into_inner());
            sigma_rules.push(sigma_rule);
            return Ok(());
        }

        // Try to parse as custom detection rule
        if let Ok(rule) = serde_yaml::from_str::<DetectionRule>(&content) {
            let mut rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
            rules.push(rule);
            return Ok(());
        }

        Err("Failed to parse rule file".to_string())
    }

    /// Add a custom rule
    pub fn add_rule(&self, rule: DetectionRule) {
        {
            let mut rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
            rules.push(rule);
        }
        self.recompile_rules();
    }

    /// Compile rules for performance
    fn recompile_rules(&self) {
        let mut compiled = self
            .compiled_rules
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());

        for rule in rules.iter() {
            if rule.enabled {
                let compiled_rule = self.compile_rule(rule);
                compiled.insert(rule.id.clone(), compiled_rule);
            }
        }
    }

    /// Compile a single rule
    fn compile_rule(&self, rule: &DetectionRule) -> CompiledRule {
        let mut compiled = CompiledRule {
            rule_id: rule.id.clone(),
            name: rule.name.clone(),
            severity: rule.severity.clone(),
            conditions: Vec::new(),
        };

        #[allow(clippy::regex_creation_in_loops)]
        for cond in &rule.conditions {
            let compiled_cond = match cond.operator {
                ConditionOperator::Contains => CompiledCondition::Contains(
                    cond.field.clone(),
                    self.extract_string_value(&cond.value),
                ),
                ConditionOperator::Matches => CompiledCondition::Matches(
                    cond.field.clone(),
                    Regex::new(&self.extract_string_value(&cond.value))
                        .unwrap_or_else(|_| Regex::new(".*").unwrap()),
                ),
                ConditionOperator::Equals => {
                    CompiledCondition::Equals(cond.field.clone(), self.extract_value(&cond.value))
                }
                ConditionOperator::GreaterThan => CompiledCondition::GreaterThan(
                    cond.field.clone(),
                    self.extract_f64(&cond.value).unwrap_or(0.0),
                ),
                _ => CompiledCondition::Equals(cond.field.clone(), cond.value.clone()),
            };
            compiled.conditions.push(compiled_cond);
        }

        compiled
    }

    /// Match an event against all rules
    pub fn match_event(&self, event: &EnrichedEvent) -> Vec<RuleMatch> {
        if !self.enabled {
            return Vec::new();
        }

        let mut matches = Vec::new();
        let compiled_rules = self
            .compiled_rules
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        for (_id, rule) in compiled_rules.iter() {
            if self.evaluate_rule(rule, event) {
                matches.push(RuleMatch {
                    rule_id: rule.rule_id.clone(),
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    matched_conditions: rule.conditions.len(),
                });
            }
        }

        matches
    }

    /// Evaluate a compiled rule against an event
    fn evaluate_rule(&self, rule: &CompiledRule, event: &EnrichedEvent) -> bool {
        for cond in &rule.conditions {
            if !self.evaluate_condition(cond, event) {
                return false;
            }
        }
        true
    }

    /// Evaluate a condition against an event
    fn evaluate_condition(&self, cond: &CompiledCondition, event: &EnrichedEvent) -> bool {
        let (_field, result) = match cond {
            CompiledCondition::Equals(field, expected) => {
                let value = self.get_event_value(field, event);
                (field.clone(), value == *expected)
            }
            CompiledCondition::Contains(field, substring) => {
                let value = self.get_event_value(field, event);
                (field.clone(), value.to_string().contains(substring))
            }
            CompiledCondition::Matches(field, regex) => {
                let value = self.get_event_value(field, event);
                (field.clone(), regex.is_match(&value.to_string()))
            }
            CompiledCondition::GreaterThan(field, threshold) => {
                let value = self.get_event_value(field, event);
                (
                    field.clone(),
                    self.extract_f64(&value)
                        .map(|v| v > *threshold)
                        .unwrap_or(false),
                )
            }
            CompiledCondition::LessThan(field, threshold) => {
                let value = self.get_event_value(field, event);
                (
                    field.clone(),
                    self.extract_f64(&value)
                        .map(|v| v < *threshold)
                        .unwrap_or(false),
                )
            }
        };

        result
    }

    /// Get a value from an event by field path
    fn get_event_value(&self, field: &str, event: &EnrichedEvent) -> serde_json::Value {
        match field {
            "event_type" => serde_json::json!(event.base.event_type),
            "severity" => serde_json::json!(format!("{:?}", event.severity)),
            "category" => serde_json::json!(format!("{:?}", event.base.category)),
            "pid" => serde_json::json!(event.base.pid),
            "comm" => serde_json::json!(event.base.comm),
            "details" => serde_json::json!(event.base.details),
            "risk_score" => serde_json::json!(event.risk_score),
            "is_expected" => serde_json::json!(event.is_expected),
            _ => serde_json::json!(null),
        }
    }

    fn extract_string_value(&self, value: &serde_json::Value) -> String {
        value.as_str().unwrap_or("").to_string()
    }

    fn extract_f64(&self, value: &serde_json::Value) -> Option<f64> {
        value
            .as_f64()
            .or(value.as_u64().map(|u| u as f64))
            .or(value.as_i64().map(|i| i as f64))
    }

    fn extract_value(&self, value: &serde_json::Value) -> serde_json::Value {
        value.clone()
    }

    /// Get rule count
    pub fn get_rule_count(&self) -> usize {
        let rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        let sigma_rules = self.sigma_rules.lock().unwrap_or_else(|e| e.into_inner());
        rules.len() + sigma_rules.len()
    }

    /// Get all rules
    pub fn get_all_rules(&self) -> Vec<DetectionRule> {
        let rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        rules.clone()
    }
}

/// Compiled rule for efficient matching
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule_id: String,
    pub name: String,
    pub severity: Severity,
    pub conditions: Vec<CompiledCondition>,
}

#[derive(Debug, Clone)]
pub enum CompiledCondition {
    Equals(String, serde_json::Value),
    Contains(String, String),
    Matches(String, Regex),
    GreaterThan(String, f64),
    LessThan(String, f64),
}

/// Result of a rule match
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub matched_conditions: usize,
}

/// Sigma rule format support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    pub id: String,
    pub status: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub tags: Option<Vec<String>>,
    pub level: Option<String>,
    pub falsepositives: Option<Vec<String>>,
    pub logsource: Option<SigmaLogSource>,
    pub detection: Option<SigmaDetection>,
    pub fields: Option<Vec<String>>,
    pub references: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaLogSource {
    pub product: Option<String>,
    pub service: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaDetection {
    pub selection: Option<HashMap<String, serde_yaml::Value>>,
    pub filter: Option<HashMap<String, serde_yaml::Value>>,
    pub condition: Option<String>,
}

impl SigmaRule {
    /// Convert Sigma rule to internal DetectionRule format
    pub fn to_detection_rule(&self) -> Option<DetectionRule> {
        let detection = self.detection.as_ref()?;
        let selection = detection.selection.as_ref()?;
        let _condition = detection.condition.as_ref()?;

        let mut conditions = Vec::new();

        for (field, value) in selection {
            let operator = match value {
                serde_yaml::Value::String(s) if s.starts_with("*") => ConditionOperator::Contains,
                serde_yaml::Value::String(_) => ConditionOperator::Equals,
                serde_yaml::Value::Number(_) => ConditionOperator::GreaterThan,
                _ => ConditionOperator::Equals,
            };

            conditions.push(RuleCondition {
                field: field.clone(),
                operator,
                value: serde_json::to_value(value).ok()?,
            });
        }

        let severity = match self.level.as_deref() {
            Some("critical") => Severity::Critical,
            Some("high") => Severity::High,
            Some("medium") => Severity::Medium,
            Some("low") => Severity::Low,
            _ => Severity::Medium,
        };

        Some(DetectionRule {
            id: self.id.clone(),
            name: self.title.clone(),
            description: self.description.clone().unwrap_or_default(),
            severity,
            conditions,
            actions: vec![RuleAction::Alert],
            enabled: self.status.as_deref() != Some("deprecated"),
            tags: self.tags.clone().unwrap_or_default(),
        })
    }
}

/// Built-in detection rules
pub fn get_builtin_rules() -> Vec<DetectionRule> {
    vec![
        // File exfiltration detection
        DetectionRule {
            id: "builtin_file_exfil_001".to_string(),
            name: "File Exfiltration Pattern".to_string(),
            description:
                "Detect potential file exfiltration: multiple reads followed by network connections"
                    .to_string(),
            severity: Severity::Critical,
            conditions: vec![RuleCondition {
                field: "category".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("FileAccess"),
            }],
            actions: vec![RuleAction::Alert, RuleAction::Score(30.0)],
            enabled: true,
            tags: vec!["exfiltration".to_string(), "data-loss".to_string()],
        },
        // Privilege escalation detection
        DetectionRule {
            id: "builtin_priv_esc_001".to_string(),
            name: "Privilege Escalation Attempt".to_string(),
            description: "Detect privilege escalation via setuid/setgid".to_string(),
            severity: Severity::Critical,
            conditions: vec![RuleCondition {
                field: "details".to_string(),
                operator: ConditionOperator::Contains,
                value: serde_json::json!("setuid"),
            }],
            actions: vec![RuleAction::Alert, RuleAction::Score(40.0)],
            enabled: true,
            tags: vec!["privilege-escalation".to_string()],
        },
        // Shell spawning detection
        DetectionRule {
            id: "builtin_shell_001".to_string(),
            name: "Shell Spawn Detected".to_string(),
            description: "Detect shell spawning from unusual process".to_string(),
            severity: Severity::High,
            conditions: vec![RuleCondition {
                field: "details".to_string(),
                operator: ConditionOperator::Contains,
                value: serde_json::json!("execve"),
            }],
            actions: vec![RuleAction::Alert],
            enabled: true,
            tags: vec!["execution".to_string(), "shell".to_string()],
        },
        // Mass file access detection
        DetectionRule {
            id: "builtin_mass_access_001".to_string(),
            name: "Mass File Access".to_string(),
            description: "Detect unusual number of file access operations".to_string(),
            severity: Severity::Medium,
            conditions: vec![RuleCondition {
                field: "category".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("FileAccess"),
            }],
            actions: vec![RuleAction::Log],
            enabled: true,
            tags: vec!["reconnaissance".to_string()],
        },
        // Suspicious network connections
        DetectionRule {
            id: "builtin_network_suspicious_001".to_string(),
            name: "Suspicious Network Connection".to_string(),
            description: "Detect connections to suspicious ports".to_string(),
            severity: Severity::High,
            conditions: vec![RuleCondition {
                field: "category".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("Network"),
            }],
            actions: vec![RuleAction::Alert, RuleAction::Score(20.0)],
            enabled: true,
            tags: vec!["command-and-control".to_string()],
        },
        // Persistence attempt
        DetectionRule {
            id: "builtin_persistence_001".to_string(),
            name: "Persistence Attempt".to_string(),
            description: "Detect file creation in startup locations".to_string(),
            severity: Severity::High,
            conditions: vec![RuleCondition {
                field: "details".to_string(),
                operator: ConditionOperator::Contains,
                value: serde_json::json!("/etc/"),
            }],
            actions: vec![RuleAction::Alert],
            enabled: true,
            tags: vec!["persistence".to_string()],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_engine() {
        let engine = RulesEngine::new(true);

        // Add a test rule
        let rule = DetectionRule {
            id: "test_001".to_string(),
            name: "Test Rule".to_string(),
            description: "Test rule for unit testing".to_string(),
            severity: Severity::High,
            conditions: vec![RuleCondition {
                field: "category".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("FileAccess"),
            }],
            actions: vec![RuleAction::Alert],
            enabled: true,
            tags: vec!["test".to_string()],
        };

        engine.add_rule(rule);

        // Test matching
        let event = EnrichedEvent {
            base: RawEvent::new(
                "syscall".to_string(),
                1234,
                "openat file".to_string(),
                EventCategory::FileAccess,
            ),
            ..Default::default()
        };

        let matches = engine.match_event(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "test_001");
    }

    #[test]
    fn test_sigma_rule_parsing() {
        let sigma_yaml = r#"
title: Test Sigma Rule
id: sigma-test-001
status: stable
description: A test sigma rule
level: high
tags:
  - attack.execution
detection:
  selection:
    EventID: 4688
    CommandLine|contains: 'calc.exe'
  condition: selection
"#;

        let sigma_rule: SigmaRule = serde_yaml::from_str(sigma_yaml).unwrap();
        assert_eq!(sigma_rule.title, "Test Sigma Rule");
        assert_eq!(sigma_rule.level, Some("high".to_string()));

        let detection_rule = sigma_rule.to_detection_rule().unwrap();
        assert_eq!(detection_rule.id, "sigma-test-001");
        assert_eq!(detection_rule.severity, Severity::High);
    }
}

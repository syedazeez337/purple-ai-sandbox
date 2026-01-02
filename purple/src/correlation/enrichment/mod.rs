// purple/src/correlation/enrichment/mod.rs
//!
//! Event enrichment module providing:
//! - Threat intelligence integration
//! - MITRE ATT&CK mapping
//! - Event severity classification
//! - IOC detection and enrichment

use crate::correlation::models::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

#[inline]
fn extract_after_delimiter(details: &str, delimiter: &str, default: &str) -> String {
    details
        .split(delimiter)
        .nth(1)
        .unwrap_or(default)
        .split(',')
        .next()
        .unwrap_or(default)
        .trim()
        .to_string()
}

#[inline]
fn extract_after_prefix(details: &str, prefix: &str) -> String {
    details
        .split(prefix)
        .nth(1)
        .unwrap_or("")
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

#[inline]
fn extract_u64_after(details: &str, delimiter: &str) -> u64 {
    details
        .split(delimiter)
        .nth(1)
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

#[inline]
fn extract_first_part(details: &str, default: &str) -> String {
    details.split('[').next().unwrap_or(default).to_string()
}

/// Threat intelligence service
#[derive(Debug, Clone)]
pub struct ThreatIntelligenceService {
    config: ThreatIntelligenceConfig,
}

impl Default for ThreatIntelligenceService {
    fn default() -> Self {
        Self::new(ThreatIntelligenceConfig::default())
    }
}

impl ThreatIntelligenceService {
    pub fn new(config: ThreatIntelligenceConfig) -> Self {
        Self { config }
    }

    /// Check if an IP is malicious
    pub async fn check_ip(&self, ip: &Ipv4Addr) -> Option<ThreatIndicator> {
        if !self.config.enabled {
            return None;
        }
        self.check_known_malicious_ip(ip)
    }

    /// Check domain against threat intelligence
    pub async fn check_domain(&self, domain: &str) -> Option<ThreatIndicator> {
        if !self.config.enabled {
            return None;
        }
        self.check_known_malicious_domain(&domain.to_lowercase())
    }

    /// Check file hash against threat intelligence
    pub async fn check_hash(&self, hash: &str) -> Option<ThreatIndicator> {
        if !self.config.enabled {
            return None;
        }
        self.check_known_malicious_hash(&hash.to_lowercase())
    }

    /// Built-in check for known malicious IPs (limited sample)
    fn check_known_malicious_ip(&self, _ip: &Ipv4Addr) -> Option<ThreatIndicator> {
        // In production, this would check against a comprehensive database
        // For now, return None as this is a demo
        None
    }

    /// Built-in check for known malicious domains
    fn check_known_malicious_domain(&self, _domain: &str) -> Option<ThreatIndicator> {
        // In production, this would check against a comprehensive database
        None
    }

    /// Built-in check for known malicious hashes
    fn check_known_malicious_hash(&self, _hash: &str) -> Option<ThreatIndicator> {
        // In production, this would check against a comprehensive database
        None
    }
}

/// Represents a known threat indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub ioc_type: IocType,
    pub value: String,
    pub severity: Severity,
    pub confidence: f32,
    pub source: String,
    pub description: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub tags: Vec<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IocType {
    #[serde(rename = "ipv4")]
    IPv4,
    #[serde(rename = "ipv6")]
    IPv6,
    #[serde(rename = "domain")]
    Domain,
    #[serde(rename = "url")]
    Url,
    #[serde(rename = "hash_md5")]
    HashMD5,
    #[serde(rename = "hash_sha1")]
    HashSHA1,
    #[serde(rename = "hash_sha256")]
    HashSHA256,
    #[serde(rename = "email")]
    Email,
    #[serde(rename = "mutex")]
    Mutex,
    #[serde(rename = "registry")]
    Registry,
}

pub enum IndicatorOfCompromise {
    Ip(Ipv4Addr, ThreatIndicator),
    Domain(String, ThreatIndicator),
    Hash(String, ThreatIndicator),
}

/// MITRE ATT&CK Mapping Service
#[derive(Debug, Clone, Default)]
pub struct AttackMappingService;

impl AttackMappingService {
    /// Map a syscall to ATT&CK techniques
    pub fn map_syscall(syscall_nr: u64, args: &[u64]) -> Vec<AttackTechnique> {
        let mut techniques = Vec::new();

        // Map syscall number to techniques
        let syscall_map: HashMap<u64, Vec<(&str, &str)>> = [
            (0, vec![("T1005", "Data from Local System")]), // read
            (2, vec![("T1059", "Command and Scripting Interpreter")]), // creat
            (3, vec![("T1005", "Data from Local System")]), // close
            (9, vec![("T1055", "Process Injection")]),      // mmap
            (10, vec![("T1055", "Process Injection")]),     // mprotect
            (11, vec![("T1059", "Command and Scripting Interpreter")]), // brk
            (21, vec![("T1005", "Data from Local System")]), // access
            (59, vec![("T1218", "Signed Binary Proxy Execution")]), // execve (indirectly)
            (231, vec![("T1204", "User Execution")]),       // execveat
            (
                257,
                vec![
                    ("T1005", "Data from Local System"),
                    ("T1083", "File and Directory Discovery"),
                ],
            ), // openat
            (262, vec![("T1005", "Data from Local System")]), // newfstatat
            (263, vec![("T1562", "Impair Defenses")]),      // pg
            (264, vec![("T1578", "Modify Authentication Process")]), // umount
        ]
        .iter()
        .cloned()
        .collect();

        if let Some(mappings) = syscall_map.get(&syscall_nr) {
            for (technique_id, technique_name) in mappings {
                techniques.push(AttackTechnique {
                    technique_id: technique_id.to_string(),
                    technique_name: technique_name.to_string(),
                    tactic: Self::get_tactic_for_technique(technique_id),
                    confidence: 0.7,
                });
            }
        }

        // Additional mapping based on arguments
        if syscall_nr == 59 || syscall_nr == 231 {
            // execve/execveat with shell argument
            if args.len() > 1 {
                techniques.push(AttackTechnique {
                    technique_id: "T1059".to_string(),
                    technique_name: "Command and Scripting Interpreter".to_string(),
                    tactic: "Execution".to_string(),
                    confidence: 0.8,
                });
            }
        }

        techniques
    }

    /// Map file operations to ATT&CK techniques
    pub fn map_file_operation(operation: &str, filepath: &str) -> Vec<AttackTechnique> {
        let mut techniques = Vec::new();

        match operation.to_lowercase().as_str() {
            op if op.contains("read") || op.contains("open") => {
                techniques.push(AttackTechnique {
                    technique_id: "T1005".to_string(),
                    technique_name: "Data from Local System".to_string(),
                    tactic: "Collection".to_string(),
                    confidence: 0.7,
                });
                techniques.push(AttackTechnique {
                    technique_id: "T1083".to_string(),
                    technique_name: "File and Directory Discovery".to_string(),
                    tactic: "Discovery".to_string(),
                    confidence: 0.6,
                });
            }
            op if op.contains("write") || op.contains("create") => {
                techniques.push(AttackTechnique {
                    technique_id: "T1565".to_string(),
                    technique_name: "Data Manipulation".to_string(),
                    tactic: "Impact".to_string(),
                    confidence: 0.7,
                });

                // Check for persistence locations
                if filepath.contains("/etc/")
                    || filepath.contains("/cron")
                    || filepath.contains("/systemd")
                {
                    techniques.push(AttackTechnique {
                        technique_id: "T1543".to_string(),
                        technique_name: "Create or Modify System Process".to_string(),
                        tactic: "Persistence".to_string(),
                        confidence: 0.85,
                    });
                }
            }
            op if op.contains("delete") || op.contains("unlink") => {
                techniques.push(AttackTechnique {
                    technique_id: "T1070".to_string(),
                    technique_name: "Indicator Removal".to_string(),
                    tactic: "Defense Evasion".to_string(),
                    confidence: 0.75,
                });
            }
            _ => {}
        }

        techniques
    }

    /// Map network operations to ATT&CK techniques
    pub fn map_network_operation(
        _dest_ip: &str,
        dest_port: u16,
        bytes: u64,
    ) -> Vec<AttackTechnique> {
        let mut techniques = Vec::new();

        // Suspicious ports
        let suspicious_ports = [22, 23, 445, 139, 3389, 5900];
        if suspicious_ports.contains(&dest_port) {
            techniques.push(AttackTechnique {
                technique_id: "T1041".to_string(),
                technique_name: "Exfiltration Over C2 Channel".to_string(),
                tactic: "Exfiltration".to_string(),
                confidence: 0.6,
            });
        }

        // Large data transfers
        if bytes > 1000000 {
            techniques.push(AttackTechnique {
                technique_id: "T1041".to_string(),
                technique_name: "Exfiltration Over C2 Channel".to_string(),
                tactic: "Exfiltration".to_string(),
                confidence: 0.7,
            });
        }

        // Check for known C2 ports
        let c2_ports = [4444, 5555, 8080, 443, 80];
        if c2_ports.contains(&dest_port) {
            techniques.push(AttackTechnique {
                technique_id: "T1071".to_string(),
                technique_name: "Application Layer Protocol".to_string(),
                tactic: "Command and Control".to_string(),
                confidence: 0.5,
            });
        }

        techniques
    }

    fn get_tactic_for_technique(technique_id: &str) -> String {
        let technique_tactics: HashMap<&str, &str> = [
            ("T1005", "Collection"),
            ("T1055", "Privilege Escalation"),
            ("T1059", "Execution"),
            ("T1083", "Discovery"),
            ("T1204", "Execution"),
            ("T1562", "Defense Evasion"),
            ("T1578", "Persistence"),
            ("T1565", "Impact"),
            ("T1070", "Defense Evasion"),
            ("T1041", "Exfiltration"),
            ("T1071", "Command and Control"),
            ("T1218", "Defense Evasion"),
            ("T1543", "Persistence"),
        ]
        .into();

        technique_tactics
            .get(technique_id)
            .copied()
            .unwrap_or("Unknown")
            .to_string()
    }
}

/// ATT&CK technique mapping result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub confidence: f32,
}

/// Event Enricher - adds metadata and classification to events
#[derive(Debug, Clone)]
pub struct EventEnricher {
    threat_intel: ThreatIntelligenceService,
    _attack_mapper: AttackMappingService,
    severity_rules: SeverityClassifier,
}

impl Default for EventEnricher {
    fn default() -> Self {
        Self::new(ThreatIntelligenceConfig::default())
    }
}

impl EventEnricher {
    pub fn new(threat_config: ThreatIntelligenceConfig) -> Self {
        Self {
            threat_intel: ThreatIntelligenceService::new(threat_config),
            _attack_mapper: AttackMappingService,
            severity_rules: SeverityClassifier,
        }
    }

    /// Enrich a raw event with additional metadata
    pub async fn enrich(&self, event: RawEvent, intent: Option<&LlmIntent>) -> EnrichedEvent {
        let mut enriched = EnrichedEvent {
            base: event.clone(),
            intent_id: intent.map(|i| i.intent_id.clone()),
            severity: self.severity_rules.classify(&event),
            ..Default::default()
        };

        match event.category {
            EventCategory::Syscall => {
                let syscall_nr = self.extract_syscall_nr(&event.details);
                let args = self.extract_args(&event.details);
                let techniques = AttackMappingService::map_syscall(syscall_nr, &args);
                for tech in &techniques {
                    enriched.attack_tactics.push(tech.tactic.clone());
                    enriched.attack_techniques.push(tech.technique_id.clone());
                }
            }
            EventCategory::FileAccess => {
                let operation = self.extract_file_operation(&event.details);
                let filepath = self.extract_filepath(&event.details);
                let techniques = AttackMappingService::map_file_operation(&operation, &filepath);
                for tech in &techniques {
                    enriched.attack_tactics.push(tech.tactic.clone());
                    enriched.attack_techniques.push(tech.technique_id.clone());
                }
            }
            EventCategory::Network => {
                let (dest_ip, dest_port, bytes) = self.extract_network_info(&event.details);
                let techniques =
                    AttackMappingService::map_network_operation(&dest_ip, dest_port, bytes);
                for tech in &techniques {
                    enriched.attack_tactics.push(tech.tactic.clone());
                    enriched.attack_techniques.push(tech.technique_id.clone());
                }

                // Check threat intelligence for IP
                if let Ok(ip) = dest_ip.parse::<Ipv4Addr>()
                    && let Some(indicator) = self.threat_intel.check_ip(&ip).await
                {
                    enriched.risk_score = indicator.severity.numeric_value();
                    enriched.confidence = indicator.confidence;
                    enriched
                        .indicators
                        .push(format!("Malicious IP: {}", dest_ip));
                }
            }
            _ => {}
        }

        // Check if event matches expected intent
        if let Some(intent) = intent {
            enriched.is_expected = self.is_expected_event(&event, intent);
        }

        enriched.risk_score = enriched.severity.numeric_value() * enriched.confidence;

        enriched
    }

    fn extract_syscall_nr(&self, details: &str) -> u64 {
        details
            .split("nr=")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    fn extract_args(&self, details: &str) -> [u64; 3] {
        let mut args = [0u64; 3];
        if let Some(args_str) = details.split("args=(").nth(1) {
            let parts: Vec<&str> = args_str.trim_matches(')').split(",").collect();
            for (i, part) in parts.iter().take(3).enumerate() {
                args[i] = part.trim().parse().unwrap_or(0);
            }
        }
        args
    }

    fn extract_file_operation(&self, details: &str) -> String {
        extract_first_part(details, "unknown")
    }

    fn extract_filepath(&self, details: &str) -> String {
        extract_after_prefix(details, "filename=")
    }

    fn extract_network_info(&self, details: &str) -> (String, u16, u64) {
        let dest_ip = extract_after_prefix(details, "dest=");
        let dest_port = extract_after_delimiter(details, "dest=", "0")
            .parse()
            .unwrap_or(0);
        let bytes = extract_u64_after(details, "bytes=");

        (dest_ip, dest_port, bytes)
    }

    fn is_expected_event(&self, event: &RawEvent, intent: &LlmIntent) -> bool {
        // Check if event type is expected
        if !intent.expected_actions.is_empty() {
            for expected in &intent.expected_actions {
                if event
                    .details
                    .to_lowercase()
                    .contains(&expected.to_lowercase())
                {
                    return true;
                }
            }
        }

        // Check if category is expected
        if !intent.expected_categories.is_empty()
            && intent.expected_categories.contains(&event.category)
        {
            return true;
        }

        false
    }
}

/// Severity classification rules
#[derive(Debug, Clone, Default)]
pub struct SeverityClassifier;

impl SeverityClassifier {
    pub fn classify(&self, event: &RawEvent) -> Severity {
        let details_lower = event.details.to_lowercase();

        // Critical severity events
        let critical_patterns = [
            "mount",
            "umount",
            "pivot_root",
            "chroot",
            "kexec",
            "init_module",
            "delete_module",
            "ptrace",
            "process_vm_read",
            "process_vm_write",
            "setuid",
            "setgid",
            "setreuid",
            "setregid",
        ];

        for pattern in &critical_patterns {
            if details_lower.contains(pattern) {
                return Severity::Critical;
            }
        }

        // High severity events
        let high_patterns = [
            "execve", "fork", "clone", "vfork", "socket", "connect", "bind", "listen", "openat",
            "creat", "unlink", "rename", "chmod", "chown", "chgrp",
        ];

        for pattern in &high_patterns {
            if details_lower.contains(pattern) {
                return Severity::High;
            }
        }

        // Medium severity events
        let medium_patterns = [
            "read", "write", "close", "lseek", "stat", "fstat", "lstat", "access", "brk", "mmap",
            "mprotect", "munmap",
        ];

        for pattern in &medium_patterns {
            if details_lower.contains(pattern) {
                return Severity::Medium;
            }
        }

        Severity::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_enrichment() {
        let enricher = EventEnricher::new(ThreatIntelligenceConfig::default());

        let raw_event = RawEvent::new(
            "syscall".to_string(),
            1234,
            "Syscall[nr=59, args=(0x0, 0x0, 0x0), comm=test]".to_string(),
            EventCategory::Syscall,
        );

        let enriched = enricher.enrich(raw_event, None).await;

        assert_eq!(enriched.base.pid, 1234);
        assert!(!enriched.attack_techniques.is_empty());
    }

    #[test]
    fn test_severity_classification() {
        let classifier = SeverityClassifier::default();

        let critical_event = RawEvent::new(
            "syscall".to_string(),
            1234,
            "mount namespace operation".to_string(),
            EventCategory::Syscall,
        );
        assert_eq!(classifier.classify(&critical_event), Severity::Critical);

        let normal_event = RawEvent::new(
            "syscall".to_string(),
            1234,
            "read file operation".to_string(),
            EventCategory::Syscall,
        );
        assert_eq!(classifier.classify(&normal_event), Severity::Medium);
    }

    #[test]
    fn test_attack_mapping() {
        let mapper = AttackMappingService::default();
        let _ = mapper;

        let techniques = AttackMappingService::map_syscall(59, &[0, 0, 0]);
        assert!(!techniques.is_empty());
        assert!(techniques.iter().any(|t| t.technique_id == "T1059"));
    }
}

// purple/src/correlation/models/mod.rs
//!
//! Core data models for the correlation engine

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Unique session identifier
pub type SessionId = String;
/// Unique event identifier
pub type EventId = String;
/// Unique intent identifier  
pub type IntentId = String;
/// Risk score type (0-100)
pub type RiskScore = f32;

/// Severity levels for events and anomalies
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Severity {
    #[serde(rename = "critical")]
    Critical,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "informational")]
    #[default]
    Informational,
}

impl Severity {
    pub fn numeric_value(&self) -> f32 {
        match self {
            Severity::Critical => 100.0,
            Severity::High => 75.0,
            Severity::Medium => 50.0,
            Severity::Low => 25.0,
            Severity::Informational => 5.0,
        }
    }

    /// Convert from z-score magnitude to severity level
    pub fn from_z_score(z_score: f64) -> Self {
        if z_score >= 5.0 {
            Severity::Critical
        } else if z_score >= 3.0 {
            Severity::High
        } else if z_score >= 2.0 {
            Severity::Medium
        } else if z_score >= 1.0 {
            Severity::Low
        } else {
            Severity::Informational
        }
    }
}

/// Event categories for classification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EventCategory {
    #[serde(rename = "syscall")]
    #[default]
    Syscall,
    #[serde(rename = "file_access")]
    FileAccess,
    #[serde(rename = "network")]
    Network,
    #[serde(rename = "process")]
    Process,
    #[serde(rename = "memory")]
    Memory,
    #[serde(rename = "capability")]
    Capability,
    #[serde(rename = "resource")]
    Resource,
    #[serde(rename = "api_call")]
    ApiCall,
    #[serde(rename = "authentication")]
    Authentication,
    #[serde(rename = "configuration")]
    Configuration,
}

/// Types of anomalies that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    #[serde(rename = "rate_exceeded")]
    RateExceeded,
    #[serde(rename = "sequence_violation")]
    SequenceViolation,
    #[serde(rename = "statistical_outlier")]
    StatisticalOutlier,
    #[serde(rename = "behavioral_drift")]
    BehavioralDrift,
    #[serde(rename = "permission_escalation")]
    PermissionEscalation,
    #[serde(rename = "data_exfiltration")]
    DataExfiltration,
    #[serde(rename = "persistence_attempt")]
    PersistenceAttempt,
    #[serde(rename = "command_injection")]
    CommandInjection,
    #[serde(rename = "network_anomaly")]
    NetworkAnomaly,
    #[serde(rename = "resource_abuse")]
    ResourceAbuse,
    #[serde(rename = "unknown")]
    Unknown,
}

/// Recommended actions for detected anomalies
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RecommendedAction {
    #[serde(rename = "none")]
    #[default]
    None,
    #[serde(rename = "log")]
    Log,
    #[serde(rename = "alert")]
    Alert,
    #[serde(rename = "block")]
    Block,
    #[serde(rename = "terminate")]
    Terminate,
    #[serde(rename = "isolate")]
    Isolate,
    #[serde(rename = "notify_admin")]
    NotifyAdmin,
}

/// LLM Intent representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmIntent {
    pub intent_id: IntentId,
    pub timestamp: u64,
    pub prompt: String,
    pub expected_actions: Vec<String>,
    pub expected_categories: Vec<EventCategory>,
    pub expected_files: Vec<String>,
    pub expected_networks: Vec<String>,
    pub confidence: f32,
    pub metadata: HashMap<String, String>,
    pub profile_name: String,
    pub sandbox_id: Option<SessionId>,
}

impl Default for LlmIntent {
    fn default() -> Self {
        Self {
            intent_id: Uuid::new_v4().to_string(),
            timestamp: now_timestamp(),
            prompt: String::new(),
            expected_actions: Vec::new(),
            expected_categories: Vec::new(),
            expected_files: Vec::new(),
            expected_networks: Vec::new(),
            confidence: 0.8,
            metadata: HashMap::new(),
            profile_name: String::new(),
            sandbox_id: None,
        }
    }
}

impl LlmIntent {
    pub fn new(prompt: String, expected_actions: Vec<String>, profile_name: String) -> Self {
        Self {
            intent_id: Uuid::new_v4().to_string(),
            timestamp: now_timestamp(),
            prompt,
            expected_actions,
            expected_categories: Vec::new(),
            expected_files: Vec::new(),
            expected_networks: Vec::new(),
            confidence: 0.8,
            metadata: HashMap::new(),
            profile_name,
            sandbox_id: None,
        }
    }
}

/// Base observed event from eBPF or other sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub event_id: EventId,
    pub event_type: String,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    pub details: String,
    pub category: EventCategory,
}

impl RawEvent {
    pub fn new(event_type: String, pid: u32, details: String, category: EventCategory) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            event_type,
            timestamp: now_timestamp(),
            pid,
            tid: 0,
            comm: String::new(),
            details,
            category,
        }
    }
}

/// Enriched event with correlation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEvent {
    pub base: RawEvent,
    pub intent_id: Option<IntentId>,
    pub severity: Severity,
    pub attack_tactics: Vec<String>,
    pub attack_techniques: Vec<String>,
    pub risk_score: RiskScore,
    pub confidence: f32,
    pub matched_rules: Vec<String>,
    pub indicators: Vec<String>,
    pub enriched_fields: HashMap<String, String>,
    pub sequence_position: usize,
    pub is_expected: bool,
    pub behavioral_features: BehavioralFeatures,
}

impl Default for EnrichedEvent {
    fn default() -> Self {
        Self {
            base: RawEvent::new(
                "unknown".to_string(),
                0,
                String::new(),
                EventCategory::Syscall,
            ),
            intent_id: None,
            severity: Severity::default(),
            attack_tactics: Vec::new(),
            attack_techniques: Vec::new(),
            risk_score: 0.0,
            confidence: 0.5,
            matched_rules: Vec::new(),
            indicators: Vec::new(),
            enriched_fields: HashMap::new(),
            sequence_position: 0,
            is_expected: true,
            behavioral_features: BehavioralFeatures::default(),
        }
    }
}

/// Behavioral features extracted from events
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BehavioralFeatures {
    pub file_access_count: u64,
    pub network_connections: u64,
    pub unique_files: usize,
    pub unique_hosts: usize,
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    pub syscall_diversity: usize,
    pub process_creations: u64,
    pub privileged_operations: u64,
    pub network_bytes_out: u64,
    pub network_bytes_in: u64,
}

/// Detected anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub anomaly_id: String,
    pub event_id: EventId,
    pub session_id: SessionId,
    pub anomaly_type: AnomalyType,
    pub severity: Severity,
    pub description: String,
    pub evidence: Vec<Evidence>,
    pub recommended_action: RecommendedAction,
    pub confidence: f32,
    pub risk_score: RiskScore,
    pub timestamp: u64,
    pub attack_tactics: Vec<String>,
    pub attack_techniques: Vec<String>,
}

impl Anomaly {
    pub fn new(
        event_id: EventId,
        session_id: SessionId,
        anomaly_type: AnomalyType,
        severity: Severity,
        description: String,
    ) -> Self {
        let risk_score = severity.numeric_value();
        Self {
            anomaly_id: Uuid::new_v4().to_string(),
            event_id,
            session_id,
            anomaly_type,
            severity,
            description,
            evidence: Vec::new(),
            recommended_action: RecommendedAction::default(),
            confidence: 0.8,
            risk_score,
            timestamp: now_timestamp(),
            attack_tactics: Vec::new(),
            attack_techniques: Vec::new(),
        }
    }
}

/// Evidence supporting an anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub field: String,
    pub value: String,
    pub expected_value: Option<String>,
    pub deviation: f32,
    pub description: String,
}

/// Detected attack pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPattern {
    pub pattern_id: String,
    pub pattern_name: String,
    pub severity: Severity,
    pub events: Vec<EventId>,
    pub attack_tactics: Vec<String>,
    pub attack_techniques: Vec<String>,
    pub description: String,
    pub confidence: f32,
    pub first_event_time: u64,
    pub last_event_time: u64,
}

/// Risk score breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoreBreakdown {
    pub base_score: f32,
    pub severity_modifier: f32,
    pub confidence_modifier: f32,
    pub temporal_modifier: f32,
    pub cumulative_score: f32,
    pub risk_level: RiskLevel,
    pub factors: Vec<RiskFactor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    #[serde(rename = "critical")]
    Critical,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "minimal")]
    Minimal,
}

impl RiskLevel {
    pub fn from_score(score: f32) -> Self {
        if score >= 80.0 {
            RiskLevel::Critical
        } else if score >= 60.0 {
            RiskLevel::High
        } else if score >= 40.0 {
            RiskLevel::Medium
        } else if score >= 20.0 {
            RiskLevel::Low
        } else {
            RiskLevel::Minimal
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub name: String,
    pub contribution: f32,
    pub description: String,
}

/// Correlation session - container for a complete correlation analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationSession {
    pub session_id: SessionId,
    pub sandbox_id: Option<SessionId>,
    pub profile_name: String,
    pub intent_id: Option<IntentId>,
    pub start_time: u64,
    pub end_time: u64,
    pub status: SessionStatus,
    pub events: Vec<EnrichedEvent>,
    pub anomalies: Vec<Anomaly>,
    pub patterns: Vec<DetectedPattern>,
    pub risk_score: RiskScoreBreakdown,
    pub attack_coverage: Vec<String>,
    pub total_events: usize,
    pub filtered_events: usize,
}

impl Default for CorrelationSession {
    fn default() -> Self {
        let now = now_timestamp();
        Self {
            session_id: Uuid::new_v4().to_string(),
            sandbox_id: None,
            profile_name: String::new(),
            intent_id: None,
            start_time: now,
            end_time: now,
            status: SessionStatus::Active,
            events: Vec::new(),
            anomalies: Vec::new(),
            patterns: Vec::new(),
            risk_score: RiskScoreBreakdown::default(),
            attack_coverage: Vec::new(),
            total_events: 0,
            filtered_events: 0,
        }
    }
}

impl CorrelationSession {
    pub fn new(profile_name: String) -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            sandbox_id: None,
            profile_name,
            intent_id: None,
            start_time: now_timestamp(),
            end_time: 0,
            status: SessionStatus::Active,
            events: Vec::new(),
            anomalies: Vec::new(),
            patterns: Vec::new(),
            risk_score: RiskScoreBreakdown::default(),
            attack_coverage: Vec::new(),
            total_events: 0,
            filtered_events: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "timeout")]
    Timeout,
    #[serde(rename = "terminated")]
    Terminated,
}

/// Configuration for correlation engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    pub correlation_window_seconds: u64,
    pub max_events_per_session: usize,
    pub anomaly_detection: AnomalyDetectionConfig,
    pub threat_intelligence: ThreatIntelligenceConfig,
    pub risk_scoring: RiskScoringConfig,
    pub rules: RulesConfig,
    pub storage: StorageConfig,
    pub attack_mapping: bool,
    pub enable_intent_linking: bool,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            correlation_window_seconds: 300,
            max_events_per_session: 10000,
            anomaly_detection: AnomalyDetectionConfig::default(),
            threat_intelligence: ThreatIntelligenceConfig::default(),
            risk_scoring: RiskScoringConfig::default(),
            rules: RulesConfig::default(),
            storage: StorageConfig::default(),
            attack_mapping: true,
            enable_intent_linking: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectionConfig {
    pub enabled: bool,
    pub statistical_threshold: f32,
    pub rate_threshold: u64,
    pub sequence_lookbehind: usize,
    pub min_anomaly_confidence: f32,
    pub enable_behavioral_baseline: bool,
}

impl Default for AnomalyDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            statistical_threshold: 3.0,
            rate_threshold: 100,
            sequence_lookbehind: 10,
            min_anomaly_confidence: 0.7,
            enable_behavioral_baseline: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligenceConfig {
    pub enabled: bool,
    pub local_cache_ttl_seconds: u64,
    pub external_sources: Vec<ThreatIntelSource>,
    pub auto_enrich: bool,
}

impl Default for ThreatIntelligenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            local_cache_ttl_seconds: 3600,
            external_sources: Vec::new(),
            auto_enrich: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelSource {
    pub name: String,
    pub url: String,
    pub api_key: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoringConfig {
    pub base_score: f32,
    pub severity_weights: HashMap<String, f32>,
    pub temporal_decay: f32,
    pub confidence_impact: f32,
}

impl Default for RiskScoringConfig {
    fn default() -> Self {
        let mut weights = HashMap::new();
        weights.insert("critical".to_string(), 30.0);
        weights.insert("high".to_string(), 20.0);
        weights.insert("medium".to_string(), 10.0);
        weights.insert("low".to_string(), 5.0);

        Self {
            base_score: 50.0,
            severity_weights: weights,
            temporal_decay: 0.9,
            confidence_impact: 0.15,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    pub enabled: bool,
    pub rule_paths: Vec<PathBuf>,
    pub custom_rules: Vec<DetectionRule>,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rule_paths: Vec::new(),
            custom_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub conditions: Vec<RuleCondition>,
    pub actions: Vec<RuleAction>,
    pub enabled: bool,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionOperator {
    #[serde(rename = "eq")]
    Equals,
    #[serde(rename = "neq")]
    NotEquals,
    #[serde(rename = "gt")]
    GreaterThan,
    #[serde(rename = "gte")]
    GreaterThanOrEqual,
    #[serde(rename = "lt")]
    LessThan,
    #[serde(rename = "lte")]
    LessThanOrEqual,
    #[serde(rename = "contains")]
    Contains,
    #[serde(rename = "matches")]
    Matches,
    #[serde(rename = "in")]
    InList,
    #[serde(rename = "exists")]
    Exists,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    #[serde(rename = "alert")]
    Alert,
    #[serde(rename = "block")]
    Block,
    #[serde(rename = "log")]
    Log,
    #[serde(rename = "score")]
    Score(f32),
    #[serde(rename = "tag")]
    Tag(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub enabled: bool,
    pub storage_path: PathBuf,
    pub retention_days: u32,
    pub compression: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            storage_path: PathBuf::from("./data/correlation"),
            retention_days: 30,
            compression: true,
        }
    }
}

impl Default for RiskScoreBreakdown {
    fn default() -> Self {
        Self {
            base_score: 50.0,
            severity_modifier: 0.0,
            confidence_modifier: 0.0,
            temporal_modifier: 0.0,
            cumulative_score: 50.0,
            risk_level: RiskLevel::Minimal,
            factors: Vec::new(),
        }
    }
}

/// OCSF (Open Cybersecurity Schema) compatible export format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfEvent {
    pub activity_id: u32,
    pub category_name: String,
    pub class_name: String,
    pub severity: String,
    pub severity_id: u32,
    pub time: u64,
    pub raw_data: HashMap<String, serde_json::Value>,
    pub actor: Option<OcsfActor>,
    pub target: Option<OcsfTarget>,
    pub network: Option<OcsfNetwork>,
}

/// Helper function to get current timestamp
pub fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Duration from current time helper
pub fn duration_ago(duration: Duration) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(duration.as_secs())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfActor {
    pub pid: u32,
    pub name: String,
    pub session_uuid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfTarget {
    pub path: Option<String>,
    pub file: Option<OcsfFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfFile {
    pub name: String,
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfNetwork {
    pub protocol_name: String,
    pub direction: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub bytes: u64,
}

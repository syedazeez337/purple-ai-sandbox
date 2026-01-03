// purple/src/correlation/engine/mod.rs
//!
//! Core correlation engine providing:
//! - Statistical anomaly detection
//! - Behavioral analysis
//! - Pattern matching
//! - Sequence correlation

use crate::correlation::enrichment::EventEnricher;
use crate::correlation::models::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Statistical helper functions
#[allow(dead_code)]
mod statistics {
    use std::f64;

    /// Calculate mean of a slice
    pub fn mean(data: &[f64]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let sum: f64 = data.iter().sum();
        sum / data.len() as f64
    }

    /// Calculate standard deviation
    pub fn standard_deviation(data: &[f64]) -> f64 {
        if data.len() <= 1 {
            return 0.0;
        }
        let avg = mean(data);
        let variance: f64 = data.iter().map(|value| (value - avg).powi(2)).sum();
        (variance / (data.len() - 1) as f64).sqrt()
    }

    /// Calculate z-score for a value
    pub fn z_score(value: f64, mean: f64, std_dev: f64) -> f64 {
        if std_dev == 0.0 {
            return 0.0;
        }
        (value - mean) / std_dev
    }

    /// Calculate interquartile range
    pub fn iqr(data: &mut [f64]) -> (f64, f64) {
        if data.len() < 4 {
            return (0.0, 0.0);
        }
        data.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let q1_idx = data.len() / 4;
        let q3_idx = data.len() * 3 / 4;
        (data[q1_idx], data[q3_idx])
    }

    /// Calculate entropy of a distribution
    pub fn entropy(counts: &[usize]) -> f64 {
        let total: usize = counts.iter().sum();
        if total == 0 {
            return 0.0;
        }
        counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / total as f64;
                -p * p.log2()
            })
            .sum()
    }

    /// Rolling average
    pub fn rolling_average(data: &[f64], window: usize) -> Vec<f64> {
        if window == 0 || data.is_empty() {
            return Vec::new();
        }
        data.windows(window).map(mean).collect()
    }
}

use statistics::*;

/// Behavioral baseline for a profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralBaseline {
    pub profile_name: String,
    pub mean_event_rate: f64,
    pub std_event_rate: f64,
    pub mean_file_ops: f64,
    pub std_file_ops: f64,
    pub mean_network_ops: f64,
    pub std_network_ops: f64,
    pub common_syscalls: HashMap<String, f64>,
    pub common_files: HashSet<String>,
    pub common_hosts: HashSet<String>,
    pub sequence_patterns: Vec<Vec<String>>,
    pub last_updated: u64,
}

impl Default for BehavioralBaseline {
    fn default() -> Self {
        Self {
            profile_name: String::new(),
            mean_event_rate: 10.0,
            std_event_rate: 5.0,
            mean_file_ops: 5.0,
            std_file_ops: 3.0,
            mean_network_ops: 2.0,
            std_network_ops: 1.5,
            common_syscalls: HashMap::new(),
            common_files: HashSet::new(),
            common_hosts: HashSet::new(),
            sequence_patterns: Vec::new(),
            last_updated: 0,
        }
    }
}

impl BehavioralBaseline {
    pub fn new(profile_name: String) -> Self {
        Self {
            profile_name,
            ..Default::default()
        }
    }

    /// Update baseline with new session data
    pub fn update(&mut self, _features: &BehavioralFeatures) {
        // In production, this would use more sophisticated update logic
        // with exponential moving averages
        self.last_updated = now_timestamp();
    }

    /// Check if current behavior deviates from baseline
    pub fn detect_drift(&self, features: &BehavioralFeatures) -> Vec<DriftIndicator> {
        let mut indicators = Vec::new();

        // Event rate anomaly
        let event_rate = features.file_access_count
            + features.network_connections
            + features.syscall_diversity as u64;
        let z_rate = z_score(event_rate as f64, self.mean_event_rate, self.std_event_rate);
        if z_rate.abs() > 3.0 {
            indicators.push(DriftIndicator {
                metric: "event_rate".to_string(),
                expected: self.mean_event_rate,
                observed: event_rate as f64,
                deviation: z_rate,
                severity: if z_rate.abs() > 4.0 {
                    Severity::High
                } else {
                    Severity::Medium
                },
            });
        }

        indicators
    }
}

#[derive(Debug, Clone)]
pub struct DriftIndicator {
    pub metric: String,
    pub expected: f64,
    pub observed: f64,
    pub deviation: f64,
    pub severity: Severity,
}

/// Main correlation engine
#[derive(Debug)]
pub struct CorrelationEngine {
    config: CorrelationConfig,
    baselines: Arc<Mutex<HashMap<String, BehavioralBaseline>>>,
    sessions: Arc<Mutex<HashMap<SessionId, CorrelationSession>>>,
    enricher: EventEnricher,
    pattern_detector: RwLock<PatternDetector>,
    sequence_analyzer: RwLock<SequenceAnalyzer>,
    _event_tx: Option<mpsc::Sender<EnrichedEvent>>,
}

impl Clone for CorrelationEngine {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            baselines: Arc::clone(&self.baselines),
            sessions: Arc::clone(&self.sessions),
            enricher: self.enricher.clone(),
            pattern_detector: RwLock::new(PatternDetector::default()),
            sequence_analyzer: RwLock::new(SequenceAnalyzer::default()),
            _event_tx: None,
        }
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new(CorrelationConfig::default())
    }
}

impl CorrelationEngine {
    pub fn new(config: CorrelationConfig) -> Self {
        Self {
            config: config.clone(),
            baselines: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            enricher: EventEnricher::new(config.threat_intelligence.clone()),
            pattern_detector: RwLock::new(PatternDetector::default()),
            sequence_analyzer: RwLock::new(SequenceAnalyzer::new(
                config.anomaly_detection.sequence_lookbehind,
            )),
            _event_tx: None,
        }
    }

    /// Start a new correlation session
    pub fn start_session(&self, profile_name: String, _sandbox_id: Option<SessionId>) -> SessionId {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let session = CorrelationSession::new(profile_name.clone());
        let session_id = session.session_id.clone();

        sessions.insert(session_id.clone(), session);

        // Ensure baseline exists for this profile
        let mut baselines = self.baselines.lock().unwrap_or_else(|e| e.into_inner());
        if !baselines.contains_key(&profile_name) {
            baselines.insert(profile_name.clone(), BehavioralBaseline::new(profile_name));
        }

        session_id
    }

    /// Register an LLM intent for correlation
    pub async fn register_intent(&self, session_id: &SessionId, intent: LlmIntent) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(session) = sessions.get_mut(session_id) {
            session.intent_id = Some(intent.intent_id.clone());
        }
    }

    /// Process an incoming raw event
    #[allow(clippy::await_holding_lock)]
    pub async fn process_event(
        &self,
        session_id: &SessionId,
        raw_event: RawEvent,
    ) -> Option<Anomaly> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let session = match sessions.get_mut(session_id) {
            Some(s) => s,
            None => return None,
        };

        // Get intent if available
        let _intent: Option<LlmIntent> = None;

        // Enrich the event
        let enriched = self.enricher.enrich(raw_event, None).await;

        // Add sequence position
        let sequence_pos = session.events.len();
        let mut enriched = enriched;
        enriched.sequence_position = sequence_pos;

        // Store the event
        session.events.push(enriched.clone());

        // Check for anomalies
        let anomaly = self.detect_anomaly(session, &enriched).await;

        // Update pattern detection
        self.pattern_detector.write().unwrap().update(&enriched);

        self.sequence_analyzer.write().unwrap().add_event(&enriched);

        anomaly
    }

    /// Detect anomalies in an event
    async fn detect_anomaly(
        &self,
        session: &CorrelationSession,
        event: &EnrichedEvent,
    ) -> Option<Anomaly> {
        let mut anomalies = Vec::new();

        // Rate-based anomaly detection
        let rate_anomaly = self.detect_rate_anomaly(session);
        if let Some(a) = rate_anomaly {
            anomalies.push(a);
        }

        // Statistical outlier detection
        let stats_anomaly = self.detect_statistical_anomaly(session, event);
        if let Some(a) = stats_anomaly {
            anomalies.push(a);
        }

        // Unexpected event category
        if !event.is_expected {
            let mut anomaly = Anomaly::new(
                event.base.event_id.clone(),
                session.session_id.clone(),
                AnomalyType::BehavioralDrift,
                Severity::Medium,
                format!("Unexpected event category: {:?}", event.base.category),
            );
            anomaly.confidence = 0.7;
            anomalies.push(anomaly);
        }

        // Return the highest severity anomaly
        anomalies
            .into_iter()
            .max_by_key(|a| a.severity.numeric_value() as i32)
    }

    /// Detect rate-based anomalies
    fn detect_rate_anomaly(&self, session: &CorrelationSession) -> Option<Anomaly> {
        let window_seconds = self.config.correlation_window_seconds;
        let now = now_timestamp();
        let window_start = now.saturating_sub(window_seconds);

        // Count events in window
        let recent_events: Vec<_> = session
            .events
            .iter()
            .filter(|e| e.base.timestamp >= window_start)
            .collect();

        let rate = recent_events.len() as u64 / window_seconds;

        if rate > self.config.anomaly_detection.rate_threshold {
            return Some(Anomaly::new(
                recent_events
                    .last()
                    .map(|e| e.base.event_id.clone())
                    .unwrap_or_default(),
                session.session_id.clone(),
                AnomalyType::RateExceeded,
                Severity::High,
                format!(
                    "Event rate {} exceeds threshold {}",
                    rate, self.config.anomaly_detection.rate_threshold
                ),
            ));
        }

        None
    }

    /// Detect statistical outliers
    fn detect_statistical_anomaly(
        &self,
        session: &CorrelationSession,
        event: &EnrichedEvent,
    ) -> Option<Anomaly> {
        let profile_name = &session.profile_name;
        let baselines = self.baselines.lock().unwrap_or_else(|e| e.into_inner());
        let baseline = baselines.get(profile_name)?;

        // Check event rate against baseline
        let recent_count = session.events.len();
        let z_rate = z_score(
            recent_count as f64,
            baseline.mean_event_rate,
            baseline.std_event_rate,
        );

        if z_rate.abs() > self.config.anomaly_detection.statistical_threshold as f64 {
            return Some(Anomaly::new(
                event.base.event_id.clone(),
                session.session_id.clone(),
                AnomalyType::StatisticalOutlier,
                Severity::from_z_score(z_rate.abs()),
                format!("Event rate deviation: z-score {:.2}", z_rate),
            ));
        }

        None
    }

    /// Complete a correlation session and generate results
    #[allow(clippy::await_holding_lock)]
    pub async fn complete_session(&self, session_id: &SessionId) -> Option<CorrelationSession> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(session) = sessions.get_mut(session_id) {
            session.end_time = now_timestamp();
            session.status = SessionStatus::Completed;
            session.total_events = session.events.len();

            // Analyze patterns
            let patterns = self
                .pattern_detector
                .read()
                .unwrap()
                .detect_patterns(&session.events);
            session.patterns = patterns;

            // Calculate final risk score
            session.risk_score = self.calculate_risk_score(session).await;

            // Collect ATT&CK coverage
            let mut tactics = HashSet::new();
            for event in &session.events {
                for tactic in &event.attack_tactics {
                    tactics.insert(tactic.clone());
                }
            }
            session.attack_coverage = tactics.into_iter().collect();

            Some(session.clone())
        } else {
            None
        }
    }

    /// Calculate overall risk score for a session
    async fn calculate_risk_score(&self, session: &CorrelationSession) -> RiskScoreBreakdown {
        let mut breakdown = RiskScoreBreakdown {
            base_score: self.config.risk_scoring.base_score,
            ..Default::default()
        };

        // Severity modifier from anomalies
        let mut severity_total = 0.0;
        for anomaly in &session.anomalies {
            severity_total += anomaly.severity.numeric_value();
        }
        breakdown.severity_modifier = (severity_total / session.anomalies.len().max(1) as f32)
            * self
                .config
                .risk_scoring
                .severity_weights
                .get("high")
                .copied()
                .unwrap_or(20.0)
            / 100.0;

        // Confidence modifier
        let avg_confidence: f32 = session
            .anomalies
            .iter()
            .map(|a| a.confidence)
            .chain(session.events.iter().map(|e| e.confidence))
            .sum::<f32>()
            / (session.anomalies.len() + session.events.len()).max(1) as f32;
        breakdown.confidence_modifier = avg_confidence * self.config.risk_scoring.confidence_impact;

        // Temporal modifier (decay over time)
        let elapsed = session.end_time.saturating_sub(session.start_time);
        breakdown.temporal_modifier = breakdown.severity_modifier
            * (1.0
                - self
                    .config
                    .risk_scoring
                    .temporal_decay
                    .powf(elapsed as f32 / 3600.0));

        // Calculate cumulative score
        breakdown.cumulative_score =
            (breakdown.base_score + breakdown.severity_modifier + breakdown.confidence_modifier
                - breakdown.temporal_modifier)
                .clamp(0.0, 100.0);

        breakdown.risk_level = RiskLevel::from_score(breakdown.cumulative_score);

        breakdown
    }

    /// Get active sessions
    pub fn get_active_sessions(&self) -> Vec<SessionId> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions
            .iter()
            .filter(|(_, s)| s.status == SessionStatus::Active)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get session by ID
    pub fn get_session(&self, session_id: &SessionId) -> Option<CorrelationSession> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.get(session_id).cloned()
    }
}

/// Pattern detector for common attack patterns
#[derive(Debug, Clone, Default)]
pub struct PatternDetector {
    _file_to_network_pattern: usize,
    _privilege_escalation_pattern: usize,
    _persistence_pattern: usize,
    _reconnaissance_pattern: usize,
    current_sequence: Vec<String>,
}

impl PatternDetector {
    pub fn update(&mut self, event: &EnrichedEvent) {
        // Update internal state for pattern detection
        self.current_sequence.push(event.base.event_type.clone());
        if self.current_sequence.len() > 20 {
            self.current_sequence.remove(0);
        }
    }

    pub fn detect_patterns(&self, events: &[EnrichedEvent]) -> Vec<DetectedPattern> {
        let mut patterns = Vec::new();

        // Detect file exfiltration pattern
        if self.detect_file_exfiltration(events) {
            patterns.push(DetectedPattern {
                pattern_id: Uuid::new_v4().to_string(),
                pattern_name: "File Exfiltration".to_string(),
                severity: Severity::Critical,
                events: events.iter().map(|e| e.base.event_id.clone()).collect(),
                attack_tactics: vec!["Collection".to_string(), "Exfiltration".to_string()],
                attack_techniques: vec!["T1005".to_string(), "T1041".to_string()],
                description: "Detected pattern consistent with file exfiltration".to_string(),
                confidence: 0.85,
                first_event_time: events.first().map(|e| e.base.timestamp).unwrap_or(0),
                last_event_time: events.last().map(|e| e.base.timestamp).unwrap_or(0),
            });
        }

        // Detect privilege escalation
        if self.detect_privilege_escalation(events) {
            patterns.push(DetectedPattern {
                pattern_id: Uuid::new_v4().to_string(),
                pattern_name: "Privilege Escalation".to_string(),
                severity: Severity::Critical,
                events: events.iter().map(|e| e.base.event_id.clone()).collect(),
                attack_tactics: vec!["Privilege Escalation".to_string()],
                attack_techniques: vec!["T1055".to_string()],
                description: "Detected pattern consistent with privilege escalation".to_string(),
                confidence: 0.8,
                first_event_time: events.first().map(|e| e.base.timestamp).unwrap_or(0),
                last_event_time: events.last().map(|e| e.base.timestamp).unwrap_or(0),
            });
        }

        patterns
    }

    fn detect_file_exfiltration(&self, events: &[EnrichedEvent]) -> bool {
        let mut file_reads = 0;
        let mut network_connections = 0;

        for event in events {
            if event.base.category == EventCategory::FileAccess {
                file_reads += 1;
            }
            if event.base.category == EventCategory::Network {
                network_connections += 1;
            }
        }

        file_reads > 10 && network_connections > 5
    }

    fn detect_privilege_escalation(&self, events: &[EnrichedEvent]) -> bool {
        events.iter().any(|e| {
            e.attack_techniques.contains(&"T1055".to_string())
                || e.attack_techniques.contains(&"T1548".to_string())
        })
    }
}

/// Sequence analyzer for ordered event patterns
#[derive(Debug, Clone)]
pub struct SequenceAnalyzer {
    lookbehind: usize,
    sequence_buffer: Vec<String>,
    known_malicious_sequences: Vec<Vec<&'static str>>,
}

impl Default for SequenceAnalyzer {
    fn default() -> Self {
        Self::new(10)
    }
}

impl SequenceAnalyzer {
    pub fn new(lookbehind: usize) -> Self {
        Self {
            lookbehind,
            sequence_buffer: Vec::new(),
            known_malicious_sequences: vec![
                vec!["openat", "read", "write", "connect"], // File read → Write → Exfil
                vec!["setuid", "execve"],                   // Privilege escalation
                vec!["creat", "chmod", "connect"],          // Persistence setup
            ],
        }
    }

    pub fn add_event(&mut self, event: &EnrichedEvent) {
        self.sequence_buffer.push(event.base.event_type.clone());
        if self.sequence_buffer.len() > self.lookbehind {
            self.sequence_buffer.remove(0);
        }
    }

    pub fn check_sequence(&self) -> Option<SequenceViolation> {
        for (i, seq) in self.known_malicious_sequences.iter().enumerate() {
            if self
                .sequence_buffer
                .windows(seq.len())
                .any(|window| window.iter().zip(seq.iter()).all(|(a, b)| a.as_str() == *b))
            {
                return Some(SequenceViolation {
                    sequence_index: self.sequence_buffer.len().saturating_sub(seq.len()),
                    pattern_id: i,
                    severity: Severity::High,
                });
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct SequenceViolation {
    pub sequence_index: usize,
    pub pattern_id: usize,
    pub severity: Severity,
}

use crate::correlation::models::now_timestamp;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_correlation_engine() {
        let engine = CorrelationEngine::default();
        let session_id = engine.start_session("test-profile".to_string(), None);

        // Process some events
        let event = RawEvent::new(
            "syscall".to_string(),
            1234,
            "openat file operation".to_string(),
            EventCategory::FileAccess,
        );

        let anomaly = engine.process_event(&session_id, event).await;
        assert!(anomaly.is_none() || anomaly.unwrap().severity == Severity::High);

        // Complete session
        let session = engine.complete_session(&session_id).await;
        assert!(session.is_some());
        let session = session.unwrap();
        assert_eq!(session.status, SessionStatus::Completed);
    }

    #[test]
    fn test_statistics() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert_eq!(mean(&data), 5.5);
        assert!(standard_deviation(&data) > 0.0);

        let z = z_score(10.0, 5.5, 2.87);
        assert!((z - 1.57).abs() < 0.1);
    }

    #[test]
    fn test_pattern_detection() {
        let detector = PatternDetector::default();

        // Simulate file exfiltration pattern
        let events = (0..15)
            .map(|_| EnrichedEvent {
                base: RawEvent::new(
                    "file_access".to_string(),
                    0,
                    "read".to_string(),
                    EventCategory::FileAccess,
                ),
                ..Default::default()
            })
            .chain((0..6).map(|_| EnrichedEvent {
                base: RawEvent::new(
                    "network".to_string(),
                    0,
                    "connect".to_string(),
                    EventCategory::Network,
                ),
                ..Default::default()
            }))
            .collect::<Vec<_>>();

        let patterns = detector.detect_patterns(&events);
        assert!(
            patterns
                .iter()
                .any(|p| p.pattern_name == "File Exfiltration")
        );
    }
}

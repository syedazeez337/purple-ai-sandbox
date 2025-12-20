//! Correlation engine for linking LLM intents with observed behavior

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

/// LLM intent representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmIntent {
    pub intent_id: String,
    pub timestamp: u64,
    pub prompt: String,
    pub expected_actions: Vec<String>,
}

/// Observed event with correlation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedEvent {
    pub event_type: String,
    pub timestamp: u64,
    pub details: String,
    pub intent_id: Option<String>,
}

/// Correlation result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // TODO: Use in correlation reporting
pub struct CorrelationResult {
    pub intent_id: String,
    pub prompt: String,
    pub observed_events: Vec<ObservedEvent>,
    pub anomalies: Vec<String>,
    pub correlation_score: f32,
}

/// Correlation engine
#[derive(Debug)]
pub struct CorrelationEngine {
    #[allow(dead_code)] // TODO: Use in correlation logic
    intent_window: VecDeque<LlmIntent>,
    #[allow(dead_code)] // TODO: Use in correlation logic
    event_window: VecDeque<ObservedEvent>,
    #[allow(dead_code)] // TODO: Use in correlation logic
    correlation_window_seconds: u64,
}

impl CorrelationEngine {
    /// Create a new correlation engine
    pub fn new(correlation_window_seconds: u64) -> Self {
        Self {
            intent_window: VecDeque::new(),
            event_window: VecDeque::new(),
            correlation_window_seconds,
        }
    }

    /// Register an LLM intent
    #[allow(dead_code)] // TODO: Use in correlation logic
    pub fn register_intent(&mut self, intent: LlmIntent) {
        self.intent_window.push_back(intent);
        self.cleanup_old_entries();
    }

    /// Register an observed event
    #[allow(dead_code)] // TODO: Use in correlation logic
    pub fn register_event(&mut self, event: ObservedEvent) {
        self.event_window.push_back(event);
        self.cleanup_old_entries();
    }

    /// Clean up old entries based on time window
    #[allow(dead_code)] // TODO: Use in correlation logic
    fn cleanup_old_entries(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cutoff = now.saturating_sub(self.correlation_window_seconds);

        // Cleanup intents
        while let Some(intent) = self.intent_window.front() {
            if intent.timestamp < cutoff {
                self.intent_window.pop_front();
            } else {
                break;
            }
        }

        // Cleanup events
        while let Some(event) = self.event_window.front() {
            if event.timestamp < cutoff {
                self.event_window.pop_front();
            } else {
                break;
            }
        }
    }

    /// Correlate intents with observed events
    #[allow(dead_code)] // TODO: Use in correlation logic
    pub fn correlate(&self) -> Vec<CorrelationResult> {
        let mut results = Vec::new();

        for intent in &self.intent_window {
            let mut observed_events = Vec::new();
            let mut anomalies = Vec::new();

            // Find events that match this intent
            for event in &self.event_window {
                if let Some(intent_id) = &event.intent_id
                    && intent_id == &intent.intent_id
                {
                    observed_events.push(event.clone());
                }
            }

            // Check for anomalies (events not matching expected actions)
            for event in &self.event_window {
                if let Some(intent_id) = &event.intent_id
                    && intent_id == &intent.intent_id
                {
                    let is_expected = intent
                        .expected_actions
                        .iter()
                        .any(|expected| event.details.contains(expected));

                    if !is_expected {
                        anomalies.push(format!("Unexpected event: {}", event.details));
                    }
                }
            }

            // Calculate correlation score (simple implementation)
            let correlation_score = if observed_events.is_empty() {
                0.0
            } else {
                let expected_count = intent.expected_actions.len() as f32;
                let observed_count = observed_events.len() as f32;
                observed_count / expected_count.max(1.0)
            };

            results.push(CorrelationResult {
                intent_id: intent.intent_id.clone(),
                prompt: intent.prompt.clone(),
                observed_events,
                anomalies,
                correlation_score,
            });
        }

        results
    }

    /// Process eBPF events and correlate with intents
    #[cfg(feature = "ebpf")]
    #[allow(dead_code)] // TODO: Use in correlation logic
    pub fn process_ebpf_event(&mut self, event: &crate::sandbox::ebpf::loader::EbpfEvent) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let observed_event = match event {
            crate::sandbox::ebpf::loader::EbpfEvent::Syscall(syscall) => ObservedEvent {
                event_type: "syscall".to_string(),
                timestamp,
                details: format!("{}", syscall),
                intent_id: None,
            },
            crate::sandbox::ebpf::loader::EbpfEvent::FileAccess(file) => ObservedEvent {
                event_type: "file_access".to_string(),
                timestamp,
                details: format!("{}", file),
                intent_id: None,
            },
            crate::sandbox::ebpf::loader::EbpfEvent::Network(network) => ObservedEvent {
                event_type: "network".to_string(),
                timestamp,
                details: format!("{}", network),
                intent_id: None,
            },
        };

        self.register_event(observed_event);
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new(300) // 5 minute window by default
    }
}

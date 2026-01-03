// purple/src/correlation/storage/mod.rs
//!
//! Persistent storage layer for correlation data using sled
//!
//! Provides:
//! - Event storage and retrieval
//! - Session persistence
//! - Baseline storage
//! - Rule storage

use crate::correlation::engine::BehavioralBaseline;
use crate::correlation::models::*;
use serde::{Deserialize, Serialize};
use sled::{Config, Db, Tree};
use std::collections::HashMap;

#[inline]
fn json_to_string<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| e.to_string())
}

#[inline]
fn string_to_json<T: for<'de> Deserialize<'de>>(json: &str) -> Option<T> {
    serde_json::from_str(json).ok()
}

use std::sync::{Arc, Mutex};

/// Trait for correlation storage implementations
#[async_trait::async_trait]
pub trait CorrelationStorageTrait: Send + Sync {
    async fn store_session(&self, session: &CorrelationSession) -> Result<(), String>;
    async fn get_session(&self, session_id: &SessionId) -> Option<CorrelationSession>;
    async fn store_event(
        &self,
        session_id: &SessionId,
        event: &EnrichedEvent,
    ) -> Result<(), String>;
    async fn get_session_events(&self, session_id: &SessionId) -> Vec<EnrichedEvent>;
    async fn store_baseline(&self, baseline: &BehavioralBaseline) -> Result<(), String>;
    async fn get_baseline(&self, profile_name: &str) -> Option<BehavioralBaseline>;
    async fn store_rule(&self, rule: &DetectionRule) -> Result<(), String>;
    async fn get_all_rules(&self) -> Vec<DetectionRule>;
    async fn export_session_ocsf(&self, session_id: &SessionId) -> Option<Vec<OcsfEvent>>;
}

/// Sled-based persistent storage for correlation engine
#[derive(Debug, Clone)]
pub struct SledCorrelationStorage {
    db: Arc<Mutex<Db>>,
    config: StorageConfig,
}

impl Default for SledCorrelationStorage {
    fn default() -> Self {
        Self::new(StorageConfig::default())
    }
}

impl SledCorrelationStorage {
    /// Open or create storage
    pub fn new(config: StorageConfig) -> Self {
        // Ensure parent directory exists
        if let Some(parent) = config.storage_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let db_config = Config::new()
            .path(&config.storage_path)
            .temporary(config.retention_days == 0)
            .flush_every_ms(Some(5000));

        let db = db_config.open().unwrap_or_else(|e| {
            log::warn!("Failed to open correlation storage, using temporary: {}", e);
            Config::new().temporary(true).open().unwrap()
        });

        Self {
            db: Arc::new(Mutex::new(db)),
            config,
        }
    }

    /// Store a correlation session
    pub fn store_session(&self, session: &CorrelationSession) -> Result<(), String> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let tree: Tree = db.open_tree(b"sessions").map_err(|e| e.to_string())?;

        let key = format!("session:{}", session.session_id);
        let value = json_to_string(session)?;
        tree.insert(key.as_bytes(), value.as_bytes())
            .map_err(|e| e.to_string())?;

        let index_tree: Tree = db.open_tree(b"session_index").map_err(|e| e.to_string())?;
        index_tree
            .insert(
                session.session_id.as_bytes(),
                format!("{}:{}", session.profile_name, session.start_time).as_bytes(),
            )
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Retrieve a session by ID
    pub fn get_session(&self, session_id: &SessionId) -> Option<CorrelationSession> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let tree: Tree = db.open_tree(b"sessions").ok()?;

        let key = format!("session:{}", session_id);
        let value = tree.get(key.as_bytes()).ok()??;
        let json = String::from_utf8(value.to_vec()).ok()?;

        string_to_json(&json)
    }

    /// Store an enriched event
    pub fn store_event(&self, session_id: &SessionId, event: &EnrichedEvent) -> Result<(), String> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let tree: Tree = db.open_tree(b"events").map_err(|e| e.to_string())?;

        let key = format!("event:{}:{}", session_id, event.base.event_id);
        let value = json_to_string(event)?;
        tree.insert(key.as_bytes(), value.as_bytes())
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Retrieve events for a session
    pub fn get_session_events(&self, session_id: &SessionId) -> Vec<EnrichedEvent> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let tree: Tree = if let Ok(t) = db.open_tree(b"events") {
            t
        } else {
            return Vec::new();
        };

        let prefix = format!("event:{}:", session_id);
        let mut events = Vec::new();

        for (_, value) in tree.scan_prefix(prefix.as_bytes()).flatten() {
            if let Ok(json) = String::from_utf8(value.to_vec())
                && let Ok(event) = serde_json::from_str(&json)
            {
                events.push(event);
            }
        }

        events
    }

    /// Store behavioral baseline
    pub fn store_baseline(&self, baseline: &BehavioralBaseline) -> Result<(), String> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let tree: Tree = db.open_tree(b"baselines").map_err(|e| e.to_string())?;

        let value = json_to_string(baseline)?;
        tree.insert(baseline.profile_name.as_bytes(), value.as_bytes())
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Retrieve behavioral baseline for a profile
    pub fn get_baseline(&self, profile_name: &str) -> Option<BehavioralBaseline> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let tree: Tree = if let Ok(t) = db.open_tree(b"baselines") {
            t
        } else {
            return None;
        };

        let value = tree.get(profile_name.as_bytes()).ok()??;
        let json = String::from_utf8(value.to_vec()).ok()?;

        string_to_json(&json)
    }

    /// Store a detection rule
    pub fn store_rule(&self, rule: &DetectionRule) -> Result<(), String> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let tree: Tree = db.open_tree(b"rules").map_err(|e| e.to_string())?;

        let value = json_to_string(rule)?;
        tree.insert(rule.id.as_bytes(), value.as_bytes())
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Retrieve all stored rules
    pub fn get_all_rules(&self) -> Vec<DetectionRule> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let tree: Tree = if let Ok(t) = db.open_tree(b"rules") {
            t
        } else {
            return Vec::new();
        };

        let mut rules = Vec::new();
        for (_, value) in tree.iter().flatten() {
            if let Ok(json) = String::from_utf8(value.to_vec())
                && let Ok(rule) = serde_json::from_str(&json)
            {
                rules.push(rule);
            }
        }
        rules
    }

    /// List sessions by profile
    pub fn list_sessions_by_profile(&self, profile_name: &str) -> Vec<SessionId> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let tree: Tree = if let Ok(t) = db.open_tree(b"session_index") {
            t
        } else {
            return Vec::new();
        };

        let mut session_ids = Vec::new();
        for (key, value) in tree.iter().flatten() {
            let key_str = String::from_utf8(key.to_vec()).unwrap_or_default();
            let value_str = String::from_utf8(value.to_vec()).unwrap_or_default();

            if value_str.starts_with(profile_name) {
                session_ids.push(key_str);
            }
        }
        session_ids
    }

    /// Get session count
    pub fn get_session_count(&self) -> usize {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let tree: Tree = if let Ok(t) = db.open_tree(b"sessions") {
            t
        } else {
            return 0;
        };
        tree.len()
    }

    /// Clean up old sessions
    pub fn cleanup_old_sessions(&self) -> Result<usize, String> {
        let retention_seconds = self.config.retention_days as u64 * 86400;
        let cutoff = now_timestamp().saturating_sub(retention_seconds);

        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let tree: Tree = db.open_tree(b"sessions").map_err(|e| e.to_string())?;
        let index_tree: Tree = db.open_tree(b"session_index").map_err(|e| e.to_string())?;

        let mut removed = 0;

        // Collect keys to remove
        let mut keys_to_remove = Vec::new();
        for (key, _value) in tree.iter().flatten() {
            if let Ok(json) = String::from_utf8(key.to_vec())
                && let Ok(session) = serde_json::from_str::<CorrelationSession>(&json)
                && session.end_time > 0
                && session.end_time < cutoff
            {
                keys_to_remove.push(session.session_id.clone());
            }
        }

        // Remove old sessions
        for session_id in keys_to_remove {
            tree.remove(format!("session:{}", session_id).as_bytes())
                .ok();
            index_tree.remove(session_id.as_bytes()).ok();
            removed += 1;
        }

        Ok(removed)
    }

    /// Export session to OCSF format
    pub fn export_session_ocsf(&self, session_id: &SessionId) -> Option<Vec<OcsfEvent>> {
        let _session = self.get_session(session_id)?;
        let events = self.get_session_events(session_id);

        let mut ocsf_events = Vec::new();

        for event in events {
            let activity_id = match event.base.category {
                EventCategory::Syscall => 1,
                EventCategory::FileAccess => 2,
                EventCategory::Network => 3,
                _ => 99,
            };

            let category_name = format!("{:?}", event.base.category);

            let mut raw_data = HashMap::new();
            raw_data.insert(
                "event_id".to_string(),
                serde_json::json!(event.base.event_id),
            );
            raw_data.insert(
                "event_type".to_string(),
                serde_json::json!(event.base.event_type),
            );
            raw_data.insert("details".to_string(), serde_json::json!(event.base.details));
            raw_data.insert(
                "risk_score".to_string(),
                serde_json::json!(event.risk_score),
            );
            raw_data.insert(
                "is_expected".to_string(),
                serde_json::json!(event.is_expected),
            );

            ocsf_events.push(OcsfEvent {
                activity_id: activity_id as u32,
                category_name,
                class_name: "SystemActivity".to_string(),
                severity: format!("{:?}", event.severity),
                severity_id: event.severity.numeric_value() as u32,
                time: event.base.timestamp,
                raw_data,
                actor: Some(OcsfActor {
                    pid: event.base.pid,
                    name: event.base.comm.clone(),
                    session_uuid: session_id.clone(),
                }),
                target: None,
                network: None,
            });
        }

        Some(ocsf_events)
    }

    /// Compact storage (note: sled doesn't have a compact method on Db reference)
    #[allow(dead_code)]
    pub fn compact(&self) -> Result<(), String> {
        // sled::Db doesn't expose compact() on references
        // In production, you would use sled::Config::compact() instead
        Ok(())
    }
}

use crate::correlation::models::now_timestamp;

/// In-memory storage for testing
#[derive(Debug, Clone, Default)]
pub struct MemoryStorage {
    sessions: Arc<Mutex<HashMap<SessionId, CorrelationSession>>>,
    events: Arc<Mutex<HashMap<(SessionId, EventId), EnrichedEvent>>>,
    baselines: Arc<Mutex<HashMap<String, BehavioralBaseline>>>,
    rules: Arc<Mutex<HashMap<String, DetectionRule>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store_session(&self, session: &CorrelationSession) -> Result<(), String> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.insert(session.session_id.clone(), session.clone());
        Ok(())
    }

    pub fn get_session(&self, session_id: &SessionId) -> Option<CorrelationSession> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(session_id)
            .cloned()
    }

    pub fn store_event(&self, session_id: &SessionId, event: &EnrichedEvent) -> Result<(), String> {
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        events.insert(
            (session_id.clone(), event.base.event_id.clone()),
            event.clone(),
        );
        Ok(())
    }

    pub fn get_session_events(&self, session_id: &SessionId) -> Vec<EnrichedEvent> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|((sid, _), _)| sid == session_id)
            .map(|(_, e)| e.clone())
            .collect()
    }

    pub fn store_baseline(&self, baseline: &BehavioralBaseline) -> Result<(), String> {
        let mut baselines = self.baselines.lock().unwrap_or_else(|e| e.into_inner());
        baselines.insert(baseline.profile_name.clone(), baseline.clone());
        Ok(())
    }

    pub fn get_baseline(&self, profile_name: &str) -> Option<BehavioralBaseline> {
        self.baselines
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(profile_name)
            .cloned()
    }

    pub fn store_rule(&self, rule: &DetectionRule) -> Result<(), String> {
        let mut rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        rules.insert(rule.id.clone(), rule.clone());
        Ok(())
    }

    pub fn get_all_rules(&self) -> Vec<DetectionRule> {
        self.rules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }
}

#[async_trait::async_trait]
impl CorrelationStorageTrait for MemoryStorage {
    async fn store_session(&self, session: &CorrelationSession) -> Result<(), String> {
        self.store_session(session)
    }

    async fn get_session(&self, session_id: &SessionId) -> Option<CorrelationSession> {
        self.get_session(session_id)
    }

    async fn store_event(
        &self,
        session_id: &SessionId,
        event: &EnrichedEvent,
    ) -> Result<(), String> {
        self.store_event(session_id, event)
    }

    async fn get_session_events(&self, session_id: &SessionId) -> Vec<EnrichedEvent> {
        self.get_session_events(session_id)
    }

    async fn store_baseline(&self, baseline: &BehavioralBaseline) -> Result<(), String> {
        self.store_baseline(baseline)
    }

    async fn get_baseline(&self, profile_name: &str) -> Option<BehavioralBaseline> {
        self.get_baseline(profile_name)
    }

    async fn store_rule(&self, rule: &DetectionRule) -> Result<(), String> {
        self.store_rule(rule)
    }

    async fn get_all_rules(&self) -> Vec<DetectionRule> {
        self.get_all_rules()
    }

    async fn export_session_ocsf(&self, _session_id: &SessionId) -> Option<Vec<OcsfEvent>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_storage() {
        let storage = MemoryStorage::new();

        // Store a session
        let session = CorrelationSession::new("test-profile".to_string());
        storage.store_session(&session).unwrap();

        // Retrieve session
        let retrieved = storage.get_session(&session.session_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().profile_name, "test-profile");
    }

    #[test]
    fn test_event_storage() {
        let storage = MemoryStorage::new();
        let session_id = "test-session-123".to_string();

        let event = EnrichedEvent {
            base: RawEvent::new(
                "syscall".to_string(),
                1234,
                "test event".to_string(),
                EventCategory::Syscall,
            ),
            ..Default::default()
        };

        storage.store_event(&session_id, &event).unwrap();
        let events = storage.get_session_events(&session_id);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_baseline_storage() {
        let storage = MemoryStorage::new();
        let baseline = BehavioralBaseline::new("test-profile".to_string());

        storage.store_baseline(&baseline).unwrap();
        let retrieved = storage.get_baseline("test-profile");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().profile_name, "test-profile");
    }
}

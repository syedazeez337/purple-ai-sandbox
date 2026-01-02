// purple/src/correlation/api/mod.rs
//!
//! REST API handlers for correlation engine operations
//!
//! Endpoints:
//! - POST /api/v1/correlation/sessions - Create session
//! - GET /api/v1/correlation/sessions/{id} - Get session
//! - POST /api/v1/correlation/sessions/{id}/events - Add event
//! - POST /api/v1/correlation/sessions/{id}/intents - Register intent
//! - POST /api/v1/correlation/sessions/{id}/complete - Complete session
//! - GET /api/v1/correlation/sessions/{id}/report - Get report
//! - GET /api/v1/correlation/sessions/{id}/ocsf - Export OCSF
//! - GET /api/v1/correlation/active - List active sessions
//! - POST /api/v1/correlation/rules - Add rule
//! - GET /api/v1/correlation/rules - List rules

use crate::correlation::engine::CorrelationEngine;
use crate::correlation::models::*;
use crate::correlation::rules::RulesEngine;
use crate::correlation::storage::{CorrelationStorageTrait, MemoryStorage};
use axum::{extract::*, routing::*, Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;

/// API state
#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<Mutex<CorrelationEngine>>,
    pub rules_engine: Arc<Mutex<RulesEngine>>,
    pub storage: Arc<Mutex<dyn CorrelationStorageTrait + Send>>,
}

impl ApiState {
    pub fn new(
        engine: Arc<Mutex<CorrelationEngine>>,
        rules_engine: Arc<Mutex<RulesEngine>>,
        storage: Arc<Mutex<dyn CorrelationStorageTrait + Send>>,
    ) -> Self {
        Self {
            engine,
            rules_engine,
            storage,
        }
    }
}

/// Request/response models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub profile_name: String,
    pub sandbox_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterIntentRequest {
    pub prompt: String,
    pub expected_actions: Vec<String>,
    pub expected_categories: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitEventRequest {
    pub event_type: String,
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    pub details: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddRuleRequest {
    pub rule: DetectionRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReportResponse {
    pub session: CorrelationSession,
    pub anomaly_summary: AnomalySummary,
    pub attack_coverage: Vec<AttackTechniqueSummary>,
    pub risk_assessment: RiskAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalySummary {
    pub total: usize,
    pub by_type: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
    pub top_anomalies: Vec<Anomaly>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechniqueSummary {
    pub technique_id: String,
    pub technique_name: String,
    pub count: usize,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub overall_score: f32,
    pub risk_level: String,
    pub recommendations: Vec<String>,
}

/// Create API router
pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/correlation/sessions", post(create_session).get(list_sessions))
        .route(
            "/api/v1/correlation/sessions/:id",
            get(get_session).delete(delete_session),
        )
        .route(
            "/api/v1/correlation/sessions/:id/events",
            post(submit_event).get(get_events),
        )
        .route("/api/v1/correlation/sessions/:id/intents", post(register_intent))
        .route(
            "/api/v1/correlation/sessions/:id/complete",
            post(complete_session),
        )
        .route(
            "/api/v1/correlation/sessions/:id/report",
            get(get_session_report),
        )
        .route(
            "/api/v1/correlation/sessions/:id/ocsf",
            get(get_session_ocsf),
        )
        .route("/api/v1/correlation/active", get(get_active_sessions))
        .route("/api/v1/correlation/rules", post(add_rule).get(list_rules))
        .with_state(state)
}

/// Create a new correlation session
async fn create_session(
    State(state): State<ApiState>,
    Json(req): Json<CreateSessionRequest>,
) -> Json<CreateSessionResponse> {
    let engine = state.engine.lock().await;
    let session_id = engine.start_session(req.profile_name, req.sandbox_id);

    Json(CreateSessionResponse {
        session_id,
        status: "active".to_string(),
    })
}

/// List all sessions
async fn list_sessions(State(state): State<ApiState>) -> Json<Vec<SessionSummary>> {
    let engine = state.engine.lock().await;
    let sessions = engine.get_active_sessions();

    let summaries: Vec<SessionSummary> = sessions
        .iter()
        .filter_map(|id| {
            engine.get_session(id).map(|s| SessionSummary {
                session_id: s.session_id,
                profile_name: s.profile_name,
                status: format!("{:?}", s.status),
                start_time: s.start_time,
                end_time: s.end_time,
                event_count: s.events.len(),
                anomaly_count: s.anomalies.len(),
                risk_score: s.risk_score.cumulative_score,
            })
        })
        .collect();

    Json(summaries)
}

/// Get session details
async fn get_session(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Json<Option<CorrelationSession>> {
    let engine = state.engine.lock().await;
    Json(engine.get_session(&id))
}

/// Delete a session
async fn delete_session(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Json<DeleteResponse> {
    let engine = state.engine.lock().await;
    let session = engine.complete_session(&id).await;

    let deleted = session.is_some();
    Json(DeleteResponse { deleted })
}

/// Submit an event to a session
async fn submit_event(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
    Json(req): Json<SubmitEventRequest>,
) -> Json<Option<Anomaly>> {
    let engine = state.engine.lock().await;

    let category = match req.category.as_str() {
        "syscall" => EventCategory::Syscall,
        "file_access" => EventCategory::FileAccess,
        "network" => EventCategory::Network,
        _ => EventCategory::Syscall,
    };

    let raw_event = RawEvent {
        event_id: Uuid::new_v4().to_string(),
        event_type: req.event_type,
        timestamp: now_timestamp(),
        pid: req.pid,
        tid: req.tid,
        comm: req.comm,
        details: req.details,
        category,
    };

    let anomaly = engine.process_event(&session_id, raw_event).await;

    Json(anomaly)
}

/// Get events for a session
async fn get_events(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
) -> Json<Option<Vec<EnrichedEvent>>> {
    let engine = state.engine.lock().await;
    let session = engine.get_session(&session_id);

    Json(session.map(|s| s.events))
}

/// Register an intent for a session
async fn register_intent(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
    Json(req): Json<RegisterIntentRequest>,
) -> Json<IntentResponse> {
    let engine = state.engine.lock().await;

    let expected_categories: Vec<EventCategory> = req
        .expected_categories
        .iter()
        .filter_map(|c| match c.as_str() {
            "syscall" => Some(EventCategory::Syscall),
            "file_access" => Some(EventCategory::FileAccess),
            "network" => Some(EventCategory::Network),
            _ => None,
        })
        .collect();

    let intent = LlmIntent {
        intent_id: Uuid::new_v4().to_string(),
        timestamp: now_timestamp(),
        prompt: req.prompt,
        expected_actions: req.expected_actions.clone(),
        expected_categories,
        expected_files: Vec::new(),
        expected_networks: Vec::new(),
        confidence: req.confidence,
        metadata: HashMap::new(),
        profile_name: String::new(),
        sandbox_id: None,
    };

    engine.register_intent(&session_id, intent).await;

    Json(IntentResponse {
        registered: true,
        session_id,
    })
}

/// Complete a session and generate results
async fn complete_session(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
) -> Json<Option<CorrelationSession>> {
    let mut engine = state.engine.lock().await;
    
    let session = engine.complete_session(&session_id).await;

    // Persist to storage
    if let Some(ref s) = session {
        let storage = state.storage.lock().await;
        storage.store_session(s).await.ok();
    }

    Json(session)
}

/// Get session report
async fn get_session_report(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
) -> Json<Option<SessionReportResponse>> {
    let engine = state.engine.lock().await;
    let storage = state.storage.lock().await;

    // Try to get from storage first, fall back to engine
    let session = match storage.get_session(&session_id).await
        .or_else(|| engine.get_session(&session_id)) {
        Some(s) => s,
        None => return Json(None),
    };

    // Build anomaly summary
    let mut by_type = HashMap::new();
    let mut by_severity = HashMap::new();

    for anomaly in &session.anomalies {
        *by_type.entry(format!("{:?}", anomaly.anomaly_type)).or_insert(0) += 1;
        *by_severity.entry(format!("{:?}", anomaly.severity)).or_insert(0) += 1;
    }

    let anomaly_summary = AnomalySummary {
        total: session.anomalies.len(),
        by_type,
        by_severity,
        top_anomalies: session.anomalies.iter().take(5).cloned().collect(),
    };

    // Build ATT&CK summary
    let mut attack_counts: HashMap<String, (String, usize, f32)> = HashMap::new();
    for event in &session.events {
        for (i, tech_id) in event.attack_techniques.iter().enumerate() {
            let tactic = event.attack_tactics.get(i).cloned().unwrap_or_default();
            if let Some(entry) = attack_counts.get_mut(tech_id) {
                entry.1 += 1;
                entry.2 = (entry.2 + event.confidence) / 2.0;
            } else {
                attack_counts.insert(tech_id.clone(), (tactic.clone(), 1, event.confidence));
            }
        }
    }

    let attack_summary: Vec<AttackTechniqueSummary> = attack_counts
        .into_iter()
        .map(|(id, (name, count, conf))| AttackTechniqueSummary {
            technique_id: id,
            technique_name: name,
            count,
            confidence: conf,
        })
        .collect();

    // Risk assessment
    let risk_level = format!("{:?}", session.risk_score.risk_level);
    let recommendations = generate_recommendations(&session);

    let report = SessionReportResponse {
        session: session.clone(),
        anomaly_summary,
        attack_coverage: attack_summary,
        risk_assessment: RiskAssessment {
            overall_score: session.risk_score.cumulative_score,
            risk_level,
            recommendations,
        },
    };

    Json(Some(report))
}

/// Get session in OCSF format
async fn get_session_ocsf(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
) -> Json<Option<Vec<OcsfEvent>>> {
    let storage = state.storage.lock().await;
    let events = storage.export_session_ocsf(&session_id).await;
    Json(events)
}

/// Get active sessions
async fn get_active_sessions(State(state): State<ApiState>) -> Json<Vec<SessionId>> {
    let engine = state.engine.lock().await;
    Json(engine.get_active_sessions())
}

/// Add a detection rule
async fn add_rule(
    State(state): State<ApiState>,
    Json(req): Json<AddRuleRequest>,
) -> Json<RuleAddedResponse> {
    let rules_engine = state.rules_engine.lock().await;
    rules_engine.add_rule(req.rule);
    Json(RuleAddedResponse { added: true })
}

/// List all rules
async fn list_rules(State(state): State<ApiState>) -> Json<Vec<DetectionRule>> {
    let rules_engine = state.rules_engine.lock().await;
    let storage = state.storage.lock().await;

    let engine_rules = rules_engine.get_all_rules();
    let storage_rules = storage.get_all_rules().await;

    // Combine and deduplicate
    let mut all_rules = engine_rules;
    for rule in storage_rules {
        if !all_rules.iter().any(|r| r.id == rule.id) {
            all_rules.push(rule);
        }
    }

    Json(all_rules)
}

/// Helper functions
fn generate_recommendations(session: &CorrelationSession) -> Vec<String> {
    let mut recommendations = Vec::new();

    if session.risk_score.cumulative_score >= 80.0 {
        recommendations.push("CRITICAL: Immediate review required - risk score indicates severe anomaly".to_string());
    }

    if session.anomalies.iter().any(|a| a.anomaly_type == AnomalyType::DataExfiltration) {
        recommendations.push("POTENTIAL DATA EXFILTRATION DETECTED: Review file access patterns and network connections".to_string());
    }

    if session.anomalies.iter().any(|a| a.anomaly_type == AnomalyType::PermissionEscalation) {
        recommendations.push("PRIVILEGE ESCALATION DETECTED: Review capability and permission changes".to_string());
    }

    if !session.attack_coverage.is_empty() {
        recommendations.push(format!("ATT&CK techniques detected: {}. Consider implementing detection rules.", 
            session.attack_coverage.join(", ")));
    }

    if recommendations.is_empty() {
        recommendations.push("No critical anomalies detected. Session appears normal.".to_string());
    }

    recommendations
}

// Response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub profile_name: String,
    pub status: String,
    pub start_time: u64,
    pub end_time: u64,
    pub event_count: usize,
    pub anomaly_count: usize,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentResponse {
    pub registered: bool,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAddedResponse {
    pub added: bool,
}

/// Start API server
pub async fn start_api(state: ApiState, address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let router = create_router(state);
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

use crate::correlation::models::now_timestamp;

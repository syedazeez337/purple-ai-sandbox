// purple/src/correlation/api/mod.rs
//!
//! REST API handlers for the correlation engine.
//!
//! Routes (all prefixed with `/api/v1/correlation`):
//! - POST   /sessions                    → create session
//! - GET    /sessions                    → list active sessions
//! - GET    /sessions/:id                → get session status
//! - POST   /sessions/:id/events         → submit event
//! - POST   /sessions/:id/intents        → register LLM intent
//! - POST   /sessions/:id/complete       → complete session & score
//! - GET    /sessions/:id/report         → fetch report (JSON)
//! - GET    /rules                       → list detection rules

use crate::correlation::{
    engine::CorrelationEngine,
    models::{EventCategory, LlmIntent, RawEvent},
    rules::RulesEngine,
    storage::CorrelationStorageTrait,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared state for the correlation API.
///
/// `CorrelationEngine` already uses internal `Arc<Mutex<...>>` for its maps,
/// so it can be cloned cheaply without an outer Mutex.
#[derive(Clone)]
pub struct ApiState {
    pub engine: CorrelationEngine,
    pub rules_engine: Arc<Mutex<RulesEngine>>,
    pub storage: Arc<Mutex<dyn CorrelationStorageTrait + Send + Sync>>,
}

impl ApiState {
    pub fn new(
        engine: CorrelationEngine,
        rules_engine: RulesEngine,
        storage: Arc<Mutex<dyn CorrelationStorageTrait + Send + Sync>>,
    ) -> Self {
        Self {
            engine,
            rules_engine: Arc::new(Mutex::new(rules_engine)),
            storage,
        }
    }
}

// ---------------------------------------------------------------------------
// Request / response models
// ---------------------------------------------------------------------------

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
pub struct SubmitEventRequest {
    pub event_type: String,
    pub pid: u32,
    pub details: String,
    /// One of: "syscall", "file_access", "network", "process", "memory", "capability", "resource"
    #[serde(default = "default_category")]
    pub category: String,
}

fn default_category() -> String {
    "syscall".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterIntentRequest {
    pub prompt: String,
    #[serde(default)]
    pub expected_actions: Vec<String>,
    #[serde(default)]
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub profile_name: String,
    pub status: String,
    pub event_count: usize,
    pub anomaly_count: usize,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    pub name: String,
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn create_session(
    State(state): State<ApiState>,
    Json(body): Json<CreateSessionRequest>,
) -> (StatusCode, Json<CreateSessionResponse>) {
    let session_id = state
        .engine
        .start_session(body.profile_name.clone(), body.sandbox_id);

    // Persist to storage
    if let Some(session) = state.engine.get_session(&session_id) {
        let storage = state.storage.lock().await;
        storage.store_session(&session).await.ok();
    }

    (
        StatusCode::CREATED,
        Json(CreateSessionResponse {
            session_id,
            status: "active".to_string(),
        }),
    )
}

async fn list_sessions(State(state): State<ApiState>) -> Json<Vec<SessionSummary>> {
    let session_ids = state.engine.get_active_sessions();
    let summaries = session_ids
        .into_iter()
        .filter_map(|id| {
            state.engine.get_session(&id).map(|s| SessionSummary {
                session_id: id,
                profile_name: s.profile_name.clone(),
                status: format!("{:?}", s.status),
                event_count: s.events.len(),
                anomaly_count: s.anomalies.len(),
                risk_score: s.risk_score.cumulative_score as f64,
            })
        })
        .collect();
    Json(summaries)
}

async fn get_session(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.engine.get_session(&session_id) {
        Some(session) => {
            let value = serde_json::to_value(&session).unwrap_or(serde_json::Value::Null);
            Ok(Json(value))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn submit_event(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
    Json(body): Json<SubmitEventRequest>,
) -> StatusCode {
    let category = match body.category.as_str() {
        "file_access" => EventCategory::FileAccess,
        "network" => EventCategory::Network,
        "process" => EventCategory::Process,
        "memory" => EventCategory::Memory,
        "capability" => EventCategory::Capability,
        "resource" => EventCategory::Resource,
        _ => EventCategory::Syscall,
    };

    let event = RawEvent::new(body.event_type, body.pid, body.details, category);

    // process_event holds a std::sync::MutexGuard across an .await internally,
    // making its future !Send. Use block_in_place to run it on the current thread
    // without crossing a Send boundary in the handler future.
    let engine = state.engine.clone();
    let sid = session_id.clone();
    tokio::task::block_in_place(move || {
        tokio::runtime::Handle::current().block_on(engine.process_event(&sid, event))
    });

    // Update persistent storage
    if let Some(session) = state.engine.get_session(&session_id) {
        let storage = state.storage.lock().await;
        storage.store_session(&session).await.ok();
    }

    StatusCode::ACCEPTED
}

async fn register_intent(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
    Json(body): Json<RegisterIntentRequest>,
) -> StatusCode {
    let intent = LlmIntent::new(body.prompt, body.expected_actions, body.model);
    state.engine.register_intent(&session_id, intent).await;

    if let Some(session) = state.engine.get_session(&session_id) {
        let storage = state.storage.lock().await;
        storage.store_session(&session).await.ok();
    }

    StatusCode::ACCEPTED
}

async fn complete_session(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // complete_session holds a std::sync::MutexGuard across an .await internally,
    // making its future !Send. Use block_in_place to avoid crossing Send boundary.
    let engine = state.engine.clone();
    let sid = session_id.clone();
    let result = tokio::task::block_in_place(move || {
        tokio::runtime::Handle::current().block_on(engine.complete_session(&sid))
    });

    match result {
        Some(session) => {
            {
                let storage = state.storage.lock().await;
                storage.store_session(&session).await.ok();
            }
            let value = serde_json::to_value(&session).unwrap_or(serde_json::Value::Null);
            Ok(Json(value))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_report(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Try live engine first, then persistent storage
    if let Some(session) = state.engine.get_session(&session_id) {
        let value = serde_json::to_value(&session).unwrap_or(serde_json::Value::Null);
        return Ok(Json(value));
    }

    let storage = state.storage.lock().await;
    match storage.get_session(&session_id).await {
        Some(s) => {
            let value = serde_json::to_value(&s).unwrap_or(serde_json::Value::Null);
            Ok(Json(value))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn list_rules(State(state): State<ApiState>) -> Json<Vec<RuleInfo>> {
    let engine = state.rules_engine.lock().await;
    let rules = engine
        .get_all_rules()
        .into_iter()
        .map(|r| RuleInfo {
            name: r.name,
            enabled: r.enabled,
        })
        .collect();
    Json(rules)
}

// ---------------------------------------------------------------------------
// Router builder
// ---------------------------------------------------------------------------

/// Build an axum Router for the correlation engine API, mounted at the
/// prefix `/api/v1/correlation`.
pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/sessions", post(create_session))
        .route("/sessions", get(list_sessions))
        .route("/sessions/:id", get(get_session))
        .route("/sessions/:id/events", post(submit_event))
        .route("/sessions/:id/intents", post(register_intent))
        .route("/sessions/:id/complete", post(complete_session))
        .route("/sessions/:id/report", get(get_report))
        .route("/rules", get(list_rules))
        .with_state(state)
}

/// Start a standalone correlation API server (used for testing / dedicated deployments).
pub async fn start_api(
    state: ApiState,
    address: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new().nest("/api/v1/correlation", create_router(state));

    let listener = tokio::net::TcpListener::bind(address).await?;
    log::info!("Correlation API server listening on {}", address);
    axum::serve(listener, app).await?;
    Ok(())
}

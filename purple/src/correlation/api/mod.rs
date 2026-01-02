// purple/src/correlation/api/mod.rs
//!
//! REST API handlers for correlation engine operations
//!
//! This module provides REST API endpoints for the correlation engine.
//! Currently disabled pending refactoring to fix axum handler trait bounds.
//!
//! Endpoints (when implemented):
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

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

/// API state - uses Arc<Mutex<...>> for Shareable state
#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<Mutex<crate::correlation::CorrelationEngine>>,
    pub rules_engine: Arc<Mutex<crate::correlation::rules::RulesEngine>>,
    pub storage: Arc<Mutex<dyn crate::correlation::storage::CorrelationStorageTrait + Send + Sync>>,
}

impl ApiState {
    pub fn new(
        engine: Arc<Mutex<crate::correlation::CorrelationEngine>>,
        rules_engine: Arc<Mutex<crate::correlation::rules::RulesEngine>>,
        storage: Arc<Mutex<dyn crate::correlation::storage::CorrelationStorageTrait + Send + Sync>>,
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
pub struct SubmitEventRequest {
    pub event_type: String,
    pub pid: u32,
    pub details: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterIntentRequest {
    pub prompt: String,
    pub expected_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub profile_name: String,
    pub status: String,
    pub start_time: i64,
    pub end_time: Option<i64>,
    pub event_count: usize,
    pub anomaly_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub deleted: bool,
}

/// Create API router with state
///
/// TODO: Fix handler trait bounds for axum 0.7.x
/// The current implementation has issues with:
/// - State<ApiState> requiring ApiState: Clone
/// - Arc<Mutex<T>> not being properly Clone for complex T
/// - Need to refactor to use simpler state types or different architecture
pub fn create_router(_state: ApiState) {}

/// Start API server
///
/// This is a placeholder - the full API implementation requires
/// significant refactoring to work with axum's state management.
pub async fn start_api(_state: ApiState, _address: &str) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

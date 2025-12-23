// purple/src/api/handlers.rs
// API handlers for Purple AI Sandbox

use crate::api::models::*;
use crate::error::{PurpleError, Result};
use crate::sandbox::manager::SandboxManager;
use axum::{extract::{Path, State}, Json};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct AppState {
    pub sandbox_manager: Arc<Mutex<SandboxManager>>,
}

pub async fn create_sandbox(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<CreateSandboxRequest>,
) -> Result<Json<CreateSandboxResponse>> {
    let mut manager = app_state
        .sandbox_manager
        .lock()
        .await;
    let sandbox_id = manager.create_sandbox(payload.name.clone(), payload.profile.clone())?;

    let response = CreateSandboxResponse {
        sandbox_id,
        name: payload.name,
        status: "created".to_string(),
    };

    Ok(Json(response))
}

pub async fn list_sandboxes(
    State(app_state): State<Arc<AppState>>,
) -> Result<Json<Vec<SandboxStatus>>> {
    let manager = app_state
        .sandbox_manager
        .lock()
        .await;
    let sandboxes = manager.list_sandboxes();

    let statuses = sandboxes
        .into_iter()
        .map(|(id, sandbox)| SandboxStatus {
            sandbox_id: id,
            name: sandbox.name,
            status: format!("{:?}", sandbox.status),
            created_at: chrono::Local::now().to_rfc3339(),
            profile: sandbox.profile,
        })
        .collect();

    Ok(Json(statuses))
}

pub async fn get_sandbox_status(
    State(app_state): State<Arc<AppState>>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxStatus>> {
    let manager = app_state
        .sandbox_manager
        .lock()
        .await;
    let sandbox = manager.get_sandbox(&sandbox_id.to_string())?;

    let status = SandboxStatus {
        sandbox_id,
        name: sandbox.name,
        status: format!("{:?}", sandbox.status),
        created_at: chrono::Local::now().to_rfc3339(),
        profile: sandbox.profile,
    };

    Ok(Json(status))
}

pub async fn stop_sandbox(
    State(app_state): State<Arc<AppState>>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<()>> {
    let mut manager = app_state
        .sandbox_manager
        .lock()
        .await;
    manager.cleanup_sandbox(&sandbox_id.to_string())?;
    Ok(Json(()))
}

pub async fn execute_command(
    State(app_state): State<Arc<AppState>>,
    Path(sandbox_id): Path<Uuid>,
    Json(payload): Json<ExecuteCommandRequest>,
) -> Result<Json<ExecuteCommandResponse>> {
    let mut manager = app_state
        .sandbox_manager
        .lock()
        .await;
    let result = manager.execute_command(&sandbox_id.to_string(), &payload.command, payload.timeout_seconds)?;

    let response = ExecuteCommandResponse {
        exit_code: result.exit_code,
        stdout: result.stdout,
        stderr: result.stderr,
    };

    Ok(Json(response))
}
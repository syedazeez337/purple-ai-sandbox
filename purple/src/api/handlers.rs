// purple/src/api/handlers.rs
// API handlers for Purple AI Sandbox

use crate::api::models::*;
use crate::error::{PurpleError, Result};
use crate::sandbox::manager::SandboxManager;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct AppState {
    pub sandbox_manager: Arc<Mutex<SandboxManager>>,
}

pub async fn create_sandbox(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<CreateSandboxRequest>,
) -> Result<(StatusCode, Json<CreateSandboxResponse>)> {
    let mut manager = app_state.sandbox_manager.lock().await;

    // Validate profile name before building the path
    let profile = payload.profile.trim().to_string();
    if profile.is_empty() || profile.contains("..") || profile.contains('/') {
        return Err(PurpleError::PolicyError("Invalid profile name".to_string()));
    }

    // Load and compile policy from profile name
    let policy_file = format!("./policies/{}.yaml", profile);
    let policy = crate::policy::parser::load_policy_from_file(std::path::Path::new(&policy_file))
        .map_err(|e| {
            PurpleError::PolicyError(format!("Failed to load policy '{}': {}", profile, e))
        })?
        .compile()
        .map_err(|e| PurpleError::PolicyError(e))?;

    // Default command if not provided
    let command = match payload.command {
        Some(cmd) if !cmd.is_empty() => cmd,
        _ => vec!["/bin/echo".to_string(), "Sandbox started".to_string()],
    };

    let sandbox_id = manager.create_sandbox(policy, command, profile.clone())?;

    let response = CreateSandboxResponse {
        sandbox_id,
        name: payload.name,
        status: "created".to_string(),
        profile,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn list_sandboxes(
    State(app_state): State<Arc<AppState>>,
) -> Result<Json<Vec<SandboxStatusResponse>>> {
    let manager = app_state.sandbox_manager.lock().await;
    let sandboxes = manager.list_sandboxes_detailed()?;

    let statuses = sandboxes
        .into_iter()
        .map(|(id, status, metadata)| SandboxStatusResponse {
            sandbox_id: id,
            name: metadata.name,
            status: format!("{:?}", status),
            created_at: metadata.created_at,
            profile: metadata.profile_name,
        })
        .collect();

    Ok(Json(statuses))
}

pub async fn get_sandbox_status(
    State(app_state): State<Arc<AppState>>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxStatusResponse>> {
    let manager = app_state.sandbox_manager.lock().await;
    let id_str = sandbox_id.to_string();
    let (status, metadata) = manager.get_sandbox_status_with_metadata(&id_str)?;

    let response = SandboxStatusResponse {
        sandbox_id: id_str,
        name: metadata.name,
        status: format!("{:?}", status),
        created_at: metadata.created_at,
        profile: metadata.profile_name,
    };

    Ok(Json(response))
}

pub async fn stop_sandbox(
    State(app_state): State<Arc<AppState>>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<StatusCode> {
    let mut manager = app_state.sandbox_manager.lock().await;
    manager.cleanup_sandbox(&sandbox_id.to_string())?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn execute_command(
    State(app_state): State<Arc<AppState>>,
    Path(sandbox_id): Path<Uuid>,
    Json(_payload): Json<ExecuteCommandRequest>,
) -> Result<Json<ExecuteCommandResponse>> {
    let manager = app_state.sandbox_manager.lock().await;
    let exit_code = manager.execute_sandbox(&sandbox_id.to_string())?;

    let response = ExecuteCommandResponse {
        exit_code,
        stdout: String::new(),
        stderr: String::new(),
    };

    Ok(Json(response))
}

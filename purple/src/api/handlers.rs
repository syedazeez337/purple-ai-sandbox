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

    // Load and compile policy from profile name
    let policy_file = format!("./policies/{}.yaml", payload.profile);
    let policy = crate::policy::parser::load_policy_from_file(std::path::Path::new(&policy_file))
        .map_err(|e| PurpleError::PolicyError(format!("Failed to load policy: {}", e)))?
        .compile()
        .map_err(|e| PurpleError::PolicyError(e))?;

    // Default command if not provided
    let command = if payload.command.is_empty() {
        vec!["/bin/echo".to_string(), "Sandbox started".to_string()]
    } else {
        payload.command
    };

    let sandbox_id = manager.create_sandbox(policy, command)?;

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
        .map(|(id, status)| SandboxStatus {
            sandbox_id: id.parse().unwrap_or_default(),
            name: "sandbox".to_string(), // Placeholder - manager doesn't track names
            status: format!("{:?}", status),
            created_at: chrono::Local::now().to_rfc3339(),
            profile: "default".to_string(), // Placeholder - manager doesn't track profiles
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
    let status = manager.get_sandbox_status(&sandbox_id.to_string())?;

    let status_response = SandboxStatus {
        sandbox_id,
        name: "sandbox".to_string(), // Placeholder - manager doesn't track names
        status: format!("{:?}", status),
        created_at: chrono::Local::now().to_rfc3339(),
        profile: "default".to_string(), // Placeholder - manager doesn't track profiles
    };

    Ok(Json(status_response))
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

    // Execute the sandbox and get exit code
    let exit_code = manager.execute_sandbox(&sandbox_id.to_string())?;

    let response = ExecuteCommandResponse {
        exit_code,
        stdout: "Command executed via sandbox".to_string(),
        stderr: "".to_string(),
    };

    Ok(Json(response))
}
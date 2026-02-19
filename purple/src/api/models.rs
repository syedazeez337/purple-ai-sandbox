// purple/src/api/models.rs
// API models for Purple AI Sandbox

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateSandboxRequest {
    pub name: String,
    pub profile: String,
    pub command: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateSandboxResponse {
    pub sandbox_id: String,
    pub name: String,
    pub status: String,
    pub profile: String,
}

/// Sandbox status as returned by list and get endpoints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxStatusResponse {
    pub sandbox_id: String,
    pub name: String,
    pub status: String,
    pub created_at: String,
    pub profile: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecuteCommandRequest {
    pub command: Vec<String>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecuteCommandResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub details: Option<String>,
}

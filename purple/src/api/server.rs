// purple/src/api/server.rs
// API server for Purple AI Sandbox

use crate::api::handlers::*;
use crate::error::{PurpleError, Result};
use crate::sandbox::manager::SandboxManager;
use axum::{
    routing::{delete, get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use axum::http::Method;
use http::header::{ACCEPT, CONTENT_TYPE};
use tower_http::cors::{Any, CorsLayer};

pub struct ApiServer {
    address: SocketAddr,
}

impl ApiServer {
    pub fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    pub async fn run(&self) -> Result<()> {
        let sandbox_manager = Arc::new(Mutex::new(SandboxManager::new()));
        let app_state = Arc::new(AppState {
            sandbox_manager: sandbox_manager.clone(),
        });

        let app = Router::new()
            .route("/sandboxes", post(create_sandbox))
            .route("/sandboxes", get(list_sandboxes))
            .route("/sandboxes/:sandbox_id", get(get_sandbox_status))
            .route("/sandboxes/:sandbox_id", delete(stop_sandbox))
            .route("/sandboxes/:sandbox_id/exec", post(execute_command))
            .layer(
                CorsLayer::new()
                    // Only allow specific origins (whitelist)
                    .allow_origin(
                        ["http://localhost:8080", "http://localhost:3000"]
                            .iter()
                            .cloned()
                            .map(|origin| origin.parse().unwrap())
                            .collect::<Vec<_>>()
                    )
                    // Only allow needed methods
                    .allow_methods([
                        Method::GET,
                        Method::POST,
                        Method::DELETE,
                    ])
                    // Only allow needed headers
                    .allow_headers([CONTENT_TYPE, ACCEPT])
                    // Don't allow credentials
                    .allow_credentials(false),
            )
            .with_state(app_state);

        log::info!("🚀 Starting API server on {}", self.address);
        
        let listener = tokio::net::TcpListener::bind(self.address)
            .await
            .map_err(|e| PurpleError::ApiError(format!("Failed to bind to address {}: {}", self.address, e)))?;

        axum::serve(listener, app)
            .await
            .map_err(|e| PurpleError::ApiError(format!("Server runtime error: {}", e)))?;

        Ok(())
    }
}

pub async fn start_api_server(address: SocketAddr) -> Result<()> {
    let server = ApiServer::new(address);
    server.run().await
}
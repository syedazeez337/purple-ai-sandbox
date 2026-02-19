// purple/src/api/server.rs
// API server for Purple AI Sandbox

use crate::api::handlers::*;
use crate::error::{PurpleError, Result};
use crate::sandbox::manager::SandboxManager;
use axum::http::{HeaderValue, Method};
use axum::{
    Router,
    routing::{delete, get, post},
};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

/// Builds the list of allowed CORS origins.
///
/// Sources (highest precedence first):
/// 1. `PURPLE_ALLOWED_ORIGINS` environment variable — comma-separated list of
///    fully-qualified origins, e.g. `http://localhost:8080,https://dashboard.example.com`
/// 2. Hard-coded development defaults: `http://localhost:8080` and
///    `http://localhost:3000`
fn allowed_origins() -> Vec<HeaderValue> {
    let raw = std::env::var("PURPLE_ALLOWED_ORIGINS").unwrap_or_default();
    if !raw.trim().is_empty() {
        raw.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|origin| origin.parse::<HeaderValue>().ok())
            .collect()
    } else {
        vec![
            "http://localhost:8080".parse().unwrap(),
            "http://localhost:3000".parse().unwrap(),
        ]
    }
}

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

        // API key from environment; fall back to a clearly-labeled dev key.
        let api_key = std::env::var("PURPLE_API_KEY").unwrap_or_else(|_| {
            log::warn!(
                "PURPLE_API_KEY not set — using insecure development key. \
                     Set this variable before deploying to production."
            );
            "dev-key-change-before-production".to_string()
        });

        let app = Router::new()
            .route("/api/v1/sandboxes", post(create_sandbox))
            .route("/api/v1/sandboxes", get(list_sandboxes))
            .route("/api/v1/sandboxes/:sandbox_id", get(get_sandbox_status))
            .route("/api/v1/sandboxes/:sandbox_id", delete(stop_sandbox))
            .route("/api/v1/sandboxes/:sandbox_id/exec", post(execute_command))
            .layer(
                CorsLayer::new()
                    .allow_origin(allowed_origins())
                    .allow_methods([Method::GET, Method::POST, Method::DELETE])
                    .allow_headers([CONTENT_TYPE, ACCEPT, AUTHORIZATION])
                    .allow_credentials(false),
            )
            // Note: For production rate limiting, use a reverse proxy (nginx, caddy, etc.)
            // Bearer token authentication
            .layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    let api_key = api_key.clone();
                    async move {
                        let auth_header = req
                            .headers()
                            .get("Authorization")
                            .and_then(|v| v.to_str().ok());

                        match auth_header {
                            Some(key) if key == format!("Bearer {}", api_key) => {
                                Ok(next.run(req).await)
                            }
                            Some(_) => Err((
                                axum::http::StatusCode::UNAUTHORIZED,
                                "Invalid API key".to_string(),
                            )),
                            None => Err((
                                axum::http::StatusCode::UNAUTHORIZED,
                                "Missing Authorization header".to_string(),
                            )),
                        }
                    }
                },
            ))
            .with_state(app_state);

        log::info!("Starting Purple API server on {}", self.address);
        log::info!(
            "Allowed CORS origins: {:?}",
            std::env::var("PURPLE_ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:8080,http://localhost:3000".to_string())
        );

        let listener = tokio::net::TcpListener::bind(self.address)
            .await
            .map_err(|e| {
                PurpleError::ApiError(format!("Failed to bind {}: {}", self.address, e))
            })?;

        axum::serve(listener, app)
            .await
            .map_err(|e| PurpleError::ApiError(format!("Server error: {}", e)))?;

        Ok(())
    }
}

pub async fn start_api_server(address: SocketAddr) -> Result<()> {
    let server = ApiServer::new(address);
    server.run().await
}

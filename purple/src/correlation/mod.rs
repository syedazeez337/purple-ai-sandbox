// purple/src/correlation/mod.rs
//!
//! # State-of-the-Art Correlation Engine for Purple AI Sandbox
//!
//! A production-grade correlation engine that provides:
//! - Intent-behavior correlation for AI agents
//! - Statistical anomaly detection
//! - MITRE ATT&CK mapping and threat intelligence
//! - Risk scoring and behavioral analysis
//! - Sigma rule support for detection
//! - Persistent storage with OCSF export
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                      Correlation Engine                              │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────────┐│
//! │  │   Event   │  │  Intent   │  │  Threat   │  │  Rule Engine      ││
//! │  │ Enrichment│  │  Linker   │  │ Intel     │  │  (Sigma Rules)    ││
//! │  └───────────┘  └───────────┘  └───────────┘  └───────────────────┘│
//! │         │              │              │                │            │
//! │         └──────────────┼──────────────┼────────────────┘            │
//! │                        │              │                             │
//! │                 ┌──────▼──────┐       │                             │
//! │                 │   Anomaly   │◄──────┘                             │
//! │                 │  Detector   │                                      │
//! │                 └──────┬──────┘                                      │
//! │                        │                                             │
//! │                        ▼                                             │
//! │                 ┌──────────────┐                                     │
//! │                 │    Risk      │                                     │
//! │                 │   Scorer     │                                     │
//! │                 └──────┬──────┘                                     │
//! │                        │                                             │
//! │                        ▼                                             │
//! │                 ┌──────────────┐    ┌─────────────────────────────┐  │
//! │                 │  Correlation │    │  MITRE ATT&CK               │  │
//! │                 │   Engine     │───►│  Mapper & Tactic Detection  │  │
//! │                 └──────────────┘    └─────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```

pub mod api;
pub mod cli;
pub mod engine;
pub mod enrichment;
pub mod models;
pub mod rules;
pub mod storage;

pub use engine::*;
pub use models::*;
pub use storage::*;

/// Current version of the correlation engine
pub const CORRELATION_VERSION: &str = "1.0.0";

/// Default correlation configuration
#[derive(Debug, Clone)]
pub struct DefaultCorrelationConfig;

impl DefaultCorrelationConfig {
    pub const CORRELATION_WINDOW_SECONDS: u64 = 300;
    pub const MAX_EVENTS_PER_SESSION: usize = 10_000;
    pub const ANOMALY_Z_THRESHOLD: f32 = 3.0;
    pub const RATE_THRESHOLD_PER_SEC: u64 = 100;
    pub const SEQUENCE_LOOKBEHIND: usize = 10;
    pub const BASE_RISK_SCORE: f32 = 50.0;
    pub const EVENT_BUFFER_SIZE: usize = 1000;
}

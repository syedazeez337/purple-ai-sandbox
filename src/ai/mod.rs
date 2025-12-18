// purple/src/ai/mod.rs
//! AI-specific features for Purple sandbox
//!
//! This module provides:
//! - LLM API call interception and monitoring
//! - Token budget enforcement
//! - Cost tracking and calculation
//! - Prompt analysis and security

pub mod api_monitor;
pub mod budget;
pub mod cost;

pub use api_monitor::LLMAPIMonitor;
pub use budget::{Budget, BudgetEnforcer, BudgetExceeded};
pub use cost::{CostCalculator, ModelPricing};

/// AI-specific policies from YAML
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct AIPolicies {
    /// Token and cost budget limits
    #[serde(default)]
    pub budget: Option<BudgetConfig>,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limits: Option<RateLimits>,

    /// Allowed LLM API providers
    #[serde(default)]
    pub llm_apis: Option<LLMAPIConfig>,

    /// Security settings
    #[serde(default)]
    pub security: Option<SecurityConfig>,

    /// Monitoring settings
    #[serde(default)]
    pub monitoring: Option<MonitoringConfig>,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct BudgetConfig {
    pub max_tokens: Option<u64>,
    pub max_cost: Option<String>, // e.g., "$10.00"
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct RateLimits {
    pub requests_per_minute: Option<u32>,
    pub tokens_per_minute: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct LLMAPIConfig {
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub block_unknown: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ProviderConfig {
    pub name: String,
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub models: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub prompt_injection_detection: bool,
    #[serde(default)]
    pub sensitive_data_scanning: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct MonitoringConfig {
    #[serde(default)]
    pub log_prompts: bool,
    #[serde(default)]
    pub log_responses: bool,
    #[serde(default = "default_true")]
    pub log_tokens: bool,
    #[serde(default = "default_true")]
    pub log_costs: bool,
}

fn default_true() -> bool {
    true
}

impl Default for AIPolicies {
    fn default() -> Self {
        Self {
            budget: None,
            rate_limits: None,
            llm_apis: None,
            security: None,
            monitoring: Some(MonitoringConfig {
                log_prompts: false,
                log_responses: false,
                log_tokens: true,
                log_costs: true,
            }),
        }
    }
}

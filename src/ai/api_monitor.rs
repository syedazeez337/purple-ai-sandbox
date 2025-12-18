#![allow(dead_code)]
// purple/src/ai/api_monitor.rs
//! Monitor and parse LLM API calls

use crate::ai::cost::CostCalculator;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Tracks LLM API calls during sandbox execution
#[derive(Debug, Clone)]
pub struct LLMAPIMonitor {
    calls: Arc<Mutex<Vec<APICall>>>,
}

impl LLMAPIMonitor {
    pub fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record an API call
    pub fn record_call(&self, call: APICall) {
        log::info!(
            "LLM API call: {} model={} tokens={} cost=${}",
            call.provider,
            call.model,
            call.total_tokens(),
            CostCalculator::format_cost(call.cost_cents)
        );

        let mut calls = self.calls.lock().unwrap();
        calls.push(call);
    }

    /// Parse OpenAI API response and record
    pub fn parse_openai_response(&self, model: &str, response_json: &str) -> Result<APICall> {
        let response: OpenAIResponse = serde_json::from_str(response_json)?;

        let cost_cents = CostCalculator::calculate_or_estimate(
            model,
            response.usage.prompt_tokens,
            response.usage.completion_tokens,
        );

        let call = APICall {
            provider: "openai".to_string(),
            model: model.to_string(),
            prompt_tokens: response.usage.prompt_tokens,
            completion_tokens: response.usage.completion_tokens,
            cost_cents,
            timestamp: std::time::SystemTime::now(),
        };

        self.record_call(call.clone());
        Ok(call)
    }

    /// Parse Anthropic API response and record
    pub fn parse_anthropic_response(&self, model: &str, response_json: &str) -> Result<APICall> {
        let response: AnthropicResponse = serde_json::from_str(response_json)?;

        let cost_cents = CostCalculator::calculate_or_estimate(
            model,
            response.usage.input_tokens,
            response.usage.output_tokens,
        );

        let call = APICall {
            provider: "anthropic".to_string(),
            model: model.to_string(),
            prompt_tokens: response.usage.input_tokens,
            completion_tokens: response.usage.output_tokens,
            cost_cents,
            timestamp: std::time::SystemTime::now(),
        };

        self.record_call(call.clone());
        Ok(call)
    }

    /// Get all recorded API calls
    pub fn get_calls(&self) -> Vec<APICall> {
        self.calls.lock().unwrap().clone()
    }

    /// Get total usage statistics
    pub fn get_totals(&self) -> UsageStats {
        let calls = self.calls.lock().unwrap();

        let mut stats = UsageStats::default();
        for call in calls.iter() {
            stats.total_calls += 1;
            stats.total_tokens += call.total_tokens();
            stats.total_cost_cents += call.cost_cents;
        }

        stats
    }
}

impl Default for LLMAPIMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a single LLM API call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APICall {
    pub provider: String,
    pub model: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cost_cents: u64,
    pub timestamp: std::time::SystemTime,
}

impl APICall {
    pub fn total_tokens(&self) -> u64 {
        self.prompt_tokens + self.completion_tokens
    }

    pub fn cost_dollars(&self) -> f64 {
        self.cost_cents as f64 / 100.0
    }
}

/// Aggregated usage statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UsageStats {
    pub total_calls: usize,
    pub total_tokens: u64,
    pub total_cost_cents: u64,
}

impl UsageStats {
    pub fn cost_dollars(&self) -> f64 {
        self.total_cost_cents as f64 / 100.0
    }
}

// OpenAI API response format
#[derive(Debug, Deserialize)]
struct OpenAIResponse {
    usage: OpenAIUsage,
}

#[derive(Debug, Deserialize)]
struct OpenAIUsage {
    prompt_tokens: u64,
    completion_tokens: u64,
    #[allow(dead_code)]
    total_tokens: u64,
}

// Anthropic API response format
#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    usage: AnthropicUsage,
}

#[derive(Debug, Deserialize)]
struct AnthropicUsage {
    input_tokens: u64,
    output_tokens: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_openai_response() {
        let monitor = LLMAPIMonitor::new();

        let response = r#"{
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "created": 1677652288,
            "model": "gpt-3.5-turbo",
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 20,
                "total_tokens": 30
            },
            "choices": []
        }"#;

        let call = monitor
            .parse_openai_response("gpt-3.5-turbo", response)
            .unwrap();

        assert_eq!(call.provider, "openai");
        assert_eq!(call.model, "gpt-3.5-turbo");
        assert_eq!(call.prompt_tokens, 10);
        assert_eq!(call.completion_tokens, 20);
        assert_eq!(call.total_tokens(), 30);
        assert!(call.cost_cents > 0);
    }

    #[test]
    fn test_parse_anthropic_response() {
        let monitor = LLMAPIMonitor::new();

        let response = r#"{
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [],
            "model": "claude-3-5-sonnet-20241022",
            "usage": {
                "input_tokens": 15,
                "output_tokens": 25
            }
        }"#;

        let call = monitor
            .parse_anthropic_response("claude-3-5-sonnet-20241022", response)
            .unwrap();

        assert_eq!(call.provider, "anthropic");
        assert_eq!(call.model, "claude-3-5-sonnet-20241022");
        assert_eq!(call.prompt_tokens, 15);
        assert_eq!(call.completion_tokens, 25);
        assert_eq!(call.total_tokens(), 40);
        assert!(call.cost_cents > 0);
    }

    #[test]
    fn test_totals() {
        let monitor = LLMAPIMonitor::new();

        // Record multiple calls
        monitor.record_call(APICall {
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            cost_cents: 450,
            timestamp: std::time::SystemTime::now(),
        });

        monitor.record_call(APICall {
            provider: "anthropic".to_string(),
            model: "claude-3-5-sonnet-20241022".to_string(),
            prompt_tokens: 200,
            completion_tokens: 100,
            cost_cents: 540,
            timestamp: std::time::SystemTime::now(),
        });

        let stats = monitor.get_totals();
        assert_eq!(stats.total_calls, 2);
        assert_eq!(stats.total_tokens, 450);
        assert_eq!(stats.total_cost_cents, 990);
    }
}

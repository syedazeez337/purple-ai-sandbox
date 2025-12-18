#![allow(dead_code)]
// purple/src/ai/cost.rs
//! LLM API cost calculation based on token usage

use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Pricing for a specific model (per 1000 tokens)
#[derive(Debug, Clone, Copy)]
pub struct ModelPricing {
    /// Cost per 1000 input tokens (in cents)
    pub input_per_1k_cents: u64,
    /// Cost per 1000 output tokens (in cents)
    pub output_per_1k_cents: u64,
}

/// Database of model pricing (updated as of Dec 2024)
static PRICING: Lazy<HashMap<&'static str, ModelPricing>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // OpenAI models
    m.insert(
        "gpt-4",
        ModelPricing {
            input_per_1k_cents: 3000,  // $30.00 / 1M tokens = $0.03 / 1k
            output_per_1k_cents: 6000, // $60.00 / 1M tokens = $0.06 / 1k
        },
    );
    m.insert(
        "gpt-4-turbo",
        ModelPricing {
            input_per_1k_cents: 1000,  // $10.00 / 1M
            output_per_1k_cents: 3000, // $30.00 / 1M
        },
    );
    m.insert(
        "gpt-3.5-turbo",
        ModelPricing {
            input_per_1k_cents: 50,   // $0.50 / 1M
            output_per_1k_cents: 150, // $1.50 / 1M
        },
    );

    // Anthropic models
    m.insert(
        "claude-3-5-sonnet-20241022",
        ModelPricing {
            input_per_1k_cents: 300,   // $3.00 / 1M
            output_per_1k_cents: 1500, // $15.00 / 1M
        },
    );
    m.insert(
        "claude-3-opus-20240229",
        ModelPricing {
            input_per_1k_cents: 1500,  // $15.00 / 1M
            output_per_1k_cents: 7500, // $75.00 / 1M
        },
    );
    m.insert(
        "claude-3-sonnet-20240229",
        ModelPricing {
            input_per_1k_cents: 300,   // $3.00 / 1M
            output_per_1k_cents: 1500, // $15.00 / 1M
        },
    );
    m.insert(
        "claude-3-haiku-20240307",
        ModelPricing {
            input_per_1k_cents: 25,   // $0.25 / 1M
            output_per_1k_cents: 125, // $1.25 / 1M
        },
    );

    m
});

/// Calculate LLM API costs
pub struct CostCalculator;

impl CostCalculator {
    /// Calculate cost for a specific model and token usage
    ///
    /// Returns cost in cents to avoid floating point issues
    pub fn calculate(model: &str, prompt_tokens: u64, completion_tokens: u64) -> Option<u64> {
        let pricing = PRICING.get(model)?;

        let input_cost = (prompt_tokens * pricing.input_per_1k_cents) / 1000;
        let output_cost = (completion_tokens * pricing.output_per_1k_cents) / 1000;

        Some(input_cost + output_cost)
    }

    /// Calculate cost with fallback pricing if model unknown
    pub fn calculate_or_estimate(model: &str, prompt_tokens: u64, completion_tokens: u64) -> u64 {
        Self::calculate(model, prompt_tokens, completion_tokens).unwrap_or_else(|| {
            // Fallback: use GPT-3.5-turbo pricing (most common)
            log::warn!("Unknown model '{}', using fallback pricing", model);
            let fallback = PRICING.get("gpt-3.5-turbo").unwrap();
            let input_cost = (prompt_tokens * fallback.input_per_1k_cents) / 1000;
            let output_cost = (completion_tokens * fallback.output_per_1k_cents) / 1000;
            input_cost + output_cost
        })
    }

    /// Get all known models
    pub fn known_models() -> Vec<&'static str> {
        PRICING.keys().copied().collect()
    }

    /// Check if a model is known
    pub fn is_known_model(model: &str) -> bool {
        PRICING.contains_key(model)
    }

    /// Get pricing for a model
    pub fn get_pricing(model: &str) -> Option<ModelPricing> {
        PRICING.get(model).copied()
    }

    /// Format cost in cents as dollar string
    pub fn format_cost(cents: u64) -> String {
        format!("${:.2}", cents as f64 / 100.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpt4_cost() {
        // GPT-4: $0.03 input, $0.06 output per 1k tokens
        let cost = CostCalculator::calculate("gpt-4", 1000, 1000).unwrap();
        assert_eq!(cost, 9000); // $0.09 in cents = 9000
    }

    #[test]
    fn test_gpt35_cost() {
        // GPT-3.5-turbo: $0.0005 input, $0.0015 output per 1k tokens
        let cost = CostCalculator::calculate("gpt-3.5-turbo", 1000, 1000).unwrap();
        assert_eq!(cost, 200); // $0.002 in cents = 200
    }

    #[test]
    fn test_claude_cost() {
        // Claude 3.5 Sonnet: $0.003 input, $0.015 output per 1k tokens
        let cost = CostCalculator::calculate("claude-3-5-sonnet-20241022", 1000, 1000).unwrap();
        assert_eq!(cost, 1800); // $0.018 in cents = 1800
    }

    #[test]
    fn test_unknown_model() {
        // Should use fallback pricing
        let cost = CostCalculator::calculate_or_estimate("unknown-model", 1000, 1000);
        assert!(cost > 0); // Should return some cost
    }

    #[test]
    fn test_format_cost() {
        assert_eq!(CostCalculator::format_cost(100), "$1.00");
        assert_eq!(CostCalculator::format_cost(50), "$0.50");
        assert_eq!(CostCalculator::format_cost(1), "$0.01");
    }
}

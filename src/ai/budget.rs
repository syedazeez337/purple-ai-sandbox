// purple/src/ai/budget.rs
//! Token budget tracking and enforcement

use crate::error::{PurpleError, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Budget limits for a sandbox session
#[derive(Debug, Clone)]
pub struct Budget {
    pub max_tokens: Option<u64>,
    pub max_cost_cents: Option<u64>, // Cost in cents to avoid floating point
}

impl Budget {
    pub fn new(max_tokens: Option<u64>, max_cost: Option<String>) -> Result<Self> {
        let max_cost_cents = if let Some(cost_str) = max_cost {
            Some(Self::parse_cost(&cost_str)?)
        } else {
            None
        };

        Ok(Self {
            max_tokens,
            max_cost_cents,
        })
    }

    /// Parse cost string like "$10.00" into cents
    fn parse_cost(cost_str: &str) -> Result<u64> {
        let clean = cost_str.trim().trim_start_matches('$');
        let dollars: f64 = clean
            .parse()
            .map_err(|_| PurpleError::PolicyError(format!("Invalid cost format: {}", cost_str)))?;

        Ok((dollars * 100.0) as u64)
    }
}

/// Tracks token usage and enforces budget limits
#[derive(Debug, Clone)]
pub struct BudgetEnforcer {
    budget: Budget,
    current_tokens: Arc<AtomicU64>,
    current_cost_cents: Arc<Mutex<u64>>,
}

impl BudgetEnforcer {
    pub fn new(budget: Budget) -> Self {
        Self {
            budget,
            current_tokens: Arc::new(AtomicU64::new(0)),
            current_cost_cents: Arc::new(Mutex::new(0)),
        }
    }

    /// Check if we can afford this usage, and update if allowed
    pub fn check_and_update(&self, tokens: u64, cost_cents: u64) -> Result<()> {
        // Check token limit
        if let Some(max_tokens) = self.budget.max_tokens {
            let new_total = self.current_tokens.fetch_add(tokens, Ordering::SeqCst) + tokens;

            if new_total > max_tokens {
                log::error!(
                    "Token budget exceeded: {} / {} tokens",
                    new_total,
                    max_tokens
                );
                return Err(PurpleError::ResourceError(format!(
                    "Token budget exceeded: used {} tokens, limit is {}",
                    new_total, max_tokens
                )));
            }

            log::debug!(
                "Token usage: {} / {} ({:.1}%)",
                new_total,
                max_tokens,
                (new_total as f64 / max_tokens as f64) * 100.0
            );
        } else {
            // No limit, just track
            let new_total = self.current_tokens.fetch_add(tokens, Ordering::SeqCst) + tokens;
            log::debug!("Token usage: {} (no limit)", new_total);
        }

        // Check cost limit
        if let Some(max_cost_cents) = self.budget.max_cost_cents {
            let mut current = self.current_cost_cents.lock().unwrap();
            *current += cost_cents;

            if *current > max_cost_cents {
                log::error!(
                    "Cost budget exceeded: ${:.2} / ${:.2}",
                    *current as f64 / 100.0,
                    max_cost_cents as f64 / 100.0
                );
                return Err(PurpleError::ResourceError(format!(
                    "Cost budget exceeded: spent ${:.2}, limit is ${:.2}",
                    *current as f64 / 100.0,
                    max_cost_cents as f64 / 100.0
                )));
            }

            log::debug!(
                "Cost: ${:.2} / ${:.2} ({:.1}%)",
                *current as f64 / 100.0,
                max_cost_cents as f64 / 100.0,
                (*current as f64 / max_cost_cents as f64) * 100.0
            );
        } else {
            // No limit, just track
            let mut current = self.current_cost_cents.lock().unwrap();
            *current += cost_cents;
            log::debug!("Cost: ${:.2} (no limit)", *current as f64 / 100.0);
        }

        Ok(())
    }

    /// Get current usage statistics
    pub fn get_usage(&self) -> BudgetUsage {
        BudgetUsage {
            tokens_used: self.current_tokens.load(Ordering::SeqCst),
            cost_cents: *self.current_cost_cents.lock().unwrap(),
        }
    }

    /// Reset usage counters (for testing or new session)
    pub fn reset(&self) {
        self.current_tokens.store(0, Ordering::SeqCst);
        *self.current_cost_cents.lock().unwrap() = 0;
    }
}

/// Current budget usage
#[derive(Debug, Clone, Copy)]
pub struct BudgetUsage {
    pub tokens_used: u64,
    pub cost_cents: u64,
}

impl BudgetUsage {
    pub fn cost_dollars(&self) -> f64 {
        self.cost_cents as f64 / 100.0
    }
}

/// Error type for budget exceeded
#[derive(Debug)]
pub enum BudgetExceeded {
    Tokens(u64),
    Cost(u64),
}

impl std::fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetExceeded::Tokens(used) => write!(f, "Token budget exceeded: {} tokens", used),
            BudgetExceeded::Cost(cents) => {
                write!(f, "Cost budget exceeded: ${:.2}", *cents as f64 / 100.0)
            }
        }
    }
}

impl std::error::Error for BudgetExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cost() {
        assert_eq!(Budget::parse_cost("$10.00").unwrap(), 1000);
        assert_eq!(Budget::parse_cost("$0.50").unwrap(), 50);
        assert_eq!(Budget::parse_cost("100").unwrap(), 10000);
    }

    #[test]
    fn test_budget_enforcement() {
        let budget = Budget {
            max_tokens: Some(1000),
            max_cost_cents: Some(100), // $1.00
        };
        let enforcer = BudgetEnforcer::new(budget);

        // Should succeed
        assert!(enforcer.check_and_update(500, 50).is_ok());

        // Should succeed (total 1000 tokens, $1.00)
        assert!(enforcer.check_and_update(500, 50).is_ok());

        // Should fail - exceeds token limit
        assert!(enforcer.check_and_update(1, 0).is_err());
    }

    #[test]
    fn test_no_limits() {
        let budget = Budget {
            max_tokens: None,
            max_cost_cents: None,
        };
        let enforcer = BudgetEnforcer::new(budget);

        // Should always succeed
        assert!(enforcer.check_and_update(1000000, 100000).is_ok());

        let usage = enforcer.get_usage();
        assert_eq!(usage.tokens_used, 1000000);
        assert_eq!(usage.cost_cents, 100000);
    }
}

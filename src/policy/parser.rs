// purple/src/policy/parser.rs

use super::Policy;
use std::fs;
use std::path::Path;

/// Loads a policy from a YAML file.
pub fn load_policy_from_file(path: &Path) -> Result<Policy, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    let policy: Policy = serde_yaml::from_str(&contents)?;
    Ok(policy)
}

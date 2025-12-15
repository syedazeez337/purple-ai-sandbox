// src/tests/test_policy.rs

use crate::policy::parser::load_policy_from_file;
use std::path::PathBuf;

#[test]
fn test_load_valid_policy() {
    let policy_path = PathBuf::from("./policies/ai-dev-safe.yaml");
    let result = load_policy_from_file(&policy_path);
    
    assert!(result.is_ok(), "Should be able to load valid policy");
    
    let policy = result.unwrap();
    assert_eq!(policy.name, "ai-dev-safe");
    assert!(policy.description.is_some());
    assert_eq!(policy.description.unwrap(), "Policy for a development AI agent with safe defaults.");
}

#[test]
fn test_policy_compilation() {
    let policy_path = PathBuf::from("./policies/ai-dev-safe.yaml");
    let policy = load_policy_from_file(&policy_path).unwrap();
    
    let compiled = policy.compile();
    assert!(compiled.is_ok(), "Policy should compile successfully");
    
    let compiled_policy = compiled.unwrap();
    assert_eq!(compiled_policy.name, "ai-dev-safe");
    assert_eq!(compiled_policy.syscalls.default_deny, true);
    assert!(!compiled_policy.syscalls.allowed_syscall_numbers.is_empty());
    assert_eq!(compiled_policy.capabilities.default_drop, true);
    assert!(!compiled_policy.capabilities.added_capabilities.is_empty());
}

#[test]
fn test_syscall_compilation() {
    let policy_path = PathBuf::from("./policies/ai-dev-safe.yaml");
    let policy = load_policy_from_file(&policy_path).unwrap();
    let compiled = policy.compile().unwrap();
    
    // Check that known syscalls are compiled correctly
    let allowed_syscalls = compiled.syscalls.allowed_syscall_numbers;
    
    // These syscall numbers should be present based on the policy
    assert!(allowed_syscalls.contains(&0));    // read
    assert!(allowed_syscalls.contains(&1));    // write
    assert!(allowed_syscalls.contains(&59));   // execve
    assert!(allowed_syscalls.contains(&257));  // openat
    assert!(allowed_syscalls.contains(&231));  // exit_group
}

#[test]
fn test_resource_compilation() {
    let policy_path = PathBuf::from("./policies/ai-dev-safe.yaml");
    let policy = load_policy_from_file(&policy_path).unwrap();
    let compiled = policy.compile().unwrap();
    
    let resources = compiled.resources;
    
    // Check that resource limits are parsed correctly
    assert_eq!(resources.cpu_shares, Some(0.5));
    assert_eq!(resources.memory_limit_bytes, Some(2147483648)); // 2GB in bytes
    assert_eq!(resources.pids_limit, Some(100));
    assert_eq!(resources.session_timeout_seconds, Some(3600));
}

#[test]
fn test_network_compilation() {
    let policy_path = PathBuf::from("./policies/ai-dev-safe.yaml");
    let policy = load_policy_from_file(&policy_path).unwrap();
    let compiled = policy.compile().unwrap();
    
    let network = compiled.network;
    
    // Check network policy compilation
    assert_eq!(network.isolated, false);
    assert!(network.allowed_outgoing_ports.contains(&443)); // HTTPS
    assert!(network.allowed_outgoing_ports.contains(&53));  // DNS
    assert!(network.allowed_incoming_ports.is_empty());
}
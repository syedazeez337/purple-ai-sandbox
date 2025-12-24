//! Property-based tests for Purple AI Sandbox
//!
//! These tests use proptest to discover edge cases through randomized input generation.

use proptest::prelude::*;
use std::path::PathBuf;

use crate::sandbox::syscall_table::{get_syscall_number, resolve_syscall_names};

proptest! {
    #[test]
    fn syscall_resolution_never_panics(names in prop::collection::vec("[a-zA-Z0-9_]*", 0..50)) {
        let _ = resolve_syscall_names(&names);
    }

    #[test]
    fn syscall_resolution_count_bounded(names in prop::collection::vec("[a-z_]+", 0..100)) {
        let numbers = resolve_syscall_names(&names);
        prop_assert!(numbers.len() <= names.len());
    }

    #[test]
    fn valid_syscalls_always_resolve(
        name in prop::sample::select(vec!["read", "write", "open", "close", "exit", "execve", "fork", "clone"])
    ) {
        let result = get_syscall_number(&name);
        prop_assert!(result.is_some(), "Valid syscall {} should resolve", name);
    }
}

proptest! {
    #[test]
    fn memory_format_parsing_safe(
        num in 1u64..1000u64,
        suffix in prop::sample::select(vec!["", "K", "M", "G", "KB", "MB", "GB"])
    ) {
        let input = format!("{}{}", num, suffix);
        let _ = crate::policy::compiler::parse_memory_size(&input);
    }

    #[test]
    fn negative_memory_rejected(num in 1i64..1000i64) {
        let input = format!("-{}M", num);
        let result = crate::policy::compiler::parse_memory_size(&input);
        prop_assert!(result.is_err(), "Negative memory {} should be rejected", input);
    }
}

proptest! {
    #[test]
    fn invalid_ports_rejected(port in 65536u32..100000u32) {
        let result = crate::policy::compiler::parse_port(&port.to_string());
        prop_assert!(result.is_err(), "Port {} should be rejected", port);
    }

    #[test]
    fn valid_ports_accepted(port in 1u16..=65535u16) {
        let result = crate::policy::compiler::parse_port(&port.to_string());
        prop_assert!(result.is_ok(), "Port {} should be accepted", port);
    }
}

proptest! {
    #[test]
    fn path_traversal_rejected(
        prefix in "[a-z/]*",
        suffix in "[a-z/]*"
    ) {
        let malicious = format!("{}/../../{}", prefix, suffix);
        let path = PathBuf::from(&malicious);
        let result = crate::policy::compiler::validate_path(&path, "test", false);
        prop_assert!(result.is_err(), "Path traversal {} should be rejected", malicious);
    }

    #[test]
    fn absolute_safe_paths_accepted(
        dir in prop::sample::select(vec!["/tmp", "/var/tmp", "/usr/bin", "/opt"])
    ) {
        let path = PathBuf::from(dir);
        let result = crate::policy::compiler::validate_path(&path, "test", false);
        prop_assert!(result.is_ok(), "Safe path {} should be accepted", dir);
    }
}

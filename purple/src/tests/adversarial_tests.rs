//! Adversarial security tests
//!
//! These tests attempt to escape or circumvent sandbox protections.
//! All tests should FAIL (i.e., the attack should be blocked).

use crate::policy::Policy;
use crate::sandbox::syscall_table::resolve_syscall_names;
use std::path::PathBuf;

#[test]
fn test_path_traversal_dot_dot_slash() {
    let malicious_paths = vec![
        "../../../etc/passwd",
        "foo/../../../etc/shadow",
        "/tmp/../../../root/.ssh/id_rsa",
        "....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
    ];

    for path in malicious_paths {
        let result = crate::policy::compiler::validate_path(&PathBuf::from(path), "test", false);
        assert!(
            result.is_err(),
            "Path traversal should be blocked: {}",
            path
        );
    }
}

#[test]
fn test_symlink_escape_paths() {
    let symlink_paths = vec!["/proc/self/cwd/../../../etc/passwd"];

    for path in symlink_paths {
        let result = crate::policy::compiler::validate_path(&PathBuf::from(path), "test", false);
        assert!(
            result.is_err(),
            "Symlink escape should be blocked: {}",
            path
        );
    }
}

#[test]
fn test_sensitive_directories_blocked() {
    let forbidden = vec![
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/root",
        "/boot",
        "/proc/kcore",
        "/sys/kernel/security",
        "/dev/mem",
        "/dev/kmem",
    ];

    for path in forbidden {
        let result = crate::policy::compiler::validate_path(&PathBuf::from(path), "test", true);
        assert!(
            result.is_err(),
            "Forbidden path should be blocked: {}",
            path
        );
    }
}

#[test]
fn test_malformed_yaml_handling() {
    let long_input = "a".repeat(1_000_000);
    let malformed_yamls = vec![
        "name: test\nsyscalls: {{{invalid",
        "name: \x00null_byte\nsyscalls: {}",
        &long_input,
    ];

    for yaml in malformed_yamls {
        let result = serde_yaml::from_str::<Policy>(yaml);
        if result.is_ok() {
            let policy = result.unwrap();
            let _ = policy.compile();
        }
    }
}

#[test]
fn test_resource_limit_bypass() {
    let test_cases = vec![("-1", false), ("1E100", false)];

    for (input, should_pass) in test_cases {
        let result = crate::policy::compiler::parse_memory_size(input);
        if should_pass {
            assert!(result.is_ok(), "Should accept: {}", input);
        } else {
            assert!(result.is_err(), "Should reject: {}", input);
        }
    }
}

#[test]
fn test_unknown_syscall_handling() {
    let unknown_syscalls = vec![
        "definitely_not_a_syscall".to_string(),
        "read; rm -rf /".to_string(),
        "$(whoami)".to_string(),
        "\x00\x01\x02".to_string(),
    ];

    let result = resolve_syscall_names(&unknown_syscalls);
    assert!(result.is_empty(), "Unknown syscalls should be rejected");
}

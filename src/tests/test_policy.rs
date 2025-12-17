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
    assert_eq!(
        policy.description.unwrap(),
        "Policy for a development AI agent with safe defaults."
    );
}

#[test]
fn test_policy_compilation() {
    let policy_path = PathBuf::from("./policies/ai-dev-safe.yaml");
    let policy = load_policy_from_file(&policy_path).unwrap();

    let compiled = policy.compile();
    assert!(compiled.is_ok(), "Policy should compile successfully");

    let compiled_policy = compiled.unwrap();
    assert_eq!(compiled_policy.name, "ai-dev-safe");
    assert_eq!(compiled_policy.syscalls.default_deny, false);
    assert!(!compiled_policy.syscalls.allowed_syscall_numbers.is_empty());
    assert_eq!(compiled_policy.capabilities.default_drop, true);
    // Note: ai-dev-safe policy has add: [] (no added capabilities), which is valid
    assert!(compiled_policy.capabilities.added_capabilities.is_empty());
}

#[test]
fn test_syscall_compilation() {
    let policy_path = PathBuf::from("./policies/ai-dev-safe.yaml");
    let policy = load_policy_from_file(&policy_path).unwrap();
    let compiled = policy.compile().unwrap();

    // Check that known syscalls are compiled correctly
    let allowed_syscalls = compiled.syscalls.allowed_syscall_numbers;

    // These syscall numbers should be present based on the policy
    assert!(allowed_syscalls.contains(&0)); // read
    assert!(allowed_syscalls.contains(&1)); // write
    assert!(allowed_syscalls.contains(&59)); // execve
    assert!(allowed_syscalls.contains(&257)); // openat
    assert!(allowed_syscalls.contains(&231)); // exit_group
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
    assert!(network.allowed_outgoing_ports.contains(&53)); // DNS
    assert!(network.allowed_incoming_ports.is_empty());
}

// ============================================================================
// Path Validation Security Tests
// ============================================================================

use crate::policy::{
    AuditPolicy, CapabilityPolicy, FilesystemPolicy, NetworkPolicy, PathMapping, Policy,
    ResourcePolicy, SyscallPolicy,
};

/// Helper function to create a minimal valid policy for testing
fn create_test_policy_with_paths(
    immutable_paths: Vec<PathMapping>,
    scratch_paths: Vec<PathBuf>,
    output_paths: Vec<PathMapping>,
    working_dir: PathBuf,
) -> Policy {
    Policy {
        name: "test-policy".to_string(),
        description: Some("Test policy".to_string()),
        filesystem: FilesystemPolicy {
            immutable_paths,
            scratch_paths,
            output_paths,
            working_dir,
        },
        syscalls: SyscallPolicy {
            default_deny: true,
            allow: vec!["read".to_string(), "write".to_string()],
            deny: vec![],
        },
        resources: ResourcePolicy {
            cpu_shares: Some(0.5),
            memory_limit_bytes: None,
            pids_limit: None,
            block_io_limit: None,
            session_timeout_seconds: None,
        },
        capabilities: CapabilityPolicy {
            default_drop: true,
            add: vec![],
            drop: vec![],
        },
        network: NetworkPolicy {
            isolated: true,
            allow_outgoing: vec![],
            allow_incoming: vec![],
        },
        audit: AuditPolicy {
            enabled: false,
            log_path: PathBuf::from("/tmp/audit.log"),
            detail_level: vec![],
        },
    }
}

#[test]
fn test_path_traversal_blocked() {
    // Test that path traversal sequences are blocked
    let policy = create_test_policy_with_paths(
        vec![],
        vec![PathBuf::from("../../../etc")], // Path traversal attempt
        vec![],
        PathBuf::from("/tmp"),
    );

    let result = policy.compile();
    assert!(result.is_err(), "Path traversal should be rejected");
    assert!(result.unwrap_err().contains("Path traversal"));
}

#[test]
fn test_path_traversal_in_working_dir_blocked() {
    let policy = create_test_policy_with_paths(
        vec![],
        vec![PathBuf::from("/tmp")],
        vec![],
        PathBuf::from("/tmp/../tmp/../root"), // Path traversal in working dir
    );

    let result = policy.compile();
    assert!(
        result.is_err(),
        "Path traversal in working_dir should be rejected"
    );
    assert!(result.unwrap_err().contains("Path traversal"));
}

#[test]
fn test_relative_path_blocked() {
    // Test that relative paths are blocked
    let policy = create_test_policy_with_paths(
        vec![],
        vec![PathBuf::from("relative/path")], // Relative path
        vec![],
        PathBuf::from("/tmp"),
    );

    let result = policy.compile();
    assert!(result.is_err(), "Relative paths should be rejected");
    assert!(result.unwrap_err().contains("Relative path"));
}

#[test]
fn test_etc_shadow_blocked() {
    // Test that /etc/shadow is explicitly blocked
    let policy = create_test_policy_with_paths(
        vec![],
        vec![PathBuf::from("/tmp")],
        vec![PathMapping {
            host_path: PathBuf::from("/etc/shadow"),
            sandbox_path: PathBuf::from("/output/shadow"),
        }],
        PathBuf::from("/tmp"),
    );

    let result = policy.compile();
    assert!(result.is_err(), "/etc/shadow should be rejected");
    assert!(result.unwrap_err().contains("Forbidden path"));
}

#[test]
fn test_root_directory_blocked() {
    // Test that /root is blocked
    let policy = create_test_policy_with_paths(
        vec![],
        vec![PathBuf::from("/tmp")],
        vec![PathMapping {
            host_path: PathBuf::from("/root"),
            sandbox_path: PathBuf::from("/output/root"),
        }],
        PathBuf::from("/tmp"),
    );

    let result = policy.compile();
    assert!(result.is_err(), "/root should be rejected");
    assert!(result.unwrap_err().contains("Forbidden path"));
}

#[test]
fn test_home_directory_blocked() {
    // Test that /home/* is blocked
    let policy = create_test_policy_with_paths(
        vec![],
        vec![PathBuf::from("/tmp")],
        vec![PathMapping {
            host_path: PathBuf::from("/home/user/.ssh"),
            sandbox_path: PathBuf::from("/output/ssh"),
        }],
        PathBuf::from("/tmp"),
    );

    let result = policy.compile();
    assert!(result.is_err(), "/home/* should be rejected");
    assert!(result.unwrap_err().contains("Forbidden path prefix"));
}

#[test]
fn test_etc_ssh_blocked() {
    // Test that /etc/ssh is blocked
    let policy = create_test_policy_with_paths(
        vec![PathMapping {
            host_path: PathBuf::from("/etc/ssh/sshd_config"),
            sandbox_path: PathBuf::from("/config/ssh"),
        }],
        vec![PathBuf::from("/tmp")],
        vec![],
        PathBuf::from("/tmp"),
    );

    let result = policy.compile();
    assert!(result.is_err(), "/etc/ssh should be rejected");
    assert!(result.unwrap_err().contains("Forbidden path prefix"));
}

#[test]
fn test_valid_paths_accepted() {
    // Test that valid paths are accepted
    let policy = create_test_policy_with_paths(
        vec![PathMapping {
            host_path: PathBuf::from("/usr/bin"),
            sandbox_path: PathBuf::from("/usr/bin"),
        }],
        vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")],
        vec![PathMapping {
            host_path: PathBuf::from("/var/lib/purple/output"),
            sandbox_path: PathBuf::from("/output"),
        }],
        PathBuf::from("/tmp"),
    );

    let result = policy.compile();
    assert!(
        result.is_ok(),
        "Valid paths should be accepted: {:?}",
        result.err()
    );
}

#[test]
fn test_boot_directory_blocked() {
    // Test that /boot is blocked
    let policy = create_test_policy_with_paths(
        vec![PathMapping {
            host_path: PathBuf::from("/boot"),
            sandbox_path: PathBuf::from("/boot"),
        }],
        vec![PathBuf::from("/tmp")],
        vec![],
        PathBuf::from("/tmp"),
    );

    let result = policy.compile();
    assert!(result.is_err(), "/boot should be rejected");
    assert!(result.unwrap_err().contains("Forbidden path"));
}

#[test]
fn test_proc_sys_dev_blocked() {
    // Test that /proc, /sys, /dev are blocked
    for path in &["/proc", "/sys", "/dev"] {
        let policy = create_test_policy_with_paths(
            vec![PathMapping {
                host_path: PathBuf::from(*path),
                sandbox_path: PathBuf::from(*path),
            }],
            vec![PathBuf::from("/tmp")],
            vec![],
            PathBuf::from("/tmp"),
        );

        let result = policy.compile();
        assert!(result.is_err(), "{} should be rejected", path);
    }
}

// ============================================================================
// Resource Validation Tests
// ============================================================================

/// Helper to create a policy with specific resource settings
fn create_test_policy_with_resources(
    memory_limit: Option<&str>,
    block_io_limit: Option<&str>,
) -> Policy {
    Policy {
        name: "resource-test".to_string(),
        description: Some("Resource test policy".to_string()),
        filesystem: FilesystemPolicy {
            immutable_paths: vec![],
            scratch_paths: vec![PathBuf::from("/tmp")],
            output_paths: vec![],
            working_dir: PathBuf::from("/tmp"),
        },
        syscalls: SyscallPolicy {
            default_deny: true,
            allow: vec!["read".to_string(), "write".to_string()],
            deny: vec![],
        },
        resources: ResourcePolicy {
            cpu_shares: Some(0.5),
            memory_limit_bytes: memory_limit.map(String::from),
            pids_limit: Some(50),
            block_io_limit: block_io_limit.map(String::from),
            session_timeout_seconds: None,
        },
        capabilities: CapabilityPolicy {
            default_drop: true,
            add: vec![],
            drop: vec![],
        },
        network: NetworkPolicy {
            isolated: true,
            allow_outgoing: vec![],
            allow_incoming: vec![],
        },
        audit: AuditPolicy {
            enabled: false,
            log_path: PathBuf::from("/tmp/audit.log"),
            detail_level: vec![],
        },
    }
}

#[test]
fn test_invalid_memory_format_rejected() {
    let policy = create_test_policy_with_resources(Some("invalid_format"), None);
    let result = policy.compile();
    assert!(result.is_err(), "Invalid memory format should be rejected");
    assert!(result.unwrap_err().contains("Invalid memory_limit_bytes"));
}

#[test]
fn test_valid_memory_formats_accepted() {
    // Test various valid memory formats
    let test_cases = vec![
        ("2G", 2 * 1024 * 1024 * 1024),
        ("512M", 512 * 1024 * 1024),
        ("1024K", 1024 * 1024),
        ("1GB", 1024 * 1024 * 1024),
        ("256MB", 256 * 1024 * 1024),
        ("1073741824", 1073741824), // Raw bytes
    ];

    for (input, expected) in test_cases {
        let policy = create_test_policy_with_resources(Some(input), None);
        let result = policy.compile();
        assert!(
            result.is_ok(),
            "Memory format '{}' should be accepted",
            input
        );
        let compiled = result.unwrap();
        assert_eq!(
            compiled.resources.memory_limit_bytes,
            Some(expected),
            "Memory '{}' should parse to {} bytes",
            input,
            expected
        );
    }
}

#[test]
fn test_invalid_io_format_rejected() {
    let policy = create_test_policy_with_resources(None, Some("invalid_io"));
    let result = policy.compile();
    assert!(result.is_err(), "Invalid I/O format should be rejected");
    assert!(result.unwrap_err().contains("Invalid block_io_limit"));
}

#[test]
fn test_valid_io_formats_accepted() {
    // Test various valid I/O formats
    let test_cases = vec![
        ("100MBps", 100 * 1024 * 1024),
        ("1GBps", 1024 * 1024 * 1024),
        ("500KBps", 500 * 1024),
        ("1000Bps", 1000),
    ];

    for (input, expected) in test_cases {
        let policy = create_test_policy_with_resources(None, Some(input));
        let result = policy.compile();
        assert!(result.is_ok(), "I/O format '{}' should be accepted", input);
        let compiled = result.unwrap();
        assert_eq!(
            compiled.resources.block_io_limit_bytes_per_sec,
            Some(expected),
            "I/O '{}' should parse to {} bytes/sec",
            input,
            expected
        );
    }
}

#[test]
fn test_empty_memory_value_rejected() {
    let policy = create_test_policy_with_resources(Some(""), None);
    let result = policy.compile();
    assert!(result.is_err(), "Empty memory value should be rejected");
}

#[test]
fn test_negative_memory_rejected() {
    let policy = create_test_policy_with_resources(Some("-1G"), None);
    let result = policy.compile();
    assert!(result.is_err(), "Negative memory should be rejected");
}

// ============================================================================
// Network Port Validation Tests
// ============================================================================

/// Helper to create a policy with specific network settings
fn create_test_policy_with_ports(outgoing: Vec<&str>, incoming: Vec<&str>) -> Policy {
    Policy {
        name: "network-test".to_string(),
        description: Some("Network test policy".to_string()),
        filesystem: FilesystemPolicy {
            immutable_paths: vec![],
            scratch_paths: vec![PathBuf::from("/tmp")],
            output_paths: vec![],
            working_dir: PathBuf::from("/tmp"),
        },
        syscalls: SyscallPolicy {
            default_deny: true,
            allow: vec!["read".to_string(), "write".to_string()],
            deny: vec![],
        },
        resources: ResourcePolicy {
            cpu_shares: None,
            memory_limit_bytes: None,
            pids_limit: None,
            block_io_limit: None,
            session_timeout_seconds: None,
        },
        capabilities: CapabilityPolicy {
            default_drop: true,
            add: vec![],
            drop: vec![],
        },
        network: NetworkPolicy {
            isolated: false,
            allow_outgoing: outgoing.iter().map(|s| s.to_string()).collect(),
            allow_incoming: incoming.iter().map(|s| s.to_string()).collect(),
        },
        audit: AuditPolicy {
            enabled: false,
            log_path: PathBuf::from("/tmp/audit.log"),
            detail_level: vec![],
        },
    }
}

#[test]
fn test_valid_ports_accepted() {
    let policy = create_test_policy_with_ports(vec!["443", "80", "53"], vec!["8080"]);
    let result = policy.compile();
    assert!(result.is_ok(), "Valid ports should be accepted");
    let compiled = result.unwrap();
    assert!(compiled.network.allowed_outgoing_ports.contains(&443));
    assert!(compiled.network.allowed_outgoing_ports.contains(&80));
    assert!(compiled.network.allowed_incoming_ports.contains(&8080));
}

#[test]
fn test_port_exceeds_max_rejected() {
    let policy = create_test_policy_with_ports(vec!["99999"], vec![]);
    let result = policy.compile();
    assert!(result.is_err(), "Port exceeding 65535 should be rejected");
    assert!(result.unwrap_err().contains("exceeds maximum"));
}

#[test]
fn test_negative_port_rejected() {
    let policy = create_test_policy_with_ports(vec!["-1"], vec![]);
    let result = policy.compile();
    assert!(result.is_err(), "Negative port should be rejected");
    assert!(result.unwrap_err().contains("negative"));
}

#[test]
fn test_invalid_port_string_rejected() {
    let policy = create_test_policy_with_ports(vec!["abc"], vec![]);
    let result = policy.compile();
    assert!(result.is_err(), "Non-numeric port should be rejected");
}

#[test]
fn test_port_zero_rejected() {
    let policy = create_test_policy_with_ports(vec!["0"], vec![]);
    let result = policy.compile();
    assert!(result.is_err(), "Port 0 should be rejected");
    assert!(result.unwrap_err().contains("reserved"));
}

#[test]
fn test_boundary_port_accepted() {
    // Test edge cases: port 1 and port 65535
    let policy = create_test_policy_with_ports(vec!["1", "65535"], vec![]);
    let result = policy.compile();
    assert!(result.is_ok(), "Boundary ports should be accepted");
    let compiled = result.unwrap();
    assert!(compiled.network.allowed_outgoing_ports.contains(&1));
    assert!(compiled.network.allowed_outgoing_ports.contains(&65535));
}

// ============================================================================
// Syscall Policy Validation Tests
// ============================================================================

#[test]
fn test_empty_syscall_list_with_default_deny_rejected() {
    // Policy with default_deny=true but no allowed syscalls should be rejected
    let policy = Policy {
        name: "empty-syscalls".to_string(),
        description: Some("Empty syscall test".to_string()),
        filesystem: FilesystemPolicy {
            immutable_paths: vec![],
            scratch_paths: vec![PathBuf::from("/tmp")],
            output_paths: vec![],
            working_dir: PathBuf::from("/tmp"),
        },
        syscalls: SyscallPolicy {
            default_deny: true,
            allow: vec![], // Empty!
            deny: vec![],
        },
        resources: ResourcePolicy {
            cpu_shares: None,
            memory_limit_bytes: None,
            pids_limit: None,
            block_io_limit: None,
            session_timeout_seconds: None,
        },
        capabilities: CapabilityPolicy {
            default_drop: true,
            add: vec![],
            drop: vec![],
        },
        network: NetworkPolicy {
            isolated: true,
            allow_outgoing: vec![],
            allow_incoming: vec![],
        },
        audit: AuditPolicy {
            enabled: false,
            log_path: PathBuf::from("/tmp/audit.log"),
            detail_level: vec![],
        },
    };

    let result = policy.compile();
    assert!(
        result.is_err(),
        "Empty syscall list with default_deny should be rejected"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("no syscalls are allowed"),
        "Error should mention no syscalls allowed"
    );
}

#[test]
fn test_empty_syscall_list_with_default_allow_accepted() {
    // Policy with default_deny=false and empty allow list is valid (allows everything)
    let policy = Policy {
        name: "default-allow".to_string(),
        description: Some("Default allow test".to_string()),
        filesystem: FilesystemPolicy {
            immutable_paths: vec![],
            scratch_paths: vec![PathBuf::from("/tmp")],
            output_paths: vec![],
            working_dir: PathBuf::from("/tmp"),
        },
        syscalls: SyscallPolicy {
            default_deny: false, // Allow by default
            allow: vec![],
            deny: vec![],
        },
        resources: ResourcePolicy {
            cpu_shares: None,
            memory_limit_bytes: None,
            pids_limit: None,
            block_io_limit: None,
            session_timeout_seconds: None,
        },
        capabilities: CapabilityPolicy {
            default_drop: true,
            add: vec![],
            drop: vec![],
        },
        network: NetworkPolicy {
            isolated: true,
            allow_outgoing: vec![],
            allow_incoming: vec![],
        },
        audit: AuditPolicy {
            enabled: false,
            log_path: PathBuf::from("/tmp/audit.log"),
            detail_level: vec![],
        },
    };

    let result = policy.compile();
    assert!(
        result.is_ok(),
        "Empty syscall list with default_deny=false should be accepted"
    );
}

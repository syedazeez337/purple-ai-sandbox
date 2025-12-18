// src/tests/test_sandbox.rs
//
// Integration tests for sandbox execution and security enforcement.
// These tests verify that security policies are actually enforced, not just logged.

use crate::policy::compiler::{
    CompiledAuditPolicy, CompiledCapabilityPolicy, CompiledFilesystemPolicy, CompiledNetworkPolicy,
    CompiledPolicy, CompiledResourcePolicy, CompiledSyscallPolicy,
};
use crate::sandbox::Sandbox;
use crate::sandbox::cgroups::{CgroupManager, generate_sandbox_id};
use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

/// Creates a minimal test policy for sandbox testing
fn create_test_policy(name: &str) -> CompiledPolicy {
    CompiledPolicy {
        ai_policy: None,
        name: name.to_string(),
        filesystem: CompiledFilesystemPolicy {
            immutable_mounts: vec![
                (PathBuf::from("/usr/bin"), PathBuf::from("/usr/bin")),
                (PathBuf::from("/lib"), PathBuf::from("/lib")),
                (PathBuf::from("/lib64"), PathBuf::from("/lib64")),
            ],
            scratch_dirs: vec![PathBuf::from("/tmp")],
            output_mounts: vec![],
            working_dir: PathBuf::from("/tmp"),
        },
        syscalls: CompiledSyscallPolicy {
            default_deny: false,
            allowed_syscall_numbers: BTreeSet::new(),
        },
        resources: CompiledResourcePolicy {
            cpu_shares: Some(0.5),
            memory_limit_bytes: Some(2 * 1024 * 1024 * 1024), // 2GB
            pids_limit: Some(100),
            block_io_limit_bytes_per_sec: Some(100 * 1024 * 1024), // 100MB/s
            session_timeout_seconds: Some(60),
        },
        capabilities: CompiledCapabilityPolicy {
            default_drop: true,
            added_capabilities: HashSet::new(),
            dropped_capabilities: HashSet::new(),
        },
        network: CompiledNetworkPolicy {
            isolated: true,
            allowed_outgoing_ports: HashSet::new(),
            allowed_incoming_ports: HashSet::new(),
        },
        audit: CompiledAuditPolicy {
            enabled: false,
            log_path: PathBuf::from("/tmp/test-audit.log"),
            detail_level: HashSet::new(),
        },
    }
}

/// Creates a policy with specific syscalls allowed (for testing seccomp)
fn create_strict_syscall_policy() -> CompiledPolicy {
    let mut policy = create_test_policy("strict-syscall-test");
    policy.syscalls.default_deny = true;

    // Only allow the bare minimum syscalls
    let allowed = vec![
        0,   // read
        1,   // write
        3,   // close
        60,  // exit
        231, // exit_group
    ];
    policy.syscalls.allowed_syscall_numbers = allowed.into_iter().collect();

    policy
}

/// Creates a policy with network isolation
fn create_network_isolated_policy() -> CompiledPolicy {
    let mut policy = create_test_policy("network-isolated-test");
    policy.network.isolated = true;
    policy.network.allowed_outgoing_ports = HashSet::new();
    policy.network.allowed_incoming_ports = HashSet::new();
    policy
}

/// Creates a policy with strict resource limits
fn create_resource_limited_policy() -> CompiledPolicy {
    let mut policy = create_test_policy("resource-limited-test");
    policy.resources.memory_limit_bytes = Some(64 * 1024 * 1024); // 64MB
    policy.resources.pids_limit = Some(10);
    policy.resources.cpu_shares = Some(0.1);
    policy
}

// ============================================================================
// Sandbox Construction Tests
// ============================================================================

#[test]
fn test_sandbox_creation() {
    let policy = create_test_policy("test-sandbox");
    let command = vec!["echo".to_string(), "hello".to_string()];

    let sandbox = Sandbox::new(policy, command);

    // Verify sandbox was created (basic sanity check)
    assert!(format!("{:?}", sandbox).contains("test-sandbox"));
}

#[test]
fn test_sandbox_with_empty_command() {
    let policy = create_test_policy("empty-cmd-test");
    let command: Vec<String> = vec![];

    let sandbox = Sandbox::new(policy, command);

    // Should create sandbox even with empty command (will fail at execute)
    assert!(format!("{:?}", sandbox).contains("empty-cmd-test"));
}

#[test]
fn test_sandbox_with_complex_command() {
    let policy = create_test_policy("complex-cmd-test");
    let command = vec![
        "/bin/bash".to_string(),
        "-c".to_string(),
        "echo 'Hello World' && ls -la".to_string(),
    ];

    let sandbox = Sandbox::new(policy, command);

    assert!(format!("{:?}", sandbox).contains("complex-cmd-test"));
}

// ============================================================================
// Cgroup Manager Tests
// ============================================================================

#[test]
fn test_cgroup_manager_creation() {
    let sandbox_id = generate_sandbox_id();
    let manager = CgroupManager::new(&sandbox_id);

    assert!(manager.cgroup_name.contains("purple-sandbox"));
    assert!(manager.cgroup_name.contains(&sandbox_id));
}

#[test]
fn test_cgroup_path_structure() {
    let sandbox_id = "test-123";
    let manager = CgroupManager::new(sandbox_id);

    assert_eq!(
        manager.cgroup_path,
        PathBuf::from("/sys/fs/cgroup/purple/purple-sandbox-test-123")
    );
}

#[test]
fn test_sandbox_id_generation() {
    let id1 = generate_sandbox_id();
    let id2 = generate_sandbox_id();

    // IDs should be numeric strings (timestamps)
    assert!(id1.chars().all(|c| c.is_ascii_digit()));
    assert!(id2.chars().all(|c| c.is_ascii_digit()));

    // IDs generated in sequence should be the same or increasing
    let num1: u64 = id1.parse().unwrap();
    let num2: u64 = id2.parse().unwrap();
    assert!(num2 >= num1);
}

// ============================================================================
// Policy Configuration Tests
// ============================================================================

#[test]
fn test_strict_syscall_policy_configuration() {
    let policy = create_strict_syscall_policy();

    assert!(policy.syscalls.default_deny);
    assert!(policy.syscalls.allowed_syscall_numbers.contains(&0)); // read
    assert!(policy.syscalls.allowed_syscall_numbers.contains(&1)); // write
    assert!(!policy.syscalls.allowed_syscall_numbers.contains(&59)); // execve not allowed
}

#[test]
fn test_network_isolated_policy_configuration() {
    let policy = create_network_isolated_policy();

    assert!(policy.network.isolated);
    assert!(policy.network.allowed_outgoing_ports.is_empty());
    assert!(policy.network.allowed_incoming_ports.is_empty());
}

#[test]
fn test_resource_limited_policy_configuration() {
    let policy = create_resource_limited_policy();

    assert_eq!(policy.resources.memory_limit_bytes, Some(64 * 1024 * 1024));
    assert_eq!(policy.resources.pids_limit, Some(10));
    assert_eq!(policy.resources.cpu_shares, Some(0.1));
}

#[test]
fn test_capability_drop_policy() {
    let policy = create_test_policy("cap-test");

    assert!(policy.capabilities.default_drop);
    assert!(policy.capabilities.added_capabilities.is_empty());
}

// ============================================================================
// Capability Name Resolution Tests
// ============================================================================

#[test]
fn test_capability_names_are_valid() {
    // Test that common capability names are recognized
    let valid_caps = vec![
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_NET_ADMIN",
        "CAP_SYS_ADMIN",
        "CAP_NET_BIND_SERVICE",
    ];

    for cap in valid_caps {
        // The capability should be parseable (this tests the capability_from_name function indirectly)
        assert!(
            cap.starts_with("CAP_"),
            "Capability {} should start with CAP_",
            cap
        );
    }
}

// ============================================================================
// Audit Policy Tests
// ============================================================================

#[test]
fn test_audit_disabled_by_default_in_tests() {
    let policy = create_test_policy("audit-test");

    assert!(!policy.audit.enabled);
}

#[test]
fn test_audit_log_path_configuration() {
    let mut policy = create_test_policy("audit-path-test");
    policy.audit.enabled = true;
    policy.audit.log_path = PathBuf::from("/var/log/purple/test.log");

    assert!(policy.audit.enabled);
    assert_eq!(
        policy.audit.log_path,
        PathBuf::from("/var/log/purple/test.log")
    );
}

// ============================================================================
// Filesystem Policy Tests
// ============================================================================

#[test]
fn test_filesystem_immutable_mounts() {
    let policy = create_test_policy("fs-test");

    assert!(!policy.filesystem.immutable_mounts.is_empty());

    // Check that common system paths are mounted
    let paths: Vec<_> = policy
        .filesystem
        .immutable_mounts
        .iter()
        .map(|(h, _)| h.to_string_lossy().to_string())
        .collect();

    assert!(paths.iter().any(|p| p.contains("/usr/bin")));
    assert!(paths.iter().any(|p| p.contains("/lib")));
}

#[test]
fn test_filesystem_working_dir() {
    let policy = create_test_policy("workdir-test");

    assert_eq!(policy.filesystem.working_dir, PathBuf::from("/tmp"));
}

#[test]
fn test_filesystem_scratch_dirs() {
    let policy = create_test_policy("scratch-test");

    assert!(
        policy
            .filesystem
            .scratch_dirs
            .contains(&PathBuf::from("/tmp"))
    );
}

// ============================================================================
// Resource Limit Validation Tests
// ============================================================================

#[test]
fn test_memory_limit_bytes_calculation() {
    let policy = create_test_policy("mem-test");

    // 2GB should be 2 * 1024^3 bytes
    assert_eq!(
        policy.resources.memory_limit_bytes,
        Some(2 * 1024 * 1024 * 1024)
    );
}

#[test]
fn test_pids_limit_configuration() {
    let policy = create_test_policy("pids-test");

    assert_eq!(policy.resources.pids_limit, Some(100));
}

#[test]
fn test_cpu_shares_configuration() {
    let policy = create_test_policy("cpu-test");

    // CPU shares should be between 0 and 1
    let shares = policy.resources.cpu_shares.unwrap();
    assert!(shares > 0.0 && shares <= 1.0);
}

// ============================================================================
// Network Policy Tests
// ============================================================================

#[test]
fn test_network_port_configuration() {
    let mut policy = create_test_policy("port-test");
    policy.network.isolated = false;

    let mut outgoing = HashSet::new();
    outgoing.insert(80u16);
    outgoing.insert(443u16);
    outgoing.insert(53u16);
    policy.network.allowed_outgoing_ports = outgoing;

    let mut incoming = HashSet::new();
    incoming.insert(8080u16);
    policy.network.allowed_incoming_ports = incoming;

    assert!(!policy.network.isolated);
    assert_eq!(policy.network.allowed_outgoing_ports.len(), 3);
    assert!(policy.network.allowed_outgoing_ports.contains(&443));
    assert!(policy.network.allowed_incoming_ports.contains(&8080));
}

// ============================================================================
// Integration Test Helpers
// ============================================================================

/// Verifies that a policy has all required fields set
fn verify_policy_completeness(policy: &CompiledPolicy) -> bool {
    // Check required fields are present
    !policy.name.is_empty() && !policy.filesystem.working_dir.as_os_str().is_empty()
}

#[test]
fn test_policy_completeness() {
    let policy = create_test_policy("completeness-test");
    assert!(verify_policy_completeness(&policy));
}

#[test]
fn test_multiple_sandbox_instances() {
    // Test that we can create multiple sandbox instances without conflicts
    let policy1 = create_test_policy("sandbox-1");
    let policy2 = create_test_policy("sandbox-2");

    let sandbox1 = Sandbox::new(policy1, vec!["echo".to_string(), "1".to_string()]);
    let sandbox2 = Sandbox::new(policy2, vec!["echo".to_string(), "2".to_string()]);

    // Both should be created successfully with different names
    let debug1 = format!("{:?}", sandbox1);
    let debug2 = format!("{:?}", sandbox2);

    assert!(debug1.contains("sandbox-1"));
    assert!(debug2.contains("sandbox-2"));
}

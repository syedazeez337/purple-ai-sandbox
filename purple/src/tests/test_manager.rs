// purple/src/tests/test_manager.rs

use crate::policy::compiler::{
    CompiledAuditPolicy, CompiledCapabilityPolicy, CompiledFilesystemPolicy, CompiledNetworkPolicy,
    CompiledPolicy, CompiledResourcePolicy, CompiledSyscallPolicy,
};
use crate::sandbox::manager::SandboxManager;
use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

/// Creates a minimal test policy for manager testing
fn create_test_policy(name: &str) -> CompiledPolicy {
    CompiledPolicy {
        ai_policy: None,
        name: name.to_string(),
        filesystem: CompiledFilesystemPolicy {
            immutable_mounts: vec![],
            scratch_dirs: vec![],
            output_mounts: vec![],
            working_dir: PathBuf::from("/tmp"),
        },
        syscalls: CompiledSyscallPolicy {
            default_deny: false,
            allowed_syscall_numbers: BTreeSet::new(),
        },
        resources: CompiledResourcePolicy {
            cpu_shares: Some(1.0),                 // 1.0 CPU
            memory_limit_bytes: Some(1024 * 1024), // 1MB
            pids_limit: Some(100),
            block_io_limit_bytes_per_sec: None,
            session_timeout_seconds: None,
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
            blocked_ips: HashSet::new(),
        },
        audit: CompiledAuditPolicy {
            enabled: false,
            log_path: PathBuf::from("/tmp/test-audit.log"),
            detail_level: HashSet::new(),
        },
        ebpf_monitoring: crate::policy::EbpfMonitoringPolicy::default(),
    }
}

#[test]
fn test_manager_resource_allocation_lifecycle() {
    let mut manager = SandboxManager::new();
    let initial_status = manager.get_resource_pool_status();

    // Initial state check
    assert_eq!(initial_status.allocated_cpu, 0.0);
    assert_eq!(initial_status.allocated_memory, 0);

    // Create a sandbox
    let policy = create_test_policy("test-lifecycle");
    let command = vec!["echo".to_string(), "test".to_string()];

    // Check if we can allocate
    let sandbox_id = manager
        .create_sandbox(policy, command)
        .expect("Failed to create sandbox");

    // Check allocation increased
    let status_after_create = manager.get_resource_pool_status();
    assert_eq!(status_after_create.allocated_cpu, 1.0);
    assert_eq!(status_after_create.allocated_memory, 1); // 1MB

    // Cleanup sandbox
    manager
        .cleanup_sandbox(&sandbox_id)
        .expect("Failed to cleanup sandbox");

    // Check allocation released
    let status_after_cleanup = manager.get_resource_pool_status();
    assert_eq!(status_after_cleanup.allocated_cpu, 0.0);
    assert_eq!(status_after_cleanup.allocated_memory, 0);
}

#[test]
fn test_manager_resource_limit_enforcement() {
    let mut manager = SandboxManager::new();

    // Default pool is 4 CPU, 8192 MB

    // Create a policy that requests too much CPU
    let mut huge_cpu_policy = create_test_policy("huge-cpu");
    huge_cpu_policy.resources.cpu_shares = Some(100.0); // Request 100 CPUs

    let result = manager.create_sandbox(huge_cpu_policy, vec!["echo".to_string()]);
    assert!(result.is_err(), "Should fail to allocate 100 CPUs");

    // Create a policy that requests too much Memory
    let mut huge_mem_policy = create_test_policy("huge-mem");
    huge_mem_policy.resources.memory_limit_bytes = Some(100 * 1024 * 1024 * 1024); // 100GB

    let result = manager.create_sandbox(huge_mem_policy, vec!["echo".to_string()]);
    assert!(result.is_err(), "Should fail to allocate 100GB RAM");
}

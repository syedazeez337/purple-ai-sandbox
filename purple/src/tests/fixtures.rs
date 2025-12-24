//! Test fixtures and builders for Purple testing
//!
//! Provides fluent builders for creating test policies and sandboxes.

use crate::policy::compiler::CompiledPolicy;
use crate::policy::{
    AuditPolicy, CapabilityPolicy, FilesystemPolicy, NetworkPolicy, PathMapping, Policy,
    ResourcePolicy, SyscallPolicy,
};
use std::path::PathBuf;

pub struct PolicyBuilder {
    name: String,
    syscalls: SyscallPolicy,
    resources: ResourcePolicy,
    network: NetworkPolicy,
    filesystem: FilesystemPolicy,
    capabilities: CapabilityPolicy,
    audit: AuditPolicy,
}

impl PolicyBuilder {
    #[allow(dead_code)]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            syscalls: SyscallPolicy {
                default_deny: false,
                allow: vec![],
                deny: vec![],
                advanced_rules: vec![],
            },
            resources: ResourcePolicy {
                cpu_shares: Some(0.5),
                memory_limit_bytes: Some("256M".to_string()),
                pids_limit: Some(50),
                block_io_limit: None,
                session_timeout_seconds: Some(60),
            },
            network: NetworkPolicy {
                isolated: true,
                allow_outgoing: vec![],
                allow_incoming: vec![],
                blocked_ips: vec![],
                dns_servers: None,
            },
            filesystem: FilesystemPolicy {
                immutable_paths: vec![],
                scratch_paths: vec![PathBuf::from("/tmp")],
                output_paths: vec![],
                working_dir: PathBuf::from("/tmp"),
            },
            capabilities: CapabilityPolicy {
                default_drop: true,
                add: vec![],
                drop: vec![],
            },
            audit: AuditPolicy {
                enabled: false,
                log_path: PathBuf::from("/tmp/audit.log"),
                detail_level: vec![],
            },
        }
    }

    pub fn with_default_deny(mut self) -> Self {
        self.syscalls.default_deny = true;
        self
    }

    pub fn allow_syscalls(mut self, syscalls: &[&str]) -> Self {
        self.syscalls.allow = syscalls.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn deny_syscalls(mut self, syscalls: &[&str]) -> Self {
        self.syscalls.deny = syscalls.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_memory_limit(mut self, limit: &str) -> Self {
        self.resources.memory_limit_bytes = Some(limit.to_string());
        self
    }

    pub fn with_pids_limit(mut self, limit: u64) -> Self {
        self.resources.pids_limit = Some(limit);
        self
    }

    pub fn with_network_isolated(mut self) -> Self {
        self.network.isolated = true;
        self
    }

    pub fn allow_ports(mut self, ports: &[u16]) -> Self {
        self.network.allow_outgoing = ports.iter().map(|p| p.to_string()).collect();
        self
    }

    pub fn with_mount(mut self, host: &str, sandbox: &str) -> Self {
        self.filesystem.immutable_paths.push(PathMapping {
            host_path: PathBuf::from(host),
            sandbox_path: PathBuf::from(sandbox),
        });
        self
    }

    pub fn build(self) -> Policy {
        Policy {
            name: self.name,
            description: Some("Test policy".to_string()),
            syscalls: self.syscalls,
            resources: self.resources,
            network: self.network,
            filesystem: self.filesystem,
            capabilities: self.capabilities,
            audit: self.audit,
            ai_policy: None,
            ebpf_monitoring: Default::default(),
        }
    }

    pub fn build_compiled(self) -> Result<CompiledPolicy, String> {
        self.build().compile()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_minimal_policy() {
        let policy = PolicyBuilder::new("minimal").build();
        assert_eq!(policy.name, "minimal");
    }

    #[test]
    fn example_strict_policy() {
        let policy = PolicyBuilder::new("strict")
            .with_default_deny()
            .allow_syscalls(&["read", "write", "exit", "exit_group"])
            .with_memory_limit("64M")
            .with_pids_limit(10)
            .with_network_isolated()
            .build();

        assert!(policy.syscalls.default_deny);
        assert_eq!(policy.syscalls.allow.len(), 4);
    }

    #[test]
    fn example_compiled_policy() {
        let compiled = PolicyBuilder::new("compiled-test")
            .allow_syscalls(&["read", "write"])
            .build_compiled();

        assert!(compiled.is_ok());
    }
}

// purple/src/policy/mod.rs

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub mod compiler;
pub mod parser; // Add this line

/// Top-level policy configuration for an AI agent's execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub description: Option<String>,
    pub filesystem: FilesystemPolicy,
    pub syscalls: SyscallPolicy,
    pub resources: ResourcePolicy,
    pub capabilities: CapabilityPolicy,
    pub network: NetworkPolicy,
    pub audit: AuditPolicy,
    /// AI-specific policies (optional)
    #[serde(default)]
    pub ai_policy: Option<crate::ai::AIPolicies>,
    /// eBPF monitoring configuration (optional)
    #[serde(default)]
    pub ebpf_monitoring: EbpfMonitoringPolicy,
}

/// Defines filesystem access rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    /// List of paths that are immutable (read-only) inside the sandbox.
    /// These are typically bind-mounted from the host.
    #[serde(default)]
    pub immutable_paths: Vec<PathMapping>,
    /// List of paths that are scratch (writable, disposable) inside the sandbox.
    /// These are typically temporary directories created for the sandbox session.
    #[serde(default)]
    pub scratch_paths: Vec<PathBuf>,
    /// List of paths that are output (write-only, review-gated) inside the sandbox.
    /// These are typically bind-mounted from the host with write-only permissions if possible,
    /// or marked for special handling by the orchestrator.
    #[serde(default)]
    pub output_paths: Vec<PathMapping>,
    /// Specifies the working directory for the sandboxed process.
    pub working_dir: PathBuf,
}

/// A mapping from a host path to a sandbox path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathMapping {
    pub host_path: PathBuf,
    pub sandbox_path: PathBuf,
}

/// Defines allowed and denied syscalls.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyscallPolicy {
    /// If true, all syscalls are denied by default unless explicitly allowed.
    /// This should always be true based on the axioms.
    pub default_deny: bool,
    /// List of syscalls to explicitly allow.
    #[serde(default)]
    pub allow: Vec<String>,
    /// List of syscalls to explicitly deny (overrides allow if conflict).
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Defines resource limits for the sandbox.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourcePolicy {
    /// CPU share/limit (e.g., "1.0" for one CPU, or "0.5" for half a CPU).
    pub cpu_shares: Option<f64>,
    /// Memory limit in bytes (e.g., "1G", "512M").
    pub memory_limit_bytes: Option<String>,
    /// Maximum number of processes allowed.
    pub pids_limit: Option<u64>,
    /// Disk I/O limits (TODO: More detailed structure for disk I/O).
    pub block_io_limit: Option<String>,
    /// Session timeout in seconds.
    pub session_timeout_seconds: Option<u64>,
}

/// Defines Linux capabilities to be granted or dropped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityPolicy {
    /// If true, all capabilities are dropped by default unless explicitly added.
    /// This should always be true based on the axioms.
    pub default_drop: bool,
    /// List of capabilities to explicitly add (e.g., "CAP_NET_RAW").
    #[serde(default)]
    pub add: Vec<String>,
    /// List of capabilities to drop when default_drop is false.
    #[serde(default)]
    pub drop: Vec<String>,
}

/// Defines network access rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// If true, the sandbox will have no network access (e.g., isolated network namespace).
    pub isolated: bool,
    /// Allowed outgoing connections (e.g., "8.8.8.8:53").
    #[serde(default)]
    pub allow_outgoing: Vec<String>,
    /// Allowed incoming connections.
    #[serde(default)]
    pub allow_incoming: Vec<String>,
}

/// Defines audit logging settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditPolicy {
    /// If true, generate detailed JSON audit logs.
    pub enabled: bool,
    /// Path to store audit logs within the host.
    pub log_path: PathBuf,
    /// Level of detail for logs (e.g., "syscall", "filesystem", "resource").
    #[serde(default)]
    pub detail_level: Vec<String>,
}

/// Defines eBPF monitoring configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EbpfMonitoringPolicy {
    /// If true, enable eBPF monitoring.
    #[serde(default)]
    pub enabled: bool,
    /// If true, trace syscalls.
    #[serde(default)]
    pub trace_syscalls: bool,
    /// If true, trace file access.
    #[serde(default)]
    pub trace_files: bool,
    /// If true, trace network connections.
    #[serde(default)]
    pub trace_network: bool,
    /// If true, enable correlation between LLM intents and observed actions.
    #[serde(default)]
    pub correlation_enabled: bool,
}

impl Default for EbpfMonitoringPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            trace_syscalls: true,
            trace_files: true,
            trace_network: true,
            correlation_enabled: true,
        }
    }
}

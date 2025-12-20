// purple/src/policy/compiler.rs

use super::Policy;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

/// List of sensitive system paths that should never be exposed to sandboxes
const FORBIDDEN_HOST_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/root",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
];

/// Prefixes that are forbidden for host path bindings (sensitive areas)
const FORBIDDEN_HOST_PREFIXES: &[&str] = &[
    "/etc/ssh",
    "/etc/ssl/private",
    "/var/lib/private",
    "/home/", // Protect all user home directories by default
    "/root/",
];

/// Validates a path for security issues
/// Returns Ok(normalized_path) or Err(description of security issue)
///
/// For host paths: relative paths are resolved against the current working directory.
/// This allows policies to use convenient relative paths like "./output" while
/// maintaining security by validating the resolved absolute path.
fn validate_path(path: &Path, path_type: &str, is_host_path: bool) -> Result<PathBuf, String> {
    // Resolve relative paths to absolute for host paths
    let resolved_path = if is_host_path && !path.is_absolute() {
        // Get current working directory and resolve the relative path
        let cwd = std::env::current_dir().map_err(|e| {
            format!(
                "Cannot resolve relative path in {}: failed to get current directory: {}",
                path_type, e
            )
        })?;
        cwd.join(path)
    } else {
        path.to_path_buf()
    };

    let path_str = resolved_path.to_string_lossy();

    // Check for path traversal sequences
    if path_str.contains("..") {
        return Err(format!(
            "Path traversal detected in {}: '{}'. Paths containing '..' are not allowed.",
            path_type, path_str
        ));
    }

    // Check for relative paths (sandbox paths must still be absolute)
    if !resolved_path.is_absolute() {
        return Err(format!(
            "Relative path detected in {}: '{}'. All paths must be absolute.",
            path_type, path_str
        ));
    }

    // Check for null bytes (potential injection)
    if path_str.contains('\0') {
        return Err(format!(
            "Null byte detected in {}: path contains invalid characters.",
            path_type
        ));
    }

    // Additional checks for host paths (paths on the actual system)
    if is_host_path {
        // Get current working directory for relative path allowance check
        let cwd = std::env::current_dir().ok();

        // Check against forbidden paths
        for forbidden in FORBIDDEN_HOST_PATHS {
            if path_str == *forbidden || path_str.starts_with(&format!("{}/", forbidden)) {
                return Err(format!(
                    "Forbidden path in {}: '{}'. Access to '{}' is not allowed for security reasons.",
                    path_type, path_str, forbidden
                ));
            }
        }

        // Check against forbidden prefixes
        // Exception: allow paths under the current working directory (for relative paths)
        for prefix in FORBIDDEN_HOST_PREFIXES {
            if path_str.starts_with(prefix) {
                // Allow if the path is under the current working directory
                let is_under_cwd = cwd
                    .as_ref()
                    .is_some_and(|cwd_path| resolved_path.starts_with(cwd_path));

                if !is_under_cwd {
                    return Err(format!(
                        "Forbidden path prefix in {}: '{}'. Paths starting with '{}' are not allowed \
                         (unless they are under the current working directory).",
                        path_type, path_str, prefix
                    ));
                }
            }
        }
    }

    // Normalize the path (remove redundant separators, resolve . components)
    // Note: We can't use canonicalize() here as the path might not exist yet
    let mut normalized = PathBuf::new();
    for component in resolved_path.components() {
        use std::path::Component;
        match component {
            Component::RootDir => normalized.push("/"),
            Component::Normal(c) => normalized.push(c),
            Component::CurDir => {} // Skip "."
            Component::ParentDir => {
                // This shouldn't happen due to earlier check, but be defensive
                return Err(format!(
                    "Path traversal detected in {}: cannot use parent directory references.",
                    path_type
                ));
            }
            Component::Prefix(_) => {} // Windows-only, skip
        }
    }

    Ok(normalized)
}

/// Validates a sandbox-internal path (less restrictive than host paths)
fn validate_sandbox_path(path: &Path, path_type: &str) -> Result<PathBuf, String> {
    validate_path(path, path_type, false)
}

/// Parses a memory size string (e.g., "2G", "512M", "1073741824") into bytes
/// Returns an error for invalid formats instead of silently failing
fn parse_memory_size(size_str: &str) -> Result<u64, String> {
    let size_str = size_str.trim();

    if size_str.is_empty() {
        return Err("empty value".to_string());
    }

    // Try parsing with suffix
    if let Some(num_str) = size_str.strip_suffix('G') {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'G' suffix", num_str))?;
        return Ok(num * 1024 * 1024 * 1024);
    }

    if let Some(num_str) = size_str.strip_suffix("GB") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'GB' suffix", num_str))?;
        return Ok(num * 1024 * 1024 * 1024);
    }

    if let Some(num_str) = size_str.strip_suffix('M') {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'M' suffix", num_str))?;
        return Ok(num * 1024 * 1024);
    }

    if let Some(num_str) = size_str.strip_suffix("MB") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'MB' suffix", num_str))?;
        return Ok(num * 1024 * 1024);
    }

    if let Some(num_str) = size_str.strip_suffix('K') {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'K' suffix", num_str))?;
        return Ok(num * 1024);
    }

    if let Some(num_str) = size_str.strip_suffix("KB") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'KB' suffix", num_str))?;
        return Ok(num * 1024);
    }

    // Try parsing as raw bytes
    size_str.parse::<u64>()
        .map_err(|_| "expected format: <number>G, <number>M, <number>K, or raw bytes (e.g., '2G', '512M', '1073741824')".to_string())
}

/// Parses an I/O rate string (e.g., "100MBps", "1GBps") into bytes per second
/// Returns an error for invalid formats instead of silently failing
fn parse_io_rate(rate_str: &str) -> Result<u64, String> {
    let rate_str = rate_str.trim();

    if rate_str.is_empty() {
        return Err("empty value".to_string());
    }

    if let Some(num_str) = rate_str.strip_suffix("GBps") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'GBps' suffix", num_str))?;
        return Ok(num * 1024 * 1024 * 1024);
    }

    if let Some(num_str) = rate_str.strip_suffix("MBps") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'MBps' suffix", num_str))?;
        return Ok(num * 1024 * 1024);
    }

    if let Some(num_str) = rate_str.strip_suffix("KBps") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'KBps' suffix", num_str))?;
        return Ok(num * 1024);
    }

    if let Some(num_str) = rate_str.strip_suffix("Bps") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'Bps' suffix", num_str))?;
        return Ok(num);
    }

    // Try parsing as raw bytes per second
    rate_str.parse::<u64>()
        .map_err(|_| "expected format: <number>GBps, <number>MBps, <number>KBps, or raw bytes/sec (e.g., '100MBps', '1GBps')".to_string())
}

/// Parses a port string into a valid port number (1-65535)
/// Returns an error for invalid formats or out-of-range values
fn parse_port(port_str: &str) -> Result<u16, String> {
    let port_str = port_str.trim();

    if port_str.is_empty() {
        return Err("empty value".to_string());
    }

    // Try parsing as u16 first
    match port_str.parse::<u16>() {
        Ok(port) => {
            if port == 0 {
                Err("port 0 is reserved and not allowed".to_string())
            } else {
                Ok(port)
            }
        }
        Err(_) => {
            // Check if it's a number that's too large
            if let Ok(large_port) = port_str.parse::<u64>() {
                Err(format!(
                    "port {} exceeds maximum allowed value (65535)",
                    large_port
                ))
            } else if port_str.starts_with('-') {
                Err("negative port numbers are not allowed".to_string())
            } else {
                Err("must be a valid port number (1-65535)".to_string())
            }
        }
    }
}

/// A strict, internal representation of a policy, directly consumable by the sandbox.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub name: String,
    pub filesystem: CompiledFilesystemPolicy,
    pub syscalls: CompiledSyscallPolicy,
    pub resources: CompiledResourcePolicy,
    pub capabilities: CompiledCapabilityPolicy,
    pub network: CompiledNetworkPolicy,
    pub audit: CompiledAuditPolicy,
    /// AI-specific policies for LLM monitoring and budgeting
    pub ai_policy: Option<crate::ai::AIPolicies>,
    /// eBPF monitoring configuration
    #[allow(dead_code)] // Used in main.rs and sandbox/mod.rs
    pub ebpf_monitoring: super::EbpfMonitoringPolicy,
}

/// Compiled filesystem rules.
#[derive(Debug, Clone)]
pub struct CompiledFilesystemPolicy {
    // These will likely become more complex, e.g., `Vec<MountConfig>`
    pub immutable_mounts: Vec<(PathBuf, PathBuf)>, // (host_path, sandbox_path)
    pub scratch_dirs: Vec<PathBuf>,                // Paths *within* the sandbox
    pub output_mounts: Vec<(PathBuf, PathBuf)>,    // (host_path, sandbox_path)
    pub working_dir: PathBuf,
}

/// Compiled syscall rules. Uses `BTreeSet` for efficient checking and ordering.
#[derive(Debug, Clone)]
pub struct CompiledSyscallPolicy {
    pub default_deny: bool,
    pub allowed_syscall_numbers: BTreeSet<i64>,
}

/// Compiled resource limits.
#[derive(Debug, Clone)]
pub struct CompiledResourcePolicy {
    pub cpu_shares: Option<f64>,
    pub memory_limit_bytes: Option<u64>, // Parsed into bytes
    pub pids_limit: Option<u64>,
    pub block_io_limit_bytes_per_sec: Option<u64>, // Parsed into bytes/sec
    pub session_timeout_seconds: Option<u64>,
}

impl CompiledResourcePolicy {
    /// Checks if any resource limits are specified in the policy.
    /// Note: session_timeout_seconds doesn't require cgroups, so it's excluded.
    pub fn has_resource_limits(&self) -> bool {
        self.cpu_shares.is_some()
            || self.memory_limit_bytes.is_some()
            || self.pids_limit.is_some()
            || self.block_io_limit_bytes_per_sec.is_some()
    }
}

/// Compiled capability rules.
#[derive(Debug, Clone)]
pub struct CompiledCapabilityPolicy {
    pub default_drop: bool,
    pub added_capabilities: HashSet<String>, // Linux capability names (e.g., "CAP_NET_RAW")
    pub dropped_capabilities: HashSet<String>, // Capabilities to drop when default_drop=false
}

/// Compiled network rules.
#[derive(Debug, Clone)]
pub struct CompiledNetworkPolicy {
    pub isolated: bool,
    pub allowed_outgoing_ports: HashSet<u16>, // e.g., 443, 53
    pub allowed_incoming_ports: HashSet<u16>,
    #[allow(dead_code)]
    pub blocked_ips: HashSet<std::net::Ipv4Addr>,
}

/// Compiled audit rules.
#[derive(Debug, Clone)]
pub struct CompiledAuditPolicy {
    pub enabled: bool,
    pub log_path: PathBuf,
    pub detail_level: HashSet<String>,
}

impl Policy {
    /// Compiles a declarative Policy into a strict, internal CompiledPolicy.
    pub fn compile(&self) -> Result<CompiledPolicy, String> {
        // --- Filesystem Compilation with Security Validation ---

        // Validate and collect immutable mounts
        let mut immutable_mounts = Vec::new();
        for (idx, pm) in self.filesystem.immutable_paths.iter().enumerate() {
            let host_path = validate_path(
                &pm.host_path,
                &format!("immutable_paths[{}].host_path", idx),
                true, // is_host_path
            )?;
            let sandbox_path = validate_sandbox_path(
                &pm.sandbox_path,
                &format!("immutable_paths[{}].sandbox_path", idx),
            )?;
            immutable_mounts.push((host_path, sandbox_path));
        }

        // Validate scratch directories (sandbox-internal only)
        let mut scratch_dirs = Vec::new();
        for (idx, scratch_path) in self.filesystem.scratch_paths.iter().enumerate() {
            let validated =
                validate_sandbox_path(scratch_path, &format!("scratch_paths[{}]", idx))?;
            scratch_dirs.push(validated);
        }

        // Validate and collect output mounts
        let mut output_mounts = Vec::new();
        for (idx, pm) in self.filesystem.output_paths.iter().enumerate() {
            let host_path = validate_path(
                &pm.host_path,
                &format!("output_paths[{}].host_path", idx),
                true, // is_host_path
            )?;
            let sandbox_path = validate_sandbox_path(
                &pm.sandbox_path,
                &format!("output_paths[{}].sandbox_path", idx),
            )?;
            output_mounts.push((host_path, sandbox_path));
        }

        // Validate working directory (sandbox-internal)
        let working_dir = validate_sandbox_path(&self.filesystem.working_dir, "working_dir")?;

        let compiled_filesystem = CompiledFilesystemPolicy {
            immutable_mounts,
            scratch_dirs,
            output_mounts,
            working_dir,
        };

        // --- Syscall Compilation ---
        let mut allowed_syscall_numbers = BTreeSet::new();
        for sname in &self.syscalls.allow {
            if let Some(num) = crate::sandbox::seccomp::get_syscall_number(sname) {
                allowed_syscall_numbers.insert(num);
            } else {
                return Err(format!("Unknown syscall: {}", sname));
            }
        }
        // Deny overrides allow - removes syscalls from allowed list.
        // This is useful for explicitly blocking dangerous syscalls even if
        // they were included in the allow list, or for documentation purposes.
        for sname in &self.syscalls.deny {
            if let Some(num) = crate::sandbox::seccomp::get_syscall_number(sname) {
                allowed_syscall_numbers.remove(&num);
            } else {
                return Err(format!("Unknown syscall to deny: {}", sname));
            }
        }

        let compiled_syscalls = CompiledSyscallPolicy {
            default_deny: self.syscalls.default_deny,
            allowed_syscall_numbers,
        };

        // Validate syscall policy - empty allow list with default_deny makes sandbox unusable
        if compiled_syscalls.default_deny && compiled_syscalls.allowed_syscall_numbers.is_empty() {
            return Err(
                "Invalid syscall policy: default_deny is true but no syscalls are allowed. \
                 This would create an unusable sandbox where all syscalls are blocked. \
                 At minimum, add 'exit_group' to allow the process to terminate gracefully."
                    .to_string(),
            );
        }

        // --- Resource Compilation with Strict Validation ---
        let memory_limit_bytes = if let Some(mem_str) = &self.resources.memory_limit_bytes {
            Some(
                parse_memory_size(mem_str)
                    .map_err(|e| format!("Invalid memory_limit_bytes '{}': {}", mem_str, e))?,
            )
        } else {
            None
        };

        let block_io_limit_bytes_per_sec = if let Some(io_str) = &self.resources.block_io_limit {
            Some(
                parse_io_rate(io_str)
                    .map_err(|e| format!("Invalid block_io_limit '{}': {}", io_str, e))?,
            )
        } else {
            None
        };

        let compiled_resources = CompiledResourcePolicy {
            cpu_shares: self.resources.cpu_shares,
            memory_limit_bytes,
            pids_limit: self.resources.pids_limit,
            block_io_limit_bytes_per_sec,
            session_timeout_seconds: self.resources.session_timeout_seconds,
        };

        // --- Capability Compilation ---
        let compiled_capabilities = CompiledCapabilityPolicy {
            default_drop: self.capabilities.default_drop,
            added_capabilities: self.capabilities.add.iter().cloned().collect(),
            dropped_capabilities: self.capabilities.drop.iter().cloned().collect(),
        };

        // --- Network Compilation with Strict Validation ---
        let mut allowed_outgoing_ports = HashSet::new();
        for (idx, port_str) in self.network.allow_outgoing.iter().enumerate() {
            let port = parse_port(port_str)
                .map_err(|e| format!("Invalid allow_outgoing[{}] '{}': {}", idx, port_str, e))?;
            allowed_outgoing_ports.insert(port);
        }

        let mut allowed_incoming_ports = HashSet::new();
        for (idx, port_str) in self.network.allow_incoming.iter().enumerate() {
            let port = parse_port(port_str)
                .map_err(|e| format!("Invalid allow_incoming[{}] '{}': {}", idx, port_str, e))?;
            allowed_incoming_ports.insert(port);
        }

        let mut blocked_ips = HashSet::new();
        for (idx, ip_str) in self.network.blocked_ips.iter().enumerate() {
            let ip: std::net::Ipv4Addr = ip_str
                .parse()
                .map_err(|e| format!("Invalid blocked_ips[{}] '{}': {}", idx, ip_str, e))?;
            blocked_ips.insert(ip);
        }

        let compiled_network = CompiledNetworkPolicy {
            isolated: self.network.isolated,
            allowed_outgoing_ports,
            allowed_incoming_ports,
            blocked_ips,
        };

        // --- Audit Compilation ---
        let compiled_audit = CompiledAuditPolicy {
            enabled: self.audit.enabled,
            log_path: self.audit.log_path.clone(),
            detail_level: self.audit.detail_level.iter().cloned().collect(),
        };

        // --- AI Policy Compilation ---
        let compiled_ai_policy = self.ai_policy.clone();

        Ok(CompiledPolicy {
            name: self.name.clone(),
            filesystem: compiled_filesystem,
            syscalls: compiled_syscalls,
            resources: compiled_resources,
            capabilities: compiled_capabilities,
            network: compiled_network,
            audit: compiled_audit,
            ai_policy: compiled_ai_policy,
            ebpf_monitoring: self.ebpf_monitoring.clone(),
        })
    }
}

// TODO: Add a more comprehensive syscall name to number mapping.
// This might involve reading /usr/include/asm/unistd_64.h or using a crate like `syscalls` or `libseccomp` bindings.
